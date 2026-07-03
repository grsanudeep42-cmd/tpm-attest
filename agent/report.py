"""
agent/report.py
---------------
Bundles PCR values and IMA measurements into a signed attestation report.

The nonce for the TPM quote is supplied by the caller (fetched from the
server's GET /challenge endpoint) to implement a proper challenge-response
protocol that prevents replay attacks.

If the TPM key is not provisioned or tpm2_quote fails, a RuntimeError is
raised (fail-closed). No unauthenticated report is ever returned.

Public API
----------
    read_ek_cert() -> str | None
        Attempt to read the TPM Endorsement Key (EK) X.509 certificate from
        NVRAM (index 0x1c00002 for RSA-2048 EKs) or the raw EK public key
        from the TPM hierarchy (tpm2_readpublic -c 0x81010001). Returns a
        base64-encoded string on success, or None if the EK is inaccessible.

    generate_report(nonce: str) -> dict
        Collects PCR values, IMA Merkle tree metadata, IMA summary, and a
        TPM quote bound to the caller-supplied nonce, then returns a single
        dict suitable for JSON serialisation.

Report fields
-------------
    version           : "1.1"
    timestamp         : ISO 8601 UTC datetime string
    nonce             : 64-char hex string (server-issued challenge)
    pcrs              : dict[int, str]  - from read_pcrs()
    ima_summary       : dict            - from read_ima_summary()
    ima_merkle_root   : str             - 64-char hex Merkle root hash
    ima_merkle_depth  : int             - tree depth
    ima_leaf_count    : int             - number of IMA entries measured
    quote_available   : bool            - always True (fail-closed)
    quote_msg_b64     : base64 string
    quote_sig_b64     : base64 string
    ek_cert_b64       : base64 string | None  - EK cert or public key bytes
"""

import base64
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from agent.ima_reader import build_ima_merkle_tree, read_ima_log, read_ima_summary
from agent.pcr_reader import read_pcrs

log = logging.getLogger(__name__)

# Persistent AK key handle created during provisioning
_TPM_KEY_HANDLE  = "0x81000000"
_PCR_SELECTION   = "sha256:0,1,4,7,9,10"

# Standard NVRAM indices for TPM EK certificates (RSA-2048 and ECC P-256)
_EK_CERT_NV_RSA  = "0x1c00002"
_EK_CERT_NV_ECC  = "0x1c0000a"
# Persistent EK primary key handle (standard hierarchy handle)
_EK_KEY_HANDLE   = "0x81010001"


# ---------------------------------------------------------------------------
# EK certificate / public key extraction
# ---------------------------------------------------------------------------

def read_ek_cert() -> str | None:
    """Attempt to read the TPM EK certificate or public key and return it
    as a base64-encoded string.

    Strategy (tried in order):
    1. Read the RSA-2048 EK X.509 certificate from NVRAM (0x1c00002).
    2. Read the ECC P-256 EK X.509 certificate from NVRAM (0x1c0000a).
    3. Export the raw EK public key from the persistent handle 0x81010001
       using tpm2_readpublic.

    If all three fail, returns None and logs a warning. The caller should
    continue without the EK cert and register without one — the server will
    log a warning that the machine cannot be proven hardware-backed.

    Returns
    -------
    str | None
        Base64-encoded DER certificate bytes, or base64-encoded TPM2B_PUBLIC
        bytes, or None if the EK is completely inaccessible.
    """
    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, 0o700)
    try:
        cert_path = os.path.join(tmpdir, "ek.cert")

        # 1. Try RSA EK cert from NVRAM
        for nv_index in (_EK_CERT_NV_RSA, _EK_CERT_NV_ECC):
            res = subprocess.run(
                ["tpm2_nvread", "--hierarchy=owner", nv_index, "-o", cert_path],
                capture_output=True,
            )
            if res.returncode == 0:
                with open(cert_path, "rb") as fh:
                    cert_bytes = fh.read()
                log.info(
                    "Read EK cert from NVRAM %s (%d bytes)", nv_index, len(cert_bytes)
                )
                return base64.b64encode(cert_bytes).decode()

        # 2. Try exporting raw EK public key from the persistent handle
        pub_path = os.path.join(tmpdir, "ek.pub")
        res = subprocess.run(
            ["tpm2_readpublic", "-c", _EK_KEY_HANDLE, "-o", pub_path],
            capture_output=True,
        )
        if res.returncode == 0:
            with open(pub_path, "rb") as fh:
                pub_bytes = fh.read()
            log.info(
                "Read EK public key from handle %s (%d bytes)",
                _EK_KEY_HANDLE, len(pub_bytes),
            )
            return base64.b64encode(pub_bytes).decode()

    except Exception as exc:
        log.warning("Unexpected error reading EK: %s", exc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    log.warning(
        "Could not read EK cert or public key from TPM NVRAM or persistent handle. "
        "The server will register this machine WITHOUT hardware authenticity proof. "
        "This means the attestation CANNOT distinguish a physical TPM from swtpm."
    )
    return None


# ---------------------------------------------------------------------------
# TPM quote generation
# ---------------------------------------------------------------------------

def _run_tpm_quote(nonce_hex: str) -> tuple[str, str]:
    """Attempt a TPM2 quote and return (msg_b64, sig_b64).

    Uses a private, mode-0700 temporary directory for all intermediate files
    to eliminate symlink-based races and shared-namespace attacks on /tmp.
    The directory is cleaned up regardless of outcome.

    Parameters
    ----------
    nonce_hex:
        64-character hex string used as the qualifying data for the quote.
        Must be provided by the server (challenge-response) so the server
        can verify freshness and prevent replay attacks.

    Returns
    -------
    tuple[str, str]
        A 2-tuple of (quote_msg_b64, quote_sig_b64).

    Raises
    ------
    RuntimeError
        If tpm2_quote fails for any reason (key not provisioned, TPM error,
        missing output files). Callers should treat this as a hard failure
        and not transmit an unauthenticated report.
    """
    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, 0o700)

    quote_msg_path = os.path.join(tmpdir, "quote.msg")
    quote_sig_path = os.path.join(tmpdir, "quote.sig")
    quote_pcr_path = os.path.join(tmpdir, "pcrs.ctx")

    try:
        cmd = [
            "tpm2_quote",
            "-c", _TPM_KEY_HANDLE,
            "-l", _PCR_SELECTION,
            "-q", nonce_hex,
            "-m", quote_msg_path,
            "-s", quote_sig_path,
            "-o", quote_pcr_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(
                f"tpm2_quote failed (exit {result.returncode}) - "
                f"is the AK provisioned at {_TPM_KEY_HANDLE}?\n"
                f"stderr: {result.stderr.strip()}"
            )

        try:
            with open(quote_msg_path, "rb") as fh:
                msg_b64 = base64.b64encode(fh.read()).decode()
            with open(quote_sig_path, "rb") as fh:
                sig_b64 = base64.b64encode(fh.read()).decode()
        except OSError as exc:
            raise RuntimeError(
                f"tpm2_quote succeeded but output files are missing: {exc}"
            ) from exc

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return msg_b64, sig_b64


# ---------------------------------------------------------------------------
# Full report generation
# ---------------------------------------------------------------------------

def generate_report(nonce: str) -> dict:
    """Build and return a full attestation report as a plain dict.

    The report includes PCR values, an IMA log snapshot, an IMA summary, a
    TPM quote bound to the server-issued *nonce*, and the TPM Endorsement Key
    certificate or public key (if accessible). All fields are JSON-serialisable.

    Parameters
    ----------
    nonce:
        A 64-character hex string issued by the attestation server via
        GET /challenge. Embedding this server-generated value as the TPM
        quote's qualifying data proves that the quote was generated after
        the server issued the challenge, preventing replay attacks.

    Returns
    -------
    dict
        Attestation report with keys: version, timestamp, nonce, pcrs,
        ima_summary, ima_merkle_root, ima_merkle_depth, ima_leaf_count,
        quote_available, quote_msg_b64, quote_sig_b64, ek_cert_b64.

    Raises
    ------
    ValueError
        If the nonce is not a 64-character hex string.
    RuntimeError
        If reading PCR values, the IMA log, or the TPM quote fails.
        The agent never returns an unauthenticated report — fail-closed.
    """
    if not nonce or len(nonce) != 64:
        raise ValueError(
            f"nonce must be a 64-character hex string; got "
            f"{len(nonce) if nonce else 0} chars"
        )

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    pcrs        = read_pcrs()
    ima_summary = read_ima_summary()
    ima_entries = read_ima_log()
    ima_tree    = build_ima_merkle_tree(ima_entries)

    # Raises RuntimeError on any TPM failure (fail-closed)
    quote_msg_b64, quote_sig_b64 = _run_tpm_quote(nonce)

    # EK cert — optional but highly recommended for hardware authenticity
    ek_cert_b64 = read_ek_cert()

    return {
        "version":          "1.1",
        "timestamp":        timestamp,
        "nonce":            nonce,
        "pcrs":             pcrs,
        "ima_summary":      ima_summary,
        "ima_merkle_root":  ima_tree["root"],
        "ima_merkle_depth": ima_tree["depth"],
        "ima_leaf_count":   ima_tree["leaf_count"],
        "quote_available":  True,
        "quote_msg_b64":    quote_msg_b64,
        "quote_sig_b64":    quote_sig_b64,
        "ek_cert_b64":      ek_cert_b64,  # None if EK is inaccessible
    }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets
    _test_nonce = secrets.token_hex(32)
    report = generate_report(_test_nonce)
    # Suppress binary blobs in CLI output for readability
    display = {k: (v[:32] + "…" if isinstance(v, str) and len(v) > 40 else v)
               for k, v in report.items()}
    print(json.dumps(display, indent=2))
