"""
agent/report.py
---------------
Bundles PCR values and IMA measurements into a signed attestation report.

A fresh 32-byte random nonce is generated for each report to prevent replay
attacks.  If a persistent TPM key is loaded at handle 0x81000000, a TPM quote
covering the relevant PCR banks is included; otherwise the report is produced
without a quote and ``quote_available`` is set to False.

Public API
----------
    generate_report() -> dict
        Collects PCR values, IMA log, IMA summary, and an optional TPM quote,
        then returns a single dict suitable for JSON serialisation.

Report fields
-------------
    version          : "1.0"
    timestamp        : ISO 8601 UTC datetime string
    nonce            : 64-char hex string (32 random bytes)
    pcrs             : dict[int, str]  – from read_pcrs()
    ima_summary      : dict            – from read_ima_summary()
    ima_log          : list[dict]      – from read_ima_log()
    quote_available  : bool
    quote_msg_b64    : base64 string or null
    quote_sig_b64    : base64 string or null
"""

import base64
import json
import secrets
import subprocess
from datetime import datetime, timezone

from agent.ima_reader import read_ima_log, read_ima_summary
from agent.pcr_reader import read_pcrs

# Persistent key handle created during provisioning (tpm2_createprimary / evictcontrol)
_TPM_KEY_HANDLE = "0x81000000"
_PCR_SELECTION = "sha256:0,1,4,7,9,10"

# Temporary files for the tpm2_quote artefacts (in-memory paths on most distros)
_QUOTE_MSG_PATH = "/tmp/quote.msg"
_QUOTE_SIG_PATH = "/tmp/quote.sig"
_QUOTE_PCR_PATH = "/tmp/pcrs.ctx"


def _run_tpm_quote(nonce_hex: str) -> tuple[bool, str | None, str | None]:
    """Attempt a TPM2 quote and return (success, msg_b64, sig_b64).

    Parameters
    ----------
    nonce_hex:
        64-character hex string used as the qualifying data for the quote.

    Returns
    -------
    tuple[bool, str | None, str | None]
        A 3-tuple of (quote_available, quote_msg_b64, quote_sig_b64).
        If the quote fails for any reason, returns (False, None, None).
    """
    cmd = [
        "tpm2_quote",
        "-c", _TPM_KEY_HANDLE,
        "-l", _PCR_SELECTION,
        "-q", nonce_hex,
        "-m", _QUOTE_MSG_PATH,
        "-s", _QUOTE_SIG_PATH,
        "-o", _QUOTE_PCR_PATH,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        # Key may not be provisioned yet — degrade gracefully
        return False, None, None

    try:
        with open(_QUOTE_MSG_PATH, "rb") as fh:
            msg_b64 = base64.b64encode(fh.read()).decode()
        with open(_QUOTE_SIG_PATH, "rb") as fh:
            sig_b64 = base64.b64encode(fh.read()).decode()
    except OSError:
        # Output files not written despite zero exit — treat as unavailable
        return False, None, None

    return True, msg_b64, sig_b64


def generate_report() -> dict:
    """Build and return a full attestation report as a plain dict.

    The report includes PCR values, an IMA log snapshot, an IMA summary, and
    an optional TPM quote.  All fields are JSON-serialisable.

    Returns
    -------
    dict
        Attestation report with keys: version, timestamp, nonce, pcrs,
        ima_summary, ima_log, quote_available, quote_msg_b64, quote_sig_b64.

    Raises
    ------
    RuntimeError
        If reading PCR values or the IMA log fails (propagated from the
        respective reader modules).
    """
    nonce = secrets.token_hex(32)  # 32 bytes → 64 hex chars
    timestamp = datetime.now(tz=timezone.utc).isoformat()

    pcrs = read_pcrs()
    ima_summary = read_ima_summary()
    ima_log = read_ima_log()

    quote_available, quote_msg_b64, quote_sig_b64 = _run_tpm_quote(nonce)

    return {
        "version": "1.0",
        "timestamp": timestamp,
        "nonce": nonce,
        "pcrs": pcrs,
        "ima_summary": ima_summary,
        "ima_log": ima_log,
        "quote_available": quote_available,
        "quote_msg_b64": quote_msg_b64,
        "quote_sig_b64": quote_sig_b64,
    }


if __name__ == "__main__":
    report = generate_report()
    # Omit ima_log from console output — it can be thousands of entries long
    display = {k: v for k, v in report.items() if k != "ima_log"}
    print(json.dumps(display, indent=2))
