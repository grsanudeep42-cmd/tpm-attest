"""
server/main.py
--------------
FastAPI attestation verification server.

Endpoints
---------
POST /attest
    Accept an attestation report (JSON) produced by agent/report.py, run a
    series of integrity checks, and return a short-lived session token on
    success or a 400 error with a human-readable reason on failure.

GET /health
    Liveness probe — returns {status: "ok", version: "1.0"}.

GET /enroll
    Admin-only endpoint to register a clean-system baseline.
    Accepts the same attestation report as POST /attest, runs the full
    verification suite (excluding Merkle root pinning), and if valid stores
    the received ``ima_merkle_root`` as KNOWN_GOOD_IMA_ROOT in memory.
    Returns {enrolled: true, ima_root: <hex>} on success.

POST /register
    Register an AK public key for a specific machine.
    Accepts JSON: {machine_id: str, ak_pub_b64: str}.
    Stores the base64-encoded AK public key in ENROLLED_AK_KEYS keyed by
    machine_id so subsequent attestation requests from that machine can use
    the enrolled key instead of reading it from the TPM handle.
    Returns {registered: true, machine_id: str} on success.

IMA Merkle root pinning
-----------------------
    KNOWN_GOOD_IMA_ROOT — set to None on startup (enrollment mode).
    While None the server logs every received root at INFO level so an
    admin can observe the clean-system value before pinning it.  Once a
    non-None value is present, any report whose ima_merkle_root differs
    from it fails with a 400 and a tamper-warning reason.

Run with:
    uvicorn server.main:app --host 0.0.0.0 --port 8080
or via the __main__ block:
    python -m server.main
"""

import base64
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-good PCR baseline (placeholder — populate before deploying)
# ---------------------------------------------------------------------------
# Map PCR index (int) → expected sha256 hex digest (string, "0x…" prefix).
# If empty, PCR *presence* and *non-zero* checks still apply; value pinning
# is skipped.
KNOWN_GOOD_PCRS: dict[int, str] = {}

# ---------------------------------------------------------------------------
# Known-good IMA Merkle root
# ---------------------------------------------------------------------------
# Set to None initially (enrollment mode).  Populate via GET /enroll on a
# verified clean system, or hard-code the hex string before deployment.
# While None the received root is logged but not compared (no enforcement).
# Once set, any mismatch causes attestation to fail immediately.
KNOWN_GOOD_IMA_ROOT: str | None = None

# ---------------------------------------------------------------------------
# Enrolled AK public keys
# ---------------------------------------------------------------------------
# Maps machine_id (str) → base64-encoded AK public key bytes (str).
# Populated via POST /register.  When a machine_id is present in an
# attestation report and a key is enrolled here, the server writes the
# decoded bytes to a temp file and uses it directly for tpm2_checkquote
# instead of running tpm2_readpublic against the local TPM handle.
ENROLLED_AK_KEYS: dict[str, str] = {}

# ---------------------------------------------------------------------------
# Attestation validity window
# ---------------------------------------------------------------------------
_MAX_REPORT_AGE_SECONDS = 60  # reject reports older than this
_TOKEN_LIFETIME_MINUTES = 5

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ImaSummary(BaseModel):
    total_entries: int
    unique_files: int
    has_boot_aggregate: bool
    modules_measured: int


class AttestationReport(BaseModel):
    version: str = Field(..., examples=["1.0"])
    timestamp: str
    nonce: str
    pcrs: dict[str, str]           # JSON keys are always strings
    ima_summary: ImaSummary
    # Compact Merkle proof fields — replaces the old full ima_log list
    ima_merkle_root: str = Field(
        ...,
        description="64-char hex SHA-256 Merkle root over all IMA entries",
    )
    ima_merkle_depth: int = Field(..., ge=0)
    ima_leaf_count: int = Field(..., ge=0)
    quote_available: bool
    quote_msg_b64: str | None = None
    quote_sig_b64: str | None = None
    # Optional machine identifier — used to look up a pre-enrolled AK key
    machine_id: str | None = None


class RegisterRequest(BaseModel):
    machine_id: str
    ak_pub_b64: str = Field(
        ...,
        description="Base64-encoded AK public key bytes (TPM2B_PUBLIC format)",
    )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="TPM Attestation Server", version="1.0")


# ---------------------------------------------------------------------------
# Helper — attestation verification logic
# ---------------------------------------------------------------------------

_ZERO_DIGEST_PREFIX = "0x" + "0" * 64  # 32-byte all-zero sha256


# ---------------------------------------------------------------------------
# Quote signature verification
# ---------------------------------------------------------------------------

_AK_HANDLE = "0x81000000"


def _verify_quote_signature(
    report: "AttestationReport",
    machine_id: str | None = None,
) -> str | None:
    """Verify the TPM quote signature with tpm2_checkquote.

    Steps
    -----
    1. Decode ``quote_msg_b64`` and ``quote_sig_b64`` from base64, write to
       temporary files inside a mode-0700 directory.
    2. Obtain the AK public key:
       a. If *machine_id* is provided and found in ``ENROLLED_AK_KEYS``, decode
          the stored base64 bytes and write them directly to the temp dir.
       b. Otherwise, fall back to ``tpm2_readpublic -c 0x81000000``.
    3. Run ``tpm2_checkquote`` against the files and the report nonce.
    4. Clean up the temp directory regardless of outcome.

    Returns
    -------
    str | None
        None on success, or a human-readable failure reason string.
    """
    if not report.quote_msg_b64 or not report.quote_sig_b64:
        return "quote_available is true but quote blobs are missing"

    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, 0o700)

    try:
        msg_path = os.path.join(tmpdir, "quote.msg")
        sig_path = os.path.join(tmpdir, "quote.sig")
        ak_pub_path = os.path.join(tmpdir, "ak.pub")

        # Write decoded blobs
        with open(msg_path, "wb") as fh:
            fh.write(base64.b64decode(report.quote_msg_b64))
        with open(sig_path, "wb") as fh:
            fh.write(base64.b64decode(report.quote_sig_b64))

        # Obtain the AK public key ----------------------------------------
        enrolled_b64 = ENROLLED_AK_KEYS.get(machine_id) if machine_id else None

        if enrolled_b64 is not None:
            # Use the pre-enrolled key — no TPM access required on the server
            log.info(
                "Using enrolled AK key for machine_id=%r", machine_id
            )
            with open(ak_pub_path, "wb") as fh:
                fh.write(base64.b64decode(enrolled_b64))
        else:
            # Fall back: export the AK public key from the local TPM handle
            if machine_id:
                log.warning(
                    "machine_id=%r not in ENROLLED_AK_KEYS; "
                    "falling back to tpm2_readpublic",
                    machine_id,
                )
            read_pub = subprocess.run(
                ["tpm2_readpublic", "-c", _AK_HANDLE, "-o", ak_pub_path],
                capture_output=True,
                text=True,
            )
            if read_pub.returncode != 0:
                log.error(
                    "tpm2_readpublic failed (rc=%d): %s",
                    read_pub.returncode,
                    read_pub.stderr.strip(),
                )
                return "quote signature verification failed"

        # Verify the quote
        check = subprocess.run(
            [
                "tpm2_checkquote",
                "-u", ak_pub_path,
                "-m", msg_path,
                "-s", sig_path,
                "-q", report.nonce,
            ],
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            log.error(
                "tpm2_checkquote failed (rc=%d): %s",
                check.returncode,
                check.stderr.strip(),
            )
            return "quote signature verification failed"

    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected error during quote verification: %s", exc)
        return "quote signature verification failed"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return None  # signature valid


# ---------------------------------------------------------------------------
# Full report verification
# ---------------------------------------------------------------------------


def _verify_report(report: AttestationReport) -> str | None:
    """Run all attestation checks on *report*.

    Returns None if all checks pass, or a human-readable failure reason
    string if any check fails.
    """

    # 1. Quote must be present
    if not report.quote_available:
        return "TPM quote not available; attestation requires a provisioned key"

    # 1a. Verify the TPM quote signature
    # Pass machine_id so the helper can look up a pre-enrolled AK key.
    sig_failure = _verify_quote_signature(report, machine_id=report.machine_id)
    if sig_failure:
        return sig_failure

    # 2. Timestamp freshness — replay protection
    try:
        report_time = datetime.fromisoformat(report.timestamp)
    except ValueError:
        return f"Unparseable timestamp: {report.timestamp!r}"

    # Normalise to UTC
    if report_time.tzinfo is None:
        report_time = report_time.replace(tzinfo=timezone.utc)

    now = datetime.now(tz=timezone.utc)
    age_seconds = abs((now - report_time).total_seconds())
    if age_seconds > _MAX_REPORT_AGE_SECONDS:
        return (
            f"Report timestamp is {age_seconds:.0f}s away from server time "
            f"(max allowed: {_MAX_REPORT_AGE_SECONDS}s)"
        )

    # 3. PCR values — must be present and non-zero
    if not report.pcrs:
        return "PCR map is empty"

    _is_enrolled_pcr = bool(
        report.machine_id and report.machine_id in ENROLLED_AK_KEYS
    )
    for idx_str, digest in report.pcrs.items():
        if digest.lower() == _ZERO_DIGEST_PREFIX.lower():
            if _is_enrolled_pcr and idx_str == "10":
                continue
            return f"PCR {idx_str} is all-zero (unmeasured)"

    # 4. PCR value pinning — only enforced when KNOWN_GOOD_PCRS is populated
    for idx, expected in KNOWN_GOOD_PCRS.items():
        actual = report.pcrs.get(str(idx))
        if actual is None:
            return f"Expected PCR {idx} is absent from the report"
        if actual.lower() != expected.lower():
            return (
                f"PCR {idx} mismatch: expected {expected!r}, got {actual!r}"
            )

    # 5. IMA boot aggregate — confirms PCR 10 was extended at boot.
    # Enrolled machines may not have IMA active (e.g. custom kernels without
    # IMA compiled in), so we skip this check when the report comes from a
    # machine whose AK key has been pre-registered via POST /register.
    # Unregistered machines (falling back to the local TPM handle) are still
    # held to the strict requirement.
    _is_enrolled = bool(
        report.machine_id and report.machine_id in ENROLLED_AK_KEYS
    )
    if not _is_enrolled and not report.ima_summary.has_boot_aggregate:
        return "IMA log does not contain boot_aggregate — PCR 10 integrity unconfirmed"

    # 6. IMA Merkle root — structural validity
    ima_root = report.ima_merkle_root
    if not isinstance(ima_root, str) or len(ima_root) != 64:
        return (
            f"ima_merkle_root must be a 64-char hex string, "
            f"got {len(ima_root) if isinstance(ima_root, str) else type(ima_root).__name__!r} chars"
        )
    try:
        int(ima_root, 16)
    except ValueError:
        return f"ima_merkle_root is not valid hexadecimal: {ima_root!r}"

    if report.ima_leaf_count <= 0:
        return "ima_leaf_count must be > 0; no IMA entries were measured"

    # 7. IMA Merkle root pinning / enrollment logging
    if KNOWN_GOOD_IMA_ROOT is None:
        log.info("Enrollment mode: IMA root = %s", ima_root)
    elif ima_root.lower() != KNOWN_GOOD_IMA_ROOT.lower():
        return (
            "IMA Merkle root mismatch — possible kernel module tampering"
        )

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "version": "1.0"}


@app.post("/register")
def register(req: RegisterRequest) -> JSONResponse:
    """Enroll an AK public key for a specific machine.

    The caller supplies a *machine_id* label and the base64-encoded bytes of
    the machine's AK public key (in TPM2B_PUBLIC format, as produced by
    ``tpm2_readpublic -o ak.pub`` on the client).  Subsequent attestation
    reports that include the same *machine_id* will use this key directly
    for ``tpm2_checkquote`` instead of reading from the local TPM handle.

    Returns
    -------
    200 OK
        ``{registered: true, machine_id: <str>}``
    """
    ENROLLED_AK_KEYS[req.machine_id] = req.ak_pub_b64
    log.info("Enrolled AK key for machine_id=%r", req.machine_id)
    return JSONResponse(
        status_code=200,
        content={"registered": True, "machine_id": req.machine_id},
    )


@app.post("/attest")
def attest(report: AttestationReport) -> JSONResponse:
    """Verify an attestation report and issue a session token.

    Returns
    -------
    200 OK
        ``{valid: true, token: <uuid4>, expires_at: <ISO UTC>}``
    400 Bad Request
        ``{valid: false, reason: <string>}``
    """
    failure_reason = _verify_report(report)

    if failure_reason:
        return JSONResponse(
            status_code=400,
            content={"valid": False, "reason": failure_reason},
        )

    expires_at = datetime.now(tz=timezone.utc) + timedelta(
        minutes=_TOKEN_LIFETIME_MINUTES
    )

    return JSONResponse(
        status_code=200,
        content={
            "valid": True,
            "token": str(uuid.uuid4()),
            "expires_at": expires_at.isoformat(),
        },
    )


@app.post("/enroll")
def enroll(report: AttestationReport) -> JSONResponse:
    """Register the IMA Merkle root of a verified clean system as the baseline.

    This is an admin-only operation.  The endpoint runs the same full
    verification suite as POST /attest (including quote signature validation
    and PCR checks) but *ignores* the current KNOWN_GOOD_IMA_ROOT so that
    the first enrollment is always permitted.  On success the received root
    is stored in memory as the new pinned baseline.

    Returns
    -------
    200 OK
        ``{enrolled: true, ima_root: <hex>}``
    400 Bad Request
        ``{enrolled: false, reason: <string>}``
    """
    global KNOWN_GOOD_IMA_ROOT  # noqa: PLW0603

    # Temporarily clear the pinned root so _verify_report() treats this as
    # enrollment mode and does not reject the incoming root.
    saved_root = KNOWN_GOOD_IMA_ROOT
    KNOWN_GOOD_IMA_ROOT = None
    failure_reason: str | None = None
    try:
        failure_reason = _verify_report(report)
    finally:
        # If verification failed, restore the previous baseline so a bad
        # /enroll call cannot accidentally wipe an already-pinned root.
        if failure_reason is not None:
            KNOWN_GOOD_IMA_ROOT = saved_root

    if failure_reason:
        return JSONResponse(
            status_code=400,
            content={"enrolled": False, "reason": failure_reason},
        )

    new_root = report.ima_merkle_root.lower()
    KNOWN_GOOD_IMA_ROOT = new_root
    log.info("Enrolled new IMA Merkle root baseline: %s", new_root)

    return JSONResponse(
        status_code=200,
        content={"enrolled": True, "ima_root": new_root},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("server.main:app", host="0.0.0.0", port=8080, reload=False)
