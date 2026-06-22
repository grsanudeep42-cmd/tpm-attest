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

Run with:
    uvicorn server.main:app --host 0.0.0.0 --port 8080
or via the __main__ block:
    python -m server.main
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Known-good PCR baseline (placeholder — populate before deploying)
# ---------------------------------------------------------------------------
# Map PCR index (int) → expected sha256 hex digest (string, "0x…" prefix).
# If empty, PCR *presence* and *non-zero* checks still apply; value pinning
# is skipped.
KNOWN_GOOD_PCRS: dict[int, str] = {}

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
    ima_log: list[dict[str, Any]] = Field(default_factory=list)
    quote_available: bool
    quote_msg_b64: str | None = None
    quote_sig_b64: str | None = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="TPM Attestation Server", version="1.0")


# ---------------------------------------------------------------------------
# Helper — attestation verification logic
# ---------------------------------------------------------------------------

_ZERO_DIGEST_PREFIX = "0x" + "0" * 64  # 32-byte all-zero sha256


def _verify_report(report: AttestationReport) -> str | None:
    """Run all attestation checks on *report*.

    Returns None if all checks pass, or a human-readable failure reason
    string if any check fails.
    """

    # 1. Quote must be present
    if not report.quote_available:
        return "TPM quote not available; attestation requires a provisioned key"

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

    for idx_str, digest in report.pcrs.items():
        if digest.lower() == _ZERO_DIGEST_PREFIX.lower():
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

    # 5. IMA boot aggregate — confirms PCR 10 was extended at boot
    if not report.ima_summary.has_boot_aggregate:
        return "IMA log does not contain boot_aggregate — PCR 10 integrity unconfirmed"

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "version": "1.0"}


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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("server.main:app", host="0.0.0.0", port=8080, reload=False)
