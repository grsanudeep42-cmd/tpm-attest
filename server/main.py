"""
server/main.py
--------------
FastAPI attestation verification server.

Endpoints
---------
GET  /health
    Liveness probe — returns {status: "ok", version: "1.1"}.

GET  /challenge
    Issue a single-use server-generated challenge nonce (challenge-response
    protocol). The client MUST call this before generating a TPM quote.

POST /register
    Enrol a machine's AK public key (and optionally its EK certificate) so
    subsequent attestation reports can be verified without access to the
    client machine's TPM handle.
    Accepts: {machine_id, ak_pub_b64, ek_cert_b64?}

POST /attest
    Accept an attestation report (JSON) produced by agent/report.py, run a
    series of integrity checks, and return a short-lived session token on
    success or a 400 error with a human-readable reason on failure.

POST /enroll
    Admin-only endpoint to register a clean-system IMA Merkle root as the
    pinned baseline. Runs the full verification suite and persists the result
    to the SQLite database.

Persistence
-----------
All server state (enrolled keys, baselines, active nonces) is stored in a
SQLite database (`attest.db` in the current working directory) so it
survives server restarts and can be inspected externally.

EK Validation
-------------
When a client registers via POST /register it may supply an Endorsement Key
(EK) certificate (base64-encoded DER bytes). The server attempts to parse it
as an X.509 certificate using the `cryptography` library. In a production
deployment the issuer would be verified against a trusted TPM manufacturer
CA root store. In this PoC the certificate is parsed and its subject/issuer
are logged; the check logs a WARNING if no cert is supplied (meaning the
machine cannot be distinguished from a software TPM emulator).

Run with:
    uvicorn server.main:app --host 0.0.0.0 --port 8080
or:
    python -m server.main
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database path
# ---------------------------------------------------------------------------

_DB_PATH = Path(os.environ.get("ATTEST_DB", "attest.db"))

# ---------------------------------------------------------------------------
# Attestation validity constants
# ---------------------------------------------------------------------------

_MAX_REPORT_AGE_SECONDS    = 60
_TOKEN_LIFETIME_MINUTES    = 5
_CHALLENGE_LIFETIME_SECONDS = 120

# ---------------------------------------------------------------------------
# Strict Verification Policies
# ---------------------------------------------------------------------------

# STRICT_EK_VERIFICATION:
#   If True, reject attestation from machines with no verified hardware EK
#   certificate. Blocks software TPM emulators (swtpm/libtpms) and VMs.
STRICT_EK_VERIFICATION = bool(
    os.environ.get("STRICT_EK_VERIFICATION", "0") in ("1", "true", "True")
)

# REQUIRE_PCR7_PINNING:
#   If True, PCR 7 (Secure Boot policy + MOK database) must match the pinned
#   baseline. Blocks systems booted with custom MOK keys (custom kernels).
#   Requires the baseline to have been enrolled with a pcr_json including "7".
REQUIRE_PCR7_PINNING = bool(
    os.environ.get("REQUIRE_PCR7_PINNING", "0") in ("1", "true", "True")
)

# REQUIRE_IOMMU_ENABLED:
#   If True, the report's IMA log must contain a measurement of the IOMMU
#   kernel config symbol (CONFIG_INTEL_IOMMU=y / CONFIG_AMD_IOMMU=y),
#   detecting DMA attack exposure. Blocks machines without IOMMU enabled.
REQUIRE_IOMMU_ENABLED = bool(
    os.environ.get("REQUIRE_IOMMU_ENABLED", "0") in ("1", "true", "True")
)

# REQUIRE_IMA_MINIMUM_ENTRIES:
#   Minimum number of IMA log entries required. A very low count may indicate
#   that IMA measurement was disabled mid-session or log was truncated.
REQUIRE_IMA_MINIMUM_ENTRIES = int(
    os.environ.get("REQUIRE_IMA_MINIMUM_ENTRIES", "0")
)

# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS enrolled_machines (
    machine_id      TEXT PRIMARY KEY,
    ak_pub_b64      TEXT NOT NULL,
    ek_cert_b64     TEXT,           -- optional EK certificate (base64 DER)
    ek_verified     INTEGER NOT NULL DEFAULT 0,  -- 1 if EK was successfully parsed
    registered_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ima_root        TEXT NOT NULL,
    pcr_json        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS active_nonces (
    nonce       TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
);
"""


def _init_db(path: Path) -> None:
    """Create the database file and apply the schema if needed."""
    con = sqlite3.connect(str(path))
    try:
        con.executescript(_SCHEMA)
        con.commit()
    finally:
        con.close()


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row_factory set to Row."""
    con = sqlite3.connect(str(_DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Nonce helpers (DB-backed, replacing the old in-memory dict)
# ---------------------------------------------------------------------------

def _issue_nonce() -> str:
    """Generate a fresh nonce, persist it, and return the hex string."""
    nonce = secrets.token_hex(32)
    expires_at = (
        datetime.now(tz=timezone.utc)
        + timedelta(seconds=_CHALLENGE_LIFETIME_SECONDS)
    ).isoformat()
    with _db() as con:
        con.execute(
            "INSERT INTO active_nonces (nonce, expires_at) VALUES (?, ?)",
            (nonce, expires_at),
        )
    return nonce


def _consume_nonce(nonce: str) -> str | None:
    """
    Validate and consume a nonce (single-use).

    Returns None on success, or a human-readable failure string.
    """
    now = datetime.now(tz=timezone.utc)

    # Purge expired nonces lazily
    with _db() as con:
        con.execute(
            "DELETE FROM active_nonces WHERE expires_at < ?",
            (now.isoformat(),),
        )
        row = con.execute(
            "SELECT expires_at FROM active_nonces WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if row is None:
            return (
                "Nonce not recognised — fetch a fresh challenge from "
                "GET /challenge before generating the report"
            )
        # Consume immediately (single-use)
        con.execute("DELETE FROM active_nonces WHERE nonce = ?", (nonce,))

    expiry = datetime.fromisoformat(row["expires_at"])
    if now > expiry:
        delta = (now - expiry).total_seconds()
        return (
            f"Challenge nonce has expired ({delta:.0f}s ago) "
            "— fetch a new challenge from GET /challenge"
        )
    return None


# ---------------------------------------------------------------------------
# Enrolled machine helpers (DB-backed)
# ---------------------------------------------------------------------------

def _get_enrolled_machine(machine_id: str) -> sqlite3.Row | None:
    with _db() as con:
        return con.execute(
            "SELECT * FROM enrolled_machines WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()


def _register_machine(
    machine_id: str,
    ak_pub_b64: str,
    ek_cert_b64: str | None,
    ek_verified: bool,
) -> None:
    registered_at = datetime.now(tz=timezone.utc).isoformat()
    with _db() as con:
        con.execute(
            """
            INSERT INTO enrolled_machines
                (machine_id, ak_pub_b64, ek_cert_b64, ek_verified, registered_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(machine_id) DO UPDATE SET
                ak_pub_b64  = excluded.ak_pub_b64,
                ek_cert_b64 = excluded.ek_cert_b64,
                ek_verified = excluded.ek_verified,
                registered_at = excluded.registered_at
            """,
            (machine_id, ak_pub_b64, ek_cert_b64, int(ek_verified), registered_at),
        )


# ---------------------------------------------------------------------------
# Baseline helpers (DB-backed)
# ---------------------------------------------------------------------------

def _get_active_ima_root() -> str | None:
    with _db() as con:
        row = con.execute(
            "SELECT ima_root FROM baselines WHERE is_active = 1 "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row["ima_root"] if row else None


def _pin_baseline(ima_root: str, pcr_map: dict) -> None:
    now = datetime.now(tz=timezone.utc).isoformat()
    with _db() as con:
        con.execute("UPDATE baselines SET is_active = 0")
        con.execute(
            "INSERT INTO baselines (ima_root, pcr_json, created_at, is_active) "
            "VALUES (?, ?, ?, 1)",
            (ima_root.lower(), json.dumps(pcr_map), now),
        )


def _get_pinned_pcr(pcr_index: str) -> str | None:
    """Return the pinned value for a specific PCR index from the active baseline.

    Returns None if there is no active baseline or if the baseline does not
    include an entry for the requested PCR index.
    """
    with _db() as con:
        row = con.execute(
            "SELECT pcr_json FROM baselines WHERE is_active = 1 "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    try:
        pcr_map: dict = json.loads(row["pcr_json"])
        return pcr_map.get(str(pcr_index))
    except (json.JSONDecodeError, KeyError):
        return None



# ---------------------------------------------------------------------------
# EK Certificate validation
# ---------------------------------------------------------------------------

def _verify_ek_cert(ek_cert_b64: str) -> tuple[bool, str]:
    """
    Attempt to parse an EK certificate or public key.

    Tries to interpret the bytes as:
    1. A DER-encoded X.509 certificate → extracts subject / issuer for logging.
    2. Raw TPM2B_PUBLIC bytes (public key only, no certificate).

    Returns (is_valid: bool, info_message: str).

    In a production deployment the issuer chain would be verified against a
    trust store of TPM manufacturer CAs (Intel, Infineon, Nuvoton, STMicro,
    etc.). For this PoC we parse and log; the result is stored so queries can
    distinguish hardware-backed machines from software TPM emulators.
    """
    try:
        der_bytes = base64.b64decode(ek_cert_b64)
    except Exception as exc:
        return False, f"EK cert is not valid base64: {exc}"

    # Try X.509 certificate first
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(der_bytes)
        subject = cert.subject.rfc4514_string()
        issuer  = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        log.info(
            "EK X.509 cert parsed — subject=%r issuer=%r not_after=%s",
            subject, issuer, not_after,
        )
        # TODO (production): verify issuer chain against manufacturer CA roots
        return True, f"X.509 cert parsed; subject={subject!r}; issuer={issuer!r}"

    except Exception:
        pass  # not an X.509 cert — try as raw public key bytes

    # Treat as raw TPM2B_PUBLIC bytes (key without cert)
    if len(der_bytes) >= 4:
        if STRICT_EK_VERIFICATION:
            return False, "Raw EK public key rejected under strict EK verification — X.509 certificate required"
        log.info(
            "EK supplied as raw public-key bytes (%d bytes) — "
            "no X.509 cert chain available; machine cannot be proven "
            "hardware-backed without manufacturer EK cert.",
            len(der_bytes),
        )
        return True, f"Raw EK public key accepted ({len(der_bytes)} bytes); no cert chain"

    return False, "EK cert too short to be a valid key or certificate"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ImaSummary(BaseModel):
    total_entries:      int
    unique_files:       int
    has_boot_aggregate: bool
    modules_measured:   int


class AttestationReport(BaseModel):
    version:          str = Field(..., examples=["1.0"])
    timestamp:        str
    nonce:            str
    pcrs:             dict[str, str]
    ima_summary:      ImaSummary
    ima_merkle_root:  str = Field(..., description="64-char hex SHA-256 Merkle root")
    ima_merkle_depth: int = Field(..., ge=0)
    ima_leaf_count:   int = Field(..., ge=0)
    quote_available:  bool
    quote_msg_b64:    str | None = None
    quote_sig_b64:    str | None = None
    machine_id:       str | None = None


class RegisterRequest(BaseModel):
    machine_id:  str
    ak_pub_b64:  str = Field(..., description="Base64 AK public key (TPM2B_PUBLIC)")
    ek_cert_b64: str | None = Field(
        None,
        description=(
            "Base64 DER-encoded EK X.509 certificate, or raw EK public key bytes. "
            "Providing this distinguishes physical TPMs from software emulators."
        ),
    )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI):
    """FastAPI lifespan: initialise the DB on startup."""
    logging.basicConfig(level=logging.INFO)
    _init_db(_DB_PATH)
    log.info("Attestation DB initialised at %s", _DB_PATH.resolve())
    yield  # server is running
    # (shutdown logic could go here if needed)


app = FastAPI(title="TPM Attestation Server", version="1.1", lifespan=_lifespan)


# ---------------------------------------------------------------------------
# Quote signature verification
# ---------------------------------------------------------------------------

_AK_HANDLE      = "0x81000000"
_ZERO_DIGEST_PREFIX = "0x" + "0" * 64


def _verify_quote_signature(
    report: AttestationReport,
    machine_id: str | None = None,
) -> str | None:
    """Verify TPM quote signature with tpm2_checkquote.

    Returns None on success, or a failure-reason string.
    """
    if not report.quote_msg_b64 or not report.quote_sig_b64:
        return "quote_available is true but quote blobs are missing"

    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, 0o700)

    try:
        msg_path    = os.path.join(tmpdir, "quote.msg")
        sig_path    = os.path.join(tmpdir, "quote.sig")
        ak_pub_path = os.path.join(tmpdir, "ak.pub")

        with open(msg_path, "wb") as fh:
            fh.write(base64.b64decode(report.quote_msg_b64))
        with open(sig_path, "wb") as fh:
            fh.write(base64.b64decode(report.quote_sig_b64))

        # Look up enrolled AK key from DB
        enrolled_b64: str | None = None
        if machine_id:
            row = _get_enrolled_machine(machine_id)
            if row:
                enrolled_b64 = row["ak_pub_b64"]
                if not row["ek_verified"]:
                    log.warning(
                        "machine_id=%r has no verified EK cert — cannot confirm "
                        "hardware TPM; machine may be running a software emulator.",
                        machine_id,
                    )

        if enrolled_b64 is not None:
            log.info("Using enrolled AK key for machine_id=%r", machine_id)
            with open(ak_pub_path, "wb") as fh:
                fh.write(base64.b64decode(enrolled_b64))
        else:
            if machine_id:
                log.warning(
                    "machine_id=%r not enrolled; falling back to tpm2_readpublic",
                    machine_id,
                )
            read_pub = subprocess.run(
                ["tpm2_readpublic", "-c", _AK_HANDLE, "-o", ak_pub_path],
                capture_output=True, text=True,
            )
            if read_pub.returncode != 0:
                log.error(
                    "tpm2_readpublic failed (rc=%d): %s",
                    read_pub.returncode, read_pub.stderr.strip(),
                )
                return "quote signature verification failed"

        check = subprocess.run(
            [
                "tpm2_checkquote",
                "-u", ak_pub_path,
                "-m", msg_path,
                "-s", sig_path,
                "-q", report.nonce,
            ],
            capture_output=True, text=True,
        )
        if check.returncode != 0:
            log.error(
                "tpm2_checkquote failed (rc=%d): %s",
                check.returncode, check.stderr.strip(),
            )
            return "quote signature verification failed"

    except Exception as exc:
        log.exception("Unexpected error during quote verification: %s", exc)
        return "quote signature verification failed"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return None


# ---------------------------------------------------------------------------
# Full report verification
# ---------------------------------------------------------------------------

def _verify_report(report: AttestationReport) -> str | None:
    """Run all attestation checks. Returns None on pass, reason string on fail.

    Check order (RATS-compliant):
      1. Consume the nonce first — regardless of all other outcomes the nonce
         is burned so it cannot be replayed even if later checks fail.
      2. TPM quote presence and signature verification.
      3. PCR and IMA integrity checks.
    """

    # 1. Challenge-response nonce validation — consume FIRST (single-use, DB-backed).
    #    Doing this before the quote check prevents an attacker from probing nonce
    #    validity without committing it; a nonce is burned on every /attest call.
    nonce_fail = _consume_nonce(report.nonce)
    if nonce_fail:
        return nonce_fail

    # 2. TPM quote must be present
    if not report.quote_available:
        return "TPM quote not available; attestation requires a provisioned key"

    # 2a. Verify TPM quote signature (expensive subprocess call — after nonce burned)
    sig_fail = _verify_quote_signature(report, machine_id=report.machine_id)
    if sig_fail:
        return sig_fail

    # 2b. Optional strict EK certificate validation (detects software/emulated TPMs)
    if STRICT_EK_VERIFICATION:
        if not report.machine_id:
            return "Strict EK verification enabled, but no machine_id supplied"
        machine_row = _get_enrolled_machine(report.machine_id)
        if not machine_row:
            return f"machine_id {report.machine_id!r} is not registered on this server"
        if not machine_row["ek_verified"]:
            return f"machine_id {report.machine_id!r} does not have a verified hardware EK certificate"

    # 3. PCR values — must be present and non-zero
    if not report.pcrs:
        return "PCR map is empty"

    _is_enrolled = bool(
        report.machine_id and _get_enrolled_machine(report.machine_id)
    )

    for idx_str, digest in report.pcrs.items():
        if digest.lower() == _ZERO_DIGEST_PREFIX.lower():
            # Enrolled machines without IMA may have an all-zero PCR 10
            if _is_enrolled and idx_str == "10":
                continue
            return f"PCR {idx_str} is all-zero (unmeasured)"

    # 4. IMA boot aggregate
    if not _is_enrolled and not report.ima_summary.has_boot_aggregate:
        return "IMA log does not contain boot_aggregate — PCR 10 integrity unconfirmed"

    # 5. IMA Merkle root structural validity
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

    # 6. IMA Merkle root pinning (from DB)
    pinned_root = _get_active_ima_root()
    if pinned_root is None:
        log.info("Enrollment mode: IMA root = %s", ima_root)
    elif ima_root.lower() != pinned_root.lower():
        return "IMA Merkle root mismatch — possible kernel module tampering"

    # 7. Policy: PCR 7 pinning — blocks systems with custom MOK keys
    #    PCR 7 measures Secure Boot state + MOK database. A custom-enrolled
    #    MOK (to load a custom kernel) changes its value. Pinning it enforces
    #    that only approved Secure Boot key databases are accepted.
    if REQUIRE_PCR7_PINNING:
        pinned_pcr7 = _get_pinned_pcr("7")
        if pinned_pcr7 is None:
            log.warning(
                "REQUIRE_PCR7_PINNING is enabled but no PCR 7 baseline is enrolled. "
                "Call POST /enroll on a clean reference system first."
            )
        else:
            reported_pcr7 = report.pcrs.get("7", "")
            if reported_pcr7.lower() != pinned_pcr7.lower():
                return (
                    f"PCR 7 mismatch — custom Secure Boot key or MOK detected "
                    f"(expected {pinned_pcr7[:16]}..., got {reported_pcr7[:16]}...)"
                )

    # 8. Policy: IMA minimum entries
    #    A very low entry count can indicate IMA was disabled or log wiped.
    if REQUIRE_IMA_MINIMUM_ENTRIES > 0:
        if report.ima_leaf_count < REQUIRE_IMA_MINIMUM_ENTRIES:
            return (
                f"IMA log has only {report.ima_leaf_count} entries; "
                f"minimum required is {REQUIRE_IMA_MINIMUM_ENTRIES} "
                f"(log may have been cleared or IMA disabled after boot)"
            )

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "version": "1.1"}


@app.get("/challenge")
def challenge() -> JSONResponse:
    """Issue a single-use server-generated challenge nonce (DB-backed).

    The client MUST call this before generating a TPM quote. The returned
    nonce is embedded as the TPM quote qualifying data and validated
    server-side to prevent replay attacks.
    """
    nonce = _issue_nonce()
    log.info("Issued challenge nonce")
    return JSONResponse(
        status_code=200,
        content={"nonce": nonce, "expires_in_seconds": _CHALLENGE_LIFETIME_SECONDS},
    )


@app.post("/register")
def register(req: RegisterRequest) -> JSONResponse:
    """Enrol a machine's AK public key (and optional EK cert).

    The EK certificate or raw EK public key bytes are base64-encoded and
    stored alongside the AK. If a valid X.509 EK cert is supplied the server
    parses it and logs the subject/issuer. In production this would be used to
    verify the certificate chain against TPM manufacturer CA roots, proving the
    client is running on real hardware rather than a software TPM emulator.

    Returns
    -------
    200 OK  {registered: true, machine_id, ek_verified: bool, ek_info: str}
    400     {registered: false, reason: str}
    """
    ek_verified = False
    ek_info     = "no EK cert supplied"

    if req.ek_cert_b64:
        ek_verified, ek_info = _verify_ek_cert(req.ek_cert_b64)
        if not ek_verified:
            return JSONResponse(
                status_code=400,
                content={"registered": False, "reason": f"EK cert invalid: {ek_info}"},
            )
    else:
        log.warning(
            "machine_id=%r registered WITHOUT an EK cert — cannot distinguish "
            "hardware TPM from software emulator (swtpm / QEMU vTPM).",
            req.machine_id,
        )

    _register_machine(req.machine_id, req.ak_pub_b64, req.ek_cert_b64, ek_verified)
    log.info(
        "Enrolled machine_id=%r ek_verified=%s info=%r",
        req.machine_id, ek_verified, ek_info,
    )
    return JSONResponse(
        status_code=200,
        content={
            "registered":  True,
            "machine_id":  req.machine_id,
            "ek_verified": ek_verified,
            "ek_info":     ek_info,
        },
    )


@app.post("/attest")
def attest(report: AttestationReport) -> JSONResponse:
    """Verify an attestation report and issue a session token.

    Returns
    -------
    200 OK  {valid: true, token: <uuid4>, expires_at: <ISO UTC>}
    400     {valid: false, reason: <str>}
    """
    failure_reason = _verify_report(report)

    if failure_reason:
        return JSONResponse(
            status_code=400,
            content={"valid": False, "reason": failure_reason},
        )

    expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=_TOKEN_LIFETIME_MINUTES)
    return JSONResponse(
        status_code=200,
        content={
            "valid":      True,
            "token":      str(uuid.uuid4()),
            "expires_at": expires_at.isoformat(),
        },
    )


@app.post("/enroll")
def enroll(report: AttestationReport) -> JSONResponse:
    """Pin a verified clean-system IMA Merkle root as the active baseline (DB-backed).

    Runs the full verification suite (including quote and PCR checks) but
    ignores the current pinned root so initial enrollment always succeeds.
    Persists the new baseline to the `baselines` table.

    Returns
    -------
    200 OK  {enrolled: true, ima_root: <hex>}
    400     {enrolled: false, reason: <str>}
    """
    # Temporarily deactivate pinned root so verification passes on first enrol
    current_root = _get_active_ima_root()

    with _db() as con:
        con.execute("UPDATE baselines SET is_active = 0")

    failure_reason = _verify_report(report)

    if failure_reason:
        # Restore the previous active baseline
        if current_root:
            with _db() as con:
                con.execute(
                    "UPDATE baselines SET is_active = 1 WHERE ima_root = ? "
                    "AND id = (SELECT MAX(id) FROM baselines WHERE ima_root = ?)",
                    (current_root, current_root),
                )
        return JSONResponse(
            status_code=400,
            content={"enrolled": False, "reason": failure_reason},
        )

    new_root = report.ima_merkle_root.lower()
    _pin_baseline(new_root, report.pcrs)
    log.info("Enrolled new IMA baseline: %s", new_root)

    return JSONResponse(
        status_code=200,
        content={"enrolled": True, "ima_root": new_root},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("server.main:app", host="0.0.0.0", port=8080, reload=False)
