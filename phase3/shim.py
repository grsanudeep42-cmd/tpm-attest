#!/usr/bin/env python3
"""
phase3/shim.py
--------------
EAC shim: bridges the game client (via Unix socket) to the TPM attestation
server. Implements incremental IMA caching for sub-second repeat attestation
and automatic machine registration on first startup.

Incremental IMA Caching
-----------------------
The IMA log is append-only — once a file is measured its entry never changes.
A full rehash of the log takes ~12–15 seconds on a machine that has been
running for several hours (thousands of measured files). The shim avoids this
on every subsequent attestation by maintaining a persistent in-memory cache:

    _IMA_LEAF_CACHE   : list[bytes]  – raw 32-byte leaf hashes already computed
    _IMA_LINE_OFFSET  : int          – count of lines already incorporated

On each attestation request the shim calls read_ima_log(start_line=offset)
to retrieve ONLY the new lines, hashes them using build_incremental_merkle_tree,
appends them to the cache, and updates the offset. The full Merkle root is
recomputed over all cached leaves (fast; no I/O). This reduces repeat
attestation latency from ~15 s to < 1 s.

Auto-Registration
-----------------
On first startup the shim attempts to register the local machine with the
attestation server (POST /register) using the AK public key from
tpm2_readpublic and the EK certificate/public key from read_ek_cert().
If the machine is already registered the server returns 200 and the shim
proceeds normally. If the server is unreachable at startup the shim logs a
warning and continues; registration will be attempted again on the next
restart.

Flow per connection:
  1. Accept a connection on /tmp/eac_shim.sock
  2. Read the EAC handshake JSON from the game client
  3. Fetch a single-use challenge nonce from GET /challenge
  4. Build attestation report: PCRs + IMA (incremental) + TPM quote
  5. POST the report to /attest
  6. If {valid: true} → reply {valid: true, token: <token>}
     Otherwise        → reply {valid: false, reason: <reason>}

Usage:
  python3 -m phase3.shim
  # or directly:
  python3 phase3/shim.py

Environment variables (optional):
  ATTEST_URL      — attestation server URL (default: http://localhost:8080/attest)
  CHALLENGE_URL   — challenge endpoint   (default: http://localhost:8080/challenge)
  REGISTER_URL    — register endpoint    (default: http://localhost:8080/register)
  SHIM_SOCK       — Unix socket path     (default: /tmp/eac_shim.sock)
  MACHINE_ID      — unique machine label (default: hostname)
"""

import base64
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

# Add repo root to sys.path so 'agent' is importable when run directly
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOCKET_PATH:   str = os.environ.get("SHIM_SOCK",       "/tmp/eac_shim.sock")
ATTEST_URL:    str = os.environ.get("ATTEST_URL",       "http://localhost:8080/attest")
CHALLENGE_URL: str = os.environ.get("CHALLENGE_URL",    "http://localhost:8080/challenge")
REGISTER_URL:  str = os.environ.get("REGISTER_URL",     "http://localhost:8080/register")
MACHINE_ID:    str = os.environ.get("MACHINE_ID",       socket.gethostname())

RECV_BUF:       int = 8192
ATTEST_TIMEOUT: int = 30   # seconds

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[shim] %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("shim")

# ---------------------------------------------------------------------------
# Incremental IMA leaf cache (module-level, lives for the daemon lifetime)
# ---------------------------------------------------------------------------

_IMA_LEAF_CACHE:  list[bytes] = []   # raw 32-byte SHA-256 leaf hashes
_IMA_LINE_OFFSET: int         = 0    # number of IMA lines already incorporated


# ---------------------------------------------------------------------------
# Auto-registration helpers
# ---------------------------------------------------------------------------

def _read_ak_pub_b64() -> str | None:
    """Export the AK public key from handle 0x81000000 and return base64."""
    _AK_HANDLE = "0x81000000"
    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, 0o700)
    pub_path = os.path.join(tmpdir, "ak.pub")
    try:
        res = subprocess.run(
            ["tpm2_readpublic", "-c", _AK_HANDLE, "-o", pub_path],
            capture_output=True,
        )
        if res.returncode != 0:
            log.warning(
                "tpm2_readpublic failed (rc=%d) — cannot auto-register",
                res.returncode,
            )
            return None
        with open(pub_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode()
    except Exception as exc:
        log.warning("Error reading AK public key: %s", exc)
        return None
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _auto_register() -> None:
    """Register this machine with the attestation server on startup.

    Reads the AK public key and EK certificate (via agent.report.read_ek_cert)
    and POSTs them to POST /register. If registration succeeds, the server
    stores the AK key and EK cert in its SQLite database so future attestations
    do not need to fall back to tpm2_readpublic on the server side.

    Logs a warning (but does NOT abort) if the server is unreachable or the
    AK key cannot be read.
    """
    log.info("Auto-registration: reading AK public key for machine_id=%r …", MACHINE_ID)
    ak_pub_b64 = _read_ak_pub_b64()
    if not ak_pub_b64:
        log.warning("Auto-registration skipped — could not read AK public key.")
        return

    # Read EK cert (returns None if not accessible — that's OK)
    ek_cert_b64: str | None = None
    try:
        from agent.report import read_ek_cert  # noqa: PLC0415
        ek_cert_b64 = read_ek_cert()
        if ek_cert_b64:
            log.info("EK cert/key read successfully — will submit to server.")
        else:
            log.warning(
                "EK cert not available — machine will be registered WITHOUT "
                "hardware authenticity proof (indistinguishable from swtpm)."
            )
    except Exception as exc:
        log.warning("Could not import read_ek_cert: %s", exc)

    payload = json.dumps({
        "machine_id":  MACHINE_ID,
        "ak_pub_b64":  ak_pub_b64,
        "ek_cert_b64": ek_cert_b64,
    }).encode("utf-8")

    req = urllib.request.Request(
        REGISTER_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=ATTEST_TIMEOUT) as resp:
            body = json.loads(resp.read())
        log.info(
            "Auto-registration successful: machine_id=%r ek_verified=%s info=%r",
            body.get("machine_id"),
            body.get("ek_verified"),
            body.get("ek_info"),
        )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        log.warning("Auto-registration HTTP error %d: %s", exc.code, body)
    except urllib.error.URLError as exc:
        log.warning(
            "Auto-registration failed — server unreachable at %s: %s. "
            "Continuing without registration; server will fall back to "
            "tpm2_readpublic for quote verification.",
            REGISTER_URL, exc.reason,
        )
    except Exception as exc:
        log.warning("Auto-registration unexpected error: %s", exc)


# ---------------------------------------------------------------------------
# Incremental IMA report collection
# ---------------------------------------------------------------------------

def _collect_report_incremental(nonce: str) -> dict:
    """Build the attestation report using incremental IMA hashing.

    On the first call this behaves identically to generate_report() but
    also populates the module-level leaf cache. On subsequent calls only
    new IMA lines are read and hashed, making the operation extremely fast.

    Parameters
    ----------
    nonce:
        Server-issued 64-char hex challenge nonce.

    Returns
    -------
    dict
        Attestation report dict (same schema as generate_report()).

    Raises
    ------
    RuntimeError / ValueError
        Propagated from the underlying TPM and IMA reader calls.
    """
    global _IMA_LEAF_CACHE, _IMA_LINE_OFFSET

    from agent.ima_reader import (  # noqa: PLC0415
        build_incremental_merkle_tree,
        read_ima_log,
        read_ima_log_line_count,
        read_ima_summary,
    )
    from agent.pcr_reader import read_pcrs  # noqa: PLC0415
    from agent.report import _run_tpm_quote  # noqa: PLC0415

    import base64
    from datetime import datetime, timezone

    # --- PCRs and IMA summary (always full reads; cheap) ---
    pcrs        = read_pcrs()
    ima_summary = read_ima_summary()

    # --- Incremental IMA leaf hashing ---
    total_line_count = read_ima_log_line_count()
    if total_line_count < _IMA_LINE_OFFSET:
        # IMA log was reset (e.g. reboot) — flush the cache
        log.info("IMA log reset detected — flushing leaf cache.")
        _IMA_LEAF_CACHE  = []
        _IMA_LINE_OFFSET = 0

    new_entries = read_ima_log(start_line=_IMA_LINE_OFFSET)
    log.info(
        "IMA incremental: cached=%d new=%d total=%d",
        _IMA_LINE_OFFSET, len(new_entries), _IMA_LINE_OFFSET + len(new_entries),
    )

    updated_cache, ima_tree = build_incremental_merkle_tree(
        _IMA_LEAF_CACHE, new_entries, _IMA_LINE_OFFSET
    )

    # Update module-level cache
    _IMA_LEAF_CACHE  = updated_cache
    _IMA_LINE_OFFSET = ima_tree["leaf_count"]

    # --- TPM quote (bound to server nonce — fail-closed) ---
    quote_msg_b64, quote_sig_b64 = _run_tpm_quote(nonce)

    return {
        "version":          "1.1",
        "timestamp":        datetime.now(tz=timezone.utc).isoformat(),
        "nonce":            nonce,
        "machine_id":       MACHINE_ID,
        "pcrs":             pcrs,
        "ima_summary":      ima_summary,
        "ima_merkle_root":  ima_tree["root"],
        "ima_merkle_depth": ima_tree["depth"],
        "ima_leaf_count":   ima_tree["leaf_count"],
        "quote_available":  True,
        "quote_msg_b64":    quote_msg_b64,
        "quote_sig_b64":    quote_sig_b64,
    }


# ---------------------------------------------------------------------------
# Challenge-response helpers
# ---------------------------------------------------------------------------

def _get_challenge() -> str:
    """Fetch a single-use challenge nonce from GET /challenge.

    Returns
    -------
    str
        64-character hex nonce.

    Raises
    ------
    RuntimeError
        If the endpoint is unreachable or returns unexpected data.
    """
    req = urllib.request.Request(CHALLENGE_URL, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=ATTEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach challenge endpoint at {CHALLENGE_URL}: {exc.reason}"
        ) from exc

    nonce = data.get("nonce")
    if not nonce or len(nonce) != 64:
        raise RuntimeError(f"Challenge endpoint returned invalid nonce: {nonce!r}")
    log.info("Received server challenge nonce: %s...", nonce[:16])
    return nonce


def _post_report(report: dict) -> dict:
    """POST the attestation report JSON to /attest and return the parsed response."""
    payload = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(
        ATTEST_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=ATTEST_TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        log.warning("Attestation server returned HTTP %d: %s", exc.code,
                    body.decode("utf-8", errors="replace"))
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach attestation server at {ATTEST_URL}: {exc.reason}"
        ) from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Attestation server returned non-JSON body: {body!r}"
        ) from exc


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def _send_response(conn: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    try:
        conn.sendall(data)
    except OSError as exc:
        log.error("Error sending response: %s", exc)


def _handle_client(conn: socket.socket, addr: object) -> None:
    """Process one game-client connection end-to-end."""
    log.info("Connection from %s", addr)

    # 1. Read full handshake
    chunks = []
    try:
        while True:
            chunk = conn.recv(RECV_BUF)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        log.error("Error reading handshake: %s", exc)
        conn.close()
        return

    raw = b"".join(chunks).decode("utf-8", errors="replace")
    log.info("Received handshake (%d bytes): %s", len(raw), raw)

    try:
        handshake = json.loads(raw)
        log.info(
            "Handshake parsed — game_id=%s player_id=%s platform=%s",
            handshake.get("game_id"),
            handshake.get("player_id"),
            handshake.get("platform"),
        )
    except json.JSONDecodeError:
        log.warning("Could not parse handshake as JSON — proceeding anyway")
        handshake = {}

    # 2. Fetch server-generated challenge nonce (replay prevention)
    try:
        log.info("Fetching challenge nonce from %s ...", CHALLENGE_URL)
        nonce = _get_challenge()
    except RuntimeError as exc:
        log.error("Failed to fetch challenge nonce: %s", exc)
        _send_response(conn, {"valid": False, "reason": "challenge fetch failed"})
        conn.close()
        return

    # 3. Collect attestation report (incremental IMA hashing)
    try:
        log.info(
            "Collecting TPM attestation report (nonce=%s...)...", nonce[:16]
        )
        report = _collect_report_incremental(nonce)
        log.info(
            "Report collected (nonce=%s quote_available=%s ima_leaves=%d)",
            report.get("nonce"),
            report.get("quote_available"),
            report.get("ima_leaf_count", 0),
        )
    except (RuntimeError, ValueError) as exc:
        log.error("Failed to generate attestation report: %s", exc)
        _send_response(
            conn, {"valid": False, "reason": "attestation report generation failed"}
        )
        conn.close()
        return

    # Attach handshake metadata for server-side auditing
    report["eac_handshake"] = handshake

    # 4. POST to attestation server
    try:
        log.info("Posting report to %s …", ATTEST_URL)
        result = _post_report(report)
        log.info("Attestation result: %s", result)
    except RuntimeError as exc:
        log.error("Attestation POST failed: %s", exc)
        _send_response(
            conn, {"valid": False, "reason": "attestation server unreachable"}
        )
        conn.close()
        return

    # 5. Send result back to game client
    if result.get("valid") is True:
        token = result.get("token", "")
        log.info("Attestation VALID — issuing token: %s", token)
        _send_response(conn, {"valid": True, "token": token})
    else:
        reason = result.get("reason", "attestation failed")
        log.info("Attestation INVALID — reason: %s", reason)
        _send_response(conn, {"valid": False, "reason": reason})

    conn.close()


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def run_server() -> None:
    """Bind the Unix socket, auto-register this machine, and serve connections."""

    # Remove stale socket file from a previous run
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    server.listen(5)

    log.info("EAC shim listening on %s", SOCKET_PATH)
    log.info("Will POST attestation reports to %s", ATTEST_URL)
    log.info("Machine ID: %s", MACHINE_ID)

    # Attempt auto-registration on startup
    _auto_register()

    try:
        while True:
            conn, addr = server.accept()
            _handle_client(conn, addr)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        server.close()
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_server()
