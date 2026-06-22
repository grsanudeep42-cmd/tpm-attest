#!/usr/bin/env python3
"""
phase3/shim.py
--------------
EAC shim: bridges the game (mock_eac_client) to the TPM attestation server.

Flow per connection:
  1. Accept a connection on /tmp/eac_shim.sock
  2. Read the EAC handshake JSON from the game client
  3. Call agent.report.generate_report() to collect TPM/IMA data
  4. POST the report to http://localhost:8080/attest
  5. If the server returns { "valid": true, "token": "..." }
       → reply to the client: { "valid": true, "token": "<token>" }
     Otherwise
       → reply to the client: { "valid": false, "reason": "attestation failed" }

Usage:
  # From the repo root (so that 'agent' is importable):
  python3 -m phase3.shim
  # or directly:
  python3 phase3/shim.py

Environment variables (optional):
  ATTEST_URL     — override the attestation server URL
                   (default: http://localhost:8080/attest)
  SHIM_SOCK      — override the Unix socket path
                   (default: /tmp/eac_shim.sock)
"""

import json
import logging
import os
import socket
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOCKET_PATH: str = os.environ.get("SHIM_SOCK", "/tmp/eac_shim.sock")
ATTEST_URL: str  = os.environ.get("ATTEST_URL", "http://localhost:8080/attest")
RECV_BUF:   int  = 8192
ATTEST_TIMEOUT: int = 30  # seconds for the HTTP request

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
# TPM attestation
# ---------------------------------------------------------------------------

def _collect_report() -> dict:
    """Call agent.report.generate_report() and return the report dict.

    Importing here (lazily) so that the shim still starts up in environments
    where the TPM tools are not installed — the error will surface only when
    a handshake arrives.
    """
    try:
        from agent.report import generate_report  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Cannot import agent.report — run from the repo root or install the package: "
            f"{exc}"
        ) from exc

    return generate_report()


def _post_report(report: dict) -> dict:
    """POST the attestation report to the verification server.

    Parameters
    ----------
    report:
        The dict returned by generate_report().

    Returns
    -------
    dict
        The JSON body parsed from the server's response.

    Raises
    ------
    RuntimeError
        On HTTP or network errors.
    """
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
        # Read the error body — server may include a reason
        body = exc.read()
        log.warning("Attestation server returned HTTP %d: %s", exc.code, body.decode("utf-8", errors="replace"))
        # Still try to parse — some servers send JSON on 4xx/5xx
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach attestation server at {ATTEST_URL}: {exc.reason}") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Attestation server returned non-JSON body: {body!r}") from exc


# ---------------------------------------------------------------------------
# Handshake handler
# ---------------------------------------------------------------------------

def _handle_client(conn: socket.socket, addr: object) -> None:
    """Process one game-client connection end-to-end."""
    log.info("Connection from %s", addr)

    # 1. Read the full handshake (client shuts WR when done)
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

    # 2. Parse handshake JSON (informational — we forward the report regardless)
    try:
        handshake = json.loads(raw)
        log.info(
            "Handshake parsed — game_id=%s player_id=%s platform=%s",
            handshake.get("game_id"),
            handshake.get("player_id"),
            handshake.get("platform"),
        )
    except json.JSONDecodeError:
        log.warning("Could not parse handshake as JSON — proceeding with attestation anyway")
        handshake = {}

    # 3. Collect TPM attestation report
    try:
        log.info("Collecting TPM attestation report …")
        report = _collect_report()
        log.info("Report collected (nonce=%s quote_available=%s)", report.get("nonce"), report.get("quote_available"))
    except RuntimeError as exc:
        log.error("Failed to generate attestation report: %s", exc)
        _send_response(conn, {"valid": False, "reason": "attestation report generation failed"})
        conn.close()
        return

    # Attach handshake metadata to the report so the server can audit it
    report["eac_handshake"] = handshake

    # 4. POST to attestation server
    try:
        log.info("Posting report to %s …", ATTEST_URL)
        result = _post_report(report)
        log.info("Attestation result: %s", result)
    except RuntimeError as exc:
        log.error("Attestation POST failed: %s", exc)
        _send_response(conn, {"valid": False, "reason": "attestation server unreachable"})
        conn.close()
        return

    # 5. Build and send response to the game client
    if result.get("valid") is True:
        token = result.get("token", "")
        response = {"valid": True, "token": token}
        log.info("Attestation VALID — issuing token: %s", token)
    else:
        reason = result.get("reason", "attestation failed")
        response = {"valid": False, "reason": reason}
        log.info("Attestation INVALID — reason: %s", reason)

    _send_response(conn, response)
    conn.close()


def _send_response(conn: socket.socket, payload: dict) -> None:
    """Serialise *payload* as JSON and send it over *conn*."""
    data = json.dumps(payload).encode("utf-8")
    try:
        conn.sendall(data)
    except OSError as exc:
        log.error("Error sending response: %s", exc)


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def run_server() -> None:
    """Bind the Unix socket and serve connections sequentially."""

    # Remove a stale socket file from a previous run
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)

    log.info("EAC shim listening on %s", SOCKET_PATH)
    log.info("Will POST attestation reports to %s", ATTEST_URL)

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
