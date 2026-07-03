#!/usr/bin/env python3
"""
End-to-end API integration test for TPM-Attest server.

Tests:
  1. /health returns 200 v1.1
  2. /register succeeds without EK cert (warning expected)
  3. /register with a fake EK cert (raw bytes, not X.509) succeeds
  4. /challenge issues a unique nonce
  5. Stale / unknown nonce is rejected by /attest
  6. Nonce consumed on first use (replay rejected)
  7. attest.db persists all enrollments across the test
"""

import base64
import json
import os
import secrets
import sqlite3
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8080"


def get(path):
    with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as r:
        return json.loads(r.read())


def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{BASE}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def ok(label, cond, detail=""):
    sym = "✓" if cond else "✗"
    print(f"  {sym} {label}", f"({detail})" if detail else "")
    if not cond:
        sys.exit(1)


print("\n=== TPM-Attest Server Integration Tests ===\n")

# 1. Health
h = get("/health")
ok("Health check returns v1.1", h.get("version") == "1.1", h)

# 2. Register without EK cert
ak_fake = base64.b64encode(os.urandom(256)).decode()
status, body = post("/register", {"machine_id": "integ-test-01", "ak_pub_b64": ak_fake})
ok("Register without EK cert — 200 OK", status == 200, body)
ok("  ek_verified=false when no cert", body.get("ek_verified") is False)

# 3. Register with a raw 256-byte EK public key blob (not an X.509 cert)
ek_fake_bytes = base64.b64encode(os.urandom(256)).decode()
status, body = post("/register", {
    "machine_id": "integ-test-02",
    "ak_pub_b64": ak_fake,
    "ek_cert_b64": ek_fake_bytes,
})
ok("Register with raw EK key blob — 200 OK", status == 200, body)
ok("  ek_verified=true for raw key blob", body.get("ek_verified") is True)

# 4. Challenge issues a 64-char hex nonce
c = get("/challenge")
nonce = c.get("nonce", "")
ok("Challenge returns 64-char hex nonce", len(nonce) == 64, nonce[:16] + "...")

# 5. Stale / unknown nonce rejected — nonce check now fires BEFORE quote check
stale = secrets.token_hex(32)
status, body = post("/attest", {
    "version": "1.1", "timestamp": "2026-07-01T00:00:00+00:00",
    "nonce": stale, "machine_id": "integ-test-01",
    "pcrs": {"0": "0xAA", "1": "0xBB", "4": "0xCC", "7": "0xDD", "9": "0xEE", "10": "0xFF"},
    "ima_summary": {"total_entries": 5, "unique_files": 3,
                    "has_boot_aggregate": True, "modules_measured": 1},
    "ima_merkle_root": "a" * 64, "ima_merkle_depth": 2, "ima_leaf_count": 5,
    "quote_available": False,
})
ok("Unknown nonce rejected with 400", status == 400, body.get("reason", "")[:60])
ok("  Reason mentions 'Nonce not recognised' (nonce checked before quote)",
   "Nonce not recognised" in body.get("reason", ""), body.get("reason", ""))

# 6. Consume a fresh nonce, then replay it — second attempt must fail
c2 = get("/challenge")
nonce2 = c2["nonce"]
payload = {
    "version": "1.1", "timestamp": "2026-07-01T00:00:00+00:00",
    "nonce": nonce2, "machine_id": "integ-test-01",
    "pcrs": {"0": "0xAA", "1": "0xBB", "4": "0xCC", "7": "0xDD", "9": "0xEE", "10": "0xFF"},
    "ima_summary": {"total_entries": 5, "unique_files": 3,
                    "has_boot_aggregate": True, "modules_measured": 1},
    "ima_merkle_root": "a" * 64, "ima_merkle_depth": 2, "ima_leaf_count": 5,
    "quote_available": False,
}
s1, b1 = post("/attest", payload)
s2, b2 = post("/attest", payload)   # exact replay
ok("First attest with valid nonce fails at quote check (expected 400)", s1 == 400,
   b1.get("reason", ""))
ok("Replay of same nonce rejected (nonce consumed)", s2 == 400)
ok("  Replay reason is 'Nonce not recognised'",
   "Nonce not recognised" in b2.get("reason", ""), b2.get("reason", ""))

# 7. DB state check
con = sqlite3.connect("attest.db")
rows = con.execute(
    "SELECT machine_id, ek_verified FROM enrolled_machines "
    "WHERE machine_id IN ('integ-test-01','integ-test-02') ORDER BY machine_id"
).fetchall()

# nonce  → fetched via /challenge in step 4 but NEVER submitted → still active (correct)
# nonce2 → submitted to /attest in step 6 → CONSUMED → must be gone
unused_active = con.execute(
    "SELECT COUNT(*) FROM active_nonces WHERE nonce = ?", (nonce,)
).fetchone()[0]
submitted_active = con.execute(
    "SELECT COUNT(*) FROM active_nonces WHERE nonce = ?", (nonce2,)
).fetchone()[0]
con.close()

ok("DB has both enrolled machines", len(rows) == 2, rows)
ok("  integ-test-01 ek_verified=0", rows[0][1] == 0)
ok("  integ-test-02 ek_verified=1", rows[1][1] == 1)
ok("Unused challenge nonce still active in DB (correct — never submitted)",
   unused_active == 1, f"found {unused_active}")
ok("Submitted nonce consumed and removed from DB",
   submitted_active == 0, f"nonce2 still present: {submitted_active}")

print("\n=== All tests passed ✓ ===\n")
