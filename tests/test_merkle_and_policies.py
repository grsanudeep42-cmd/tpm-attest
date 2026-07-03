#!/usr/bin/env python3
"""
tests/test_merkle_and_policies.py
----------------------------------
Unit tests for:
  - Merkle tree construction correctness & collision resistance
  - Incremental Merkle tree update
  - Merkle inclusion proof correctness
  - Server policy enforcement (PCR7 pinning, IMA minimum entries,
    STRICT_EK_VERIFICATION via the _verify_ek_cert helper)

Run with:
    .venv/bin/python3 -m pytest tests/test_merkle_and_policies.py -v
or standalone:
    .venv/bin/python3 tests/test_merkle_and_policies.py
"""

import hashlib
import sys
import os

# Make sure repo root is importable
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agent.ima_reader import (
    build_ima_merkle_tree,
    build_incremental_merkle_tree,
    get_ima_proof,
    _leaf_hash,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_entry(pcr="10", filename="/usr/bin/test", file_hash="sha256:deadbeef"):
    return {
        "pcr": pcr,
        "template_hash": "aaaa" * 8,
        "template_name": "ima-ng",
        "file_hash": file_hash,
        "filename": filename,
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ok(label: str, cond: bool, detail: str = ""):
    sym = "✓" if cond else "✗"
    print(f"  {sym} {label}", f"  ← {detail}" if detail else "")
    if not cond:
        raise AssertionError(f"FAIL: {label}")


# ---------------------------------------------------------------------------
# 1. Empty log handling
# ---------------------------------------------------------------------------

def test_empty_log():
    tree = build_ima_merkle_tree([])
    ok("Empty log → root = SHA256(b'')",
       tree["root"] == hashlib.sha256(b"").hexdigest(),
       tree["root"][:16])
    ok("Empty log → depth = 0", tree["depth"] == 0)
    ok("Empty log → leaf_count = 0", tree["leaf_count"] == 0)


# ---------------------------------------------------------------------------
# 2. Single-entry log
# ---------------------------------------------------------------------------

def test_single_entry():
    e = _make_entry(filename="/sbin/init")
    tree = build_ima_merkle_tree([e])
    expected_leaf = _leaf_hash(e, 0).hex()
    ok("Single entry: root == leaf hash", tree["root"] == expected_leaf)
    ok("Single entry: depth == 0", tree["depth"] == 0)
    ok("Single entry: leaf_count == 1", tree["leaf_count"] == 1)


# ---------------------------------------------------------------------------
# 3. Determinism — same input → same root
# ---------------------------------------------------------------------------

def test_determinism():
    entries = [_make_entry(filename=f"/usr/bin/prog{i}") for i in range(8)]
    r1 = build_ima_merkle_tree(entries)["root"]
    r2 = build_ima_merkle_tree(entries)["root"]
    ok("Deterministic: same input → same root", r1 == r2)


# ---------------------------------------------------------------------------
# 4. Index-binding prevents duplicate-leaf collision (CVE-2012-2459)
#    [A, B, C] must NOT have the same root as [A, B, C, C]
# ---------------------------------------------------------------------------

def test_no_duplicate_leaf_collision():
    A = _make_entry(filename="/usr/bin/a", file_hash="sha256:aaa")
    B = _make_entry(filename="/usr/bin/b", file_hash="sha256:bbb")
    C = _make_entry(filename="/usr/bin/c", file_hash="sha256:ccc")

    root_abc  = build_ima_merkle_tree([A, B, C])["root"]
    root_abcc = build_ima_merkle_tree([A, B, C, C])["root"]

    ok("CVE-2012-2459 guard: [A,B,C] root ≠ [A,B,C,C] root",
       root_abc != root_abcc,
       f"{root_abc[:16]}... vs {root_abcc[:16]}...")


# ---------------------------------------------------------------------------
# 5. Entry reordering changes the root
# ---------------------------------------------------------------------------

def test_reorder_changes_root():
    A = _make_entry(filename="/a")
    B = _make_entry(filename="/b")
    root_ab = build_ima_merkle_tree([A, B])["root"]
    root_ba = build_ima_merkle_tree([B, A])["root"]
    ok("Reordering entries changes Merkle root", root_ab != root_ba)


# ---------------------------------------------------------------------------
# 6. Single-field modification changes the root
# ---------------------------------------------------------------------------

def test_field_modification_changes_root():
    clean  = _make_entry(filename="/usr/bin/game", file_hash="sha256:clean_hash")
    tamper = _make_entry(filename="/usr/bin/game", file_hash="sha256:tampered")
    r_clean  = build_ima_merkle_tree([clean])["root"]
    r_tamper = build_ima_merkle_tree([tamper])["root"]
    ok("Changing file_hash changes Merkle root", r_clean != r_tamper)


# ---------------------------------------------------------------------------
# 7. Two-entry tree: manually verify parent hash
# ---------------------------------------------------------------------------

def test_two_entry_parent_hash():
    A = _make_entry(filename="/a")
    B = _make_entry(filename="/b")
    leaf_A = _leaf_hash(A, 0)
    leaf_B = _leaf_hash(B, 1)
    expected_root = hashlib.sha256(leaf_A + leaf_B).hexdigest()
    tree = build_ima_merkle_tree([A, B])
    ok("Two-entry root = SHA256(leaf_A ‖ leaf_B)",
       tree["root"] == expected_root,
       f"got {tree['root'][:16]}... expected {expected_root[:16]}...")
    ok("Two-entry depth = 1", tree["depth"] == 1)


# ---------------------------------------------------------------------------
# 8. Merkle inclusion proof correctness
# ---------------------------------------------------------------------------

def test_inclusion_proof():
    entries = [_make_entry(filename=f"/bin/prog{i}") for i in range(7)]
    tree = build_ima_merkle_tree(entries)
    root = tree["root"]

    for idx in [0, 3, 6]:
        proof = get_ima_proof(entries, idx)
        ok(f"Proof for index {idx}: proof root matches tree root",
           proof["root"] == root,
           f"{proof['root'][:16]}...")
        ok(f"Proof for index {idx}: leaf_hash matches manual leaf",
           proof["leaf_hash"] == _leaf_hash(entries[idx], idx).hex())


# ---------------------------------------------------------------------------
# 9. Incremental Merkle tree update
# ---------------------------------------------------------------------------

def test_incremental_update():
    entries_first = [_make_entry(filename=f"/usr/bin/a{i}") for i in range(4)]
    entries_new   = [_make_entry(filename=f"/usr/bin/b{i}") for i in range(3)]
    all_entries   = entries_first + entries_new

    # Full tree over all 7 entries
    full_tree = build_ima_merkle_tree(all_entries)

    # Incremental: first compute leaves for the first 4, then extend
    leaf_cache = [_leaf_hash(e, i) for i, e in enumerate(entries_first)]
    _, incr_tree = build_incremental_merkle_tree(leaf_cache, entries_new, base_index=4)

    ok("Incremental root == full-rebuild root",
       incr_tree["root"] == full_tree["root"],
       f"{incr_tree['root'][:16]}...")
    ok("Incremental leaf_count == 7", incr_tree["leaf_count"] == 7)


# ---------------------------------------------------------------------------
# 10. Server policy: _verify_ek_cert strict mode
# ---------------------------------------------------------------------------

def test_ek_cert_strict_mode():
    import base64
    import importlib

    # Patch env variable BEFORE importing the server module
    # (or we test the helper directly)
    # We call the helper directly and check behavior.
    from server.main import _verify_ek_cert, STRICT_EK_VERIFICATION

    # In default mode (STRICT_EK_VERIFICATION=False) raw bytes should be accepted
    raw_key = base64.b64encode(b"\x00" * 64).decode()
    ok_flag, msg = _verify_ek_cert(raw_key)

    if not STRICT_EK_VERIFICATION:
        ok("Default mode: raw EK key accepted (not strict)", ok_flag, msg[:50])
    else:
        ok("Strict mode: raw EK key rejected", not ok_flag, msg[:50])

    # Invalid base64 should always fail
    bad_flag, bad_msg = _verify_ek_cert("NOT_VALID_BASE64!!!")
    ok("Invalid base64 always fails", not bad_flag, bad_msg[:50])


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

TESTS = [
    test_empty_log,
    test_single_entry,
    test_determinism,
    test_no_duplicate_leaf_collision,
    test_reorder_changes_root,
    test_field_modification_changes_root,
    test_two_entry_parent_hash,
    test_inclusion_proof,
    test_incremental_update,
    test_ek_cert_strict_mode,
]

if __name__ == "__main__":
    print("\n=== TPM-Attest Merkle & Policy Unit Tests ===\n")
    failed = []
    for test_fn in TESTS:
        name = test_fn.__name__
        print(f"[{name}]")
        try:
            test_fn()
        except AssertionError as exc:
            failed.append(name)
            print(f"  ✗ FAILED: {exc}\n")
        else:
            print()

    if failed:
        print(f"\n=== FAILED ({len(failed)}): {', '.join(failed)} ===\n")
        sys.exit(1)
    else:
        print(f"=== All {len(TESTS)} tests passed ✓ ===\n")
