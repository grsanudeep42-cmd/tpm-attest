"""
agent/ima_reader.py
-------------------
Reads the kernel IMA (Integrity Measurement Architecture) ascii runtime
measurement log from /sys/kernel/security/ima/ascii_runtime_measurements.

The file requires root access, so it is read via ``sudo cat`` through
subprocess.

Public API
----------
    read_ima_log(start_line: int = 0) -> list[dict]
        Parses every line in the IMA log *from start_line onwards* and
        returns a list of dicts, each with the fields:
            pcr           – PCR index string (usually "10")
            template_hash – hex digest of the IMA template record
            template_name – template identifier (e.g. "ima-ng", "ima-sig")
            file_hash     – algorithm:digest string (e.g. "sha256:abcdef…")
            filename      – path of the measured file / event name

        The ``start_line`` parameter enables **incremental reading**: a
        long-running daemon can cache previously processed entries and call
        this function with the count of already-seen lines to receive only
        the *new* entries appended since the last call.

    read_ima_log_line_count() -> int
        Return the total number of valid (parseable) lines currently in the
        IMA log without returning the parsed entries. Used by daemons to
        check whether new lines have been appended without re-reading
        everything.

    read_ima_summary() -> dict
        Aggregates the *full* log into a high-level summary dict:
            total_entries     – total number of parsed log entries
            unique_files      – count of distinct filenames
            has_boot_aggregate – True if "boot_aggregate" appears in the log
            modules_measured  – count of entries whose filename ends in
                                .ko or .ko.zst

    build_ima_merkle_tree(entries) -> dict
        Builds a binary Merkle tree over the IMA entries and returns:
            root        – hex root hash (32 bytes / 64 hex chars)
            depth       – number of levels in the tree (0 for empty log)
            leaf_count  – number of leaf nodes (== len(entries))
            leaves      – list of hex leaf hashes

    build_incremental_merkle_tree(cached_leaves, new_entries, base_index) -> tuple
        Given a list of already-computed leaf hash bytes and a list of new
        IMA entry dicts (with their absolute indices), appends new leaf
        hashes and recomputes the Merkle root efficiently.
        Returns (new_cached_leaves: list[bytes], tree_dict: dict).

    get_ima_proof(entries, index) -> dict
        Returns the Merkle inclusion proof for the entry at *index*:
            index       – the requested index
            leaf_hash   – hex hash of the leaf
            proof       – ordered list of sibling hex hashes (bottom → root)
            root        – hex root hash

Example log line
----------------
    10 3bee321a... ima-ng sha256:86a4e2c9... /path/to/file
"""

import hashlib
import json
import subprocess
from typing import Sequence

_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"


# ---------------------------------------------------------------------------
# Low-level log reading
# ---------------------------------------------------------------------------

def _read_raw_lines() -> list[str]:
    """Execute ``sudo cat`` and return *all* non-empty lines from the IMA log.

    Raises
    ------
    RuntimeError
        If the subprocess exits with a non-zero status.
    """
    result = subprocess.run(
        ["sudo", "cat", _IMA_LOG_PATH],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to read IMA log (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    return [ln for ln in result.stdout.splitlines() if ln.strip()]


def _parse_line(line: str) -> dict | None:
    """Parse a single IMA log line into a dict, or return None if malformed."""
    parts = line.strip().split(" ", 4)
    if len(parts) < 5:
        return None
    pcr, template_hash, template_name, file_hash, filename = parts
    return {
        "pcr":           pcr,
        "template_hash": template_hash,
        "template_name": template_name,
        "file_hash":     file_hash,
        "filename":      filename,
    }


# ---------------------------------------------------------------------------
# Public reading API
# ---------------------------------------------------------------------------

def read_ima_log(start_line: int = 0) -> list[dict]:
    """Read and parse the IMA ascii runtime measurement log.

    Parameters
    ----------
    start_line:
        Zero-based index of the first line to return. Defaults to 0
        (full log). Pass the number of previously processed entries to
        get only the *new* lines appended since the last call — this
        enables incremental processing in long-running daemons.

    Returns
    -------
    list[dict]
        A list of entry dicts with keys: pcr, template_hash, template_name,
        file_hash, filename. Lines that do not conform to the five-field
        format are silently skipped.

    Raises
    ------
    RuntimeError
        If the ``sudo cat`` subprocess exits with a non-zero status.
    """
    all_lines = _read_raw_lines()
    entries: list[dict] = []
    for line in all_lines[start_line:]:
        entry = _parse_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def read_ima_log_line_count() -> int:
    """Return the total number of valid parseable lines currently in the IMA log.

    Useful for daemons that want to check whether new measurements have been
    appended without re-reading every entry.

    Raises
    ------
    RuntimeError
        If the ``sudo cat`` subprocess exits with a non-zero status.
    """
    all_lines = _read_raw_lines()
    return sum(1 for ln in all_lines if _parse_line(ln) is not None)


def read_ima_summary() -> dict:
    """Return a high-level summary of the *full* IMA runtime measurement log.

    Returns
    -------
    dict
        total_entries : int
        unique_files  : int
        has_boot_aggregate : bool
        modules_measured   : int
    """
    entries = read_ima_log()
    filenames = [e["filename"] for e in entries]
    return {
        "total_entries":      len(entries),
        "unique_files":       len(set(filenames)),
        "has_boot_aggregate": any(f == "boot_aggregate" for f in filenames),
        "modules_measured":   sum(
            1 for f in filenames if f.endswith(".ko") or f.endswith(".ko.zst")
        ),
    }


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def _leaf_hash(entry: dict, index: int) -> bytes:
    """Compute the canonical leaf hash for a single IMA entry.

    The pre-image includes the absolute *index* to prevent the duplicate-leaf
    collision attack (CVE-2012-2459 equivalent):

        "<index>:<pcr>:<template_hash>:<file_hash>:<filename>"

    Because the index is baked into the pre-image, duplicating a leaf at
    position N is cryptographically distinct from a leaf at position N+1,
    making log-restructuring / appending-duplicate-entries attacks impossible.
    """
    pre_image = (
        f"{index}:{entry['pcr']}:{entry['template_hash']}"
        f":{entry['file_hash']}:{entry['filename']}"
    ).encode()
    return _sha256(pre_image)


def _reduce_to_root(layer: list[bytes]) -> tuple[list[bytes], int]:
    """Reduce *layer* to a single root node using the standard Merkle algorithm.

    Odd-length layers duplicate the last node before pairing (standard
    Bitcoin-style Merkle construction). The index-prefixed leaf hashes
    already prevent the associated collision attack.

    Returns (root_layer, depth) where root_layer is a one-element list.
    """
    depth = 0
    current: list[bytes] = list(layer)
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        current = [
            _sha256(current[i] + current[i + 1])
            for i in range(0, len(current), 2)
        ]
        depth += 1
    return current, depth


def build_ima_merkle_tree(entries: list[dict]) -> dict:
    """Build a binary Merkle tree over *entries* and return tree metadata.

    Parameters
    ----------
    entries:
        List of entry dicts as returned by :func:`read_ima_log`.

    Returns
    -------
    dict
        ``root``       – 64-char hex root hash
        ``depth``      – number of levels in the tree (leaves = level 0)
        ``leaf_count`` – number of leaf hashes
        ``leaves``     – list of 64-char hex leaf hashes
    """
    if not entries:
        return {
            "root":       hashlib.sha256(b"").hexdigest(),
            "depth":      0,
            "leaf_count": 0,
            "leaves":     [],
        }

    leaf_raw:   list[bytes] = [_leaf_hash(e, i) for i, e in enumerate(entries)]
    leaves_hex: list[str]   = [b.hex() for b in leaf_raw]

    root_layer, depth = _reduce_to_root(leaf_raw)

    return {
        "root":       root_layer[0].hex(),
        "depth":      depth,
        "leaf_count": len(leaf_raw),
        "leaves":     leaves_hex,
    }


def build_incremental_merkle_tree(
    cached_leaves: list[bytes],
    new_entries:   list[dict],
    base_index:    int,
) -> tuple[list[bytes], dict]:
    """Compute the Merkle tree root incrementally.

    Instead of re-hashing the entire IMA log on every attestation, a
    long-running daemon can maintain a cache of already-computed leaf hash
    bytes and call this function with only the *new* entries appended since
    the last attestation.

    Parameters
    ----------
    cached_leaves:
        List of raw 32-byte leaf hashes already computed for previously seen
        IMA entries (index 0 … base_index-1).
    new_entries:
        IMA entry dicts for entries at absolute positions base_index … N-1.
    base_index:
        The absolute IMA log index of the first entry in *new_entries*.
        Used to maintain correct index-prefixed pre-images.

    Returns
    -------
    tuple[list[bytes], dict]
        A 2-tuple of:
        - ``new_cached_leaves`` — the updated full list of leaf bytes
          (cached_leaves + newly computed leaves), ready to be stored for the
          next incremental call.
        - ``tree_dict``         — the same dict as :func:`build_ima_merkle_tree`
          (root, depth, leaf_count, leaves).
    """
    new_leaf_raw: list[bytes] = [
        _leaf_hash(e, base_index + i) for i, e in enumerate(new_entries)
    ]
    all_leaves = list(cached_leaves) + new_leaf_raw

    if not all_leaves:
        return [], {
            "root":       hashlib.sha256(b"").hexdigest(),
            "depth":      0,
            "leaf_count": 0,
            "leaves":     [],
        }

    root_layer, depth = _reduce_to_root(all_leaves)

    tree_dict = {
        "root":       root_layer[0].hex(),
        "depth":      depth,
        "leaf_count": len(all_leaves),
        "leaves":     [b.hex() for b in all_leaves],
    }
    return all_leaves, tree_dict


# ---------------------------------------------------------------------------
# Merkle inclusion proof
# ---------------------------------------------------------------------------

def get_ima_proof(entries: list[dict], index: int) -> dict:
    """Return the Merkle inclusion proof for the entry at *index*.

    Parameters
    ----------
    entries:
        List of entry dicts as returned by :func:`read_ima_log`.
    index:
        Zero-based position of the entry whose proof is requested.

    Returns
    -------
    dict
        ``index``     – the requested index
        ``leaf_hash`` – 64-char hex hash of the leaf at *index*
        ``proof``     – list of 64-char hex sibling hashes (bottom → root)
        ``root``      – 64-char hex root hash

    Raises
    ------
    ValueError
        If *entries* is empty.
    IndexError
        If *index* is out of range for *entries*.
    """
    if not entries:
        raise ValueError("Cannot produce a proof for an empty entry list.")
    if not (0 <= index < len(entries)):
        raise IndexError(
            f"Index {index} is out of range for {len(entries)} entries."
        )

    current_layer: list[bytes] = [_leaf_hash(e, i) for i, e in enumerate(entries)]
    leaf_hash_hex = current_layer[index].hex()

    proof: list[str] = []
    current_index = index

    while len(current_layer) > 1:
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])
        sibling_index = (
            current_index + 1 if current_index % 2 == 0 else current_index - 1
        )
        proof.append(current_layer[sibling_index].hex())
        current_layer = [
            _sha256(current_layer[i] + current_layer[i + 1])
            for i in range(0, len(current_layer), 2)
        ]
        current_index //= 2

    root_hex = current_layer[0].hex()
    return {
        "index":     index,
        "leaf_hash": leaf_hash_hex,
        "proof":     proof,
        "root":      root_hex,
    }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _entries = read_ima_log()
    _summary = read_ima_summary()
    _tree    = build_ima_merkle_tree(_entries)
    print(json.dumps(
        {
            "ima_summary":      _summary,
            "merkle_root":      _tree["root"],
            "merkle_depth":     _tree["depth"],
            "merkle_leaf_count": _tree["leaf_count"],
        },
        indent=2,
    ))
