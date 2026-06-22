"""
agent/ima_reader.py
-------------------
Reads the kernel IMA (Integrity Measurement Architecture) ascii runtime
measurement log from /sys/kernel/security/ima/ascii_runtime_measurements.

The file requires root access, so it is read via ``sudo cat`` through
subprocess.

Public API
----------
    read_ima_log() -> list[dict]
        Parses every line in the IMA log and returns a list of dicts, each
        with the fields:
            pcr           – PCR index string (usually "10")
            template_hash – hex digest of the IMA template record
            template_name – template identifier (e.g. "ima-ng", "ima-sig")
            file_hash     – algorithm:digest string (e.g. "sha256:abcdef…")
            filename      – path of the measured file / event name

    read_ima_summary() -> dict
        Aggregates the log into a high-level summary dict:
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
import math
import subprocess

_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"


def read_ima_log() -> list[dict]:
    """Read and parse the IMA ascii runtime measurement log.

    Each line is split into five whitespace-separated fields:
        <pcr> <template_hash> <template_name> <file_hash> <filename>

    Lines that do not conform to this format are silently skipped.

    Returns
    -------
    list[dict]
        A list of entry dicts with keys: pcr, template_hash, template_name,
        file_hash, filename.

    Raises
    ------
    RuntimeError
        If the ``sudo cat`` subprocess exits with a non-zero status; the
        error message contains the captured stderr output.
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

    entries: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Fields are separated by a single space.  The filename (last field)
        # may itself contain spaces, so we split into at most 5 parts.
        parts = line.split(" ", 4)
        if len(parts) < 5:
            # Malformed line – skip gracefully
            continue

        pcr, template_hash, template_name, file_hash, filename = parts
        entries.append(
            {
                "pcr": pcr,
                "template_hash": template_hash,
                "template_name": template_name,
                "file_hash": file_hash,
                "filename": filename,
            }
        )

    return entries


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def _leaf_hash(entry: dict) -> bytes:
    """Compute the canonical leaf hash for a single IMA entry.

    The pre-image is the UTF-8 encoding of::

        "<pcr>:<template_hash>:<file_hash>:<filename>"
    """
    pre_image = (
        f"{entry['pcr']}:{entry['template_hash']}"
        f":{entry['file_hash']}:{entry['filename']}"
    ).encode()
    return _sha256(pre_image)


def build_ima_merkle_tree(entries: list[dict]) -> dict:
    """Build a binary Merkle tree over *entries* and return tree metadata.

    Algorithm
    ---------
    1. Hash each entry with :func:`_leaf_hash` to produce the leaf layer.
    2. Repeatedly hash adjacent pairs — SHA-256(left_raw || right_raw) — to
       produce the next layer.  When the current layer has an odd number of
       nodes the last node is duplicated before pairing.
    3. The single node that remains after all reductions is the root.

    An empty *entries* list produces a zero-filled root and depth 0.

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
            "root": hashlib.sha256(b"").hexdigest(),
            "depth": 0,
            "leaf_count": 0,
            "leaves": [],
        }

    # --- leaf layer ---
    leaf_raw: list[bytes] = [_leaf_hash(e) for e in entries]
    leaves_hex: list[str] = [b.hex() for b in leaf_raw]

    # --- iteratively reduce to root ---
    current_layer: list[bytes] = leaf_raw
    depth = 0
    while len(current_layer) > 1:
        # Duplicate the last node when the layer length is odd
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])
        next_layer: list[bytes] = [
            _sha256(current_layer[i] + current_layer[i + 1])
            for i in range(0, len(current_layer), 2)
        ]
        current_layer = next_layer
        depth += 1

    root_hex = current_layer[0].hex()

    return {
        "root": root_hex,
        "depth": depth,
        "leaf_count": len(leaf_raw),
        "leaves": leaves_hex,
    }


def get_ima_proof(entries: list[dict], index: int) -> dict:
    """Return the Merkle inclusion proof for the entry at *index*.

    The proof is the ordered list of sibling hashes needed for a verifier to
    recompute the root from the leaf — one hash per tree level, ordered from
    the leaf level up to (but not including) the root level.

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
    IndexError
        If *index* is out of range for *entries*.
    ValueError
        If *entries* is empty.
    """
    if not entries:
        raise ValueError("Cannot produce a proof for an empty entry list.")
    if not (0 <= index < len(entries)):
        raise IndexError(
            f"Index {index} is out of range for {len(entries)} entries."
        )

    # Build the full tree layer-by-layer, recording every layer so we can
    # walk back up and collect sibling hashes.
    current_layer: list[bytes] = [_leaf_hash(e) for e in entries]
    leaf_hash_hex = current_layer[index].hex()

    proof: list[str] = []
    current_index = index

    while len(current_layer) > 1:
        # Duplicate last node for odd-length layers
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])

        # Determine the sibling index
        if current_index % 2 == 0:          # current node is a left child
            sibling_index = current_index + 1
        else:                               # current node is a right child
            sibling_index = current_index - 1

        proof.append(current_layer[sibling_index].hex())

        # Build next layer
        next_layer: list[bytes] = [
            _sha256(current_layer[i] + current_layer[i + 1])
            for i in range(0, len(current_layer), 2)
        ]
        current_layer = next_layer
        current_index //= 2

    root_hex = current_layer[0].hex()

    return {
        "index": index,
        "leaf_hash": leaf_hash_hex,
        "proof": proof,
        "root": root_hex,
    }


def read_ima_summary() -> dict:
    """Return a high-level summary of the IMA runtime measurement log.

    Returns
    -------
    dict
        A dict with the following keys:

        total_entries : int
            Total number of successfully parsed log entries.
        unique_files : int
            Number of distinct filenames observed across all entries.
        has_boot_aggregate : bool
            True if at least one entry has the filename ``boot_aggregate``,
            which indicates the TPM PCR was extended at boot time.
        modules_measured : int
            Count of entries whose filename ends with ``.ko`` or ``.ko.zst``,
            representing kernel modules that were measured.
    """
    entries = read_ima_log()

    filenames = [e["filename"] for e in entries]

    has_boot_aggregate = any(f == "boot_aggregate" for f in filenames)

    modules_measured = sum(
        1
        for f in filenames
        if f.endswith(".ko") or f.endswith(".ko.zst")
    )

    return {
        "total_entries": len(entries),
        "unique_files": len(set(filenames)),
        "has_boot_aggregate": has_boot_aggregate,
        "modules_measured": modules_measured,
    }


if __name__ == "__main__":
    _entries = read_ima_log()
    _summary = read_ima_summary()
    _tree = build_ima_merkle_tree(_entries)
    print(json.dumps(
        {
            "ima_summary": _summary,
            "merkle_root": _tree["root"],
            "merkle_depth": _tree["depth"],
            "merkle_leaf_count": _tree["leaf_count"],
        },
        indent=2,
    ))
