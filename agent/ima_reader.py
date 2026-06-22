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

Example log line
----------------
    10 3bee321a... ima-ng sha256:86a4e2c9... /path/to/file
"""

import json
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
    print(json.dumps(read_ima_summary(), indent=2))
