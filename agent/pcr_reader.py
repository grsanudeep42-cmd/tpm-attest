"""
agent/pcr_reader.py
-------------------
Reads TPM2 PCR values for the sha256 bank by invoking tpm2_pcrread.

Public API
----------
    read_pcrs() -> dict[int, str]
        Returns a mapping of PCR index → hex digest string (e.g. "0x7EF5...").
        Raises RuntimeError if tpm2_pcrread fails.
"""

import json
import re
import subprocess

# PCR indices that matter for a typical Linux attestation policy
_PCR_INDICES = [0, 1, 4, 7, 9, 10]
_BANK = "sha256"

# tpm2_pcrread output looks like:
#   sha256:
#     0 : 0x0000000000000000000000000000000000000000000000000000000000000000
#     1 : 0xABCDEF...
#     ...
_PCR_LINE_RE = re.compile(r"^\s+(\d+)\s*:\s*(0x[0-9A-Fa-f]+)\s*$")


def read_pcrs() -> dict[int, str]:
    """Shell out to tpm2_pcrread and return PCR values as {index: hex_string}.

    Raises
    ------
    RuntimeError
        If tpm2_pcrread exits with a non-zero status; the error message
        contains the captured stderr output.
    """
    spec = f"{_BANK}:{','.join(str(i) for i in _PCR_INDICES)}"
    cmd = ["tpm2_pcrread", spec]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tpm2_pcrread failed (exit {result.returncode}):\n{result.stderr.strip()}"
        )

    pcrs: dict[int, str] = {}
    for line in result.stdout.splitlines():
        m = _PCR_LINE_RE.match(line)
        if m:
            index = int(m.group(1))
            digest = m.group(2).upper().replace("0X", "0x")
            if index in _PCR_INDICES:
                pcrs[index] = digest

    # Sanity-check: warn if any expected index is missing
    missing = set(_PCR_INDICES) - pcrs.keys()
    if missing:
        raise RuntimeError(
            f"tpm2_pcrread output missing expected PCR indices: {sorted(missing)}\n"
            f"Raw output:\n{result.stdout}"
        )

    return pcrs


if __name__ == "__main__":
    print(json.dumps(read_pcrs(), indent=2))
