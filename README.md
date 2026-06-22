# tpm-attest

> **Hardware-rooted integrity attestation for Linux — a TPM 2.0-based alternative to kernel-level anti-cheat.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688)](https://fastapi.tiangolo.com/)
[![TPM 2.0](https://img.shields.io/badge/TPM-2.0-critical)](https://trustedcomputinggroup.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

Kernel-level anti-cheat systems such as **Easy Anti-Cheat (EAC)** and **BattlEye** require a ring-0 driver that hooks deeply into the Windows kernel. On Linux this driver either does not exist or relies on compatibility shims that game publishers disable.

The result: **Linux gamers are blocked from playing protected titles**, even on legitimate hardware with a clean system.

### Why Kernel Drivers Are the Wrong Solution for Linux

| Concern | Kernel Driver | TPM Attestation |
|---|---|---|
| **Security model** | Requires ring-0 privileges — a compromised driver is a rootkit | Runs in userspace; hardware enforces integrity |
| **Kernel ABI stability** | Breaks on every kernel update | Not coupled to kernel internals |
| **Open-source compatibility** | Fundamentally incompatible with GPL and the Linux security model | Fully open; no binary blobs |
| **Audit surface** | Opaque binary running in the kernel | Cryptographically auditable chain of trust |
| **Threat equivalence** | Detects runtime tampering by scanning memory | Detects tampering at boot via measured boot + IMA |

`tpm-attest` provides **equivalent integrity guarantees** — proving to a game server that the Linux client has not been tampered with — using only standard TPM 2.0 hardware and the kernel IMA subsystem, with no kernel driver required.

---

## What It Does

`tpm-attest` is a Linux **TPM 2.0 attestation agent and verification server**. It proves to a remote party that a machine booted with a known-good, unmodified software stack by:

1. **Reading PCR values** — Platform Configuration Registers extended by UEFI/GRUB/kernel during Measured Boot.
2. **Reading the IMA log** — The kernel Integrity Measurement Architecture log of every binary executed at runtime.
3. **Generating a TPM Quote** — A hardware-signed snapshot of PCR values, bound to a fresh nonce to prevent replay.
4. **Bundling and submitting** an attestation report to a verification server.
5. **Verifying** PCR values against a known-good baseline, checking IMA boot integrity, enforcing timestamp freshness, and issuing a short-lived **session token** on success.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ATTESTED MACHINE                        │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  pcr_reader  │    │  ima_reader  │    │   TPM 2.0    │  │
│  │              │    │              │    │   Hardware   │  │
│  │ tpm2_pcrread │    │ IMA ascii    │    │              │  │
│  │ sha256:      │    │ runtime      │    │ tpm2_quote   │  │
│  │ 0,1,4,7,9,10 │    │ measurements │    │ (signed PCRs)│  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │           │
│         └───────────────────┴───────────────────┘           │
│                             │                               │
│                    ┌────────▼────────┐                      │
│                    │    report.py    │                      │
│                    │                 │                      │
│                    │  version        │                      │
│                    │  timestamp      │                      │
│                    │  nonce (fresh)  │                      │
│                    │  pcrs           │                      │
│                    │  ima_summary    │                      │
│                    │  ima_log        │                      │
│                    │  quote_msg_b64  │                      │
│                    │  quote_sig_b64  │                      │
│                    └────────┬────────┘                      │
└─────────────────────────────│───────────────────────────────┘
                              │  HTTP POST /attest
                              │  (JSON attestation report)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   VERIFICATION SERVER                       │
│                    (server/main.py)                         │
│                                                             │
│   ① TPM quote present?                                      │
│   ② Report timestamp within 60s window? (replay protection) │
│   ③ PCR values non-zero? (system was measured)              │
│   ④ PCR values match known-good baseline? (if configured)   │
│   ⑤ IMA log contains boot_aggregate? (PCR 10 extended)      │
│                                                             │
│              ┌─────────────────────────┐                    │
│   PASS  ───► │  {                      │                    │
│              │    "valid": true,       │                    │
│              │    "token": "<uuid4>",  │                    │
│              │    "expires_at": "..."  │  Session Token     │
│              │  }                      │◄─────────────────  │
│              └─────────────────────────┘                    │
│                                                             │
│              ┌─────────────────────────┐                    │
│   FAIL  ───► │  {                      │                    │
│              │    "valid": false,      │                    │
│              │    "reason": "..."      │                    │
│              │  }                      │                    │
│              └─────────────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼  (Phase 3 — in progress)
              ┌───────────────────────────────┐
              │    EAC Handshake Shim         │
              │  (translates session token    │
              │   into EAC-compatible proof)  │
              └───────────────────────────────┘
```

### Data Flow Summary

```
Measured Boot → UEFI/GRUB/Kernel extends PCR 0,1,4,7
IMA subsystem → extends PCR 10 for every measured binary
tpm2_pcrread  → snapshot of sha256 PCR bank
tpm2_quote    → hardware-signed PCR snapshot + nonce
report.py     → bundles everything into JSON
POST /attest  → server verifies chain of trust
session token → (future) accepted by game server as proof of integrity
```

---

## Components

### `agent/pcr_reader.py`

Shells out to `tpm2_pcrread` to read the **sha256 PCR bank** for the following policy-relevant registers:

| PCR | Measured Content |
|-----|-----------------|
| **0** | UEFI firmware code |
| **1** | UEFI firmware configuration |
| **4** | Boot loader code (GRUB/systemd-boot) |
| **7** | Secure Boot state and policy |
| **9** | Kernel and initramfs |
| **10** | IMA runtime measurements (extended continuously) |

Returns `dict[int, str]` — PCR index → `0x<sha256 hex>`.

---

### `agent/ima_reader.py`

Reads `/sys/kernel/security/ima/ascii_runtime_measurements` (via `sudo cat`) and parses each line of the IMA log template format:

```
<pcr>  <template_hash>  <template_name>  <file_hash>  <filename>
  10   3bee321a...      ima-ng           sha256:86a4…  /usr/bin/bash
```

Provides two public functions:

- **`read_ima_log()`** — returns full parsed log as `list[dict]`
- **`read_ima_summary()`** — aggregates into `{total_entries, unique_files, has_boot_aggregate, modules_measured}`

The `boot_aggregate` entry is the anchor of the IMA chain — it proves the IMA log is rooted in the TPM state at boot time.

---

### `agent/report.py`

Bundles PCR values, IMA data, and a TPM quote into a single signed attestation report.

A fresh **32-byte random nonce** (`secrets.token_hex(32)`) is generated per report to prevent replay attacks.

The TPM quote is obtained via `tpm2_quote` using a persistent key at handle `0x81000000`. If the key is not provisioned, `quote_available` degrades gracefully to `false`.

**Report schema:**

| Field | Type | Description |
|---|---|---|
| `version` | `"1.0"` | Schema version |
| `timestamp` | ISO 8601 UTC | Report generation time |
| `nonce` | 64-char hex | Fresh random — binds quote to this report |
| `pcrs` | `dict[int, str]` | PCR index → sha256 hex digest |
| `ima_summary` | object | Aggregated IMA metrics |
| `ima_log` | `list[dict]` | Full IMA log entries |
| `quote_available` | bool | Whether TPM quote was obtained |
| `quote_msg_b64` | base64 \| null | Raw TPM quote message |
| `quote_sig_b64` | base64 \| null | TPM quote signature |

---

### `server/main.py`

A **FastAPI** verification server exposing:

#### `GET /health`
```json
{"status": "ok", "version": "1.0"}
```

#### `POST /attest`

Accepts an attestation report (JSON). Runs 5 verification checks in order:

1. **Quote presence** — report must include a TPM-signed quote
2. **Timestamp freshness** — report must be within 60 seconds of server time (replay protection)
3. **PCR non-zero** — all PCR values must be non-zero (system was measured at boot)
4. **PCR value pinning** — if `KNOWN_GOOD_PCRS` is configured, values must match exactly
5. **IMA boot aggregate** — IMA log must contain `boot_aggregate` (confirms PCR 10 integrity)

**Success response (200):**
```json
{
  "valid": true,
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2026-06-22T11:15:00+00:00"
}
```

**Failure response (400):**
```json
{
  "valid": false,
  "reason": "PCR 7 mismatch: expected '0xABCD...', got '0x1234...'"
}
```

Tokens are valid for **5 minutes** and are UUID4-format strings.

---

## Project Structure

```
tpm-attest/
├── agent/
│   ├── __init__.py
│   ├── pcr_reader.py     # Reads TPM2 PCR values via tpm2_pcrread subprocess
│   ├── ima_reader.py     # Parses /sys/kernel/security/ima/ascii_runtime_measurements
│   └── report.py         # Bundles PCRs + IMA + TPM quote → signed attestation report
├── server/
│   ├── __init__.py
│   └── main.py           # FastAPI verification server (POST /attest, GET /health)
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Linux** with TPM 2.0 | Physical TPM or emulator (`swtpm`) |
| **`tpm2-tools`** | `tpm2_pcrread`, `tpm2_quote`, `tpm2_createprimary`, `tpm2_evictcontrol` |
| **Python 3.11+** | |
| **IMA enabled in kernel** | `CONFIG_IMA=y`, mounted securityfs |
| **`sudo` access** | Required by `ima_reader` to read the IMA log |

### Install tpm2-tools

```bash
# Debian / Ubuntu
sudo apt install tpm2-tools

# Fedora / RHEL / CentOS Stream
sudo dnf install tpm2-tools

# Arch Linux
sudo pacman -S tpm2-tools
```

### Verify TPM access

```bash
# Check that /dev/tpm0 or /dev/tpmrm0 is present
ls -la /dev/tpm*

# Confirm tpm2-tools can talk to the TPM
tpm2_getcap properties-fixed
```

---

## Setup

### 1. Clone and create the virtual environment

```bash
git clone https://github.com/yourname/tpm-attest.git
cd tpm-attest

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. TPM group permissions (recommended over running as root)

```bash
# Add yourself to the tss group (manages /dev/tpmrm0)
sudo usermod -aG tss $USER

# Apply without logging out
newgrp tss

# Verify
ls -la /dev/tpmrm0
# crw-rw---- 1 root tss 10, 224 Jun 22 10:00 /dev/tpmrm0
```

### 3. Provision a persistent attestation key

This creates an RSA-2048 primary key in the TPM Owner hierarchy and persists it at handle `0x81000000`:

```bash
# Create a primary key in the owner hierarchy
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

# Persist the key at a fixed handle
tpm2_evictcontrol -C o -c primary.ctx 0x81000000

# Verify the key is persistent
tpm2_getcap handles-persistent
# - 0x81000000
```

> **Note:** The persistent handle `0x81000000` is hardcoded in `agent/report.py`. If you use a different handle, update `_TPM_KEY_HANDLE`.

### 4. Enable IMA (if not already active)

Check if IMA is running:
```bash
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements | head -3
```

If the file is missing, add to your kernel command line (e.g., in `/etc/default/grub`):
```
GRUB_CMDLINE_LINUX="... ima_policy=tcb"
```
Then run `sudo update-grub` and reboot.

### 5. Configure the PCR baseline (optional but recommended)

Edit `server/main.py` and populate `KNOWN_GOOD_PCRS` with the expected values from your trusted system:

```python
# Capture current values on a known-clean system
python -m agent.pcr_reader
```

```python
# Paste into server/main.py
KNOWN_GOOD_PCRS: dict[int, str] = {
    0: "0x3D458931A3680CA3E31DBF38DBABCD0A...",
    7: "0xB6E5E5A3C1A8D2F7...",
    # ...
}
```

---

## Running

### Attestation Agent

```bash
# Activate the virtual environment
source .venv/bin/activate

# Generate and display an attestation report (IMA log omitted from stdout)
python -m agent.report

# Run individual components for debugging:
python -m agent.pcr_reader   # PCR values only
python -m agent.ima_reader   # IMA summary only
```

### Verification Server

```bash
source .venv/bin/activate

# Start the server
uvicorn server.main:app --host 0.0.0.0 --port 8080

# Or using the module entry point
python -m server.main
```

---

## Example Output

### Agent — PCR values (`python -m agent.pcr_reader`)

```json
{
  "0": "0x3D458931A3680CA3E31DBF38DBABCD0AC27BDC95B4F5A833C33302E0C37FD5E",
  "1": "0xB16D2E0E86E23C1A5B2E3F7F00102A3E4A6D178C9A1D5E7F9B0C3D8A2F6E4C1",
  "4": "0xA7C4B3E2F1D09A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B9C8D7E6F5A4",
  "7": "0xB2F1E0D9C8B7A695847362514031201F0E0D0C0B0A090807060504030201001F",
  "9": "0xC3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3",
  "10": "0xD4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4"
}
```

### Agent — IMA summary (`python -m agent.ima_reader`)

```json
{
  "total_entries": 4821,
  "unique_files": 1203,
  "has_boot_aggregate": true,
  "modules_measured": 87
}
```

### Agent — Full attestation report (`python -m agent.report`)

```json
{
  "version": "1.0",
  "timestamp": "2026-06-22T10:47:33.214519+00:00",
  "nonce": "a3f8e2b1c94d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
  "pcrs": {
    "0": "0x3D458931A3680CA3E31DBF38DBABCD0AC27BDC95B4F5A833C33302E0C37FD5E",
    "1": "0xB16D2E0E86E23C1A5B2E3F7F00102A3E4A6D178C9A1D5E7F9B0C3D8A2F6E4C1",
    "4": "0xA7C4B3E2F1D09A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B9C8D7E6F5A4",
    "7": "0xB2F1E0D9C8B7A695847362514031201F0E0D0C0B0A090807060504030201001F",
    "9": "0xC3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3",
    "10": "0xD4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4"
  },
  "ima_summary": {
    "total_entries": 4821,
    "unique_files": 1203,
    "has_boot_aggregate": true,
    "modules_measured": 87
  },
  "quote_available": true,
  "quote_msg_b64": "ARoAAQALAAQAA...(base64-encoded TPM quote structure)...",
  "quote_sig_b64": "ABQACwAg...(base64-encoded TPMT_SIGNATURE)..."
}
```

### Server — Successful attestation (`POST /attest`)

```
HTTP 200 OK

{
  "valid": true,
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2026-06-22T10:52:33.214519+00:00"
}
```

---

## Research Context

This project is grounded in the following standards and specifications:

### TPM 2.0 — Trusted Platform Module

- [**TCG TPM 2.0 Specification**](https://trustedcomputinggroup.org/resource/tpm-library-specification/) — Part 1 (Architecture), Part 3 (Commands)
- **PCRs (Platform Configuration Registers)** — 24 hardware registers extended by `H_new = SHA256(H_old ‖ data)`. Values are monotonically chained; resetting requires a reboot.
- **TPM Quote** — A `TPMS_ATTEST` structure signed by a resident key. Proves current PCR state is bound to a specific nonce. Defined in TPM2B_ATTEST / TPM2_Quote (command code 0x0158).
- **Persistent keys** — Keys created with `tpm2_createprimary` and evicted to NV storage via `tpm2_evictcontrol`. Survive reboots; cannot be extracted without the TPM.

### IMA — Integrity Measurement Architecture

- [**Linux IMA documentation**](https://www.kernel.org/doc/html/latest/security/IMA-templates.html)
- IMA extends **PCR 10** every time a new file is executed or mapped. The log is append-only from kernel perspective.
- The `boot_aggregate` entry is computed as `SHA256(PCR_0 ‖ PCR_1 ‖ … ‖ PCR_7)` at IMA init time, anchoring the runtime log to Measured Boot.
- Template formats: `ima` (SHA1 only), `ima-ng` (algorithm:hash), `ima-sig` (includes file signature).

### Remote Attestation

- [**IETF RATS Architecture (RFC 9334)**](https://www.rfc-editor.org/rfc/rfc9334) — defines Attester, Verifier, and Relying Party roles
- [**TCG Platform Attestation**](https://trustedcomputinggroup.org/resource/platform-certificate-profile/) — reference for device attestation certificates
- This project implements the **background-check model**: the agent (Attester) sends evidence directly to the verification server (Verifier+Relying Party combined).

### Measured Boot

- UEFI Secure Boot extends PCR 7 with the Secure Boot state and signing authority.
- GRUB2 with TPM support extends PCR 8/9 for kernel and initrd.
- Systemd-boot extends PCR 4 with the EFI application hash.

---

## Roadmap

### ✅ Phase 1 — Core Agent (Complete)

- [x] `pcr_reader.py` — reads sha256 PCR bank via `tpm2_pcrread`
- [x] `ima_reader.py` — parses IMA ascii log, computes summary metrics
- [x] `report.py` — bundles PCRs, IMA data, TPM quote into a signed report with replay-resistant nonce

### ✅ Phase 2 — Verification Server (Complete)

- [x] `server/main.py` — FastAPI server with `POST /attest` and `GET /health`
- [x] 5-check verification pipeline (quote, freshness, non-zero PCRs, baseline pinning, IMA boot aggregate)
- [x] Short-lived session token issuance (UUID4, 5-minute lifetime)

### 🔄 Phase 3 — EAC Handshake Shim (In Progress)

- [ ] Intercept EAC handshake at the Wine/Proton layer
- [ ] Translate TPM session token into EAC-compatible attestation proof
- [ ] Expose a local IPC socket for Proton to query attestation state
- [ ] Integration tests against EAC sandbox endpoint

### 🗓 Phase 4 — Hardening & Distribution

- [ ] Quote signature verification (currently checks presence only — needs full `TPMT_SIGNATURE` verification via `tpm2_checkquote`)
- [ ] EK certificate chain validation against manufacturer CA
- [ ] Persistent token storage with revocation
- [ ] Packaging: systemd service unit for the agent, Docker image for the server
- [ ] Support for `swtpm` in CI for integration testing without physical TPM hardware

---

## Security Considerations

> **This is a research / proof-of-concept project.** Do not use in production without completing Phase 4 hardening.

- **Quote signature is not yet fully verified** — the server currently checks that `quote_available: true` but does not cryptographically verify the `TPMT_SIGNATURE` against the EK public key. This is the most critical gap for Phase 4.
- **KNOWN_GOOD_PCRS is empty by default** — PCR pinning is skipped unless you populate this dict. Without it, any machine with a TPM and IMA enabled will pass.
- **The IMA log is trusted as-read** — a kernel-level attacker who can modify the IMA log subsystem could forge entries. The TPM quote partially mitigates this (PCR 10 reflects IMA state), but full mitigation requires verifying the quote signature chain.
- **Nonce freshness** is enforced by a 60-second timestamp window, not by verifying the nonce is embedded in the quote's qualifying data. Phase 4 will add proper qualifying data validation.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) — the userspace TPM2 toolchain this project shells out to
- [Linux IMA subsystem](https://sourceforge.net/p/linux-ima/wiki/Home/) — kernel integrity measurement infrastructure
- [TCG Trusted Computing Group](https://trustedcomputinggroup.org/) — TPM 2.0 specification authors
- [IETF RATS Working Group](https://datatracker.ietf.org/wg/rats/about/) — remote attestation architecture standards
