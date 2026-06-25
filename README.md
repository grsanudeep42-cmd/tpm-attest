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
3. **Building an IMA Merkle tree** — A compact SHA-256 binary Merkle tree over all IMA entries, producing a single root hash that summarises the entire runtime measurement log.
4. **Generating a TPM Quote** — A hardware-signed snapshot of PCR values, bound to a fresh nonce to prevent replay.
5. **Bundling and submitting** an attestation report to a verification server.
6. **Verifying** PCR values, quote signature (via `tpm2_checkquote`), IMA Merkle root integrity, and timestamp freshness — then issuing a short-lived **session token** on success.
7. **Intercepting the EAC handshake** via an `LD_PRELOAD` hook that transparently gates game session start on a valid attestation token.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ATTESTED MACHINE                        │
│                                                             │
│  ┌──────────────┐    ┌──────────────────────┐  ┌─────────┐  │
│  │  pcr_reader  │    │      ima_reader       │  │ TPM 2.0 │  │
│  │ tpm2_pcrread │    │  IMA log → Merkle    │  │Hardware │  │
│  │ sha256:      │    │  tree (root+depth+   │  │tpm2_quote│ │
│  │ 0,1,4,7,9,10 │    │  leaf_count)         │  │         │  │
│  └──────┬───────┘    └──────────┬───────────┘  └────┬────┘  │
│         └──────────────────────┴──────────────────┘         │
│                                │                             │
│                       ┌────────▼────────┐                    │
│                       │    report.py    │                    │
│                       │  nonce (fresh)  │                    │
│                       │  pcrs           │                    │
│                       │  ima_summary    │                    │
│                       │  ima_merkle_root│                    │
│                       │  quote_msg_b64  │                    │
│                       │  quote_sig_b64  │                    │
│                       └────────┬────────┘                    │
│                                │                             │
│  ┌─────────────────────────────┴──────────────┐              │
│  │  phase3/shim.py  (Unix socket daemon)      │              │
│  │  Bridges eac_hook.so ↔ attestation server  │              │
│  └─────────────────────────────┬──────────────┘              │
│                                │                             │
│  ┌─────────────────────────────┴──────────────┐              │
│  │  phase3/eac_hook.so  (LD_PRELOAD)          │              │
│  │  Intercepts EOS_AntiCheatClient_* symbols  │              │
│  │  Blocks game until valid token received    │              │
│  └────────────────────────────────────────────┘              │
└─────────────────────────────│───────────────────────────────┘
                              │  HTTP POST /attest
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   VERIFICATION SERVER                       │
│                    (server/main.py)                         │
│                                                             │
│   ① TPM quote present?                                      │
│   ② Quote signature valid? (tpm2_checkquote)                │
│   ③ Report timestamp within 60s? (replay protection)        │
│   ④ PCR values non-zero?                                    │
│   ⑤ PCR values match known-good baseline? (if configured)   │
│   ⑥ IMA log contains boot_aggregate?                        │
│   ⑦ IMA Merkle root valid? (matches pinned baseline)        │
│                                                             │
│   POST /register — enroll an AK public key by machine_id    │
│   POST /enroll   — pin current IMA Merkle root as baseline  │
│                                                             │
│   PASS ──► { "valid": true, "token": "<uuid4>",             │
│              "expires_at": "<ISO UTC>" }                     │
│   FAIL ──► { "valid": false, "reason": "..." }              │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### `agent/pcr_reader.py`

Reads the **sha256 PCR bank** via `tpm2_pcrread` for policy-relevant registers:

| PCR | Measured Content |
|-----|-----------------|
| **0** | UEFI firmware code |
| **1** | UEFI firmware configuration |
| **4** | Boot loader code (GRUB/systemd-boot) |
| **7** | Secure Boot state and policy |
| **9** | Kernel and initramfs |
| **10** | IMA runtime measurements (extended continuously) |

### `agent/ima_reader.py`

Reads `/sys/kernel/security/ima/ascii_runtime_measurements` and provides:

- **`read_ima_log()`** — full parsed log as `list[dict]`
- **`read_ima_summary()`** — aggregated metrics: `{total_entries, unique_files, has_boot_aggregate, modules_measured}`
- **`build_ima_merkle_tree(entries)`** — builds a SHA-256 binary Merkle tree over all IMA entries; returns `{root, depth, leaf_count, leaves}`
- **`get_ima_proof(entries, index)`** — returns the Merkle inclusion proof for any single entry

The `boot_aggregate` entry anchors the IMA log to TPM state at boot. The Merkle root compresses thousands of entries into a single 64-char hex string that the server can pin and compare.

### `agent/report.py`

Bundles PCR values, IMA Merkle tree metadata, IMA summary, and a TPM quote into one signed attestation report.

A fresh **32-byte random nonce** is generated per report to prevent replay attacks. The nonce is passed as `tpm2_quote` qualifying data, binding the quote to this specific report.

**Report schema:**

| Field | Type | Description |
|---|---|---|
| `version` | `"1.0"` | Schema version |
| `timestamp` | ISO 8601 UTC | Report generation time |
| `nonce` | 64-char hex | Fresh random — binds quote to this report |
| `pcrs` | `dict[str, str]` | PCR index → sha256 hex digest |
| `ima_summary` | object | `{total_entries, unique_files, has_boot_aggregate, modules_measured}` |
| `ima_merkle_root` | 64-char hex | SHA-256 Merkle root over all IMA entries |
| `ima_merkle_depth` | int | Tree depth |
| `ima_leaf_count` | int | Number of IMA entries |
| `quote_available` | bool | Whether TPM quote was obtained |
| `quote_msg_b64` | base64 \| null | Raw TPM quote message (`TPMS_ATTEST`) |
| `quote_sig_b64` | base64 \| null | TPM quote signature (`TPMT_SIGNATURE`) |
| `machine_id` | str \| null | Optional — used to look up a pre-enrolled AK key |

### `server/main.py`

A **FastAPI** verification server exposing four endpoints:

#### `GET /health`
```json
{"status": "ok", "version": "1.0"}
```

#### `POST /attest`

Runs **7 verification checks** in order:

1. **Quote presence** — report must include a TPM-signed quote
2. **Quote signature** — `tpm2_checkquote` verifies the `TPMT_SIGNATURE` against the AK public key
3. **Timestamp freshness** — report must be within 60 seconds (replay protection)
4. **PCR non-zero** — all PCR values must be non-zero
5. **PCR value pinning** — if `KNOWN_GOOD_PCRS` is configured, values must match exactly
6. **IMA boot aggregate** — IMA log must contain `boot_aggregate`
7. **IMA Merkle root** — structural validity check; if `KNOWN_GOOD_IMA_ROOT` is pinned, root must match

**Success (200):**
```json
{"valid": true, "token": "<uuid4>", "expires_at": "<ISO UTC>"}
```
**Failure (400):**
```json
{"valid": false, "reason": "PCR 7 mismatch: expected '0xABCD...', got '0x1234...'"}
```

Tokens are valid for **5 minutes**.

#### `POST /register`

Enroll an AK public key for a specific machine (for cross-machine attestation):

```json
{"machine_id": "my-gaming-rig", "ak_pub_b64": "<base64 TPM2B_PUBLIC>"}
```
```json
{"registered": true, "machine_id": "my-gaming-rig"}
```

When a machine submits an attestation report with a matching `machine_id`, the server uses the enrolled key for `tpm2_checkquote` instead of reading from its own TPM handle.

#### `POST /enroll`

Pin the IMA Merkle root of a verified clean system as the baseline. Runs full attestation verification first, then stores the `ima_merkle_root` as `KNOWN_GOOD_IMA_ROOT`. Future reports must match this root.

```json
{"enrolled": true, "ima_root": "<64-char hex>"}
```

### `phase3/eac_hook.c` + `phase3/shim.py`

The **Phase 3 EAC intercept layer**:

- **`eac_hook.so`** — An `LD_PRELOAD` shared library that intercepts `EOS_AntiCheatClient_AddNotifyMessageToServer` (the EAC SDK entry point). Before resolving the real symbol, it connects to a Unix socket (`/tmp/eac_shim.sock`), sends a handshake, and waits for an attestation result. If `{"valid": true}` is returned, it resolves the real EAC symbol and allows the game to proceed.
- **`shim.py`** — A Unix socket daemon that bridges the game hook to the attestation server. Accepts connections from `eac_hook.so`, calls `generate_report()`, POSTs to `/attest`, and returns the result.
- **`fake_game.c`** — A mock game binary that calls the EAC SDK entry point, used to demonstrate the full intercept flow without a real game.

---

## Project Structure

```
tpm-attest/
├── agent/
│   ├── __init__.py
│   ├── pcr_reader.py     # Reads TPM2 PCR values via tpm2_pcrread
│   ├── ima_reader.py     # Parses IMA log; builds SHA-256 Merkle tree
│   └── report.py         # Bundles PCRs + IMA Merkle + TPM quote → report
├── phase3/
│   ├── eac_hook.c        # LD_PRELOAD hook — intercepts EAC SDK entry point
│   ├── eos_stub.c        # Mock EOS SDK stub for local testing
│   ├── fake_game.c       # Mock game binary that calls EAC SDK
│   ├── mock_eac_client.c # Standalone test client for the shim socket
│   ├── shim.py           # Unix socket daemon: game ↔ attestation server
│   └── Makefile          # Builds eac_hook.so, libeos_sdk.so, fake_game
├── paper/
│   └── research_paper.md # Full research paper draft
├── server/
│   ├── __init__.py
│   └── main.py           # FastAPI server (POST /attest /register /enroll, GET /health)
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Linux** with TPM 2.0 | Physical TPM or emulator (`swtpm`) |
| **`tpm2-tools`** | `tpm2_pcrread`, `tpm2_quote`, `tpm2_checkquote`, `tpm2_createprimary`, `tpm2_evictcontrol`, `tpm2_readpublic` |
| **Python 3.11+** | |
| **IMA enabled in kernel** | `CONFIG_IMA=y`, mounted securityfs |
| **`sudo` access** | Required by `ima_reader` to read the IMA log |
| **gcc + make** | Only needed to rebuild `phase3/` binaries from source |

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
ls -la /dev/tpm*
tpm2_getcap properties-fixed
```

---

## Setup

### 1. Clone and create the virtual environment

```bash
git clone https://github.com/grsanudeep42-cmd/tpm-attest.git
cd tpm-attest

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. TPM group permissions (recommended over running as root)

```bash
sudo usermod -aG tss $USER
newgrp tss
ls -la /dev/tpmrm0
# crw-rw---- 1 root tss 10, 224 ...
```

### 3. Provision a persistent attestation key

```bash
# Create a primary key in the owner hierarchy
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

# Persist the key at a fixed handle
tpm2_evictcontrol -C o -c primary.ctx 0x81000000

# Verify
tpm2_getcap handles-persistent
# - 0x81000000
```

> **Note:** The persistent handle `0x81000000` is hardcoded in `agent/report.py`. Update `_TPM_KEY_HANDLE` if you use a different handle.

### 4. Enable IMA (if not already active)

```bash
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements | head -3
```

If the file is missing, add to your kernel command line in `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX="... ima_policy=tcb"
```
Then run `sudo update-grub` and reboot.

### 5. Configure baselines (optional but recommended)

**PCR pinning** — capture current values on a known-clean system:
```bash
python -m agent.pcr_reader
```
Paste into `server/main.py` → `KNOWN_GOOD_PCRS`.

**IMA Merkle root pinning** — enroll via the server after starting it:
```bash
# Generate a report and POST it to /enroll
python -m agent.report | curl -s -X POST http://localhost:8080/enroll \
  -H "Content-Type: application/json" -d @-
# {"enrolled": true, "ima_root": "<64-char hex>"}
```

---

## Running

### Option A — Full pipeline (Phases 1+2+3)

**Terminal 1 — Verification server:**
```bash
source .venv/bin/activate
uvicorn server.main:app --host 0.0.0.0 --port 8080
```

**Terminal 2 — EAC shim:**
```bash
source .venv/bin/activate
python3 phase3/shim.py
# [shim] INFO EAC shim listening on /tmp/eac_shim.sock
```

**Terminal 3 — Mock game (triggers full intercept):**
```bash
cd phase3
LD_PRELOAD=./eac_hook.so ./fake_game
# [hook] EOS_AntiCheatClient_AddNotifyMessageToServer intercepted
# [hook] Attestation result: valid=1
# [game] EAC registered — gameplay running
```

### Option B — Agent + server only (Phases 1+2)

```bash
source .venv/bin/activate

# Generate a report and submit it
python -m agent.report | curl -s -X POST http://localhost:8080/attest \
  -H "Content-Type: application/json" -d @-

# Or run components individually
python -m agent.pcr_reader    # PCR values only
python -m agent.ima_reader    # IMA summary + Merkle root
```

### Build phase3 binaries from source

```bash
cd phase3
make clean && make
# Produces: eac_hook.so  libeos_sdk.so  fake_game  mock_eac_client
```

---

## Cross-Machine Attestation

`tpm-attest` supports **remote attestation across machines** — the attestation agent and verification server do not need to share a TPM.

### Setup

**On the client machine** — export the AK public key:
```bash
tpm2_readpublic -c 0x81000000 -o ak.pub
AK_B64=$(base64 -w0 ak.pub)
```

**Register with the server:**
```bash
curl -s -X POST http://<server>:8080/register \
  -H "Content-Type: application/json" \
  -d "{\"machine_id\": \"my-gaming-rig\", \"ak_pub_b64\": \"$AK_B64\"}"
# {"registered": true, "machine_id": "my-gaming-rig"}
```

**Submit attestation reports** from the client with `machine_id` set:
```python
report = generate_report()
report["machine_id"] = "my-gaming-rig"
# POST to /attest — server uses enrolled key, no TPM access needed server-side
```

---

## Example Output

### PCR values (`python -m agent.pcr_reader`)

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

### IMA summary + Merkle tree (`python -m agent.ima_reader`)

```json
{
  "ima_summary": {
    "total_entries": 4821,
    "unique_files": 1203,
    "has_boot_aggregate": true,
    "modules_measured": 87
  },
  "merkle_root": "a3f8e2b1c94d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
  "merkle_depth": 13,
  "merkle_leaf_count": 4821
}
```

### Successful attestation (`POST /attest`)

```
HTTP 200 OK
{"valid": true, "token": "550e8400-e29b-41d4-a716-446655440000", "expires_at": "2026-06-22T10:52:33+00:00"}
```

---

## Roadmap

### ✅ Phase 1 — Core Agent (Complete)

- [x] `pcr_reader.py` — reads sha256 PCR bank via `tpm2_pcrread`
- [x] `ima_reader.py` — parses IMA ascii log, computes summary metrics
- [x] `report.py` — bundles PCRs, IMA data, TPM quote with replay-resistant nonce

### ✅ Phase 2 — Verification Server (Complete)

- [x] `server/main.py` — FastAPI server with 4 endpoints
- [x] 7-check verification pipeline including full `tpm2_checkquote` signature verification
- [x] IMA Merkle tree — compact integrity proof replacing full log transmission
- [x] `POST /register` — cross-machine AK key enrollment
- [x] `POST /enroll` — IMA Merkle root baseline pinning
- [x] Short-lived session token issuance (UUID4, 5-minute lifetime)

### ✅ Phase 3 — EAC Handshake Shim (Complete)

- [x] `eac_hook.so` — LD_PRELOAD hook intercepting EOS SDK anti-cheat entry point
- [x] `shim.py` — Unix socket daemon bridging game hook to attestation server
- [x] `fake_game` + `libeos_sdk.so` — mock environment for end-to-end testing
- [x] Full pipeline verified: hook → shim → agent → server → token → game proceeds

### 🗓 Phase 4 — Hardening & Distribution

- [ ] EK certificate chain validation against manufacturer CA
- [ ] Proper nonce embedding verification in quote qualifying data
- [ ] Persistent token storage with revocation
- [ ] Packaging: systemd service unit for the agent, Docker image for the server
- [ ] `swtpm` integration in CI for testing without physical TPM hardware
- [ ] Proton/Wine integration (replace mock EAC SDK with real handshake protocol)

---

## Security Considerations

> **This is a research / proof-of-concept project.** Do not use in production without completing Phase 4 hardening.

- **Quote signature is fully verified** via `tpm2_checkquote` against the enrolled or local AK public key. The critical Phase 3 gap is closed.
- **KNOWN_GOOD_PCRS is empty by default** — PCR pinning is skipped unless you populate this dict. Without it, any machine with a TPM and IMA enabled will pass.
- **KNOWN_GOOD_IMA_ROOT starts as None** — the server logs received roots (enrollment mode) until you call `POST /enroll` on a verified clean system.
- **Nonce freshness** is enforced by a 60-second timestamp window. Phase 4 will add proper qualifying data validation to verify the nonce is embedded in the quote structure itself.
- **AK keys are in-memory only** — `ENROLLED_AK_KEYS` is reset on server restart. Phase 4 will add persistent storage.

---

## Research Context

### TPM 2.0 — Trusted Platform Module

- [**TCG TPM 2.0 Specification**](https://trustedcomputinggroup.org/resource/tpm-library-specification/) — Part 1 (Architecture), Part 3 (Commands)
- **PCRs** — 24 hardware registers extended by `H_new = SHA256(H_old ‖ data)`. Values are monotonically chained; resetting requires a reboot.
- **TPM Quote** — A `TPMS_ATTEST` structure signed by a resident key. Proves current PCR state is bound to a specific nonce. Command code `0x0158`.

### IMA — Integrity Measurement Architecture

- [**Linux IMA documentation**](https://www.kernel.org/doc/html/latest/security/IMA-templates.html)
- IMA extends **PCR 10** every time a new file is executed or mapped.
- The `boot_aggregate` entry is `SHA256(PCR_0 ‖ … ‖ PCR_7)` at IMA init, anchoring the runtime log to Measured Boot.

### Remote Attestation

- [**IETF RATS Architecture (RFC 9334)**](https://www.rfc-editor.org/rfc/rfc9334) — defines Attester, Verifier, and Relying Party roles
- This project implements the **background-check model**: the agent sends evidence directly to the combined Verifier+Relying Party.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) — the userspace TPM2 toolchain this project shells out to
- [Linux IMA subsystem](https://sourceforge.net/p/linux-ima/wiki/Home/) — kernel integrity measurement infrastructure
- [TCG Trusted Computing Group](https://trustedcomputinggroup.org/) — TPM 2.0 specification authors
- [IETF RATS Working Group](https://datatracker.ietf.org/wg/rats/about/) — remote attestation architecture standards
