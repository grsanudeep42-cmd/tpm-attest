# VOID SECTOR — TPM-Attest Demo Game

A real 2-D space shooter that **gates gameplay behind hardware TPM attestation**.  
Built with Pygame 2 and wired directly into the TPM-Attest pipeline.

---

## What It Demonstrates

When you launch the game, before a single frame of gameplay is shown:

1. `game.py` calls `EOS_AntiCheatClient_BeginSession` + `EOS_AntiCheatClient_AddNotifyMessageToServer` via ctypes → `libeos_sdk.so`
2. `eac_hook.so` (injected via `LD_PRELOAD`) intercepts those calls and opens `/tmp/eac_shim.sock`
3. `shim.py` fetches a fresh nonce → builds the TPM report (PCRs + IMA Merkle tree + TPM quote) → POSTs to the attestation server
4. The server validates the quote signature, checks PCR baselines, and returns `{"valid": true/false}`
5. The game shows either **a green "ATTESTATION PASSED" screen** → gameplay starts, or a **red "ACCESS DENIED" screen** → session blocked

This is the full pipeline from Figure 1 of the paper running live.

---

## Files

```
demo_game/
  game.py        — main game (space shooter, ~500 lines, Pygame 2)
  eos_bridge.py  — ctypes bridge to libeos_sdk.so + direct socket fallback
  __init__.py

run_game.sh      — launch script (handles LD_PRELOAD + venv activation)
```

---

## Prerequisites

```bash
# pygame must be installed in the project venv
source .venv/bin/activate
pip install pygame

# phase3 must be built
cd phase3 && make all
```

---

## Running

### Full pipeline (recommended for paper demo)

Open **3 terminals**:

```bash
# Terminal 1 — attestation server
source .venv/bin/activate
python3 -m server.main

# Terminal 2 — shim daemon  
source .venv/bin/activate
python3 phase3/shim.py

# Terminal 3 — launch game (with LD_PRELOAD hook)
./run_game.sh
```

### Without the shim (standalone, attestation via direct socket)

```bash
./run_game.sh --no-hook
```

The game will show a denial screen if no shim is running (fail-closed by design).

---

## Gameplay

| Control | Action |
|---|---|
| `Arrow keys` / `WASD` | Move ship |
| `Space` / `Z` | Shoot |
| `R` | Restart after Game Over |
| `ESC` | Quit |

- **Enemies**: 3 types (Drone / Cruiser / Bomber) with distinct HP, speed, and score values
- **Waves**: Enemies get faster and more numerous each wave
- **Score**: Displayed live; high-score persists across retries in the session
- **TPM badge**: Bottom-right corner shows `TPM-ATTEST ✓ VERIFIED` during gameplay

---

## Attestation Screen States

| State | Display |
|---|---|
| Verifying | Animated spinner + live step progress (nonce → PCR → IMA → quote → POST) |
| **PASSED** | Green banner, partial token, "Press ENTER to launch game" |
| **DENIED** | Red banner, failure reason, "Press ESC to exit" |

---

## Integration with `eac_hook.c`

The hook intercepts `EOS_AntiCheatClient_AddNotifyMessageToServer` — the **exact same symbol** used in the hook, requiring zero changes to the C code. The game calls it through `libeos_sdk.so` (the EOS SDK stub), so `LD_PRELOAD=eac_hook.so` is sufficient to gate access with no game-side modification. This demonstrates the transparency of the attestation layer.
