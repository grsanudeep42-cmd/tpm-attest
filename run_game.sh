#!/usr/bin/env bash
# run_game.sh — launches VOID SECTOR with the TPM-Attest hook pipeline
#
# What this does:
#   1. Builds libeos_sdk.so and eac_hook.so (if needed)
#   2. Injects eac_hook.so via LD_PRELOAD so the game's EOS calls are intercepted
#   3. Activates the project venv (pygame lives there)
#
# Usage:
#   chmod +x run_game.sh
#   ./run_game.sh [--no-hook]   # --no-hook runs without the LD_PRELOAD hook

set -e
# run_game.sh sits in the repo root — REPO_ROOT == SCRIPT_DIR
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE3="$REPO_ROOT/phase3"
VENV="$REPO_ROOT/.venv/bin/python3"

cd "$PHASE3"
echo "[run_game] Building phase3 artifacts..."
make -s all
echo "[run_game] Build OK"

cd "$REPO_ROOT"

if [[ "$1" == "--no-hook" ]]; then
    echo "[run_game] Running WITHOUT LD_PRELOAD hook (attestation via direct socket only)"
    "$VENV" -m demo_game.game
else
    echo "[run_game] Running WITH LD_PRELOAD hook → eac_hook.so"
    echo "[run_game] Make sure shim.py + attestation server are running first!"
    echo "[run_game]   Terminal 1:  python3 -m server.main"
    echo "[run_game]   Terminal 2:  python3 phase3/shim.py"
    echo ""
    LD_PRELOAD="$PHASE3/eac_hook.so" "$VENV" -m demo_game.game
fi
