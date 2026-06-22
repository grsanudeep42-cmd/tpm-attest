# phase3/Makefile
#
# Builds the three-component EAC stub / fake-game / hook pipeline.
#
# Targets:
#   all         — build everything
#   libeos_sdk.so
#   fake_game
#   eac_hook.so
#   clean       — remove build artefacts
#   run-bare    — run fake_game against the stub with no hook
#   run-hooked  — run fake_game under the LD_PRELOAD hook
#                 (assumes /tmp/eac_shim.sock is already listening)

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -g

.PHONY: all clean run-bare run-hooked

all: libeos_sdk.so eac_hook.so fake_game

# ── EOS SDK stub ──────────────────────────────────────────────────────────────
libeos_sdk.so: eos_stub.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl
	@echo "[BUILD] $@ OK"

# ── LD_PRELOAD hook ───────────────────────────────────────────────────────────
eac_hook.so: eac_hook.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl
	@echo "[BUILD] $@ OK"

# ── Fake game ─────────────────────────────────────────────────────────────────
# No link-time dep on libeos_sdk.so: fake_game resolves EOS symbols at runtime
# via dlopen/dlsym(RTLD_DEFAULT) so LD_PRELOAD interception works correctly.
fake_game: fake_game.c libeos_sdk.so
	$(CC) $(CFLAGS) -o $@ fake_game.c -ldl
	@echo "[BUILD] $@ OK"

# ── Helpers ───────────────────────────────────────────────────────────────────
clean:
	rm -f libeos_sdk.so eac_hook.so fake_game
	@echo "[CLEAN] done"

# Run without the hook — exercises the stub directly
run-bare: all
	@echo "=== Running fake_game (no hook) ==="
	./fake_game

# Run with the hook in the LD_PRELOAD chain.
# Assumes the Python shim server is already listening on /tmp/eac_shim.sock.
run-hooked: all
	@echo "=== Running fake_game under eac_hook.so ==="
	LD_PRELOAD=$(PWD)/eac_hook.so ./fake_game
