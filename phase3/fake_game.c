/*
 * fake_game.c — Fake game that exercises the EOS Anti-Cheat client path
 *
 * Resolves EOS symbols ONLY via dlopen/dlsym at runtime (no link-time
 * dependency on libeos_sdk.so).  This ensures that when the binary is run
 * under LD_PRELOAD=eac_hook.so the preloaded symbols win the lookup and
 * every EOS call is intercepted by the hook.
 *
 * Compile: gcc -o fake_game fake_game.c -ldl
 *           (no -leos_sdk, no -Wl,-rpath)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* EOS function pointer typedefs (mirrors what eos_stub.c exports)     */
/* ------------------------------------------------------------------ */

typedef void (*fn_BeginSession)(const char *user_id);
typedef void (*fn_AddNotify)(void (*callback)(const char *, size_t));
typedef void (*fn_ReceiveMsg)(const void *data, size_t size);

/* ------------------------------------------------------------------ */
/* Callback registered with EAC — called by the EOS runtime (or stub)  */
/* ------------------------------------------------------------------ */

static void on_message_to_server(const char *message, size_t length)
{
    printf("[FAKE_GAME] on_message_to_server fired!\n");
    printf("[FAKE_GAME]   length  : %zu\n", length);
    printf("[FAKE_GAME]   payload : %.*s\n", (int)length, message);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("[FAKE_GAME] Starting up...\n");
    fflush(stdout);

    /* -------------------------------------------------------------- */
    /* 1. dlopen the EOS SDK (or our hook-replaced version)            */
    /* -------------------------------------------------------------- */
    /*
     * RTLD_LAZY | RTLD_LOCAL: do NOT promote the stub's symbols into the
     * global namespace.  LD_PRELOAD symbols are already global and take
     * priority for any subsequent dlsym(RTLD_DEFAULT, ...) call, so the
     * hook's versions of the EOS functions win the lookup below.
     */
    void *eos_handle = dlopen("./libeos_sdk.so", RTLD_LAZY | RTLD_LOCAL);
    if (!eos_handle) {
        fprintf(stderr, "[FAKE_GAME] dlopen failed: %s\n", dlerror());
        return EXIT_FAILURE;
    }
    printf("[FAKE_GAME] libeos_sdk.so loaded @ %p\n", eos_handle);

    /* -------------------------------------------------------------- */
    /* 2. Resolve symbols                                              */
    /* -------------------------------------------------------------- */
    dlerror(); /* clear any stale error */

    /*
     * Use RTLD_DEFAULT: the dynamic linker searches the global symbol table
     * in load order.  LD_PRELOAD libraries are inserted first, so if
     * eac_hook.so is preloaded its versions of the EOS symbols are returned
     * here — not the stub's.  When running without LD_PRELOAD the stub
     * symbols (loaded above via dlopen with RTLD_GLOBAL for this lookup)
     * are found instead.
     *
     * Re-open with RTLD_GLOBAL so RTLD_DEFAULT can find the stub symbols
     * when the hook is NOT preloaded.
     */
    dlclose(eos_handle);
    eos_handle = dlopen("./libeos_sdk.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!eos_handle) {
        fprintf(stderr, "[FAKE_GAME] dlopen(GLOBAL) failed: %s\n", dlerror());
        return EXIT_FAILURE;
    }
    dlerror();

    fn_BeginSession  EOS_AntiCheatClient_BeginSession =
        (fn_BeginSession)dlsym(RTLD_DEFAULT, "EOS_AntiCheatClient_BeginSession");

    fn_AddNotify     EOS_AntiCheatClient_AddNotifyMessageToServer =
        (fn_AddNotify)dlsym(RTLD_DEFAULT, "EOS_AntiCheatClient_AddNotifyMessageToServer");

    fn_ReceiveMsg    EOS_AntiCheatClient_ReceiveMessageFromServer =
        (fn_ReceiveMsg)dlsym(RTLD_DEFAULT, "EOS_AntiCheatClient_ReceiveMessageFromServer");

    const char *dlerr = dlerror();
    if (dlerr) {
        fprintf(stderr, "[FAKE_GAME] dlsym error: %s\n", dlerr);
        dlclose(eos_handle);
        return EXIT_FAILURE;
    }

    printf("[FAKE_GAME] All EOS symbols resolved.\n");
    fflush(stdout);

    /* -------------------------------------------------------------- */
    /* 3. Begin an EAC session for player "player_123"                 */
    /* -------------------------------------------------------------- */
    printf("[FAKE_GAME] Calling BeginSession(\"player_123\")...\n");
    fflush(stdout);
    EOS_AntiCheatClient_BeginSession("player_123");

    /* -------------------------------------------------------------- */
    /* 4. Register our message-to-server callback                      */
    /* -------------------------------------------------------------- */
    printf("[FAKE_GAME] Registering AddNotifyMessageToServer callback...\n");
    fflush(stdout);
    EOS_AntiCheatClient_AddNotifyMessageToServer(on_message_to_server);

    /* -------------------------------------------------------------- */
    /* 5. Send a fake integrity message toward the EAC server          */
    /* -------------------------------------------------------------- */
    const char *integrity_msg =
        "{\"check\":\"integrity\",\"platform\":\"linux\"}";
    printf("[FAKE_GAME] Sending fake integrity message: %s\n", integrity_msg);
    fflush(stdout);
    EOS_AntiCheatClient_ReceiveMessageFromServer(
        integrity_msg, strlen(integrity_msg));

    /* -------------------------------------------------------------- */
    /* 6. Wait 2 s then exit                                           */
    /* -------------------------------------------------------------- */
    printf("[FAKE_GAME] Sleeping 2 s before exit...\n");
    fflush(stdout);
    sleep(2);

    dlclose(eos_handle);
    printf("[FAKE_GAME] Done. Exiting cleanly.\n");
    return EXIT_SUCCESS;
}
