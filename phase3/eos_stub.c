/*
 * eos_stub.c — Fake EOS SDK shared library
 *
 * Exports the three EAC symbols a real game would call.
 * Compile: gcc -shared -fPIC -o libeos_sdk.so eos_stub.c -ldl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal state                                                       */
/* ------------------------------------------------------------------ */

typedef void (*EOS_MessageCallback)(const char *message, size_t length);

static EOS_MessageCallback g_registered_callback = NULL;
static char g_current_player_id[256] = {0};

/* ------------------------------------------------------------------ */
/* Exported symbols                                                     */
/* ------------------------------------------------------------------ */

/*
 * EOS_AntiCheatClient_BeginSession
 *
 * Called by the game to start an EAC session for a given player.
 * @param user_id  Null-terminated player identifier string.
 */
void EOS_AntiCheatClient_BeginSession(const char *user_id)
{
    if (!user_id) {
        fprintf(stderr, "[EOS_STUB] BeginSession called with NULL user_id\n");
        return;
    }

    strncpy(g_current_player_id, user_id, sizeof(g_current_player_id) - 1);
    g_current_player_id[sizeof(g_current_player_id) - 1] = '\0';

    printf("[EOS_STUB] BeginSession  → player_id = \"%s\"\n", g_current_player_id);
    fflush(stdout);
}

/*
 * EOS_AntiCheatClient_AddNotifyMessageToServer
 *
 * Registers a callback the EAC runtime will invoke when it wants to send
 * a message toward the anti-cheat server.
 * @param callback  Function pointer to store; called with (message, length).
 */
void EOS_AntiCheatClient_AddNotifyMessageToServer(EOS_MessageCallback callback)
{
    g_registered_callback = callback;
    printf("[EOS_STUB] AddNotifyMessageToServer → callback registered @ %p\n",
           (void *)callback);
    fflush(stdout);

    /* Immediately fire a synthetic server-to-client challenge so the fake
       game can exercise the callback right away.                         */
    if (g_registered_callback) {
        const char *synthetic = "{\"type\":\"challenge\",\"nonce\":\"deadbeef\"}";
        printf("[EOS_STUB] Firing synthetic callback: %s\n", synthetic);
        fflush(stdout);
        g_registered_callback(synthetic, strlen(synthetic));
    }
}

/*
 * EOS_AntiCheatClient_ReceiveMessageFromServer
 *
 * Called by the game to forward a raw server message into the EAC client
 * runtime.
 * @param data   Raw byte buffer coming from the anti-cheat server.
 * @param size   Length of @data in bytes.
 */
void EOS_AntiCheatClient_ReceiveMessageFromServer(const void *data, size_t size)
{
    if (!data || size == 0) {
        fprintf(stderr, "[EOS_STUB] ReceiveMessageFromServer called with empty data\n");
        return;
    }

    /* Print as a hex dump + best-effort ASCII string */
    printf("[EOS_STUB] ReceiveMessageFromServer → %zu bytes received\n", size);
    printf("[EOS_STUB]   payload (text): %.*s\n", (int)size, (const char *)data);
    printf("[EOS_STUB]   payload (hex) : ");
    for (size_t i = 0; i < size; i++)
        printf("%02x", ((const unsigned char *)data)[i]);
    printf("\n");
    fflush(stdout);
}
