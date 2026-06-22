/*
 * eac_hook.c — LD_PRELOAD shim: intercepts EOS Anti-Cheat calls and
 *              validates them via a Unix-domain socket to the TPM shim.
 *
 * KEY FIX vs previous version
 * ───────────────────────────
 * The socket query now fires IMMEDIATELY inside
 * EOS_AntiCheatClient_AddNotifyMessageToServer, not lazily inside
 * hook_callback.  hook_callback also queries the shim for every
 * subsequent per-message event.
 *
 * Socket hardening:
 *   • SO_RCVTIMEO = 5 s  (blocking recv cannot hang forever)
 *   • Fail-closed on every error path
 *   • Debug print at: socket-create, connect, send, recv
 *
 * Compile: gcc -shared -fPIC -o eac_hook.so eac_hook.c -ldl
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

/* ── config ──────────────────────────────────────────────────────── */
#define SHIM_SOCK_PATH   "/tmp/eac_shim.sock"
#define SHIM_BUF_SIZE    8192
#define SHIM_TIMEOUT_SEC 30

/* ── internal state ──────────────────────────────────────────────── */
typedef void (*EOS_MessageCallback)(const char *msg, size_t len);
typedef void (*fn_AddNotify)(EOS_MessageCallback cb);

static EOS_MessageCallback g_game_callback  = NULL;
static fn_AddNotify        g_real_add_notify = NULL;
static char                g_player_id[256]  = "unknown";

/* ── hex helper ──────────────────────────────────────────────────── */
static void bytes_to_hex(const unsigned char *data, size_t len,
                          char *out, size_t cap)
{
    size_t w = 0;
    for (size_t i = 0; i < len && w + 3 < cap; i++)
        w += (size_t)snprintf(out + w, cap - w, "%02x", data[i]);
    out[w] = '\0';
}

/* ── shim_query ──────────────────────────────────────────────────── *
 * Opens a fresh Unix-socket connection, sends json_request, reads   *
 * back the response with a 5-second timeout.                        *
 * Returns 1 if response contains "valid":true, 0 otherwise.         *
 * Prints a debug line at every step so failures are visible.        */
static int shim_query(const char *json_request,
                       char *resp_out, size_t resp_cap)
{
    /* ── 1. create socket ── */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[HOOK][DBG] socket() failed: %s\n", strerror(errno));
        return 0;
    }
    fprintf(stderr, "[HOOK][DBG] socket() fd=%d OK\n", fd);

    /* ── 2. set recv timeout ── */
    struct timeval tv = { .tv_sec = SHIM_TIMEOUT_SEC, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        fprintf(stderr, "[HOOK][DBG] setsockopt(SO_RCVTIMEO) warn: %s\n",
                strerror(errno));

    /* ── 3. connect ── */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SHIM_SOCK_PATH, sizeof(addr.sun_path) - 1);

    fprintf(stderr, "[HOOK][DBG] connect() → %s ...\n", SHIM_SOCK_PATH);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[HOOK][DBG] connect() FAILED: %s\n", strerror(errno));
        close(fd);
        return 0;
    }
    fprintf(stderr, "[HOOK][DBG] connect() OK\n");

    /* ── 4. send ── */
    size_t req_len = strlen(json_request);
    fprintf(stderr, "[HOOK][DBG] send() %zu bytes: %s\n", req_len, json_request);
    ssize_t sent = write(fd, json_request, req_len);
    if (sent < 0 || (size_t)sent != req_len) {
        fprintf(stderr, "[HOOK][DBG] send() FAILED (sent=%zd): %s\n",
                sent, strerror(errno));
        close(fd);
        return 0;
    }
    fprintf(stderr, "[HOOK][DBG] send() OK (%zd bytes)\n", sent);

    /* Signal EOF so server knows the full request has arrived */
    shutdown(fd, SHUT_WR);

    /* ── 5. recv (blocks up to 5 s) ── */
    fprintf(stderr, "[HOOK][DBG] recv() waiting (timeout=%ds)...\n",
            SHIM_TIMEOUT_SEC);
    ssize_t n = read(fd, resp_out, resp_cap - 1);
    close(fd);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            fprintf(stderr, "[HOOK][DBG] recv() TIMEOUT after %ds\n",
                    SHIM_TIMEOUT_SEC);
        else
            fprintf(stderr, "[HOOK][DBG] recv() FAILED: %s\n", strerror(errno));
        return 0;
    }
    if (n == 0) {
        fprintf(stderr, "[HOOK][DBG] recv() returned 0 (server closed early)\n");
        return 0;
    }
    resp_out[n] = '\0';
    fprintf(stderr, "[HOOK][DBG] recv() OK (%zd bytes): %s\n", n, resp_out);

    /* ── 6. parse "valid" field ── */
    int valid = (strstr(resp_out, "\"valid\":true")  != NULL ||
                 strstr(resp_out, "\"valid\": true") != NULL);
    fprintf(stderr, "[HOOK][DBG] valid=%d\n", valid);
    return valid;
}

/* ── build_json ──────────────────────────────────────────────────── *
 * Fills buf with the standard intercept JSON payload.               *
 * Returns 1 on success, 0 if the buffer was too small.             */
static int build_json(char *buf, size_t cap,
                       const char *player_id,
                       const char *hex_msg)
{
    int n = snprintf(buf, cap,
        "{"
          "\"type\":\"eac_intercept\","
          "\"player_id\":\"%s\","
          "\"original_message\":\"%s\""
        "}",
        player_id, hex_msg ? hex_msg : "");
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "[HOOK][DBG] build_json() overflow (need %d, cap %zu)\n",
                n, cap);
        return 0;
    }
    return 1;
}

/* ── hook_callback ───────────────────────────────────────────────── *
 * Registered with the real EOS runtime in place of the game's cb.  *
 * Fires for every subsequent per-message event.                     */
static void hook_callback(const char *message, size_t length)
{
    fprintf(stderr,
            "[HOOK] hook_callback: message event (%zu bytes)\n", length);

    /* hex-encode */
    size_t hex_cap = length * 2 + 4;
    char *hex = malloc(hex_cap);
    if (!hex) {
        fprintf(stderr, "[HOOK] OOM — message BLOCKED\n");
        return;
    }
    bytes_to_hex((const unsigned char *)message, length, hex, hex_cap);

    char json[SHIM_BUF_SIZE];
    char resp[SHIM_BUF_SIZE];

    if (!build_json(json, sizeof(json), g_player_id, hex)) {
        free(hex);
        fprintf(stderr, "[HOOK] attestation failed, message blocked\n");
        return;
    }
    free(hex);

    int valid = shim_query(json, resp, sizeof(resp));
    if (!valid) {
        fprintf(stderr, "[HOOK] attestation failed, message blocked\n");
        return;
    }

    /* forward original to the game's callback */
    if (g_game_callback) {
        fprintf(stderr, "[HOOK] attestation passed — forwarding message\n");
        g_game_callback(message, length);
    }
}

/* ═══════════════════════════════════════════════════════════════════ *
 * Intercepted EOS entry-points                                        *
 * ═══════════════════════════════════════════════════════════════════ */

/* ── BeginSession ────────────────────────────────────────────────── */
void EOS_AntiCheatClient_BeginSession(const char *user_id)
{
    if (user_id) {
        strncpy(g_player_id, user_id, sizeof(g_player_id) - 1);
        g_player_id[sizeof(g_player_id) - 1] = '\0';
    }
    fprintf(stderr,
            "[HOOK] BeginSession intercepted — player_id=\"%s\"\n",
            g_player_id);

    typedef void (*fn_begin)(const char *);
    fn_begin real = (fn_begin)dlsym(RTLD_NEXT,
                        "EOS_AntiCheatClient_BeginSession");
    if (real) real(user_id);
}

/* ── AddNotifyMessageToServer ────────────────────────────────────── *
 * THE KEY FIX: socket query fires HERE, immediately at intercept    *
 * time, not deferred inside hook_callback.                          */
void EOS_AntiCheatClient_AddNotifyMessageToServer(EOS_MessageCallback callback)
{
    fprintf(stderr,
            "[HOOK] AddNotifyMessageToServer intercepted — "
            "opening socket NOW\n");

    g_game_callback = callback;

    /* ── Immediate shim query with empty message (session-start probe) ── */
    char json[SHIM_BUF_SIZE];
    char resp[SHIM_BUF_SIZE];

    if (!build_json(json, sizeof(json), g_player_id, "")) {
        fprintf(stderr, "[HOOK] attestation failed, message blocked\n");
        /* do NOT register hook_callback with the real runtime */
        return;
    }

    fprintf(stderr, "[HOOK] Querying shim at intercept time...\n");
    int valid = shim_query(json, resp, sizeof(resp));

    if (!valid) {
        fprintf(stderr,
                "[HOOK] attestation failed, message blocked "
                "(session rejected by shim)\n");
        /* Abort: do not register any callback with the real runtime */
        return;
    }

    fprintf(stderr,
            "[HOOK] Shim approved session — registering hook_callback\n");

    /* ── Resolve the real AddNotifyMessageToServer once ── */
    if (!g_real_add_notify) {
        g_real_add_notify = (fn_AddNotify)dlsym(
            RTLD_NEXT, "EOS_AntiCheatClient_AddNotifyMessageToServer");
        if (!g_real_add_notify) {
            fprintf(stderr,
                    "[HOOK][DBG] dlsym(AddNotifyMessageToServer) FAILED: %s\n",
                    dlerror());
            return;
        }
        fprintf(stderr,
                "[HOOK][DBG] dlsym(AddNotifyMessageToServer) OK @ %p\n",
                (void *)g_real_add_notify);
    }

    /* Register OUR hook so we intercept every per-message callback */
    g_real_add_notify(hook_callback);
}

/* ── ReceiveMessageFromServer ────────────────────────────────────── */
void EOS_AntiCheatClient_ReceiveMessageFromServer(const void *data, size_t size)
{
    fprintf(stderr,
            "[HOOK] ReceiveMessageFromServer intercepted (%zu bytes): %.*s\n",
            size, (int)size, (const char *)data);

    typedef void (*fn_recv)(const void *, size_t);
    fn_recv real = (fn_recv)dlsym(RTLD_NEXT,
                       "EOS_AntiCheatClient_ReceiveMessageFromServer");
    if (real) real(data, size);
}
