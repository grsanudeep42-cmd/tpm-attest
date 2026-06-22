/*
 * phase3/mock_eac_client.c
 * ------------------------
 * Simulates what an EAC (Easy Anti-Cheat) client does during a handshake.
 *
 * Flow:
 *   1. Connect to Unix domain socket at /tmp/eac_shim.sock
 *   2. Send a JSON handshake: { type, game_id, player_id, platform, timestamp }
 *   3. Wait for a JSON response from the shim
 *   4. Print the response
 *   5. Exit 0 if response contains "valid":true, exit 1 otherwise
 *
 * Build:
 *   gcc -o mock_eac_client phase3/mock_eac_client.c
 *
 * Usage:
 *   ./mock_eac_client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH   "/tmp/eac_shim.sock"
#define GAME_ID       "splitgate"
#define PLAYER_ID     "test_player_123"
#define PLATFORM      "linux"
#define RECV_BUF_SIZE 4096

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Returns 1 if the JSON blob contains the substring "valid":true */
static int response_is_valid(const char *json)
{
    /* Quick substring search — sufficient for well-formed single-object JSON */
    const char *needle = "\"valid\":true";
    if (strstr(json, needle) != NULL)
        return 1;

    /* Also handle whitespace variant: "valid": true */
    needle = "\"valid\": true";
    return (strstr(json, needle) != NULL) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    int sockfd;
    struct sockaddr_un addr;
    char handshake[512];
    char response[RECV_BUF_SIZE];
    ssize_t bytes_sent, bytes_recv;
    time_t ts;

    /* --- Build handshake JSON ---------------------------------------- */
    ts = time(NULL);
    int written = snprintf(
        handshake, sizeof(handshake),
        "{"
        "\"type\":\"eac_handshake\","
        "\"game_id\":\"%s\","
        "\"player_id\":\"%s\","
        "\"platform\":\"%s\","
        "\"timestamp\":%ld"
        "}",
        GAME_ID, PLAYER_ID, PLATFORM, (long)ts
    );

    if (written < 0 || (size_t)written >= sizeof(handshake)) {
        fprintf(stderr, "[mock_eac_client] ERROR: handshake message truncated\n");
        return 1;
    }

    /* --- Create Unix domain socket ------------------------------------ */
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[mock_eac_client] socket()");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* --- Connect to shim ---------------------------------------------- */
    printf("[mock_eac_client] Connecting to %s ...\n", SOCKET_PATH);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[mock_eac_client] connect()");
        close(sockfd);
        return 1;
    }
    printf("[mock_eac_client] Connected.\n");

    /* --- Send handshake ----------------------------------------------- */
    printf("[mock_eac_client] Sending handshake: %s\n", handshake);
    bytes_sent = send(sockfd, handshake, strlen(handshake), 0);
    if (bytes_sent < 0) {
        perror("[mock_eac_client] send()");
        close(sockfd);
        return 1;
    }
    printf("[mock_eac_client] Sent %zd bytes.\n", bytes_sent);

    /* Signal EOF so the shim knows the message is complete */
    shutdown(sockfd, SHUT_WR);

    /* --- Receive response --------------------------------------------- */
    printf("[mock_eac_client] Waiting for response ...\n");
    memset(response, 0, sizeof(response));

    /* Accumulate the full response (may arrive in multiple segments) */
    size_t total = 0;
    while (total < sizeof(response) - 1) {
        bytes_recv = recv(sockfd, response + total, sizeof(response) - 1 - total, 0);
        if (bytes_recv < 0) {
            perror("[mock_eac_client] recv()");
            close(sockfd);
            return 1;
        }
        if (bytes_recv == 0)
            break;   /* Server closed the connection */
        total += (size_t)bytes_recv;
    }

    close(sockfd);

    if (total == 0) {
        fprintf(stderr, "[mock_eac_client] ERROR: empty response from shim\n");
        return 1;
    }

    /* --- Print and evaluate response ---------------------------------- */
    printf("[mock_eac_client] Response (%zu bytes):\n%s\n", total, response);

    if (response_is_valid(response)) {
        printf("[mock_eac_client] Attestation VALID — session token granted.\n");
        return 0;
    } else {
        printf("[mock_eac_client] Attestation INVALID — access denied.\n");
        return 1;
    }
}
