#ifndef __COMMAND_PROCESSOR_H
#define __COMMAND_PROCESSOR_H

typedef struct {
    pid_t reverse_shell_pid;
} process_context_t;

/**
 * @brief Callback to handle received commands of type event_t.
 *
 * Every command will be parsed and executed if execution is
 * meant to be handled by userspace.
 *
 * @param ctx process_context_t
 * @param data
 * @param data_sz
 * @return int
 */
int command_processor_handle_received_command(void *ctx, void *data, size_t data_sz);

#endif /* __COMMAND_PROCESSOR_H */
