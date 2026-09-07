#ifndef __KEYLOGGER_H
#define __KEYLOGGER_H

/**
 * @brief Event structure passed to userspace
 * 
 */
struct key_event_t {
    u32 pid;
    u32 code;
    u32 value;
    char comm[16];
};

#endif /* __KEYLOGGER_H */
