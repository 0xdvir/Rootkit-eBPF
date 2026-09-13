#ifndef __KEYLOGGER_H
#define __KEYLOGGER_H

/**
 * @brief Keylogger event structure passed to userspace
 * 
 */
struct key_event_t {
    u32 code;
    u32 value;
};

#endif /* __KEYLOGGER_H */
