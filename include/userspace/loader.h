#ifndef __LOADER_H
#define __LOADER_H

#include "userspace/hider.h"

typedef struct {
    hider_context_t *hider_ctx;
} loader_context_t;

/**
 * @brief Load rootkit eBPF and receive its skeleton.
 *
 * @return struct rootkit*
 */
struct rootkit *loader_load_rootkit(loader_context_t *loader_ctx);

/**
 * @brief Unload eBPF rootkit from its skeleton.
 *
 * @param skel Rootkit eBPF skeleton.
 */
void loader_unload_rootkit(struct rootkit *skel);

#endif /* __LOADER_H */
