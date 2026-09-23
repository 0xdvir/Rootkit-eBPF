#ifndef __LOADER_H
#define __LOADER_H

/**
 * @brief Load rootkit eBPF and receive its skeleton.
 *
 * @return struct rootkit*
 */
struct rootkit *loader_load_rootkit();

/**
 * @brief Unload eBPF rootkit from its skeleton.
 *
 * @param skel Rootkit eBPF skeleton.
 */
void loader_unload_rootkit(struct rootkit *skel);

#endif /* __LOADER_H */
