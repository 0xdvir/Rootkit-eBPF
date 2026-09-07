#ifndef __ROOTKIT_LOADER_H
#define __ROOTKIT_LOADER_H

/**
 * @brief Load rootkit eBPF and receive its skeleton.
 * 
 * @return struct rootkit* 
 */
struct rootkit* load_rootkit();

/**
 * @brief Unload eBPF rootkit from its skeleton.
 * 
 * @param skel Rootkit eBPF skeleton.
 */
void unload_rootkit(struct rootkit *skel);

#endif /* __ROOTKIT_LOADER_H */
