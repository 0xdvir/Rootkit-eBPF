#ifndef __ROOTKIT_LOADER_H
#define __ROOTKIT_LOADER_H

struct rootkit* load_rootkit();
void unload_rootkit(struct rootkit *skel);

#endif /* __ROOTKIT_LOADER_H */
