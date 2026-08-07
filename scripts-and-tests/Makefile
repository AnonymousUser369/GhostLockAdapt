# GhostLock test-programs build system
# Builds the small standalone probes used to validate kernel behaviour on device.
#
# Usage:
#   make            # build all test programs
#   make test_futex # build a single one
#   make clean
#
# Requires Android NDK r29. Override with: make NDK=/path/to/android-ndk-r29

NDK ?= /mnt/Data/AI_Workspace/android-ndk-r29
TOOLCHAIN = $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
CC = $(TOOLCHAIN)/bin/aarch64-linux-android35-clang
SYSROOT = $(TOOLCHAIN)/sysroot

CFLAGS = --target=aarch64-linux-android35 --sysroot=$(SYSROOT) -O2 -static

SRCS = $(wildcard *.c)
BINS = $(SRCS:.c=)

.PHONY: all clean

all: $(BINS)
	@echo "[+] built: $(BINS)"

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS)
