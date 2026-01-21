# =============================================================================
# NanOS Makefile - Multi-Architecture Build System
# Supports: x86 (i386), ARM64 (AArch64)
# =============================================================================

# Default architecture (can override with: make ARCH=arm64)
ARCH ?= x86

# Swarm configuration (can override with: make swarm NODES=5)
NODES ?= 3

# =============================================================================
# Architecture-Specific Configuration
# =============================================================================
ifeq ($(ARCH),x86)
    # x86 (i386) Configuration
    CC      := gcc
    AS      := nasm
    LD      := ld
    OBJCOPY := objcopy
    QEMU    := qemu-system-i386

    CFLAGS  := -m32 -ffreestanding -fno-stack-protector -fno-pic \
               -nostdlib -nostdinc -Wall -Wextra -Werror \
               -O2 -std=c99 -I include -DARCH_X86 -DPLATFORM_QEMU_X86
    ASFLAGS := -f elf32
    LDFLAGS := -m elf_i386 -T linker.ld -nostdlib

    KERNEL  := nanos-x86.elf
    ISO     := nanos-x86.iso

    ASM_SRC := boot/boot.asm
    C_SRC   := kernel/kernel.c kernel/collective.c kernel/blackbox.c \
                kernel/memory/allocator.c \
                kernel/protocol/bloom.c kernel/protocol/gossip.c kernel/protocol/hmac.c \
                kernel/tactical/intelligence.c kernel/tactical/maze.c kernel/tactical/terrain.c \
                kernel/workloads/global_compute.c \
                arch/x86/console_vga.c arch/x86/serial_com.c \
                drivers/e1000_minimal.c arch/x86/hal_x86.c

    QEMU_OPTS := -netdev user,id=net0 -device e1000,netdev=net0 -m 32M
    QEMU_NET_SWARM := -netdev socket,id=net0,mcast=230.0.0.1:1234 \
                      -device e1000,netdev=net0

else ifeq ($(ARCH),arm64)
    # ARM64 (AArch64) Configuration
    CROSS   := aarch64-linux-gnu-
    CC      := $(CROSS)gcc
    AS      := $(CROSS)as
    LD      := $(CROSS)ld
    OBJCOPY := $(CROSS)objcopy
    QEMU    := qemu-system-aarch64

    CFLAGS  := -ffreestanding -fno-stack-protector -fno-pic \
               -nostdlib -nostdinc -Wall -Wextra -Werror \
               -O2 -std=c99 -I include -DARCH_ARM64 -DPLATFORM_QEMU_ARM64 \
               -mcpu=cortex-a72 -mstrict-align
    ASFLAGS :=
    LDFLAGS := -T arch/arm64/linker.ld -nostdlib

    KERNEL  := nanos-arm64.elf
    IMAGE   := nanos-arm64.bin

    ASM_SRC := arch/arm64/boot.S
    C_SRC   := kernel/kernel_portable.c kernel/collective.c drivers/virtio_net.c arch/arm64/hal_arm64.c

    QEMU_MACHINE := -M virt -cpu cortex-a72
    QEMU_OPTS := $(QEMU_MACHINE) -m 128M -nographic \
                 -device virtio-net-device,netdev=net0 \
                 -netdev user,id=net0
    QEMU_NET_SWARM := $(QEMU_MACHINE) -m 128M -nographic \
                      -device virtio-net-device,netdev=net0 \
                      -netdev socket,id=net0,mcast=230.0.0.1:1234

else ifeq ($(ARCH),arm-qemu)
    # ARM Cortex-M3 for QEMU (lm3s6965evb)
    CROSS   := arm-none-eabi-
    CC      := $(CROSS)gcc
    AS      := $(CROSS)as
    LD      := $(CROSS)ld
    OBJCOPY := $(CROSS)objcopy
    QEMU    := qemu-system-arm

    CFLAGS  := -mcpu=cortex-m3 -mthumb -ffreestanding -fno-stack-protector \
               -nostdlib -Wall -Wextra -O2 -std=c99 -I include \
               -DARCH_ARM_CORTEX_M3 -DPLATFORM_QEMU_LM3S
    LDFLAGS := -T arch/arm-qemu/linker.ld -nostdlib

    KERNEL  := nanos-arm.elf
    IMAGE   := nanos-arm.bin

    C_SRC   := arch/arm-qemu/startup.c arch/arm-qemu/nanos_arm.c \
               arch/arm-qemu/maze_arm.c arch/arm-qemu/terrain_arm.c

    QEMU_OPTS := -M lm3s6965evb -nographic
    # Swarm con multicast UDP
    QEMU_NET_SWARM := -M lm3s6965evb -nographic \
                      -netdev socket,id=net0,mcast=230.0.0.1:1234 \
                      -net nic,netdev=net0,model=stellaris

else
    $(error Unknown architecture: $(ARCH). Use ARCH=x86, ARCH=arm64, or ARCH=arm-qemu)
endif

# =============================================================================
# Object Files
# =============================================================================
ifeq ($(ARCH),x86)
    ASM_OBJ := $(ASM_SRC:.asm=.o)
else
    ASM_OBJ := $(ASM_SRC:.S=.o)
endif
C_OBJ   := $(C_SRC:.c=.o)
OBJECTS := $(ASM_OBJ) $(C_OBJ)

# =============================================================================
# Targets
# =============================================================================
.PHONY: all clean run run-elf run-arm swarm swarm3 swarm5 swarm10 swarm-arm swarm-arm3 swarm-arm5 debug help x86 arm64 arm-qemu dashboard

all: $(KERNEL)
	@echo "[OK] Built $(KERNEL) for $(ARCH)"

# Convenience targets
x86:
	$(MAKE) ARCH=x86 all

arm64:
	$(MAKE) ARCH=arm64 all

arm-qemu:
	$(MAKE) ARCH=arm-qemu all

# Quick run for ARM QEMU (embedded simulation)
run-arm:
	$(MAKE) ARCH=arm-qemu all
	@echo "[QEMU] Running NanOS ARM Cortex-M3..."
	@qemu-system-arm -M lm3s6965evb -nographic -kernel nanos-arm.elf

# =============================================================================
# Build Rules
# =============================================================================
$(KERNEL): $(OBJECTS)
	@echo "[LD] Linking $@..."
	@$(LD) $(LDFLAGS) -o $@ $^
ifeq ($(ARCH),arm64)
	@echo "[BIN] Creating binary image..."
	@$(OBJCOPY) -O binary $@ $(IMAGE)
endif
ifeq ($(ARCH),arm-qemu)
	@echo "[BIN] Creating binary image..."
	@$(OBJCOPY) -O binary $@ $(IMAGE)
endif

# x86 assembly
%.o: %.asm
	@echo "[AS] $<"
	@$(AS) $(ASFLAGS) -o $@ $<

# ARM64 assembly
%.o: %.S
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# C files
%.o: %.c
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# =============================================================================
# x86 ISO Creation
# =============================================================================
ifeq ($(ARCH),x86)
$(ISO): $(KERNEL) grub.cfg
	@echo "[ISO] Creating bootable ISO..."
	@mkdir -p iso/boot/grub
	@cp $(KERNEL) iso/boot/nanos.elf
	@cp grub.cfg iso/boot/grub/
	@grub-mkrescue -o $(ISO) iso 2>/dev/null || \
		echo "Note: grub-mkrescue not available, use 'make run-elf'"
	@rm -rf iso

grub.cfg:
	@echo 'set timeout=0' > grub.cfg
	@echo 'set default=0' >> grub.cfg
	@echo 'menuentry "NanOS - The Hive Mind" {' >> grub.cfg
	@echo '    multiboot2 /boot/nanos.elf' >> grub.cfg
	@echo '}' >> grub.cfg
endif

# =============================================================================
# Run Targets
# =============================================================================
ifeq ($(ARCH),x86)
run: $(ISO)
	@echo "[QEMU] Launching NanOS (x86)..."
	@$(QEMU) -cdrom $(ISO) $(QEMU_OPTS) -serial stdio

run-elf: $(KERNEL)
	@echo "[QEMU] Launching NanOS (x86 direct)..."
	@$(QEMU) -kernel $(KERNEL) $(QEMU_OPTS) -serial stdio

else ifeq ($(ARCH),arm64)
run: $(KERNEL)
	@echo "[QEMU] Launching NanOS (ARM64)..."
	@$(QEMU) -kernel $(KERNEL) $(QEMU_OPTS)

run-elf: run
endif

# =============================================================================
# Swarm Mode (Multiple Nodes)
# =============================================================================
swarm:
ifeq ($(ARCH),x86)
	@$(MAKE) ARCH=x86 $(ISO)
	@echo "[SWARM] Launching $(NODES) x86 nodes..."
	@for i in $$(seq 1 $(NODES)); do \
		mac=$$(printf "52:54:00:00:00:%02x" $$i); \
		$(QEMU) -cdrom $(ISO) $(QEMU_NET_SWARM),mac=$$mac -m 32M \
			-serial file:/tmp/nanos_node_$$i.log & \
		sleep 0.3; \
	done
	@echo "[SWARM] $(NODES) x86 nodes launched."
	@echo "        Logs: /tmp/nanos_node_*.log"
	@echo "        Stop: pkill qemu"
else ifeq ($(ARCH),arm64)
	@$(MAKE) ARCH=arm64 $(KERNEL)
	@echo "[SWARM] Launching $(NODES) ARM64 nodes..."
	@for i in $$(seq 1 $(NODES)); do \
		mac=$$(printf "52:54:00:00:00:%02x" $$i); \
		$(QEMU) -kernel $(KERNEL) $(QEMU_NET_SWARM),mac=$$mac & \
		sleep 0.3; \
	done
	@echo "[SWARM] $(NODES) ARM64 nodes launched."
	@echo "        Stop: pkill qemu"
else ifeq ($(ARCH),arm-qemu)
	@$(MAKE) ARCH=arm-qemu $(KERNEL)
	@echo "[SWARM] Launching $(NODES) ARM Cortex-M3 nodes with network..."
	@-pkill -f qemu-system-arm 2>/dev/null || true
	@rm -f /tmp/nanos_arm_*.log
	@for i in $$(seq 1 $(NODES)); do \
		mac=$$(printf "52:54:00:00:00:%02x" $$i); \
		qemu-system-arm -M lm3s6965evb -nographic \
			-kernel nanos-arm.elf \
			-net nic,macaddr=$$mac -net socket,mcast=230.0.0.1:1234 \
			-serial file:/tmp/nanos_arm_$$i.log </dev/null >/dev/null 2>&1 & \
		sleep 0.3; \
	done
	@echo ""
	@echo "[SWARM] $(NODES) ARM nodes running with multicast network!"
	@echo "        Logs: /tmp/nanos_arm_*.log"
	@echo "        View: tail -f /tmp/nanos_arm_*.log"
	@echo "        Stop: pkill qemu-system-arm"
endif

# Convenience swarm sizes (x86 default)
swarm3:
	@$(MAKE) ARCH=x86 swarm NODES=3

swarm5:
	@$(MAKE) ARCH=x86 swarm NODES=5

swarm10:
	@$(MAKE) ARCH=x86 swarm NODES=10

# ARM swarm convenience targets
swarm-arm:
	@$(MAKE) ARCH=arm-qemu swarm NODES=$(NODES)

swarm-arm3:
	@$(MAKE) ARCH=arm-qemu swarm NODES=3

swarm-arm5:
	@$(MAKE) ARCH=arm-qemu swarm NODES=5

# =============================================================================
# Debug Mode
# =============================================================================
debug: $(KERNEL)
	@echo "[DEBUG] Starting QEMU with GDB server..."
ifeq ($(ARCH),x86)
	@$(QEMU) -kernel $(KERNEL) $(QEMU_OPTS) -s -S &
	@echo "Connect: gdb -ex 'target remote :1234' $(KERNEL)"
else ifeq ($(ARCH),arm64)
	@$(QEMU) -kernel $(KERNEL) $(QEMU_OPTS) -s -S &
	@echo "Connect: aarch64-linux-gnu-gdb -ex 'target remote :1234' $(KERNEL)"
endif

# =============================================================================
# Clean
# =============================================================================
clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -f $(OBJECTS) grub.cfg
	@rm -f nanos-x86.elf nanos-x86.iso
	@rm -f nanos-arm64.elf nanos-arm64.bin
	@rm -rf iso

# =============================================================================
# Dashboard
# =============================================================================
dashboard:
	@echo "[DASHBOARD] Starting NanOS Web Dashboard..."
	@python3 dashboard/nanos_dashboard.py --log-dir /tmp || \
		python dashboard/nanos_dashboard.py --log-dir /tmp

# =============================================================================
# Help
# =============================================================================
help:
	@echo "NanOS Multi-Architecture Build System"
	@echo "======================================"
	@echo ""
	@echo "Usage: make [ARCH=x86|arm64|arm-qemu] [NODES=n] <target>"
	@echo ""
	@echo "Architectures:"
	@echo "  ARCH=x86      - Intel/AMD 32-bit (default)"
	@echo "  ARCH=arm64    - ARM 64-bit (AArch64)"
	@echo "  ARCH=arm-qemu - ARM Cortex-M3 (embedded simulation)"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build kernel for selected arch"
	@echo "  x86         - Build x86 kernel"
	@echo "  arm64       - Build ARM64 kernel"
	@echo "  arm-qemu    - Build ARM Cortex-M3 kernel"
	@echo "  run         - Run in QEMU (single node)"
	@echo "  run-arm     - Build and run ARM Cortex-M3"
	@echo "  swarm       - Launch N-node swarm (default 3)"
	@echo "  swarm3/5/10 - Launch x86 swarm"
	@echo "  swarm-arm   - Launch ARM Cortex-M3 swarm"
	@echo "  swarm-arm3  - Launch 3-node ARM swarm"
	@echo "  swarm-arm5  - Launch 5-node ARM swarm"
	@echo "  dashboard   - Start web dashboard (http://localhost:8080)"
	@echo "  debug       - Start with GDB debugging"
	@echo "  clean       - Remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build x86"
	@echo "  make run                # Single x86 node"
	@echo "  make swarm              # 3-node x86 swarm"
	@echo "  make run-arm            # Single ARM node"
	@echo "  make swarm-arm3         # 3-node ARM swarm"
	@echo "  make swarm-arm NODES=5  # 5-node ARM swarm"
	@echo ""
	@echo "Logs:"
	@echo "  x86: /tmp/nanos_node_*.log"
	@echo "  ARM: /tmp/nanos_arm_*.log"
	@echo ""
	@echo "Stop swarm: pkill qemu"
	@echo ""
	@echo "Requirements:"
	@echo "  x86:      gcc, nasm, qemu-system-i386"
	@echo "  arm64:    aarch64-linux-gnu-gcc, qemu-system-aarch64"
	@echo "  arm-qemu: arm-none-eabi-gcc, qemu-system-arm"
	@echo "  dashboard: python3"
