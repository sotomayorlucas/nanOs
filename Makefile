# =============================================================================
# NanOS Makefile
# Build system for the swarm unikernel
# =============================================================================

# Compiler and tools
CC      := gcc
AS      := nasm
LD      := ld
GRUB    := grub-mkrescue
QEMU    := qemu-system-i386

# Compiler flags
CFLAGS  := -m32 -ffreestanding -fno-stack-protector -fno-pic \
           -nostdlib -nostdinc -Wall -Wextra -Werror \
           -O2 -std=c99 -I include

# Assembler flags
ASFLAGS := -f elf32

# Linker flags
LDFLAGS := -m elf_i386 -T linker.ld -nostdlib

# Source files
ASM_SRC := boot/boot.asm
C_SRC   := kernel/kernel.c drivers/e1000_minimal.c

# Object files
ASM_OBJ := $(ASM_SRC:.asm=.o)
C_OBJ   := $(C_SRC:.c=.o)
OBJECTS := $(ASM_OBJ) $(C_OBJ)

# Output files
KERNEL  := nanos.elf
ISO     := nanos.iso

# Default target
.PHONY: all
all: $(ISO)

# Build the ISO image
$(ISO): $(KERNEL) grub.cfg
	@echo "[ISO] Creating bootable ISO..."
	@mkdir -p iso/boot/grub
	@cp $(KERNEL) iso/boot/
	@cp grub.cfg iso/boot/grub/
	@$(GRUB) -o $(ISO) iso 2>/dev/null || \
		xorriso -as mkisofs -b boot/grub/i386-pc/eltorito.img \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		--grub2-boot-info --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img \
		-o $(ISO) iso 2>/dev/null || \
		echo "Warning: Could not create ISO. Run kernel directly with: make run-elf"
	@rm -rf iso

# Link the kernel
$(KERNEL): $(OBJECTS)
	@echo "[LD] Linking kernel..."
	@$(LD) $(LDFLAGS) -o $@ $^

# Compile assembly
%.o: %.asm
	@echo "[AS] $<"
	@$(AS) $(ASFLAGS) -o $@ $<

# Compile C files
%.o: %.c
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# Create GRUB config
grub.cfg:
	@echo "[CFG] Creating GRUB configuration..."
	@echo 'set timeout=0' > grub.cfg
	@echo 'set default=0' >> grub.cfg
	@echo '' >> grub.cfg
	@echo 'menuentry "NanOS - The Hive Mind" {' >> grub.cfg
	@echo '    multiboot2 /boot/nanos.elf' >> grub.cfg
	@echo '}' >> grub.cfg

# Run in QEMU with networking (single node)
.PHONY: run
run: $(ISO)
	@echo "[QEMU] Launching NanOS..."
	@$(QEMU) -cdrom $(ISO) \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-m 32M \
		-serial stdio

# Run kernel directly (without ISO)
.PHONY: run-elf
run-elf: $(KERNEL)
	@echo "[QEMU] Launching NanOS (direct kernel)..."
	@$(QEMU) -kernel $(KERNEL) \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-m 32M \
		-serial stdio

# Run a swarm of nodes (requires multicast network setup)
# Each node gets its own window
.PHONY: swarm
swarm: $(ISO)
	@echo "[SWARM] Launching 3 NanOS nodes on virtual network..."
	@# Create a virtual network bridge for multicast
	@$(QEMU) -cdrom $(ISO) \
		-netdev socket,id=net0,mcast=230.0.0.1:1234 \
		-device e1000,netdev=net0,mac=52:54:00:00:00:01 \
		-m 32M -name "NanOS-Node-1" &
	@sleep 0.5
	@$(QEMU) -cdrom $(ISO) \
		-netdev socket,id=net0,mcast=230.0.0.1:1234 \
		-device e1000,netdev=net0,mac=52:54:00:00:00:02 \
		-m 32M -name "NanOS-Node-2" &
	@sleep 0.5
	@$(QEMU) -cdrom $(ISO) \
		-netdev socket,id=net0,mcast=230.0.0.1:1234 \
		-device e1000,netdev=net0,mac=52:54:00:00:00:03 \
		-m 32M -name "NanOS-Node-3" &
	@echo "[SWARM] 3 nodes launched. Press Ctrl+C to stop all."
	@wait

# Debug mode with GDB
.PHONY: debug
debug: $(KERNEL)
	@echo "[DEBUG] Starting QEMU with GDB server on :1234..."
	@$(QEMU) -kernel $(KERNEL) \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-m 32M \
		-s -S &
	@echo "Connect with: gdb -ex 'target remote :1234' $(KERNEL)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -f $(OBJECTS) $(KERNEL) $(ISO) grub.cfg
	@rm -rf iso

# Show help
.PHONY: help
help:
	@echo "NanOS Build System"
	@echo "=================="
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build ISO image (default)"
	@echo "  run      - Run single node in QEMU"
	@echo "  run-elf  - Run kernel directly without ISO"
	@echo "  swarm    - Launch 3 interconnected nodes"
	@echo "  debug    - Start with GDB debugging"
	@echo "  clean    - Remove build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  gcc, nasm, ld, qemu-system-i386"
	@echo "  grub-mkrescue or xorriso (for ISO creation)"
