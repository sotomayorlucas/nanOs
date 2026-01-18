# NERT Framework Makefile
# Build system for v0.4
#
# Copyright (c) 2026 NanOS Project
# SPDX-License-Identifier: MIT

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -std=c11
CFLAGS += -I../../include -I.

# Linker flags
LDFLAGS := -lpthread

# Directories
SRC_DIR := .
HAL_DIR := hal
CRYPTO_DIR := crypto
EXAMPLES_DIR := examples
BUILD_DIR := build
BIN_DIR := bin

# Source files
CORE_SOURCES := \
	nert_config.c \
	nert_security.c

HAL_SOURCES := \
	hal/hal_virtual.c \
	hal/hal_adapter.c

# For now, we'll use the existing nert.c from kernel/protocol
# In a full refactor, we'd move it here
NERT_CORE := ../../kernel/protocol/nert.c
NERT_DEPS := \
	../../kernel/protocol/bloom.c \
	../../kernel/protocol/gossip.c \
	../../kernel/protocol/hmac.c

# Example programs
EXAMPLES := \
	demo_node

# Object files
CORE_OBJECTS := $(CORE_SOURCES:%.c=$(BUILD_DIR)/%.o)
HAL_OBJECTS := $(HAL_SOURCES:%.c=$(BUILD_DIR)/%.o)
NERT_OBJECTS := $(BUILD_DIR)/nert_core.o
DEPS_OBJECTS := $(BUILD_DIR)/bloom.o $(BUILD_DIR)/gossip.o $(BUILD_DIR)/hmac.o

# Targets
.PHONY: all clean demo examples test help

all: $(BIN_DIR)/demo_node

help:
	@echo "NERT Framework Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build everything (default)"
	@echo "  demo         Build demo node"
	@echo "  examples     Build all examples"
	@echo "  test         Run security tests"
	@echo "  clean        Remove build artifacts"
	@echo "  help         Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make demo           # Build demo node"
	@echo "  make test           # Run security test suite"

# Create build directories
$(BUILD_DIR) $(BUILD_DIR)/hal $(BIN_DIR):
	@mkdir -p $@

# Build core framework
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Build HAL
$(BUILD_DIR)/hal/%.o: hal/%.c | $(BUILD_DIR)/hal
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Build NERT core (from kernel/protocol for now)
$(BUILD_DIR)/nert_core.o: $(NERT_CORE) | $(BUILD_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Build dependencies
$(BUILD_DIR)/bloom.o: ../../kernel/protocol/bloom.c | $(BUILD_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/gossip.o: ../../kernel/protocol/gossip.c | $(BUILD_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/hmac.o: ../../kernel/protocol/hmac.c | $(BUILD_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Build demo node
$(BIN_DIR)/demo_node: examples/demo_node.c $(CORE_OBJECTS) $(HAL_OBJECTS) $(NERT_OBJECTS) $(DEPS_OBJECTS) | $(BIN_DIR)
	@echo "  CCLD  $@"
	@$(CC) $(CFLAGS) $< $(CORE_OBJECTS) $(HAL_OBJECTS) $(NERT_OBJECTS) $(DEPS_OBJECTS) $(LDFLAGS) -o $@
	@echo ""
	@echo "✓ Demo node built: $@"
	@echo ""

demo: $(BIN_DIR)/demo_node
	@cp $(BIN_DIR)/demo_node examples/demo_node
	@echo "Copied to examples/demo_node for convenience"

examples: demo

# Run security tests
test: demo
	@echo "Running security test suite..."
	@chmod +x ../../tools/run_security_test.sh
	@../../tools/run_security_test.sh

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@rm -f examples/demo_node
	@echo "✓ Clean complete"

# Show build info
info:
	@echo "NERT Framework v0.4"
	@echo ""
	@echo "Configuration:"
	@echo "  CC:      $(CC)"
	@echo "  CFLAGS:  $(CFLAGS)"
	@echo "  LDFLAGS: $(LDFLAGS)"
	@echo ""
	@echo "Build paths:"
	@echo "  BUILD_DIR: $(BUILD_DIR)"
	@echo "  BIN_DIR:   $(BIN_DIR)"
	@echo ""
