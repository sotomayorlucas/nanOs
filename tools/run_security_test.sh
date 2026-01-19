#!/bin/bash
#
# NERT Framework - Security Testing Suite
# Runs swarm and executes security tests
#
# Copyright (c) 2026 NanOS Project
# SPDX-License-Identifier: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_BIN="$PROJECT_ROOT/lib/nert/examples/demo_node"
ATTACKER_SCRIPT="$SCRIPT_DIR/attacker.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NUM_NODES=3
MULTICAST_GROUP="239.255.0.1"
PORT=5555
LOG_DIR="$PROJECT_ROOT/logs"

echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   NERT Framework - Security Testing Suite     ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
if [ ! -f "$DEMO_BIN" ]; then
    echo -e "${RED}Error: demo_node binary not found${NC}"
    echo -e "${YELLOW}Run: make demo${NC}"
    exit 1
fi

if [ ! -f "$ATTACKER_SCRIPT" ]; then
    echo -e "${RED}Error: attacker.py not found${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found${NC}"
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    jobs -p | xargs -r kill 2>/dev/null || true
    wait
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Start nodes
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 1: Starting Swarm${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo ""

PIDS=()
for i in $(seq 1 $NUM_NODES); do
    NODE_ID=$(printf "%04X" $((0x1000 + $i)))
    LOG_FILE="$LOG_DIR/node_${NODE_ID}.log"

    echo -e "${GREEN}Starting node 0x${NODE_ID}...${NC}"
    "$DEMO_BIN" "$NODE_ID" > "$LOG_FILE" 2>&1 &
    PID=$!
    PIDS+=($PID)

    sleep 0.3
done

echo ""
echo -e "${GREEN}✓ Swarm started with $NUM_NODES nodes${NC}"
echo ""
echo -e "${YELLOW}Waiting 5 seconds for swarm to stabilize...${NC}"
sleep 5

# Run security tests
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 2: Security Tests${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo ""

# Test 1: Replay Attack
echo -e "${CYAN}Test 1: Replay Attack${NC}"
echo -e "${YELLOW}Expected: Nodes should detect and block replayed packets${NC}"
python3 "$ATTACKER_SCRIPT" --attack replay --capture 3 --count 5
echo ""
sleep 2

# Test 2: Fuzzing Attack
echo -e "${CYAN}Test 2: Payload Fuzzing${NC}"
echo -e "${YELLOW}Expected: Nodes should reject malformed packets${NC}"
python3 "$ATTACKER_SCRIPT" --attack fuzzing --count 15
echo ""
sleep 2

# Test 3: Fake Queen Attack
echo -e "${CYAN}Test 3: Fake Queen Election${NC}"
echo -e "${YELLOW}Expected: Nodes should require proper authentication${NC}"
python3 "$ATTACKER_SCRIPT" --attack fake-queen --duration 5
echo ""
sleep 2

# Test 4: DoS Attack
echo -e "${CYAN}Test 4: Denial of Service${NC}"
echo -e "${YELLOW}Expected: Nodes should handle flood gracefully${NC}"
python3 "$ATTACKER_SCRIPT" --attack dos --duration 5 --rate 50
echo ""

# Wait a bit for nodes to process everything
echo -e "${YELLOW}Waiting 3 seconds for processing...${NC}"
sleep 3

# Stop nodes gracefully to get final statistics
echo -e "${YELLOW}Stopping nodes to collect statistics...${NC}"
for pid in "${PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
done
sleep 2

# Collect results
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}PHASE 3: Results Analysis${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Node Logs Summary:${NC}"
echo ""

for i in $(seq 1 $NUM_NODES); do
    NODE_ID=$(printf "%04X" $((0x1000 + $i)))
    LOG_FILE="$LOG_DIR/node_${NODE_ID}.log"

    echo -e "${GREEN}Node 0x${NODE_ID}:${NC}"

    # Extract statistics from final summary (using awk for portability)
    if grep -q "Final Statistics" "$LOG_FILE"; then
        # Extract security stats
        SECURITY_LINE=$(grep "Security:" "$LOG_FILE" 2>/dev/null)
        if [ -n "$SECURITY_LINE" ]; then
            BAD_MAC=$(echo "$SECURITY_LINE" | awk -F'[:,]' '{for(i=1;i<=NF;i++) if($i ~ /bad MACs/) {gsub(/[^0-9]/,"",$i); print $i}}')
            REPLAY=$(echo "$SECURITY_LINE" | awk -F'[:,]' '{for(i=1;i<=NF;i++) if($i ~ /replays/) {gsub(/[^0-9]/,"",$i); print $i}}')
            echo "  Bad MAC attempts blocked: ${BAD_MAC:-0}"
            echo "  Replay attacks blocked: ${REPLAY:-0}"
        fi

        # Extract RX stats
        RX_LINE=$(grep "RX:" "$LOG_FILE" 2>/dev/null)
        if [ -n "$RX_LINE" ]; then
            RX_PKTS=$(echo "$RX_LINE" | awk '{for(i=1;i<=NF;i++) if($(i+1) ~ /packets/) print $i}')
            DUPS=$(echo "$RX_LINE" | awk '{for(i=1;i<=NF;i++) if($(i+1) ~ /duplicates/) print $i}')
            echo "  Packets received: ${RX_PKTS:-0}"
            echo "  Duplicates detected: ${DUPS:-0}"
        fi
    else
        echo "  (No statistics available)"
    fi

    echo ""
done

echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}Testing Complete${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}✓ All security tests completed${NC}"
echo -e "${CYAN}Logs saved to: $LOG_DIR${NC}"
echo ""

# Ask if user wants to see full logs
read -p "Show full logs? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    less "$LOG_DIR"/*.log
fi
