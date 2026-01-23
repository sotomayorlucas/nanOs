#!/bin/bash
#
# NERT Framework - Virtual Swarm Launcher
# Spawns multiple demo nodes for testing
#
# Copyright (c) 2026 NanOS Project
# SPDX-License-Identifier: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_BIN="$PROJECT_ROOT/lib/nert/examples/demo_node"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
# NOTE: Must match micrOS multicast config (230.0.0.1:1234)
NUM_NODES=3
MULTICAST_GROUP="230.0.0.1"
PORT=1234
LOG_DIR="$PROJECT_ROOT/logs"

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   NERT Framework - Virtual Swarm Launcher     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--nodes)
            NUM_NODES="$2"
            shift 2
            ;;
        -m|--multicast)
            MULTICAST_GROUP="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -n, --nodes N       Number of nodes to spawn (default: 3)"
            echo "  -m, --multicast IP  Multicast group (default: 230.0.0.1)"
            echo "  -p, --port PORT     UDP port (default: 1234)"
            echo "  -h, --help          Show this help"
            echo ""
            echo "Example:"
            echo "  $0 --nodes 5 --multicast 230.0.0.1 --port 1234"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if demo_node binary exists
if [ ! -f "$DEMO_BIN" ]; then
    echo -e "${RED}Error: demo_node binary not found at $DEMO_BIN${NC}"
    echo -e "${YELLOW}Please run 'make demo' first${NC}"
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down swarm...${NC}"
    jobs -p | xargs -r kill 2>/dev/null || true
    wait
    echo -e "${GREEN}All nodes stopped${NC}"
}

trap cleanup EXIT INT TERM

# Start nodes
echo -e "${GREEN}Starting $NUM_NODES nodes...${NC}"
echo ""

PIDS=()
for i in $(seq 1 $NUM_NODES); do
    # Generate unique node ID
    NODE_ID=$(printf "%04X" $((0x1000 + $i)))

    LOG_FILE="$LOG_DIR/node_${NODE_ID}.log"

    echo -e "${BLUE}[Node $i/$NUM_NODES]${NC} Starting node 0x${NODE_ID}..."
    echo -e "  Multicast: $MULTICAST_GROUP:$PORT"
    echo -e "  Log: $LOG_FILE"

    # Start node in background
    "$DEMO_BIN" "$NODE_ID" > "$LOG_FILE" 2>&1 &
    PID=$!
    PIDS+=($PID)

    echo -e "  ${GREEN}Started (PID: $PID)${NC}"
    echo ""

    # Small delay between spawns
    sleep 0.5
done

echo -e "${GREEN}✓ All $NUM_NODES nodes running${NC}"
echo ""
echo -e "${YELLOW}Monitoring logs...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all nodes${NC}"
echo ""

# Tail logs from all nodes
tail -f "$LOG_DIR"/*.log
