#!/bin/bash
# NanOS ARM Swarm Launcher
# Run from WSL: ./swarm-arm.sh [nodes]

NODES=${1:-3}
cd "$(dirname "$0")"

echo "Stopping any existing nodes..."
pkill -f qemu-system-arm 2>/dev/null
rm -f /tmp/nanos_arm_*.log
sleep 0.5

echo "Launching $NODES ARM Cortex-M3 nodes..."

for i in $(seq 1 $NODES); do
    mac=$(printf "52:54:00:00:00:%02x" $i)
    qemu-system-arm -M lm3s6965evb -nographic \
        -kernel nanos-arm.elf \
        -net nic,macaddr=$mac -net socket,mcast=230.0.0.1:1234 \
        -serial file:/tmp/nanos_arm_$i.log </dev/null >/dev/null 2>&1 &
    echo "  Node $i started (MAC=$mac)"
    sleep 0.3
done

echo ""
echo "========================================="
echo "  NanOS ARM Swarm: $NODES nodes running"
echo "========================================="
echo ""
echo "Commands:"
echo "  View logs:  tail -f /tmp/nanos_arm_*.log"
echo "  Stop:       pkill qemu-system-arm"
echo ""
echo "Waiting 5 seconds for nodes to communicate..."
sleep 5

echo ""
echo "=== Status ==="
for i in $(seq 1 $NODES); do
    echo "Node $i: $(tail -1 /tmp/nanos_arm_$i.log 2>/dev/null || echo 'No output')"
done
