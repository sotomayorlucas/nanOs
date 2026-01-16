#!/usr/bin/env python3
"""
NanOS Swarm Observer - Real-time visualization of the hive mind

Joins the QEMU multicast network and displays:
- Live nodes (with roles)
- Communication graph
- Alarm propagation
- Statistics

Usage:
    python3 swarm_observer.py [--interface eth0]

Requirements:
    pip install rich  (for terminal UI)
"""

import socket
import struct
import time
import argparse
from collections import defaultdict
from datetime import datetime

# Try to import rich for fancy terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for better visualization: pip install rich")

# NanOS Protocol Constants
NANOS_MAGIC = 0x4E414E4F  # "NANO"
ETH_TYPE_NANOS = 0x4E4F   # "NO"

# Pheromone types
PHEROMONE_HELLO = 0x01
PHEROMONE_DATA = 0x02
PHEROMONE_ALARM = 0x03
PHEROMONE_ECHO = 0x04
PHEROMONE_QUEEN_CMD = 0x10
PHEROMONE_REBIRTH = 0xFE
PHEROMONE_DIE = 0xFF

# Roles
ROLES = {
    0x01: ("WORKER", "cyan"),
    0x02: ("EXPLORER", "green"),
    0x03: ("SENTINEL", "yellow"),
    0x04: ("QUEEN", "magenta"),
}

# Multicast address used by QEMU swarm mode
MCAST_GROUP = "230.0.0.1"
MCAST_PORT = 1234


class NanosPacket:
    """Parse a NanOS pheromone packet"""

    def __init__(self, data):
        if len(data) < 64:
            raise ValueError("Packet too short")

        # Parse header (24 bytes)
        self.magic = struct.unpack("<I", data[0:4])[0]
        self.node_id = struct.unpack("<I", data[4:8])[0]
        self.type = data[8]
        self.ttl = data[9]
        self.flags = data[10]
        self.version = data[11]
        self.seq = struct.unpack("<I", data[12:16])[0]
        self.hmac = data[16:24]
        self.payload = data[24:64]

        # Decode role from flags
        self.role = (self.flags >> 1) & 0x07
        self.authenticated = bool(self.flags & 0x01)

    def is_valid(self):
        return self.magic == NANOS_MAGIC

    def type_name(self):
        names = {
            PHEROMONE_HELLO: "HELLO",
            PHEROMONE_DATA: "DATA",
            PHEROMONE_ALARM: "ALARM",
            PHEROMONE_ECHO: "ECHO",
            PHEROMONE_QUEEN_CMD: "QUEEN_CMD",
            PHEROMONE_REBIRTH: "REBIRTH",
            PHEROMONE_DIE: "DIE",
        }
        return names.get(self.type, f"UNKNOWN({self.type})")

    def role_name(self):
        return ROLES.get(self.role, ("UNKNOWN", "white"))[0]

    def role_color(self):
        return ROLES.get(self.role, ("UNKNOWN", "white"))[1]


class SwarmState:
    """Track the state of the swarm"""

    def __init__(self):
        self.nodes = {}  # node_id -> last_seen, role, stats
        self.events = []  # Recent events for log
        self.stats = defaultdict(int)
        self.alarms = []  # Recent alarms
        self.deaths = []  # Recent deaths
        self.start_time = time.time()

    def process_packet(self, pkt):
        """Process a received packet"""
        if not pkt.is_valid():
            return

        node_id = pkt.node_id
        now = time.time()

        # Update node info
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "first_seen": now,
                "role": pkt.role,
                "packets": 0,
            }
            self.log_event(f"New node: {node_id:08X} ({pkt.role_name()})")

        self.nodes[node_id]["last_seen"] = now
        self.nodes[node_id]["role"] = pkt.role
        self.nodes[node_id]["packets"] += 1

        # Count packet types
        self.stats[pkt.type_name()] += 1
        self.stats["total"] += 1

        # Handle specific packet types
        if pkt.type == PHEROMONE_ALARM:
            self.alarms.append({
                "time": now,
                "from": node_id,
                "ttl": pkt.ttl,
            })
            self.log_event(f"ALARM from {node_id:08X} TTL={pkt.ttl}")
            # Keep only last 10 alarms
            self.alarms = self.alarms[-10:]

        elif pkt.type == PHEROMONE_REBIRTH:
            gen = struct.unpack("<I", pkt.payload[8:12])[0] if len(pkt.payload) >= 12 else 0
            self.deaths.append({
                "time": now,
                "node": node_id,
                "generation": gen,
            })
            self.log_event(f"Cell {node_id:08X} died (gen {gen})")
            # Remove from active nodes
            if node_id in self.nodes:
                del self.nodes[node_id]
            self.deaths = self.deaths[-10:]

        elif pkt.type == PHEROMONE_QUEEN_CMD:
            cmd = pkt.payload[:39].decode('ascii', errors='ignore').strip('\x00')
            self.log_event(f"QUEEN CMD from {node_id:08X}: {cmd}")

    def log_event(self, msg):
        """Add an event to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.events.append(f"[{timestamp}] {msg}")
        # Keep only last 20 events
        self.events = self.events[-20:]

    def get_active_nodes(self, timeout=5.0):
        """Get nodes seen within timeout seconds"""
        now = time.time()
        return {
            k: v for k, v in self.nodes.items()
            if now - v["last_seen"] < timeout
        }

    def uptime(self):
        """Get observer uptime"""
        return time.time() - self.start_time


def create_multicast_socket(interface=None):
    """Create a socket that listens to the QEMU multicast group"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the multicast port
    sock.bind(('', MCAST_PORT))

    # Join multicast group
    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Non-blocking
    sock.setblocking(False)

    return sock


def render_plain(state):
    """Render state without rich library"""
    import os
    os.system('clear' if os.name == 'posix' else 'cls')

    print("=" * 60)
    print("  NanOS Swarm Observer")
    print("=" * 60)
    print()

    active = state.get_active_nodes()
    print(f"Active Nodes: {len(active)}")
    print("-" * 40)

    for node_id, info in sorted(active.items()):
        role = ROLES.get(info["role"], ("?", ""))[0]
        age = time.time() - info["last_seen"]
        print(f"  {node_id:08X}  [{role:10}]  {info['packets']:5} pkts  ({age:.1f}s ago)")

    print()
    print("Statistics:")
    print("-" * 40)
    for key, value in sorted(state.stats.items()):
        print(f"  {key}: {value}")

    print()
    print("Recent Events:")
    print("-" * 40)
    for event in state.events[-10:]:
        print(f"  {event}")

    print()
    print(f"Uptime: {state.uptime():.0f}s | Press Ctrl+C to exit")


def render_rich(state, console):
    """Render state with rich library"""
    layout = Layout()

    # Create nodes table
    nodes_table = Table(title="Active Nodes", expand=True)
    nodes_table.add_column("Node ID", style="cyan")
    nodes_table.add_column("Role", style="green")
    nodes_table.add_column("Packets", justify="right")
    nodes_table.add_column("Last Seen", justify="right")

    active = state.get_active_nodes()
    for node_id, info in sorted(active.items()):
        role_name, role_color = ROLES.get(info["role"], ("?", "white"))
        age = time.time() - info["last_seen"]
        nodes_table.add_row(
            f"{node_id:08X}",
            f"[{role_color}]{role_name}[/{role_color}]",
            str(info["packets"]),
            f"{age:.1f}s"
        )

    # Create stats table
    stats_table = Table(title="Statistics", expand=True)
    stats_table.add_column("Type", style="cyan")
    stats_table.add_column("Count", justify="right")

    for key, value in sorted(state.stats.items()):
        stats_table.add_row(key, str(value))

    # Create events panel
    events_text = "\n".join(state.events[-15:]) if state.events else "No events yet"
    events_panel = Panel(events_text, title="Recent Events", border_style="blue")

    # Header
    header = Panel(
        f"[bold cyan]NanOS Swarm Observer[/bold cyan]\n"
        f"Active: {len(active)} nodes | Total packets: {state.stats['total']} | "
        f"Uptime: {state.uptime():.0f}s",
        style="green"
    )

    return header, nodes_table, stats_table, events_panel


def main():
    parser = argparse.ArgumentParser(description="NanOS Swarm Observer")
    parser.add_argument("--interface", "-i", help="Network interface")
    args = parser.parse_args()

    print("Starting NanOS Swarm Observer...")
    print(f"Joining multicast group {MCAST_GROUP}:{MCAST_PORT}")

    try:
        sock = create_multicast_socket(args.interface)
    except Exception as e:
        print(f"Error creating socket: {e}")
        print("Make sure you have permission and the network is available")
        return 1

    state = SwarmState()
    print("Listening for pheromones... (Press Ctrl+C to exit)")
    print()

    if RICH_AVAILABLE:
        console = Console()
        with Live(console=console, refresh_per_second=4) as live:
            try:
                while True:
                    # Try to receive packets
                    try:
                        data, addr = sock.recvfrom(2048)
                        # Skip Ethernet header simulation (QEMU sends raw)
                        # The packet starts directly with the pheromone
                        if len(data) >= 64:
                            try:
                                pkt = NanosPacket(data[:64])
                                state.process_packet(pkt)
                            except Exception:
                                pass
                    except BlockingIOError:
                        pass

                    # Render
                    header, nodes, stats, events = render_rich(state, console)
                    layout = Layout()
                    layout.split_column(
                        Layout(header, size=5),
                        Layout(name="main"),
                        Layout(events, size=18),
                    )
                    layout["main"].split_row(
                        Layout(nodes),
                        Layout(stats, size=30),
                    )
                    live.update(layout)

                    time.sleep(0.1)

            except KeyboardInterrupt:
                pass
    else:
        # Plain text mode
        try:
            while True:
                # Try to receive packets
                try:
                    data, addr = sock.recvfrom(2048)
                    if len(data) >= 64:
                        try:
                            pkt = NanosPacket(data[:64])
                            state.process_packet(pkt)
                        except Exception:
                            pass
                except BlockingIOError:
                    pass

                render_plain(state)
                time.sleep(0.5)

        except KeyboardInterrupt:
            pass

    print("\nShutting down...")
    sock.close()
    return 0


if __name__ == "__main__":
    exit(main())
