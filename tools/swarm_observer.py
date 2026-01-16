#!/usr/bin/env python3
"""
NanOS Swarm Observer v0.3 - Real-time visualization with packet injection

Joins the QEMU multicast network and displays:
- Live nodes with roles and gradient distances
- Queen election tracking
- Communication graph
- Packet statistics

New in v0.3:
- Packet injection capability
- Gradient/routing visualization
- Election monitoring

Usage:
    python3 swarm_observer.py [--interface eth0] [--inject]

Requirements:
    pip install rich  (for terminal UI)
"""

import socket
import struct
import time
import argparse
import threading
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
NANOS_VERSION = 0x0003    # v0.3

# Pheromone types
PHEROMONE_HELLO = 0x01
PHEROMONE_DATA = 0x02
PHEROMONE_ALARM = 0x03
PHEROMONE_ECHO = 0x04
PHEROMONE_ELECTION = 0x05
PHEROMONE_CORONATION = 0x06
PHEROMONE_QUERY = 0x07
PHEROMONE_QUEEN_CMD = 0x10
PHEROMONE_REBIRTH = 0xFE
PHEROMONE_DIE = 0xFF

# Roles
ROLES = {
    0x01: ("WORKER", "cyan"),
    0x02: ("EXPLORER", "green"),
    0x03: ("SENTINEL", "yellow"),
    0x04: ("QUEEN", "magenta"),
    0x05: ("CANDIDATE", "blue"),
}

# Flags
FLAG_AUTHENTICATED = (1 << 0)
FLAG_ROUTED = (1 << 5)

# Multicast address used by QEMU swarm mode
MCAST_GROUP = "230.0.0.1"
MCAST_PORT = 1234

# HMAC secret (must match NanOS)
SWARM_SECRET = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE]


def siphash_round(v0, v1, v2, v3):
    """SipHash-inspired mixing round (must match NanOS)"""
    v0 = (v0 + v1) & 0xFFFFFFFF
    v1 = ((v1 << 5) | (v1 >> 27)) & 0xFFFFFFFF
    v1 ^= v0
    v2 = (v2 + v3) & 0xFFFFFFFF
    v3 = ((v3 << 8) | (v3 >> 24)) & 0xFFFFFFFF
    v3 ^= v2
    v0 = (v0 + v3) & 0xFFFFFFFF
    v3 = ((v3 << 7) | (v3 >> 25)) & 0xFFFFFFFF
    v3 ^= v0
    v2 = (v2 + v1) & 0xFFFFFFFF
    v1 = ((v1 << 13) | (v1 >> 19)) & 0xFFFFFFFF
    v1 ^= v2
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFF


def compute_hmac(magic, node_id, ptype, ttl, seq):
    """Compute HMAC for a pheromone packet"""
    v0 = SWARM_SECRET[0] ^ magic
    v1 = SWARM_SECRET[1] ^ node_id
    v2 = SWARM_SECRET[2] ^ (ptype | (ttl << 8))
    v3 = SWARM_SECRET[3] ^ seq

    hash1 = siphash_round(v0, v1, v2, v3)
    hash1 = siphash_round(hash1, v1, v2, v3)
    hash2 = siphash_round(hash1, v0, v2, v1)

    hmac = bytes([
        (hash1 >> 0) & 0xFF,
        (hash1 >> 8) & 0xFF,
        (hash1 >> 16) & 0xFF,
        (hash1 >> 24) & 0xFF,
        (hash2 >> 0) & 0xFF,
        (hash2 >> 8) & 0xFF,
        (hash2 >> 16) & 0xFF,
        (hash2 >> 24) & 0xFF,
    ])
    return hmac


class NanosPacket:
    """Parse a NanOS pheromone packet v0.3"""

    def __init__(self, data):
        if len(data) < 64:
            raise ValueError("Packet too short")

        # Parse header (16 bytes)
        self.magic = struct.unpack("<I", data[0:4])[0]
        self.node_id = struct.unpack("<I", data[4:8])[0]
        self.type = data[8]
        self.ttl = data[9]
        self.flags = data[10]
        self.version = data[11]
        self.seq = struct.unpack("<I", data[12:16])[0]

        # Routing (8 bytes)
        self.dest_id = struct.unpack("<I", data[16:20])[0]
        self.distance = data[20]
        self.hop_count = data[21]
        self.via_node_lo = data[22]
        self.via_node_hi = data[23]

        # HMAC (8 bytes)
        self.hmac = data[24:32]

        # Payload (32 bytes)
        self.payload = data[32:64]

        # Decode role from flags
        self.role = (self.flags >> 1) & 0x07
        self.authenticated = bool(self.flags & FLAG_AUTHENTICATED)
        self.routed = bool(self.flags & FLAG_ROUTED)

    def is_valid(self):
        return self.magic == NANOS_MAGIC

    def type_name(self):
        names = {
            PHEROMONE_HELLO: "HELLO",
            PHEROMONE_DATA: "DATA",
            PHEROMONE_ALARM: "ALARM",
            PHEROMONE_ECHO: "ECHO",
            PHEROMONE_ELECTION: "ELECTION",
            PHEROMONE_CORONATION: "CORONATION",
            PHEROMONE_QUERY: "QUERY",
            PHEROMONE_QUEEN_CMD: "QUEEN_CMD",
            PHEROMONE_REBIRTH: "REBIRTH",
            PHEROMONE_DIE: "DIE",
        }
        return names.get(self.type, f"UNKNOWN({self.type})")

    def role_name(self):
        return ROLES.get(self.role, ("UNKNOWN", "white"))[0]

    def role_color(self):
        return ROLES.get(self.role, ("UNKNOWN", "white"))[1]


class NanosPacketBuilder:
    """Build NanOS pheromone packets for injection"""

    def __init__(self, node_id=0x0B5E4E34):
        self.node_id = node_id
        self.seq = 0

    def build_hello(self, role=0x01, distance=255):
        """Build a HELLO heartbeat packet"""
        pkt = bytearray(64)

        # Header
        struct.pack_into("<I", pkt, 0, NANOS_MAGIC)
        struct.pack_into("<I", pkt, 4, self.node_id)
        pkt[8] = PHEROMONE_HELLO
        pkt[9] = 1  # TTL
        pkt[10] = (role << 1)  # flags with role
        pkt[11] = NANOS_VERSION & 0xFF
        struct.pack_into("<I", pkt, 12, self.seq)
        self.seq += 1

        # Routing
        struct.pack_into("<I", pkt, 16, 0)  # dest_id (broadcast)
        pkt[20] = distance  # distance to queen
        pkt[21] = 0  # hop_count
        pkt[22] = 0  # via_node_lo
        pkt[23] = 0  # via_node_hi

        # No HMAC for hello
        return bytes(pkt)

    def build_alarm(self, ttl=5):
        """Build an ALARM packet"""
        pkt = bytearray(64)

        # Header
        struct.pack_into("<I", pkt, 0, NANOS_MAGIC)
        struct.pack_into("<I", pkt, 4, self.node_id)
        pkt[8] = PHEROMONE_ALARM
        pkt[9] = ttl
        pkt[10] = 0x02  # WORKER role
        pkt[11] = NANOS_VERSION & 0xFF
        struct.pack_into("<I", pkt, 12, self.seq)
        self.seq += 1

        # Routing
        struct.pack_into("<I", pkt, 16, 0)  # broadcast
        pkt[20] = 255  # distance
        pkt[21] = 0
        pkt[22] = 0
        pkt[23] = 0

        return bytes(pkt)

    def build_data(self, message):
        """Build a DATA packet with a message"""
        pkt = bytearray(64)

        # Header
        struct.pack_into("<I", pkt, 0, NANOS_MAGIC)
        struct.pack_into("<I", pkt, 4, self.node_id)
        pkt[8] = PHEROMONE_DATA
        pkt[9] = 3  # TTL
        pkt[10] = 0x02  # WORKER role
        pkt[11] = NANOS_VERSION & 0xFF
        struct.pack_into("<I", pkt, 12, self.seq)
        self.seq += 1

        # Routing
        struct.pack_into("<I", pkt, 16, 0)  # broadcast
        pkt[20] = 255
        pkt[21] = 0
        pkt[22] = 0
        pkt[23] = 0

        # Payload - message
        msg_bytes = message.encode('ascii')[:32]
        pkt[32:32+len(msg_bytes)] = msg_bytes

        return bytes(pkt)

    def build_queen_cmd(self, command):
        """Build an authenticated QUEEN_CMD packet"""
        pkt = bytearray(64)

        # Header
        struct.pack_into("<I", pkt, 0, NANOS_MAGIC)
        struct.pack_into("<I", pkt, 4, self.node_id)
        pkt[8] = PHEROMONE_QUEEN_CMD
        pkt[9] = 5  # TTL
        pkt[10] = FLAG_AUTHENTICATED | (0x04 << 1)  # QUEEN role + authenticated
        pkt[11] = NANOS_VERSION & 0xFF
        struct.pack_into("<I", pkt, 12, self.seq)

        # Routing
        struct.pack_into("<I", pkt, 16, 0)  # broadcast
        pkt[20] = 0  # queen is distance 0
        pkt[21] = 0
        pkt[22] = 0
        pkt[23] = 0

        # Compute HMAC
        hmac = compute_hmac(NANOS_MAGIC, self.node_id, PHEROMONE_QUEEN_CMD, 5, self.seq)
        pkt[24:32] = hmac
        self.seq += 1

        # Payload - command
        cmd_bytes = command.encode('ascii')[:32]
        pkt[32:32+len(cmd_bytes)] = cmd_bytes

        return bytes(pkt)

    def build_die(self, target_id=0):
        """Build an authenticated DIE packet (dangerous!)"""
        pkt = bytearray(64)

        # Header
        struct.pack_into("<I", pkt, 0, NANOS_MAGIC)
        struct.pack_into("<I", pkt, 4, self.node_id)
        pkt[8] = PHEROMONE_DIE
        pkt[9] = 10  # TTL
        pkt[10] = FLAG_AUTHENTICATED | (0x04 << 1)  # QUEEN role
        pkt[11] = NANOS_VERSION & 0xFF
        struct.pack_into("<I", pkt, 12, self.seq)

        # Routing
        struct.pack_into("<I", pkt, 16, target_id)  # specific target or broadcast
        pkt[20] = 0
        pkt[21] = 0
        pkt[22] = 0
        pkt[23] = 0

        # Compute HMAC
        hmac = compute_hmac(NANOS_MAGIC, self.node_id, PHEROMONE_DIE, 10, self.seq)
        pkt[24:32] = hmac
        self.seq += 1

        return bytes(pkt)


class SwarmState:
    """Track the state of the swarm"""

    def __init__(self):
        self.nodes = {}  # node_id -> info
        self.events = []
        self.stats = defaultdict(int)
        self.alarms = []
        self.deaths = []
        self.elections = []  # Track election activity
        self.queen_id = None  # Current known queen
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
                "distance": pkt.distance,
            }
            self.log_event(f"New node: {node_id:08X} ({pkt.role_name()})")

        self.nodes[node_id]["last_seen"] = now
        self.nodes[node_id]["role"] = pkt.role
        self.nodes[node_id]["packets"] += 1
        self.nodes[node_id]["distance"] = pkt.distance

        # Track queen
        if pkt.role == 0x04:  # QUEEN
            if self.queen_id != node_id:
                self.log_event(f"Queen spotted: {node_id:08X}")
                self.queen_id = node_id

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
            self.alarms = self.alarms[-10:]

        elif pkt.type == PHEROMONE_REBIRTH:
            gen = struct.unpack("<I", pkt.payload[8:12])[0] if len(pkt.payload) >= 12 else 0
            self.deaths.append({
                "time": now,
                "node": node_id,
                "generation": gen,
            })
            self.log_event(f"Cell {node_id:08X} died (gen {gen})")
            if node_id in self.nodes:
                del self.nodes[node_id]
            self.deaths = self.deaths[-10:]

        elif pkt.type == PHEROMONE_ELECTION:
            election_id = struct.unpack("<I", pkt.payload[0:4])[0]
            candidate = struct.unpack("<I", pkt.payload[4:8])[0]
            self.elections.append({
                "time": now,
                "election_id": election_id,
                "candidate": candidate,
            })
            self.log_event(f"ELECTION {election_id:08X} candidate={candidate:08X}")
            self.elections = self.elections[-20:]

        elif pkt.type == PHEROMONE_CORONATION:
            self.queen_id = node_id
            self.log_event(f"CORONATION: {node_id:08X} is new Queen!")

        elif pkt.type == PHEROMONE_QUEEN_CMD:
            cmd = pkt.payload[:32].decode('ascii', errors='ignore').strip('\x00')
            self.log_event(f"QUEEN CMD from {node_id:08X}: {cmd}")

    def log_event(self, msg):
        """Add an event to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.events.append(f"[{timestamp}] {msg}")
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
    sock.bind(('', MCAST_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setblocking(False)

    return sock


def create_send_socket():
    """Create a socket for sending to the multicast group"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return sock


def render_plain(state):
    """Render state without rich library"""
    import os
    os.system('clear' if os.name == 'posix' else 'cls')

    print("=" * 70)
    print("  NanOS Swarm Observer v0.3")
    print("=" * 70)
    print()

    active = state.get_active_nodes()
    queen_str = f"{state.queen_id:08X}" if state.queen_id else "None"
    print(f"Active Nodes: {len(active)}  |  Queen: {queen_str}")
    print("-" * 50)

    for node_id, info in sorted(active.items()):
        role = ROLES.get(info["role"], ("?", ""))[0]
        age = time.time() - info["last_seen"]
        dist = info.get("distance", 255)
        dist_str = str(dist) if dist < 255 else "INF"
        print(f"  {node_id:08X}  [{role:10}]  d={dist_str:3}  {info['packets']:5} pkts  ({age:.1f}s ago)")

    print()
    print("Statistics:")
    print("-" * 50)
    for key, value in sorted(state.stats.items()):
        print(f"  {key}: {value}")

    print()
    print("Recent Events:")
    print("-" * 50)
    for event in state.events[-10:]:
        print(f"  {event}")

    print()
    print(f"Uptime: {state.uptime():.0f}s | Press Ctrl+C to exit")


def render_rich(state, console):
    """Render state with rich library"""
    # Create nodes table
    nodes_table = Table(title="Active Nodes", expand=True)
    nodes_table.add_column("Node ID", style="cyan")
    nodes_table.add_column("Role", style="green")
    nodes_table.add_column("Distance", justify="right")
    nodes_table.add_column("Packets", justify="right")
    nodes_table.add_column("Last Seen", justify="right")

    active = state.get_active_nodes()
    for node_id, info in sorted(active.items()):
        role_name, role_color = ROLES.get(info["role"], ("?", "white"))
        age = time.time() - info["last_seen"]
        dist = info.get("distance", 255)
        dist_str = str(dist) if dist < 255 else "INF"
        nodes_table.add_row(
            f"{node_id:08X}",
            f"[{role_color}]{role_name}[/{role_color}]",
            dist_str,
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
    queen_str = f"{state.queen_id:08X}" if state.queen_id else "None"
    header = Panel(
        f"[bold cyan]NanOS Swarm Observer v0.3[/bold cyan]\n"
        f"Active: {len(active)} nodes | Queen: {queen_str} | Total: {state.stats['total']} pkts | "
        f"Uptime: {state.uptime():.0f}s",
        style="green"
    )

    return header, nodes_table, stats_table, events_panel


def injection_mode(send_sock, state):
    """Interactive injection mode"""
    builder = NanosPacketBuilder(node_id=0x0B5E4E34)  # "OBSERVER" in hex-ish

    print("\n--- Packet Injection Mode ---")
    print("Commands:")
    print("  hello           - Send HELLO heartbeat")
    print("  alarm           - Send ALARM")
    print("  data <msg>      - Send DATA with message")
    print("  queen <cmd>     - Send QUEEN_CMD (authenticated)")
    print("  die [node_id]   - Send DIE command (dangerous!)")
    print("  exit            - Return to observer mode")
    print()

    while True:
        try:
            cmd = input("inject> ").strip().lower()
            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            action = parts[0]
            arg = parts[1] if len(parts) > 1 else ""

            if action == "exit":
                break
            elif action == "hello":
                pkt = builder.build_hello()
                send_sock.sendto(pkt, (MCAST_GROUP, MCAST_PORT))
                print("Sent HELLO")
            elif action == "alarm":
                pkt = builder.build_alarm()
                send_sock.sendto(pkt, (MCAST_GROUP, MCAST_PORT))
                print("Sent ALARM")
            elif action == "data":
                if arg:
                    pkt = builder.build_data(arg)
                    send_sock.sendto(pkt, (MCAST_GROUP, MCAST_PORT))
                    print(f"Sent DATA: {arg}")
                else:
                    print("Usage: data <message>")
            elif action == "queen":
                if arg:
                    pkt = builder.build_queen_cmd(arg)
                    send_sock.sendto(pkt, (MCAST_GROUP, MCAST_PORT))
                    print(f"Sent QUEEN_CMD: {arg}")
                else:
                    print("Usage: queen <command>")
            elif action == "die":
                confirm = input("Are you sure? This will kill nodes! (yes/no): ")
                if confirm.lower() == "yes":
                    target = int(arg, 16) if arg else 0
                    pkt = builder.build_die(target)
                    send_sock.sendto(pkt, (MCAST_GROUP, MCAST_PORT))
                    print(f"Sent DIE to {target:08X if target else 'broadcast'}")
                else:
                    print("Cancelled")
            else:
                print(f"Unknown command: {action}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="NanOS Swarm Observer v0.3")
    parser.add_argument("--interface", "-i", help="Network interface")
    parser.add_argument("--inject", "-j", action="store_true", help="Enable injection mode")
    args = parser.parse_args()

    print("Starting NanOS Swarm Observer v0.3...")
    print(f"Joining multicast group {MCAST_GROUP}:{MCAST_PORT}")

    try:
        recv_sock = create_multicast_socket(args.interface)
        send_sock = create_send_socket() if args.inject else None
    except Exception as e:
        print(f"Error creating socket: {e}")
        print("Make sure you have permission and the network is available")
        return 1

    state = SwarmState()
    print("Listening for pheromones... (Press Ctrl+C to exit)")
    if args.inject:
        print("Injection mode enabled. Press 'i' to inject packets.")
    print()

    if RICH_AVAILABLE:
        console = Console()
        with Live(console=console, refresh_per_second=4) as live:
            try:
                while True:
                    # Try to receive packets
                    try:
                        data, addr = recv_sock.recvfrom(2048)
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
                if args.inject:
                    injection_mode(send_sock, state)
    else:
        # Plain text mode
        try:
            while True:
                try:
                    data, addr = recv_sock.recvfrom(2048)
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
            if args.inject:
                injection_mode(send_sock, state)

    print("\nShutting down...")
    recv_sock.close()
    if send_sock:
        send_sock.close()
    return 0


if __name__ == "__main__":
    exit(main())
