#!/usr/bin/env python3
"""
NERT Swarm Simulator
Multi-node swarm simulation for testing algorithms without hardware

Copyright (c) 2026 NanOS Project
SPDX-License-Identifier: MIT
"""

import random
import time
import hashlib
import struct
import threading
import argparse
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
from collections import defaultdict
from enum import Enum
import heapq


# =============================================================================
# Configuration
# =============================================================================

NERT_MAGIC = 0x4E
NERT_VERSION = 0x10

# Pheromone types
PHEROMONE_ECHO = 0x00
PHEROMONE_ANNOUNCE = 0x01
PHEROMONE_ELECTION = 0x02
PHEROMONE_REKEY = 0x03
PHEROMONE_DATA = 0x10
PHEROMONE_ALARM = 0x11
PHEROMONE_STIGMERGIA = 0x12
PHEROMONE_DIE = 0x13

# Stigmergia pheromone types
STIGMERGIA_DANGER = 0
STIGMERGIA_QUEEN = 1
STIGMERGIA_RESOURCE = 2
STIGMERGIA_AVOID = 3


# =============================================================================
# Network Topology Models
# =============================================================================

class TopologyType(Enum):
    FULL_MESH = "full_mesh"       # Every node can reach every other node
    RING = "ring"                  # Nodes arranged in a ring
    STAR = "star"                  # Central hub with spokes
    GRID = "grid"                  # 2D grid topology
    RANDOM = "random"              # Random connectivity
    HIERARCHICAL = "hierarchical"  # Tree-like structure


@dataclass
class NetworkLink:
    """Represents a link between two nodes"""
    source: int
    target: int
    latency_ms: float = 10.0       # One-way latency
    loss_rate: float = 0.0         # Packet loss probability (0.0-1.0)
    bandwidth_kbps: float = 1000.0  # Link bandwidth
    active: bool = True             # Link is up


@dataclass
class NetworkTopology:
    """Network topology definition"""
    nodes: Set[int] = field(default_factory=set)
    links: Dict[Tuple[int, int], NetworkLink] = field(default_factory=dict)

    def add_node(self, node_id: int):
        self.nodes.add(node_id)

    def add_link(self, source: int, target: int, **kwargs):
        """Add bidirectional link between nodes"""
        self.nodes.add(source)
        self.nodes.add(target)
        self.links[(source, target)] = NetworkLink(source, target, **kwargs)
        self.links[(target, source)] = NetworkLink(target, source, **kwargs)

    def get_neighbors(self, node_id: int) -> List[int]:
        """Get all reachable neighbors of a node"""
        neighbors = []
        for (src, dst), link in self.links.items():
            if src == node_id and link.active:
                neighbors.append(dst)
        return neighbors

    def get_link(self, source: int, target: int) -> Optional[NetworkLink]:
        return self.links.get((source, target))

    @classmethod
    def create(cls, topology_type: TopologyType, num_nodes: int, **kwargs) -> 'NetworkTopology':
        """Factory method to create topologies"""
        topo = cls()

        if topology_type == TopologyType.FULL_MESH:
            for i in range(num_nodes):
                topo.add_node(0x1000 + i)
            for i in range(num_nodes):
                for j in range(i + 1, num_nodes):
                    topo.add_link(0x1000 + i, 0x1000 + j, **kwargs)

        elif topology_type == TopologyType.RING:
            for i in range(num_nodes):
                topo.add_node(0x1000 + i)
            for i in range(num_nodes):
                topo.add_link(0x1000 + i, 0x1000 + ((i + 1) % num_nodes), **kwargs)

        elif topology_type == TopologyType.STAR:
            hub = 0x1000
            topo.add_node(hub)
            for i in range(1, num_nodes):
                spoke = 0x1000 + i
                topo.add_node(spoke)
                topo.add_link(hub, spoke, **kwargs)

        elif topology_type == TopologyType.GRID:
            size = int(num_nodes ** 0.5)
            for y in range(size):
                for x in range(size):
                    node_id = 0x1000 + y * size + x
                    topo.add_node(node_id)
                    # Horizontal link
                    if x > 0:
                        topo.add_link(node_id, 0x1000 + y * size + (x - 1), **kwargs)
                    # Vertical link
                    if y > 0:
                        topo.add_link(node_id, 0x1000 + (y - 1) * size + x, **kwargs)

        elif topology_type == TopologyType.RANDOM:
            density = kwargs.pop('density', 0.3)
            for i in range(num_nodes):
                topo.add_node(0x1000 + i)
            for i in range(num_nodes):
                for j in range(i + 1, num_nodes):
                    if random.random() < density:
                        topo.add_link(0x1000 + i, 0x1000 + j, **kwargs)
            # Ensure connectivity
            _ensure_connected(topo, num_nodes, **kwargs)

        elif topology_type == TopologyType.HIERARCHICAL:
            # Create tree with branching factor
            branch_factor = kwargs.pop('branch_factor', 3)
            node_id = 0x1000
            topo.add_node(node_id)
            queue = [node_id]
            count = 1
            while count < num_nodes and queue:
                parent = queue.pop(0)
                for _ in range(branch_factor):
                    if count >= num_nodes:
                        break
                    child = 0x1000 + count
                    topo.add_node(child)
                    topo.add_link(parent, child, **kwargs)
                    queue.append(child)
                    count += 1

        return topo


def _ensure_connected(topo: NetworkTopology, num_nodes: int, **kwargs):
    """Ensure all nodes are connected (add random links if needed)"""
    visited = set()
    if not topo.nodes:
        return

    start = min(topo.nodes)
    stack = [start]
    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        for neighbor in topo.get_neighbors(node):
            if neighbor not in visited:
                stack.append(neighbor)

    # Connect disconnected components
    unvisited = topo.nodes - visited
    while unvisited:
        disconnected = unvisited.pop()
        connected = random.choice(list(visited))
        topo.add_link(disconnected, connected, **kwargs)
        visited.add(disconnected)


# =============================================================================
# Packet Structure
# =============================================================================

@dataclass
class SimPacket:
    """Simulated NERT packet"""
    magic: int = NERT_MAGIC
    version_class: int = NERT_VERSION
    source_id: int = 0
    dest_id: int = 0  # 0 = broadcast
    seq_num: int = 0
    pheromone_type: int = 0
    payload: bytes = b''
    ttl: int = 15
    hop_count: int = 0
    timestamp: float = 0.0  # Simulation time when sent

    def pack(self) -> bytes:
        header = struct.pack(
            '<BBHHHHBB',
            self.magic,
            self.version_class,
            self.source_id,
            self.dest_id,
            self.seq_num,
            len(self.payload),
            self.pheromone_type,
            self.ttl
        )
        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> 'SimPacket':
        if len(data) < 12:
            return None
        header = struct.unpack('<BBHHHHBB', data[:12])
        pkt = cls(
            magic=header[0],
            version_class=header[1],
            source_id=header[2],
            dest_id=header[3],
            seq_num=header[4],
            pheromone_type=header[6],
            ttl=header[7]
        )
        payload_len = header[5]
        if len(data) >= 12 + payload_len:
            pkt.payload = data[12:12 + payload_len]
        return pkt


# =============================================================================
# Simulated Node
# =============================================================================

class NodeState(Enum):
    BOOTING = "booting"
    ACTIVE = "active"
    FAILED = "failed"
    COMPROMISED = "compromised"


@dataclass
class StigmergiaCell:
    """Pheromone cell for stigmergy"""
    danger: int = 0      # 0-15
    queen: int = 0       # 0-15
    resource: int = 0    # 0-15
    avoid: int = 0       # 0-15


@dataclass
class HebbianSynapse:
    """Synaptic weight for Hebbian routing"""
    weight: int = 128    # 0-255, starts neutral
    last_update: float = 0.0
    successes: int = 0
    failures: int = 0


class SimulatedNode:
    """A simulated NanOS node"""

    def __init__(self, node_id: int, simulator: 'SwarmSimulator'):
        self.node_id = node_id
        self.simulator = simulator
        self.state = NodeState.BOOTING

        # Sequence tracking
        self.tx_seq = 0
        self.rx_seqs: Dict[int, int] = {}  # Last seen seq per source

        # Neighbor discovery
        self.neighbors: Dict[int, float] = {}  # node_id -> last_seen_time
        self.neighbor_distances: Dict[int, int] = {}  # node_id -> hops

        # Hebbian routing
        self.synapses: Dict[int, HebbianSynapse] = defaultdict(HebbianSynapse)

        # Stigmergy grid (16x16)
        self.stigmergy: List[List[StigmergiaCell]] = [
            [StigmergiaCell() for _ in range(16)] for _ in range(16)
        ]

        # AIS (Artificial Immune System)
        self.ais_detectors: List[bytes] = []
        self.ais_self_profile: Set[int] = set()  # Known-good patterns

        # Queen election
        self.is_queen = False
        self.queen_id: Optional[int] = None
        self.election_priority = random.randint(0, 65535)

        # Statistics
        self.stats = {
            'tx_packets': 0,
            'rx_packets': 0,
            'rx_dropped': 0,
            'forwarded': 0,
            'anomalies_detected': 0,
            'messages_sent': 0,
            'messages_received': 0,
        }

        # Boot delay
        self.boot_complete_time = simulator.current_time + random.uniform(0.1, 0.5)

    def tick(self, current_time: float):
        """Process a simulation tick"""
        if self.state == NodeState.FAILED:
            return

        if self.state == NodeState.BOOTING:
            if current_time >= self.boot_complete_time:
                self.state = NodeState.ACTIVE
                self._on_boot_complete()
            return

        # Periodic tasks
        self._decay_stigmergy()
        self._decay_synapses()
        self._age_neighbors(current_time)

    def _on_boot_complete(self):
        """Called when node finishes booting"""
        # Announce presence
        self.send_announce()

    def send_announce(self):
        """Send ANNOUNCE pheromone"""
        payload = struct.pack('<HH', self.node_id, self.election_priority)
        self._send_packet(0, PHEROMONE_ANNOUNCE, payload)

    def send_data(self, dest_id: int, data: bytes):
        """Send DATA pheromone"""
        self._send_packet(dest_id, PHEROMONE_DATA, data)
        self.stats['messages_sent'] += 1

    def send_alarm(self, x: int, y: int, intensity: int):
        """Send ALARM pheromone (danger signal)"""
        payload = struct.pack('<BBB', x, y, intensity)
        self._send_packet(0, PHEROMONE_ALARM, payload)

    def _send_packet(self, dest_id: int, pheromone_type: int, payload: bytes):
        """Internal packet send"""
        if self.state != NodeState.ACTIVE:
            return

        pkt = SimPacket(
            source_id=self.node_id,
            dest_id=dest_id,
            seq_num=self.tx_seq,
            pheromone_type=pheromone_type,
            payload=payload,
            timestamp=self.simulator.current_time
        )
        self.tx_seq = (self.tx_seq + 1) & 0xFFFF
        self.stats['tx_packets'] += 1

        self.simulator.transmit(self.node_id, pkt)

    def receive_packet(self, pkt: SimPacket, from_neighbor: int):
        """Handle received packet"""
        if self.state != NodeState.ACTIVE:
            return

        self.stats['rx_packets'] += 1

        # Update neighbor info
        self.neighbors[pkt.source_id] = self.simulator.current_time
        if from_neighbor == pkt.source_id:
            self.neighbor_distances[pkt.source_id] = 1

        # Duplicate detection
        last_seq = self.rx_seqs.get(pkt.source_id, -1)
        if pkt.seq_num <= last_seq and last_seq - pkt.seq_num < 32768:
            self.stats['rx_dropped'] += 1
            return
        self.rx_seqs[pkt.source_id] = pkt.seq_num

        # Process by type
        if pkt.pheromone_type == PHEROMONE_ANNOUNCE:
            self._handle_announce(pkt)
        elif pkt.pheromone_type == PHEROMONE_ELECTION:
            self._handle_election(pkt)
        elif pkt.pheromone_type == PHEROMONE_DATA:
            self._handle_data(pkt)
        elif pkt.pheromone_type == PHEROMONE_ALARM:
            self._handle_alarm(pkt)
        elif pkt.pheromone_type == PHEROMONE_STIGMERGIA:
            self._handle_stigmergia(pkt)

        # Update Hebbian synapse (success)
        synapse = self.synapses[pkt.source_id]
        synapse.weight = min(255, synapse.weight + 15)  # LTP
        synapse.successes += 1
        synapse.last_update = self.simulator.current_time

        # Forward if not for us and TTL > 0
        if pkt.dest_id != 0 and pkt.dest_id != self.node_id and pkt.ttl > 1:
            self._forward_packet(pkt)

    def _handle_announce(self, pkt: SimPacket):
        """Handle ANNOUNCE pheromone"""
        if len(pkt.payload) >= 4:
            node_id, priority = struct.unpack('<HH', pkt.payload[:4])
            self.neighbors[node_id] = self.simulator.current_time

            # Queen election - higher priority wins
            if self.queen_id is None or priority > self.election_priority:
                if self.is_queen and priority > self.election_priority:
                    self.is_queen = False
                self.queen_id = node_id if priority > self.election_priority else self.queen_id

    def _handle_election(self, pkt: SimPacket):
        """Handle ELECTION pheromone"""
        if len(pkt.payload) >= 2:
            candidate_priority = struct.unpack('<H', pkt.payload[:2])[0]
            if candidate_priority > self.election_priority:
                self.is_queen = False
                self.queen_id = pkt.source_id

    def _handle_data(self, pkt: SimPacket):
        """Handle DATA pheromone"""
        if pkt.dest_id == self.node_id or pkt.dest_id == 0:
            self.stats['messages_received'] += 1
            # Callback to simulator for metrics
            self.simulator._on_message_delivered(pkt)

    def _handle_alarm(self, pkt: SimPacket):
        """Handle ALARM pheromone (danger signal)"""
        if len(pkt.payload) >= 3:
            x, y, intensity = struct.unpack('<BBB', pkt.payload[:3])
            # Update local stigmergy
            if 0 <= x < 16 and 0 <= y < 16:
                cell = self.stigmergy[y][x]
                cell.danger = min(15, cell.danger + intensity)

    def _handle_stigmergia(self, pkt: SimPacket):
        """Handle STIGMERGIA pheromone update"""
        if len(pkt.payload) >= 4:
            x, y, ptype, intensity = struct.unpack('<BBBB', pkt.payload[:4])
            if 0 <= x < 16 and 0 <= y < 16:
                cell = self.stigmergy[y][x]
                if ptype == STIGMERGIA_DANGER:
                    cell.danger = min(15, max(cell.danger, intensity))
                elif ptype == STIGMERGIA_QUEEN:
                    cell.queen = min(15, max(cell.queen, intensity))
                elif ptype == STIGMERGIA_RESOURCE:
                    cell.resource = min(15, max(cell.resource, intensity))
                elif ptype == STIGMERGIA_AVOID:
                    cell.avoid = min(15, max(cell.avoid, intensity))

    def _forward_packet(self, pkt: SimPacket):
        """Forward packet toward destination"""
        pkt.ttl -= 1
        pkt.hop_count += 1
        self.stats['forwarded'] += 1
        self.simulator.transmit(self.node_id, pkt)

    def _decay_stigmergy(self):
        """Decay pheromone intensities over time"""
        for row in self.stigmergy:
            for cell in row:
                if cell.danger > 0:
                    cell.danger -= 1
                if cell.queen > 0:
                    cell.queen -= 1
                if cell.resource > 0:
                    cell.resource -= 1
                if cell.avoid > 0:
                    cell.avoid -= 1

    def _decay_synapses(self):
        """Decay Hebbian synapse weights"""
        for synapse in self.synapses.values():
            if synapse.weight > 128:
                synapse.weight -= 1  # Decay toward neutral

    def _age_neighbors(self, current_time: float):
        """Remove stale neighbors"""
        stale = [nid for nid, last_seen in self.neighbors.items()
                 if current_time - last_seen > 30.0]  # 30s timeout
        for nid in stale:
            del self.neighbors[nid]
            if nid in self.neighbor_distances:
                del self.neighbor_distances[nid]


# =============================================================================
# Event Queue (Discrete Event Simulation)
# =============================================================================

@dataclass(order=True)
class SimEvent:
    """Simulation event"""
    time: float
    event_type: str = field(compare=False)
    data: dict = field(compare=False, default_factory=dict)


class EventQueue:
    """Priority queue for simulation events"""

    def __init__(self):
        self.heap: List[SimEvent] = []
        self.counter = 0

    def schedule(self, time: float, event_type: str, **data):
        event = SimEvent(time, event_type, data)
        heapq.heappush(self.heap, event)
        self.counter += 1

    def pop(self) -> Optional[SimEvent]:
        if self.heap:
            return heapq.heappop(self.heap)
        return None

    def peek_time(self) -> Optional[float]:
        if self.heap:
            return self.heap[0].time
        return None

    def __len__(self):
        return len(self.heap)


# =============================================================================
# Swarm Simulator
# =============================================================================

class SwarmSimulator:
    """Main swarm simulation engine"""

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self.nodes: Dict[int, SimulatedNode] = {}
        self.events = EventQueue()
        self.current_time = 0.0

        # Metrics
        self.metrics = {
            'total_packets': 0,
            'delivered_messages': 0,
            'dropped_packets': 0,
            'convergence_time': 0.0,
            'queen_elected_time': 0.0,
            'avg_latency_ms': 0.0,
            'latencies': [],
        }

        # Message tracking
        self.pending_messages: Dict[int, Tuple[float, int, int]] = {}  # seq -> (send_time, src, dst)
        self.message_seq = 0

        # Failure injection
        self.failure_schedule: List[Tuple[float, int]] = []  # (time, node_id)

        # Callbacks
        self.on_message_callback: Optional[Callable] = None

    def add_nodes(self):
        """Create nodes for all topology entries"""
        for node_id in self.topology.nodes:
            self.nodes[node_id] = SimulatedNode(node_id, self)

    def schedule_failure(self, time: float, node_id: int):
        """Schedule a node failure"""
        self.events.schedule(time, 'node_failure', node_id=node_id)

    def schedule_recovery(self, time: float, node_id: int):
        """Schedule a node recovery"""
        self.events.schedule(time, 'node_recovery', node_id=node_id)

    def inject_message(self, time: float, src_id: int, dst_id: int, data: bytes):
        """Inject a message into the simulation"""
        self.events.schedule(time, 'inject_message', src_id=src_id, dst_id=dst_id, data=data)

    def transmit(self, from_node: int, pkt: SimPacket):
        """Transmit a packet from a node"""
        self.metrics['total_packets'] += 1

        # Get neighbors in topology
        neighbors = self.topology.get_neighbors(from_node)

        # Broadcast or unicast
        if pkt.dest_id == 0:
            targets = neighbors
        else:
            targets = neighbors  # Simplified: flood to find route

        for neighbor_id in targets:
            link = self.topology.get_link(from_node, neighbor_id)
            if not link or not link.active:
                continue

            # Check packet loss
            if random.random() < link.loss_rate:
                self.metrics['dropped_packets'] += 1
                continue

            # Schedule delivery with latency
            delivery_time = self.current_time + (link.latency_ms / 1000.0)
            self.events.schedule(
                delivery_time,
                'packet_delivery',
                packet=pkt,
                to_node=neighbor_id,
                from_neighbor=from_node
            )

    def _on_message_delivered(self, pkt: SimPacket):
        """Called when a message reaches its destination"""
        self.metrics['delivered_messages'] += 1

        # Track latency
        latency = (self.current_time - pkt.timestamp) * 1000  # ms
        self.metrics['latencies'].append(latency)

        if self.on_message_callback:
            self.on_message_callback(pkt)

    def run(self, duration: float, tick_interval: float = 0.05):
        """Run simulation for specified duration"""
        end_time = duration

        # Schedule periodic ticks for all nodes
        next_tick = 0.0
        while next_tick < end_time:
            self.events.schedule(next_tick, 'tick')
            next_tick += tick_interval

        # Main event loop
        while self.events:
            event = self.events.pop()
            if event.time > end_time:
                break

            self.current_time = event.time
            self._process_event(event)

        # Calculate final metrics
        self._finalize_metrics()

    def _process_event(self, event: SimEvent):
        """Process a single event"""
        if event.event_type == 'tick':
            for node in self.nodes.values():
                node.tick(self.current_time)

        elif event.event_type == 'packet_delivery':
            pkt = event.data['packet']
            to_node = event.data['to_node']
            from_neighbor = event.data['from_neighbor']

            if to_node in self.nodes:
                self.nodes[to_node].receive_packet(pkt, from_neighbor)

        elif event.event_type == 'node_failure':
            node_id = event.data['node_id']
            if node_id in self.nodes:
                self.nodes[node_id].state = NodeState.FAILED
                print(f"[{self.current_time:.2f}s] Node {node_id:04X} FAILED")

        elif event.event_type == 'node_recovery':
            node_id = event.data['node_id']
            if node_id in self.nodes:
                self.nodes[node_id].state = NodeState.BOOTING
                self.nodes[node_id].boot_complete_time = self.current_time + 0.5
                print(f"[{self.current_time:.2f}s] Node {node_id:04X} recovering...")

        elif event.event_type == 'inject_message':
            src_id = event.data['src_id']
            dst_id = event.data['dst_id']
            data = event.data['data']
            if src_id in self.nodes:
                self.nodes[src_id].send_data(dst_id, data)

    def _finalize_metrics(self):
        """Calculate final metrics"""
        if self.metrics['latencies']:
            self.metrics['avg_latency_ms'] = sum(self.metrics['latencies']) / len(self.metrics['latencies'])

        # Check convergence (all nodes have a queen)
        queens = set()
        for node in self.nodes.values():
            if node.queen_id:
                queens.add(node.queen_id)
        if len(queens) == 1:
            self.metrics['converged'] = True
        else:
            self.metrics['converged'] = False

    def get_report(self) -> dict:
        """Generate simulation report"""
        active_nodes = sum(1 for n in self.nodes.values() if n.state == NodeState.ACTIVE)
        failed_nodes = sum(1 for n in self.nodes.values() if n.state == NodeState.FAILED)

        # Aggregate node stats
        total_tx = sum(n.stats['tx_packets'] for n in self.nodes.values())
        total_rx = sum(n.stats['rx_packets'] for n in self.nodes.values())
        total_fwd = sum(n.stats['forwarded'] for n in self.nodes.values())
        total_msg_sent = sum(n.stats['messages_sent'] for n in self.nodes.values())
        total_msg_recv = sum(n.stats['messages_received'] for n in self.nodes.values())

        # Queen info
        queens = {}
        for node in self.nodes.values():
            if node.is_queen:
                queens[node.node_id] = True

        return {
            'simulation_time': self.current_time,
            'total_nodes': len(self.nodes),
            'active_nodes': active_nodes,
            'failed_nodes': failed_nodes,
            'total_packets': self.metrics['total_packets'],
            'delivered_messages': self.metrics['delivered_messages'],
            'dropped_packets': self.metrics['dropped_packets'],
            'avg_latency_ms': self.metrics['avg_latency_ms'],
            'node_stats': {
                'total_tx': total_tx,
                'total_rx': total_rx,
                'total_forwarded': total_fwd,
                'messages_sent': total_msg_sent,
                'messages_received': total_msg_recv,
            },
            'queens': list(queens.keys()),
            'converged': self.metrics.get('converged', False),
        }


# =============================================================================
# Visualization (ASCII)
# =============================================================================

def visualize_topology_ascii(topo: NetworkTopology) -> str:
    """Generate ASCII visualization of topology"""
    lines = []
    lines.append("=" * 50)
    lines.append("Network Topology")
    lines.append("=" * 50)

    nodes = sorted(topo.nodes)
    lines.append(f"Nodes ({len(nodes)}): " + ", ".join(f"{n:04X}" for n in nodes[:10]))
    if len(nodes) > 10:
        lines.append(f"  ... and {len(nodes) - 10} more")

    # Count links per node
    link_counts = defaultdict(int)
    for (src, dst), link in topo.links.items():
        if link.active:
            link_counts[src] += 1

    lines.append(f"\nConnectivity:")
    for node_id in sorted(link_counts.keys())[:10]:
        lines.append(f"  {node_id:04X}: {link_counts[node_id]} links")

    return "\n".join(lines)


def visualize_stigmergy_ascii(node: SimulatedNode) -> str:
    """Generate ASCII visualization of stigmergy grid"""
    lines = []
    lines.append(f"Stigmergy Grid for Node {node.node_id:04X}")
    lines.append("-" * 34)

    # Show danger levels
    for y in range(16):
        row = ""
        for x in range(16):
            cell = node.stigmergy[y][x]
            if cell.danger > 10:
                row += "!"
            elif cell.danger > 5:
                row += "*"
            elif cell.danger > 0:
                row += "."
            elif cell.queen > 5:
                row += "Q"
            elif cell.resource > 5:
                row += "R"
            else:
                row += " "
            row += " "
        lines.append(row)

    return "\n".join(lines)


# =============================================================================
# Test Scenarios
# =============================================================================

def scenario_basic_convergence(num_nodes: int = 10, duration: float = 10.0):
    """Test basic swarm convergence"""
    print("\n" + "=" * 60)
    print("SCENARIO: Basic Convergence Test")
    print("=" * 60)

    topo = NetworkTopology.create(TopologyType.FULL_MESH, num_nodes, latency_ms=10.0)
    sim = SwarmSimulator(topo)
    sim.add_nodes()

    print(f"Created {num_nodes} nodes in full mesh topology")
    print(f"Running simulation for {duration}s...")

    sim.run(duration)

    report = sim.get_report()
    print("\nResults:")
    print(f"  Converged: {report['converged']}")
    print(f"  Queens: {[f'{q:04X}' for q in report['queens']]}")
    print(f"  Total packets: {report['total_packets']}")
    print(f"  Avg latency: {report['avg_latency_ms']:.2f}ms")

    return report


def scenario_node_failure(num_nodes: int = 20, failure_count: int = 5, duration: float = 30.0):
    """Test swarm resilience to node failures"""
    print("\n" + "=" * 60)
    print("SCENARIO: Node Failure Resilience")
    print("=" * 60)

    topo = NetworkTopology.create(TopologyType.RANDOM, num_nodes, latency_ms=15.0, density=0.4)
    sim = SwarmSimulator(topo)
    sim.add_nodes()

    # Schedule random failures
    nodes = list(sim.nodes.keys())
    for i in range(failure_count):
        fail_time = random.uniform(5.0, 15.0)
        fail_node = random.choice(nodes)
        sim.schedule_failure(fail_time, fail_node)
        print(f"  Scheduled failure: Node {fail_node:04X} at {fail_time:.1f}s")

        # Maybe recover
        if random.random() < 0.5:
            recover_time = fail_time + random.uniform(5.0, 10.0)
            if recover_time < duration:
                sim.schedule_recovery(recover_time, fail_node)
                print(f"  Scheduled recovery: Node {fail_node:04X} at {recover_time:.1f}s")

    print(f"\nRunning simulation for {duration}s...")
    sim.run(duration)

    report = sim.get_report()
    print("\nResults:")
    print(f"  Active nodes: {report['active_nodes']}/{report['total_nodes']}")
    print(f"  Failed nodes: {report['failed_nodes']}")
    print(f"  Converged: {report['converged']}")
    print(f"  Total packets: {report['total_packets']}")

    return report


def scenario_message_delivery(num_nodes: int = 50, num_messages: int = 100, duration: float = 60.0):
    """Test message delivery across swarm"""
    print("\n" + "=" * 60)
    print("SCENARIO: Message Delivery Test")
    print("=" * 60)

    topo = NetworkTopology.create(TopologyType.GRID, num_nodes, latency_ms=20.0, loss_rate=0.05)
    sim = SwarmSimulator(topo)
    sim.add_nodes()

    # Inject random messages
    nodes = list(sim.nodes.keys())
    print(f"Injecting {num_messages} messages...")

    for i in range(num_messages):
        src = random.choice(nodes)
        dst = random.choice(nodes)
        while dst == src:
            dst = random.choice(nodes)

        msg_time = random.uniform(2.0, duration - 5.0)
        msg_data = f"Message #{i}".encode()
        sim.inject_message(msg_time, src, dst, msg_data)

    print(f"Running simulation for {duration}s...")
    sim.run(duration)

    report = sim.get_report()
    delivery_rate = report['delivered_messages'] / num_messages * 100 if num_messages > 0 else 0

    print("\nResults:")
    print(f"  Messages sent: {num_messages}")
    print(f"  Messages delivered: {report['delivered_messages']}")
    print(f"  Delivery rate: {delivery_rate:.1f}%")
    print(f"  Avg latency: {report['avg_latency_ms']:.2f}ms")
    print(f"  Dropped packets: {report['dropped_packets']}")

    return report


def scenario_partition_healing(num_nodes: int = 30, duration: float = 60.0):
    """Test network partition and healing"""
    print("\n" + "=" * 60)
    print("SCENARIO: Network Partition & Healing")
    print("=" * 60)

    # Create two clusters connected by a single link
    topo = NetworkTopology()

    # Cluster A
    for i in range(num_nodes // 2):
        node_id = 0x1000 + i
        topo.add_node(node_id)
        for j in range(i):
            topo.add_link(node_id, 0x1000 + j, latency_ms=10.0)

    # Cluster B
    for i in range(num_nodes // 2, num_nodes):
        node_id = 0x1000 + i
        topo.add_node(node_id)
        for j in range(num_nodes // 2, i):
            topo.add_link(node_id, 0x1000 + j, latency_ms=10.0)

    # Bridge link
    bridge_link = topo.add_link(0x1000 + num_nodes // 2 - 1, 0x1000 + num_nodes // 2, latency_ms=50.0)

    sim = SwarmSimulator(topo)
    sim.add_nodes()

    # Partition at t=10s
    def partition_network():
        link = topo.get_link(0x1000 + num_nodes // 2 - 1, 0x1000 + num_nodes // 2)
        if link:
            link.active = False
        link2 = topo.get_link(0x1000 + num_nodes // 2, 0x1000 + num_nodes // 2 - 1)
        if link2:
            link2.active = False
        print(f"[10.00s] Network PARTITIONED")

    # Heal at t=30s
    def heal_network():
        link = topo.get_link(0x1000 + num_nodes // 2 - 1, 0x1000 + num_nodes // 2)
        if link:
            link.active = True
        link2 = topo.get_link(0x1000 + num_nodes // 2, 0x1000 + num_nodes // 2 - 1)
        if link2:
            link2.active = True
        print(f"[30.00s] Network HEALED")

    # Schedule events
    sim.events.schedule(10.0, 'partition', callback=partition_network)
    sim.events.schedule(30.0, 'heal', callback=heal_network)

    # Inject cross-cluster messages
    for i in range(20):
        src = 0x1000 + random.randint(0, num_nodes // 2 - 1)
        dst = 0x1000 + random.randint(num_nodes // 2, num_nodes - 1)
        sim.inject_message(random.uniform(5.0, 50.0), src, dst, f"Cross-cluster #{i}".encode())

    print(f"Running simulation for {duration}s...")

    # Custom event processing to handle partition/heal
    end_time = duration
    next_tick = 0.0
    while next_tick < end_time:
        sim.events.schedule(next_tick, 'tick')
        next_tick += 0.05

    while sim.events:
        event = sim.events.pop()
        if event.time > end_time:
            break

        sim.current_time = event.time

        if event.event_type == 'partition':
            partition_network()
        elif event.event_type == 'heal':
            heal_network()
        else:
            sim._process_event(event)

    sim._finalize_metrics()

    report = sim.get_report()
    print("\nResults:")
    print(f"  Total nodes: {report['total_nodes']}")
    print(f"  Messages delivered: {report['delivered_messages']}/20")
    print(f"  Converged after healing: {report['converged']}")

    return report


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='NERT Swarm Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run basic convergence test
  %(prog)s --scenario convergence --nodes 20

  # Test node failure resilience
  %(prog)s --scenario failure --nodes 30 --failures 5

  # Test message delivery
  %(prog)s --scenario delivery --nodes 50 --messages 200

  # Test network partition
  %(prog)s --scenario partition --nodes 40

  # Run all scenarios
  %(prog)s --scenario all
        """
    )

    parser.add_argument('--scenario', default='convergence',
                        choices=['convergence', 'failure', 'delivery', 'partition', 'all'],
                        help='Scenario to run')
    parser.add_argument('--nodes', type=int, default=20,
                        help='Number of nodes (default: 20)')
    parser.add_argument('--duration', type=float, default=30.0,
                        help='Simulation duration in seconds (default: 30)')
    parser.add_argument('--failures', type=int, default=3,
                        help='Number of node failures for failure scenario (default: 3)')
    parser.add_argument('--messages', type=int, default=50,
                        help='Number of messages for delivery scenario (default: 50)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed for reproducibility')
    parser.add_argument('--output', type=str, default=None,
                        help='Output file for JSON report')

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print("=" * 60)
    print("   NERT Swarm Simulator")
    print("   NanOS Project - Security Swarm Testing")
    print("=" * 60)

    results = []

    if args.scenario in ['convergence', 'all']:
        report = scenario_basic_convergence(args.nodes, args.duration)
        results.append(('convergence', report))

    if args.scenario in ['failure', 'all']:
        report = scenario_node_failure(args.nodes, args.failures, args.duration)
        results.append(('failure', report))

    if args.scenario in ['delivery', 'all']:
        report = scenario_message_delivery(args.nodes, args.messages, args.duration)
        results.append(('delivery', report))

    if args.scenario in ['partition', 'all']:
        report = scenario_partition_healing(args.nodes, args.duration)
        results.append(('partition', report))

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(dict(results), f, indent=2)
        print(f"\nResults written to {args.output}")

    print("\n" + "=" * 60)
    print("Simulation complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
