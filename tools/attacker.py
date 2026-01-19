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
from typing import List, Optional

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
        """
    )

    parser.add_argument('--multicast', default='239.255.0.1',
                        help='Multicast group (default: 239.255.0.1)')
    parser.add_argument('--port', type=int, default=5555,
                        help='Port (default: 5555)')
    parser.add_argument('--attacker-id', type=lambda x: int(x, 16), default=0xDEAD,
                        help='Attacker node ID in hex (default: DEAD)')

    parser.add_argument('--attack', required=True,
                        choices=['replay', 'fuzzing', 'fake-queen', 'dos', 'all'],
                        help='Attack type to execute')

    parser.add_argument('--capture', type=float, default=2.0,
                        help='Packet capture duration in seconds (default: 2)')
    parser.add_argument('--count', type=int, default=20,
                        help='Number of packets/iterations (default: 20)')
    parser.add_argument('--duration', type=float, default=10.0,
                        help='Attack duration in seconds (default: 10)')
    parser.add_argument('--rate', type=int, default=100,
                        help='DoS rate in packets/sec (default: 100)')

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

        if args.attack == 'all':
            print("\n[INFO] All attacks completed")

    except KeyboardInterrupt:
        print("\n[INFO] Attack interrupted by user")

    finally:
        attacker.close()
        print("\n[INFO] Attacker shutdown complete")


if __name__ == '__main__':
    main()
