#!/usr/bin/env python3
"""
NanOS Swarm Dashboard - Orchestration & Monitoring
Real-time monitoring and job orchestration for NanOS swarm

Usage:
    python nanos_dashboard.py [--port 8080] [--log-dir /tmp]

Then open http://localhost:8080 in your browser.
"""

import os
import re
import json
import time
import glob
import struct
import socket
import argparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import parse_qs, urlparse

# NanOS Protocol Constants
NANOS_MAGIC = 0x4E414E4F
MULTICAST_GROUP = '230.0.0.1'
MULTICAST_PORT = 1234

# Pheromone Types
PHEROMONE_JOB_START = 0x50
PHEROMONE_JOB_CHUNK = 0x51
PHEROMONE_JOB_DONE = 0x52
PHEROMONE_JOB_RESULT = 0x53

# Job Types
JOB_PRIME_SEARCH = 0x01
JOB_MONTE_CARLO_PI = 0x02
JOB_HASH_SEARCH = 0x03
JOB_REDUCE_SUM = 0x04

# Maze Exploration
PHEROMONE_MAZE_INIT = 0x70
PHEROMONE_MAZE_DISCOVER = 0x71
PHEROMONE_MAZE_SOLVED = 0x73
MAZE_SIZE = 16

# Terrain Exploration
PHEROMONE_TERRAIN_INIT = 0x80
PHEROMONE_TERRAIN_REPORT = 0x81
PHEROMONE_TERRAIN_THREAT = 0x82
PHEROMONE_TERRAIN_MOVE = 0x84
PHEROMONE_TERRAIN_STRATEGY = 0x85
TERRAIN_SIZE = 32

# Terrain types
TERRAIN_OPEN = 0
TERRAIN_FOREST = 1
TERRAIN_URBAN = 2
TERRAIN_WATER = 3
TERRAIN_ROCKY = 4
TERRAIN_MARSH = 5
TERRAIN_ROAD = 6
TERRAIN_IMPASSABLE = 7

# Terrain strategy commands
TERRAIN_CMD_HOLD = 0
TERRAIN_CMD_REGROUP = 1
TERRAIN_CMD_SPREAD = 2
TERRAIN_CMD_PATROL = 3
TERRAIN_CMD_RETREAT = 4
TERRAIN_CMD_ADVANCE = 5

# Global state
swarm_state = {
    'nodes': {},
    'events': [],
    'last_update': 0,
    'kv_operations': 0,
    'tasks_completed': 0,
    'alarms': 0,
    'sensor_readings': [],
    'jobs': {},
    'job_counter': 0,
    # Advanced dashboard fields
    'queen_id': None,
    'packets_per_second': 0,
    'active_alerts': 0,
    'sector_activity': [0] * 8,
    'detections': [],
    'correlations': [],
    # Maze exploration
    'maze': {
        'active': False,
        'solved': False,
        'started_at': 0,  # Timestamp when maze was started
        'grid': [[0] * MAZE_SIZE for _ in range(MAZE_SIZE)],
        'explorers': {},  # node_id -> {x, y, cells_explored}
        'start': [1, 1],
        'goal': [14, 14],
        'solution_path': [],
        'cells_explored': 0
    },
    # Terrain exploration
    'terrain': {
        'active': False,
        'seed': 0,
        'started_at': 0,
        'grid': [[{'base': 0, 'meta': 0} for _ in range(TERRAIN_SIZE)] for _ in range(TERRAIN_SIZE)],
        'explorers': {},  # node_id -> {x, y, heading, cells_explored, role, sensor_range}
        'threats': [],    # [{x, y, level, detect_types, confidence}]
        'objectives': [], # [{x, y, type, status}]
        'cells_explored': 0,
        'current_strategy': TERRAIN_CMD_SPREAD
    }
}
state_lock = threading.Lock()
last_packet_count = 0
last_packet_time = time.time()

# Maze simulation
maze_sim_thread = None
maze_sim_running = False

# UDP socket for multicast
udp_socket = None

def init_multicast():
    """Initialize UDP multicast socket for swarm communication"""
    global udp_socket
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        print(f"[UDP] Multicast initialized on {MULTICAST_GROUP}:{MULTICAST_PORT}")
        return True
    except Exception as e:
        print(f"[UDP] Failed to initialize multicast: {e}")
        return False

# =============================================================================
# Maze Simulation - Simulates swarm exploration when no real nodes are running
# =============================================================================

def maze_sim_worker():
    """Background thread that simulates maze exploration"""
    global maze_sim_running
    import random as rnd

    # Create simulated explorers
    num_explorers = 4
    explorers = []

    with state_lock:
        if not swarm_state['maze']['active']:
            return
        start = swarm_state['maze']['start']
        goal = swarm_state['maze']['goal']
        grid = swarm_state['maze']['grid']

    # Initialize explorers at start position
    for i in range(num_explorers):
        explorer_id = f"SIM{i:02X}"
        explorers.append({
            'id': explorer_id,
            'x': start[0],
            'y': start[1],
            'path': [(start[0], start[1])],  # Breadcrumb trail
            'visited': set(),
            'stuck': 0
        })

    directions = [(0, -1), (1, 0), (0, 1), (-1, 0)]  # N, E, S, W
    solution_found = False

    while maze_sim_running and not solution_found:
        time.sleep(0.15)  # 150ms per move for visible animation

        with state_lock:
            if not swarm_state['maze']['active']:
                break
            grid = swarm_state['maze']['grid']
            goal = swarm_state['maze']['goal']

        for exp in explorers:
            if solution_found:
                break

            x, y = exp['x'], exp['y']
            exp['visited'].add((x, y))

            # Check if reached goal
            if x == goal[0] and y == goal[1]:
                solution_found = True
                with state_lock:
                    swarm_state['maze']['solved'] = True
                    swarm_state['maze']['solution_path'] = exp['path'].copy()
                    # Mark solution path
                    for px, py in exp['path']:
                        if grid[py][px] not in [0x10, 0x20]:  # Not start/goal
                            swarm_state['maze']['grid'][py][px] = 0x02  # PATH
                    swarm_state['events'].append({
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'type': 'maze',
                        'message': f'SOLVED by {exp["id"]}! Path length: {len(exp["path"])}'
                    })
                break

            # Find valid moves (not walls, prefer unexplored)
            valid_moves = []
            unexplored_moves = []

            for dx, dy in directions:
                nx, ny = x + dx, y + dy
                if 0 <= nx < MAZE_SIZE and 0 <= ny < MAZE_SIZE:
                    cell = grid[ny][nx]
                    if cell != 0xFF:  # Not a wall
                        # Check if another explorer is there
                        occupied = False
                        for other in explorers:
                            if other['id'] != exp['id'] and other['x'] == nx and other['y'] == ny:
                                occupied = True
                                break
                        if not occupied:
                            valid_moves.append((nx, ny))
                            if (nx, ny) not in exp['visited']:
                                unexplored_moves.append((nx, ny))

            # Choose move: prefer unexplored, else backtrack
            if unexplored_moves:
                # Prioritize moves toward goal
                def goal_dist(pos):
                    return abs(pos[0] - goal[0]) + abs(pos[1] - goal[1])
                unexplored_moves.sort(key=goal_dist)
                # Add some randomness to avoid all explorers taking same path
                if len(unexplored_moves) > 1 and rnd.random() < 0.3:
                    nx, ny = rnd.choice(unexplored_moves)
                else:
                    nx, ny = unexplored_moves[0]
                exp['path'].append((nx, ny))
                exp['stuck'] = 0
            elif len(exp['path']) > 1:
                # Backtrack
                exp['path'].pop()
                nx, ny = exp['path'][-1]
                exp['stuck'] += 1
            else:
                # Stuck at start, pick random valid move
                if valid_moves:
                    nx, ny = rnd.choice(valid_moves)
                    exp['path'].append((nx, ny))
                else:
                    continue

            exp['x'], exp['y'] = nx, ny

            # Mark cell as explored
            with state_lock:
                if swarm_state['maze']['grid'][ny][nx] not in [0x10, 0x20, 0x02]:
                    swarm_state['maze']['grid'][ny][nx] = 0x01  # EXPLORED
                swarm_state['maze']['cells_explored'] = sum(
                    1 for row in swarm_state['maze']['grid']
                    for cell in row if cell in [0x01, 0x02]
                )

        # Update explorer positions in state
        with state_lock:
            swarm_state['maze']['explorers'] = {
                exp['id']: {'x': exp['x'], 'y': exp['y'], 'last_seen': time.time()}
                for exp in explorers
            }

    maze_sim_running = False

def start_maze_simulation():
    """Start the maze simulation thread"""
    global maze_sim_thread, maze_sim_running
    stop_maze_simulation()  # Stop any existing simulation
    maze_sim_running = True
    maze_sim_thread = threading.Thread(target=maze_sim_worker, daemon=True)
    maze_sim_thread.start()

def stop_maze_simulation():
    """Stop the maze simulation thread"""
    global maze_sim_running
    maze_sim_running = False

def build_pheromone(ptype, payload_data):
    """Build a 64-byte NanOS pheromone packet"""
    # Header (16 bytes)
    magic = NANOS_MAGIC
    node_id = 0xDA5B0A1D  # Dashboard identifier
    ttl = 15
    flags = 0
    version = 3
    seq = int(time.time() * 1000) & 0xFFFFFFFF

    header = struct.pack('<IIBBBBI', magic, node_id, ptype, ttl, flags, version, seq)

    # Routing (8 bytes)
    dest_id = 0  # Broadcast
    distance = 255
    hop_count = 0
    via_lo = 0
    via_hi = 0
    routing = struct.pack('<IBBBB', dest_id, distance, hop_count, via_lo, via_hi)

    # HMAC (8 bytes) - zeros for non-critical
    hmac = b'\x00' * 8

    # Payload (32 bytes)
    payload = payload_data[:32].ljust(32, b'\x00')

    return header + routing + hmac + payload

def send_pheromone(pkt):
    """Send a raw pheromone packet to the swarm via multicast"""
    eth_frame = build_eth_frame(pkt)
    if udp_socket:
        try:
            udp_socket.sendto(eth_frame, (MULTICAST_GROUP, MULTICAST_PORT))
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send pheromone: {e}")
            return False
    return False

# ============================================================================
# ARM Compact Packet Support (24-byte packets for ARM Cortex-M3 nodes)
# ============================================================================

ARM_MAGIC = 0xAA
ARM_PKT_SIZE = 24

def build_arm_pheromone(ptype, payload_data):
    """Build a 24-byte ARM-compatible compact pheromone packet"""
    # ARM packet structure:
    # magic(1) + node_id(2) + type(1) + ttl_flags(1) + seq(1) + dest_id(2) +
    # dist_hop(1) + payload(8) + hmac(4) + reserved(3) = 24 bytes
    magic = ARM_MAGIC
    node_id = 0xDA5B  # Dashboard ID (truncated)
    ttl_flags = (15 << 4) | 0  # TTL=15, flags=0
    seq = int(time.time()) & 0xFF
    dest_id = 0x0000  # Broadcast
    dist_hop = 0

    # Pack header (9 bytes)
    header = struct.pack('<BHBBHBB', magic, node_id, ptype, ttl_flags, seq, dest_id, dist_hop)

    # Payload (8 bytes)
    payload = payload_data[:8].ljust(8, b'\x00')

    # HMAC (4 bytes) - zeros
    hmac = b'\x00' * 4

    # Reserved (3 bytes)
    reserved = b'\x00' * 3

    return header + payload + hmac + reserved

def send_arm_pheromone(pkt):
    """Send a 24-byte ARM pheromone packet to the swarm"""
    eth_frame = build_eth_frame(pkt)
    if udp_socket:
        try:
            udp_socket.sendto(eth_frame, (MULTICAST_GROUP, MULTICAST_PORT))
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send ARM pheromone: {e}")
            return False
    return False

def send_arm_maze_init(start_x=1, start_y=1, goal_x=14, goal_y=14):
    """Send MAZE_INIT to ARM nodes"""
    # ARM maze init payload: start_x(1), start_y(1), goal_x(1), goal_y(1)
    payload = bytes([start_x, start_y, goal_x, goal_y, 0, 0, 0, 0])
    pkt = build_arm_pheromone(PHEROMONE_MAZE_INIT, payload)
    send_arm_pheromone(pkt)
    print(f"[ARM] Sent MAZE_INIT start=({start_x},{start_y}) goal=({goal_x},{goal_y})")
    return True

def send_arm_terrain_init(start_x=16, start_y=16):
    """Send TERRAIN_INIT to ARM nodes"""
    # ARM terrain init payload: start_x(1), start_y(1)
    payload = bytes([start_x, start_y, 0, 0, 0, 0, 0, 0])
    pkt = build_arm_pheromone(PHEROMONE_TERRAIN_INIT, payload)
    send_arm_pheromone(pkt)
    print(f"[ARM] Sent TERRAIN_INIT start=({start_x},{start_y})")
    return True

# ============================================================================
# Terrain Generation (mirrors kernel algorithm for dashboard visualization)
# ============================================================================

def terrain_hash(seed, x, y):
    """Deterministic hash from seed and position (mirrors kernel implementation)"""
    h = seed ^ (x * 374761393) ^ (y * 668265263)
    h = ((h ^ (h >> 13)) * 1274126177) & 0xFFFFFFFF
    return h ^ (h >> 16)

def terrain_from_elevation(elevation, hash_val):
    """Determine terrain type from elevation and hash (mirrors kernel)"""
    if elevation <= 1:
        return TERRAIN_MARSH if (hash_val & 0x03) == 0 else TERRAIN_OPEN
    elif elevation <= 2:
        return TERRAIN_WATER if (hash_val & 0x07) == 0 else TERRAIN_OPEN
    elif elevation <= 3:
        if (hash_val & 0x03) == 0:
            return TERRAIN_ROAD
        elif (hash_val & 0x07) < 2:
            return TERRAIN_FOREST
        return TERRAIN_OPEN
    elif elevation <= 4:
        if (hash_val & 0x07) < 2:
            return TERRAIN_URBAN
        elif (hash_val & 0x07) < 4:
            return TERRAIN_FOREST
        return TERRAIN_OPEN
    elif elevation <= 5:
        if (hash_val & 0x07) < 3:
            return TERRAIN_ROCKY
        elif (hash_val & 0x07) < 5:
            return TERRAIN_FOREST
        return TERRAIN_OPEN
    else:
        return TERRAIN_ROCKY if (hash_val & 0x03) < 2 else TERRAIN_IMPASSABLE

# Default cover/passability tables (mirrors kernel)
TERRAIN_DEFAULT_COVER = [0, 2, 3, 0, 1, 0, 0, 3]
TERRAIN_DEFAULT_PASS = [3, 2, 3, 1, 2, 1, 3, 0]

def terrain_generate_cell(seed, x, y, explored=False):
    """Generate a single terrain cell (mirrors kernel implementation)"""
    h = terrain_hash(seed, x, y)
    elevation = h & 0x07
    terrain_type = terrain_from_elevation(elevation, h >> 8)
    cover = TERRAIN_DEFAULT_COVER[terrain_type]
    passability = TERRAIN_DEFAULT_PASS[terrain_type]

    base = terrain_type | (elevation << 3) | (cover << 6)
    # meta: THREAT_UNKNOWN, passability, explored flag only if specified
    meta = (1 << 5) | (passability << 1) | (0x01 if explored else 0x00)
    return {'base': base, 'meta': meta}

def terrain_generate_grid(seed):
    """Generate full terrain grid from seed (all cells start unexplored)"""
    grid = [[terrain_generate_cell(seed, x, y, explored=False) for x in range(TERRAIN_SIZE)]
            for y in range(TERRAIN_SIZE)]
    return grid

def terrain_reveal_around(grid, seed, cx, cy, sensor_range):
    """Reveal cells around position based on sensor range (fog of war)"""
    revealed = 0
    for dy in range(-sensor_range, sensor_range + 1):
        for dx in range(-sensor_range, sensor_range + 1):
            nx, ny = cx + dx, cy + dy
            if nx < 0 or nx >= TERRAIN_SIZE or ny < 0 or ny >= TERRAIN_SIZE:
                continue
            # Manhattan distance check
            if abs(dx) + abs(dy) > sensor_range:
                continue
            # If not explored, generate and mark as explored
            if not (grid[ny][nx]['meta'] & 0x01):
                cell = terrain_generate_cell(seed, nx, ny, explored=True)
                grid[ny][nx] = cell
                revealed += 1
    return revealed

def terrain_get_type(cell):
    """Extract terrain type from cell"""
    return cell['base'] & 0x07

def terrain_get_elevation(cell):
    """Extract elevation from cell"""
    return (cell['base'] >> 3) & 0x07

def terrain_get_cover(cell):
    """Extract cover from cell"""
    return (cell['base'] >> 6) & 0x03

def terrain_get_threat(cell):
    """Extract threat level from cell"""
    return (cell['meta'] >> 5) & 0x07

def terrain_is_explored(cell):
    """Check if cell is explored"""
    return cell['meta'] & 0x01

def send_terrain_init(seed, start_x, start_y, difficulty=1):
    """Send TERRAIN_INIT pheromone to swarm"""
    # Payload: seed(4), difficulty(1), start_x(1), start_y(1), terrain_bias(1), objectives(24)
    payload = bytearray(32)
    struct.pack_into('<I', payload, 0, seed)
    payload[4] = difficulty
    payload[5] = start_x
    payload[6] = start_y
    payload[7] = 0  # terrain_bias unused

    pkt = build_pheromone(PHEROMONE_TERRAIN_INIT, bytes(payload))
    send_pheromone(pkt)
    print(f"[TERRAIN] Sent TERRAIN_INIT seed={seed:08X} start=({start_x},{start_y})")
    return seed

def send_terrain_strategy(command, target_x=16, target_y=16):
    """Send TERRAIN_STRATEGY pheromone to swarm"""
    # Payload: command(1), target_x(1), target_y(1), formation(1), issuer_id(4), waypoints(8)
    payload = bytearray(32)
    payload[0] = command
    payload[1] = target_x
    payload[2] = target_y
    payload[3] = 0  # formation unused
    struct.pack_into('<I', payload, 4, 0xDA5B0AD0)  # Dashboard issuer ID

    pkt = build_pheromone(PHEROMONE_TERRAIN_STRATEGY, bytes(payload))
    send_pheromone(pkt)
    print(f"[TERRAIN] Sent strategy cmd={command} target=({target_x},{target_y})")

def send_job_start(job_type, param1, param2, num_chunks):
    """Send JOB_START pheromone to swarm"""
    global swarm_state

    with state_lock:
        job_id = swarm_state['job_counter']
        swarm_state['job_counter'] += 1

        # Create job record
        swarm_state['jobs'][job_id] = {
            'id': job_id,
            'type': job_type,
            'type_name': get_job_type_name(job_type),
            'param1': param1,
            'param2': param2,
            'chunks_total': num_chunks,
            'chunks_done': 0,
            'result': 0,
            'status': 'running',
            'started': datetime.now().isoformat(),
            'workers': []
        }

    # Build payload: job_id(4) + job_type(1) + param1(4) + param2(4) + num_chunks(4)
    payload = struct.pack('<IBIII', job_id, job_type, param1, param2, num_chunks)

    pkt = build_pheromone(PHEROMONE_JOB_START, payload)

    # Wrap in Ethernet frame for QEMU multicast
    eth_frame = build_eth_frame(pkt)

    if udp_socket:
        try:
            udp_socket.sendto(eth_frame, (MULTICAST_GROUP, MULTICAST_PORT))
            print(f"[JOB] Sent JOB_START id={job_id} type={job_type} range={param1}-{param2}")
            return job_id
        except Exception as e:
            print(f"[JOB] Failed to send: {e}")

    return job_id

def build_eth_frame(pkt):
    """Wrap pheromone in Ethernet frame"""
    # Broadcast destination MAC
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    # Dashboard source MAC
    src_mac = b'\x52\x54\x00\xDA\x5B\x0A'
    # EtherType (custom)
    ethertype = b'\x4E\x41'  # "NA" for NanOS

    return dst_mac + src_mac + ethertype + pkt

def get_job_type_name(job_type):
    """Get human-readable job type name"""
    names = {
        JOB_PRIME_SEARCH: 'Prime Search',
        JOB_MONTE_CARLO_PI: 'Monte Carlo Pi',
        JOB_HASH_SEARCH: 'Hash Search',
        JOB_REDUCE_SUM: 'Parallel Sum'
    }
    return names.get(job_type, f'Unknown ({job_type})')

def parse_metrics_line(line):
    """Parse a [METRICS] log line into a dict (x86 format)"""
    match = re.search(r'\[METRICS\]\s+t=(\d+)s\s+node=0x([0-9A-Fa-f]+)\s+role=(\w+)\s+neighbors=(\d+)\s+rx=(\d+)\s+tx=(\d+)\s+queen=0x([0-9A-Fa-f]+)\s+dist=(\d+)', line)
    if match:
        return {
            'uptime': int(match.group(1)),
            'node_id': match.group(2).upper(),
            'role': match.group(3),
            'neighbors': int(match.group(4)),
            'rx': int(match.group(5)),
            'tx': int(match.group(6)),
            'queen_id': match.group(7).upper(),
            'distance': int(match.group(8)),
            'last_seen': time.time(),
            'platform': 'x86'
        }
    return None

def parse_arm_status_line(line):
    """Parse a [STATUS] log line into a dict (ARM format)"""
    # Format: [STATUS] Node 0x00000001 [EXPLORER] neighbors=2 rx=57 tx=30 ticks=3000
    match = re.search(r'\[STATUS\]\s+Node\s+0x([0-9A-Fa-f]+)\s+\[(\w+)\]\s+neighbors=(\d+)\s+rx=(\d+)\s+tx=(\d+)\s+ticks=(\d+)', line)
    if match:
        ticks = int(match.group(6))
        return {
            'uptime': ticks // 100,  # Convert ticks to seconds (100 ticks/sec)
            'node_id': match.group(1).upper(),
            'role': match.group(2),
            'neighbors': int(match.group(3)),
            'rx': int(match.group(4)),
            'tx': int(match.group(5)),
            'queen_id': '00000000',
            'distance': 15,
            'last_seen': time.time(),
            'platform': 'arm'
        }
    return None

def parse_job_line(line):
    """Parse job-related log lines"""
    # [JOB] Chunk 0 done: found 25 primes
    chunk_match = re.search(r'\[JOB\]\s+Chunk\s+(\d+)\s+done.*?(\d+)', line)
    if chunk_match:
        return {
            'type': 'chunk_done',
            'chunk_id': int(chunk_match.group(1)),
            'result': int(chunk_match.group(2))
        }

    # [JOB] Job 5 complete: result=12345
    complete_match = re.search(r'\[JOB\]\s+Job\s+(\d+)\s+complete.*?result=(\d+)', line)
    if complete_match:
        return {
            'type': 'job_complete',
            'job_id': int(complete_match.group(1)),
            'result': int(complete_match.group(2))
        }

    return None

def parse_event_line(line, node_file):
    """Parse various event lines"""
    events = []
    node_id = re.search(r'node_(\d+)', node_file)
    node_num = node_id.group(1) if node_id else '?'

    if 'ALARM' in line:
        events.append({'type': 'alarm', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'ELECTION' in line or 'CORONATION' in line or 'NEW QUEEN' in line:
        events.append({'type': 'election', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'KV' in line:
        events.append({'type': 'kv', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'TASK' in line or 'RESULT' in line:
        events.append({'type': 'task', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'SENSOR' in line or 'AGGREGATE' in line:
        events.append({'type': 'sensor', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'JOB' in line or 'CHUNK' in line:
        events.append({'type': 'job', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})
    if 'TERRAIN' in line:
        events.append({'type': 'terrain', 'node': node_num, 'time': datetime.now().isoformat(), 'message': line.strip()})

    return events

def monitor_logs(log_dir):
    """Background thread to monitor log files"""
    global swarm_state, last_packet_count, last_packet_time

    file_positions = {}

    while True:
        try:
            # Include both x86 and ARM log files
            log_files = glob.glob(os.path.join(log_dir, 'nanos_node_*.log'))
            log_files += glob.glob(os.path.join(log_dir, 'nanos_arm_*.log'))

            for log_file in log_files:
                try:
                    if log_file not in file_positions:
                        file_positions[log_file] = 0

                    with open(log_file, 'r', errors='ignore') as f:
                        f.seek(file_positions[log_file])
                        new_lines = f.readlines()
                        file_positions[log_file] = f.tell()

                    with state_lock:
                        for line in new_lines:
                            # Try x86 format first, then ARM format
                            metrics = parse_metrics_line(line)
                            if not metrics:
                                metrics = parse_arm_status_line(line)
                            if metrics:
                                swarm_state['nodes'][metrics['node_id']] = metrics
                                swarm_state['last_update'] = time.time()

                                # Track queen
                                if metrics['role'] == 'QUEEN':
                                    swarm_state['queen_id'] = metrics['node_id']
                                elif metrics.get('queen_id') and metrics['queen_id'] != '00000000':
                                    swarm_state['queen_id'] = metrics['queen_id']

                            # Parse detection events
                            if '[DETECT]' in line:
                                det_match = re.search(r'sector=(\d+)', line)
                                if det_match:
                                    sector = int(det_match.group(1)) % 8
                                    swarm_state['sector_activity'][sector] += 1

                                alert_match = re.search(r'>>\s*(ANOMALY|CONTACT|PROBABLE|CONFIRMED|CRITICAL)', line)
                                if alert_match and alert_match.group(1) in ['CONFIRMED', 'CRITICAL']:
                                    swarm_state['active_alerts'] += 1

                            # Parse maze events
                            if '[MAZE]' in line:
                                # Parse explorer position
                                pos_match = re.search(r'node=0x([0-9A-Fa-f]+).*pos=(\d+),(\d+)', line)
                                if pos_match:
                                    node_id = pos_match.group(1).upper()
                                    x, y = int(pos_match.group(2)), int(pos_match.group(3))
                                    if node_id not in swarm_state['maze']['explorers']:
                                        swarm_state['maze']['explorers'][node_id] = {}
                                    swarm_state['maze']['explorers'][node_id]['x'] = x
                                    swarm_state['maze']['explorers'][node_id]['y'] = y
                                    swarm_state['maze']['explorers'][node_id]['last_seen'] = time.time()

                                # Parse solved event - only if maze is active AND was started recently
                                # (prevents old log content from triggering solved)
                                if ('SOLVED' in line and swarm_state['maze']['active'] and
                                    time.time() - swarm_state['maze'].get('started_at', 0) > 2):
                                    swarm_state['maze']['solved'] = True
                                    path_match = re.search(r'path_len=(\d+)', line)
                                    if path_match:
                                        swarm_state['maze']['cells_explored'] = int(path_match.group(1))

                            # Parse terrain events
                            if '[TERRAIN]' in line:
                                # Parse explorer position: node=0x... pos=X,Y
                                pos_match = re.search(r'node=0x([0-9A-Fa-f]+).*pos=(\d+),(\d+)', line)
                                if pos_match:
                                    node_id = pos_match.group(1).upper()
                                    x, y = int(pos_match.group(2)), int(pos_match.group(3))
                                    if node_id not in swarm_state['terrain']['explorers']:
                                        swarm_state['terrain']['explorers'][node_id] = {
                                            'x': x, 'y': y, 'cells_explored': 0,
                                            'heading': 0, 'role': 'WORKER', 'sensor_range': 3
                                        }
                                    else:
                                        swarm_state['terrain']['explorers'][node_id]['x'] = x
                                        swarm_state['terrain']['explorers'][node_id]['y'] = y
                                    swarm_state['terrain']['explorers'][node_id]['last_seen'] = time.time()

                                    # Fog of war: reveal cells around explorer
                                    if swarm_state['terrain']['active'] and swarm_state['terrain']['seed']:
                                        sensor_range = swarm_state['terrain']['explorers'][node_id].get('sensor_range', 3)
                                        terrain_reveal_around(
                                            swarm_state['terrain']['grid'],
                                            swarm_state['terrain']['seed'],
                                            x, y, sensor_range
                                        )

                                # Parse explorer details: heading=N cells=X role=Y
                                heading_match = re.search(r'heading=(\d+)', line)
                                cells_match = re.search(r'cells=(\d+)', line)
                                if heading_match and pos_match:
                                    node_id = pos_match.group(1).upper()
                                    if node_id in swarm_state['terrain']['explorers']:
                                        swarm_state['terrain']['explorers'][node_id]['heading'] = int(heading_match.group(1))
                                if cells_match and pos_match:
                                    node_id = pos_match.group(1).upper()
                                    if node_id in swarm_state['terrain']['explorers']:
                                        swarm_state['terrain']['explorers'][node_id]['cells_explored'] = int(cells_match.group(1))

                                # Parse threat events: Threat at X,Y level=L
                                threat_match = re.search(r'Threat.*at\s*(\d+),(\d+)\s*level=(\d+)', line)
                                if threat_match:
                                    tx, ty, level = int(threat_match.group(1)), int(threat_match.group(2)), int(threat_match.group(3))
                                    # Update threat in state
                                    found = False
                                    for threat in swarm_state['terrain']['threats']:
                                        if threat['x'] == tx and threat['y'] == ty:
                                            threat['level'] = level
                                            threat['last_seen'] = time.time()
                                            found = True
                                            break
                                    if not found and len(swarm_state['terrain']['threats']) < 16:
                                        swarm_state['terrain']['threats'].append({
                                            'x': tx, 'y': ty, 'level': level,
                                            'detect_types': 0, 'confidence': 50,
                                            'last_seen': time.time()
                                        })

                                # Update cells explored count (count actual explored cells in grid)
                                explored_count = sum(
                                    1 for row in swarm_state['terrain']['grid']
                                    for cell in row if cell['meta'] & 0x01
                                )
                                swarm_state['terrain']['cells_explored'] = explored_count

                            job_info = parse_job_line(line)
                            if job_info:
                                if job_info['type'] == 'chunk_done':
                                    # Update job progress
                                    for jid, job in swarm_state['jobs'].items():
                                        if job['status'] == 'running':
                                            job['chunks_done'] += 1
                                            job['result'] += job_info['result']
                                elif job_info['type'] == 'job_complete':
                                    jid = job_info['job_id']
                                    if jid in swarm_state['jobs']:
                                        swarm_state['jobs'][jid]['status'] = 'completed'
                                        swarm_state['jobs'][jid]['result'] = job_info['result']

                            events = parse_event_line(line, log_file)
                            for event in events:
                                swarm_state['events'].append(event)
                                if len(swarm_state['events']) > 100:
                                    swarm_state['events'] = swarm_state['events'][-100:]

                                if event['type'] == 'alarm':
                                    swarm_state['alarms'] += 1
                                elif event['type'] == 'kv':
                                    swarm_state['kv_operations'] += 1
                                elif event['type'] == 'task' and 'completed' in event['message'].lower():
                                    swarm_state['tasks_completed'] += 1

                except Exception as e:
                    print(f"Error reading {log_file}: {e}")

            # Calculate packets per second
            with state_lock:
                total_rx = sum(n.get('rx', 0) for n in swarm_state['nodes'].values())
                now = time.time()
                if now - last_packet_time >= 1:
                    swarm_state['packets_per_second'] = total_rx - last_packet_count
                    last_packet_count = total_rx
                    last_packet_time = now

                # Decay sector activity
                swarm_state['sector_activity'] = [max(0, s - 1) for s in swarm_state['sector_activity']]

                # Decay active alerts slowly
                if swarm_state['active_alerts'] > 0:
                    swarm_state['active_alerts'] = max(0, swarm_state['active_alerts'] - 1)

                # Clean up stale nodes
                now = time.time()
                stale = [nid for nid, data in swarm_state['nodes'].items() if now - data['last_seen'] > 30]
                for nid in stale:
                    del swarm_state['nodes'][nid]

        except Exception as e:
            print(f"Monitor error: {e}")

        time.sleep(1)

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler with API endpoints"""

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == '/api/state':
            self.send_api_response()
        elif parsed.path == '/api/jobs':
            self.send_jobs_response()
        elif parsed.path == '/' or parsed.path == '/index.html':
            self.send_dashboard()
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else ''

        if parsed.path == '/api/job/submit':
            self.handle_job_submit(body)
        elif parsed.path == '/api/job/cancel':
            self.handle_job_cancel(body)
        elif parsed.path == '/api/inject/alarm':
            self.handle_inject_alarm()
        elif parsed.path == '/api/inject/election':
            self.handle_inject_election()
        elif parsed.path == '/api/inject/data':
            self.handle_inject_data(body)
        elif parsed.path == '/api/inject/threat':
            self.handle_inject_threat(body)
        elif parsed.path == '/api/inject/die':
            self.handle_inject_die()
        elif parsed.path == '/api/maze/start':
            self.handle_maze_start(body)
        elif parsed.path == '/api/maze/reset':
            self.handle_maze_reset()
        elif parsed.path == '/api/maze/simulate':
            self.handle_maze_simulate()
        elif parsed.path == '/api/terrain/start':
            self.handle_terrain_start(body)
        elif parsed.path == '/api/terrain/reset':
            self.handle_terrain_reset()
        elif parsed.path == '/api/terrain/strategy':
            self.handle_terrain_strategy(body)
        elif parsed.path == '/api/terrain/objective':
            self.handle_terrain_objective(body)
        # ARM-specific endpoints
        elif parsed.path == '/api/arm/maze/start':
            self.handle_arm_maze_start(body)
        elif parsed.path == '/api/arm/terrain/start':
            self.handle_arm_terrain_start(body)
        elif parsed.path == '/api/arm/kill':
            self.handle_arm_kill()
        else:
            self.send_error(404)

    def handle_inject_alarm(self):
        """Inject an alarm pheromone"""
        try:
            payload = struct.pack('<I28s', 0xA1A1A101, b'Dashboard triggered alarm')
            pkt = build_pheromone(0x03, payload)  # PHEROMONE_ALARM
            send_pheromone(pkt)
            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'alarm',
                    'message': 'Injected ALARM from dashboard'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_inject_election(self):
        """Inject an election pheromone to force new election"""
        try:
            payload = struct.pack('<II24s', 0xFFFFFFFF, 100, b'Force election')
            pkt = build_pheromone(0x05, payload)  # PHEROMONE_ELECTION
            send_pheromone(pkt)
            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'election',
                    'message': 'Forced queen election from dashboard'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_inject_data(self, body):
        """Inject a data pheromone"""
        try:
            data = json.loads(body) if body else {}
            message = data.get('message', 'Hello from Dashboard')[:31]
            payload = message.encode('utf-8').ljust(32, b'\x00')
            pkt = build_pheromone(0x02, payload)  # PHEROMONE_DATA
            send_pheromone(pkt)
            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'data',
                    'message': f'Sent DATA: {message}'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_inject_threat(self, body):
        """Inject a tactical detection pheromone"""
        try:
            data = json.loads(body) if body else {}
            sector = data.get('sector', 0) % 8
            det_type = data.get('type', 1)  # DETECT_MOTION
            intensity = data.get('intensity', 150)

            # Build detection payload
            payload = struct.pack('<BBBBI2h',
                det_type, 75, sector, intensity,
                int(time.time()) & 0xFFFFFFFF,
                0, 0)  # pos_x, pos_y
            pkt = build_pheromone(0x60, payload)  # PHEROMONE_DETECT
            send_pheromone(pkt)

            with state_lock:
                swarm_state['sector_activity'][sector] += 5
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'detection',
                    'message': f'Simulated threat in sector {sector}'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_inject_die(self):
        """Inject a die pheromone to kill all nodes"""
        try:
            payload = b'DASHBOARD_KILL_ALL'.ljust(32, b'\x00')
            pkt = build_pheromone(0xFF, payload)  # PHEROMONE_DIE
            send_pheromone(pkt)
            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'alarm',
                    'message': 'KILL ALL sent from dashboard'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_maze_start(self, body):
        """Generate and broadcast a new maze to the swarm"""
        import random as rnd
        try:
            data = json.loads(body) if body else {}
            difficulty = data.get('difficulty', 'medium')

            # Generate maze using recursive backtracking
            grid = [[0xFF] * MAZE_SIZE for _ in range(MAZE_SIZE)]  # All walls

            def carve(x, y):
                grid[y][x] = 0x00  # Mark as passage
                dirs = [(0, -2), (2, 0), (0, 2), (-2, 0)]
                rnd.shuffle(dirs)
                for dx, dy in dirs:
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < MAZE_SIZE and 0 <= ny < MAZE_SIZE and grid[ny][nx] == 0xFF:
                        grid[y + dy//2][x + dx//2] = 0x00  # Carve wall between
                        carve(nx, ny)

            # Start carving from (1, 1)
            carve(1, 1)

            # Set start and goal
            start_x, start_y = 1, 1
            goal_x, goal_y = MAZE_SIZE - 2, MAZE_SIZE - 2
            grid[start_y][start_x] = 0x10  # MAZE_START
            grid[goal_y][goal_x] = 0x20    # MAZE_GOAL

            # Update state
            with state_lock:
                swarm_state['maze']['active'] = True
                swarm_state['maze']['solved'] = False
                swarm_state['maze']['started_at'] = time.time()
                swarm_state['maze']['grid'] = grid
                swarm_state['maze']['start'] = [start_x, start_y]
                swarm_state['maze']['goal'] = [goal_x, goal_y]
                swarm_state['maze']['explorers'] = {}
                swarm_state['maze']['solution_path'] = []
                swarm_state['maze']['cells_explored'] = 0
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'maze',
                    'message': f'Maze started: ({start_x},{start_y}) -> ({goal_x},{goal_y})'
                })

            # Build MAZE_INIT pheromone
            # Payload: start_x(1), start_y(1), goal_x(1), goal_y(1), wall_bits(28)
            payload = bytearray(32)
            payload[0] = start_x
            payload[1] = start_y
            payload[2] = goal_x
            payload[3] = goal_y

            # Pack wall bits (cells where grid[y][x] == 0xFF)
            for i in range(min(28 * 8, MAZE_SIZE * MAZE_SIZE)):
                x = i % MAZE_SIZE
                y = i // MAZE_SIZE
                if grid[y][x] == 0xFF:
                    byte_idx = 4 + (i // 8)
                    bit_idx = i % 8
                    if byte_idx < 32:
                        payload[byte_idx] |= (1 << bit_idx)

            pkt = build_pheromone(PHEROMONE_MAZE_INIT, bytes(payload))
            send_pheromone(pkt)

            # Don't auto-start simulation - let real nodes explore
            # User can click "Simulate" button if no real nodes are running

            self.send_json_response({'success': True, 'start': [start_x, start_y], 'goal': [goal_x, goal_y]})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_maze_reset(self):
        """Reset maze state"""
        try:
            stop_maze_simulation()
            with state_lock:
                swarm_state['maze']['active'] = False
                swarm_state['maze']['solved'] = False
                swarm_state['maze']['started_at'] = 0
                swarm_state['maze']['grid'] = [[0] * MAZE_SIZE for _ in range(MAZE_SIZE)]
                swarm_state['maze']['explorers'] = {}
                swarm_state['maze']['solution_path'] = []
                swarm_state['maze']['cells_explored'] = 0
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'maze',
                    'message': 'Maze reset'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_maze_simulate(self):
        """Start simulated exploration (for demo when no real nodes)"""
        try:
            with state_lock:
                if not swarm_state['maze']['active']:
                    self.send_json_response({'success': False, 'error': 'Start maze first'}, 400)
                    return
            start_maze_simulation()
            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'maze',
                    'message': 'Simulation started (4 virtual explorers)'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_terrain_start(self, body):
        """Start terrain exploration with new seed"""
        import random as rnd
        try:
            data = json.loads(body) if body else {}
            seed = data.get('seed', rnd.randint(0, 0xFFFFFFFF))
            start_x = data.get('start_x', 16)
            start_y = data.get('start_y', 16)
            difficulty = data.get('difficulty', 1)

            # Generate terrain grid from seed
            grid = terrain_generate_grid(seed)

            # Update state
            with state_lock:
                swarm_state['terrain']['active'] = True
                swarm_state['terrain']['seed'] = seed
                swarm_state['terrain']['started_at'] = time.time()
                swarm_state['terrain']['grid'] = grid
                swarm_state['terrain']['explorers'] = {}
                swarm_state['terrain']['threats'] = []
                swarm_state['terrain']['objectives'] = []
                swarm_state['terrain']['cells_explored'] = 0
                swarm_state['terrain']['current_strategy'] = TERRAIN_CMD_SPREAD
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'terrain',
                    'message': f'Terrain started: seed={seed:08X} start=({start_x},{start_y})'
                })

            # Send pheromone to swarm
            send_terrain_init(seed, start_x, start_y, difficulty)

            self.send_json_response({
                'success': True,
                'seed': seed,
                'start': [start_x, start_y]
            })
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_terrain_reset(self):
        """Reset terrain exploration"""
        try:
            with state_lock:
                swarm_state['terrain']['active'] = False
                swarm_state['terrain']['seed'] = 0
                swarm_state['terrain']['started_at'] = 0
                swarm_state['terrain']['grid'] = [[{'base': 0, 'meta': 0}
                    for _ in range(TERRAIN_SIZE)] for _ in range(TERRAIN_SIZE)]
                swarm_state['terrain']['explorers'] = {}
                swarm_state['terrain']['threats'] = []
                swarm_state['terrain']['objectives'] = []
                swarm_state['terrain']['cells_explored'] = 0
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'terrain',
                    'message': 'Terrain exploration reset'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_terrain_strategy(self, body):
        """Send strategy command to explorers"""
        try:
            data = json.loads(body) if body else {}
            command = data.get('command', TERRAIN_CMD_SPREAD)
            target_x = data.get('target_x', 16)
            target_y = data.get('target_y', 16)

            cmd_names = ['HOLD', 'REGROUP', 'SPREAD', 'PATROL', 'RETREAT', 'ADVANCE']
            cmd_name = cmd_names[command] if command < len(cmd_names) else 'UNKNOWN'

            with state_lock:
                swarm_state['terrain']['current_strategy'] = command
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'terrain',
                    'message': f'Strategy: {cmd_name} target=({target_x},{target_y})'
                })

            send_terrain_strategy(command, target_x, target_y)
            self.send_json_response({'success': True, 'command': cmd_name})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_terrain_objective(self, body):
        """Add or update objective marker"""
        try:
            data = json.loads(body) if body else {}
            x = data.get('x', 16)
            y = data.get('y', 16)
            obj_type = data.get('type', 'waypoint')

            with state_lock:
                # Check if objective already exists at this location
                found = False
                for obj in swarm_state['terrain']['objectives']:
                    if obj['x'] == x and obj['y'] == y:
                        obj['type'] = obj_type
                        found = True
                        break
                if not found:
                    swarm_state['terrain']['objectives'].append({
                        'x': x, 'y': y, 'type': obj_type, 'status': 'pending'
                    })
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'terrain',
                    'message': f'Objective: {obj_type} at ({x},{y})'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_arm_maze_start(self, body):
        """Start maze exploration on ARM nodes"""
        try:
            data = json.loads(body) if body else {}
            start_x = data.get('start_x', 1)
            start_y = data.get('start_y', 1)
            goal_x = data.get('goal_x', 14)
            goal_y = data.get('goal_y', 14)

            send_arm_maze_init(start_x, start_y, goal_x, goal_y)

            with state_lock:
                swarm_state['maze']['active'] = True
                swarm_state['maze']['solved'] = False
                swarm_state['maze']['started_at'] = time.time()
                swarm_state['maze']['start'] = [start_x, start_y]
                swarm_state['maze']['goal'] = [goal_x, goal_y]
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'maze',
                    'message': f'ARM Maze started: ({start_x},{start_y}) -> ({goal_x},{goal_y})'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_arm_terrain_start(self, body):
        """Start terrain exploration on ARM nodes"""
        try:
            data = json.loads(body) if body else {}
            start_x = data.get('start_x', 16)
            start_y = data.get('start_y', 16)

            send_arm_terrain_init(start_x, start_y)

            with state_lock:
                swarm_state['terrain']['active'] = True
                swarm_state['terrain']['started_at'] = time.time()
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'terrain',
                    'message': f'ARM Terrain started at ({start_x},{start_y})'
                })
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 400)

    def handle_arm_kill(self):
        """Kill all ARM QEMU nodes"""
        import subprocess
        try:
            # Kill ARM QEMU processes
            if os.name == 'nt':  # Windows
                subprocess.run(['taskkill', '/F', '/IM', 'qemu-system-arm.exe'],
                             capture_output=True, timeout=5)
            else:  # Linux/Mac
                subprocess.run(['pkill', '-f', 'qemu-system-arm'],
                             capture_output=True, timeout=5)

            with state_lock:
                swarm_state['events'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': 'alarm',
                    'message': 'ARM swarm terminated'
                })
            self.send_json_response({'success': True, 'message': 'ARM swarm killed'})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def send_json_response(self, data, status=200):
        """Helper to send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def handle_job_submit(self, body):
        """Handle job submission"""
        try:
            data = json.loads(body)
            job_type = int(data.get('type', JOB_PRIME_SEARCH))
            param1 = int(data.get('param1', 1))
            param2 = int(data.get('param2', 1000))
            chunks = int(data.get('chunks', 4))

            job_id = send_job_start(job_type, param1, param2, chunks)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'job_id': job_id}).encode())
        except Exception as e:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'error': str(e)}).encode())

    def handle_job_cancel(self, body):
        """Handle job cancellation"""
        try:
            data = json.loads(body)
            job_id = int(data.get('job_id', -1))

            with state_lock:
                if job_id in swarm_state['jobs']:
                    swarm_state['jobs'][job_id]['status'] = 'cancelled'

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True}).encode())
        except Exception as e:
            self.send_response(400)
            self.end_headers()

    def send_api_response(self):
        """Send current swarm state as JSON"""
        with state_lock:
            response = json.dumps(swarm_state, default=str)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response.encode())

    def send_jobs_response(self):
        """Send jobs list as JSON"""
        with state_lock:
            response = json.dumps(list(swarm_state['jobs'].values()), default=str)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode())

    def send_dashboard(self):
        """Send the HTML dashboard"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())

    def log_message(self, format, *args):
        pass

DASHBOARD_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>NanOS Tactical Command</title>
    <meta charset="utf-8">
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0f;
            color: #00ff00;
            overflow: hidden;
        }

        /* Top Stats Bar */
        .stats-bar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 50px;
            background: linear-gradient(180deg, #1a1a2e 0%, #0a0a0f 100%);
            border-bottom: 1px solid #00ffff33;
            display: flex;
            align-items: center;
            justify-content: space-around;
            z-index: 100;
        }
        .stat-item {
            text-align: center;
        }
        .stat-value {
            font-size: 20px;
            font-weight: bold;
            color: #00ffff;
            text-shadow: 0 0 10px #00ffff;
        }
        .stat-label {
            font-size: 9px;
            color: #666;
            text-transform: uppercase;
        }

        /* Main Layout */
        .main-container {
            display: flex;
            height: calc(100vh - 50px);
            margin-top: 50px;
        }

        /* Left Panel - Topology */
        .topology-panel {
            flex: 2;
            position: relative;
            border-right: 1px solid #333;
        }
        .topology-panel h3 {
            position: absolute;
            top: 10px;
            left: 15px;
            color: #00ffff;
            font-size: 11px;
            z-index: 10;
        }
        #topology-svg {
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at center, #0f0f1a 0%, #0a0a0f 100%);
        }
        .node-circle {
            stroke: #00ffff;
            stroke-width: 2;
            cursor: pointer;
            transition: all 0.3s;
        }
        .node-circle:hover {
            stroke-width: 4;
            filter: brightness(1.3);
        }
        .node-circle.queen { fill: #ff00ff; stroke: #ff00ff; }
        .node-circle.sentinel { fill: #ff4444; stroke: #ff4444; }
        .node-circle.explorer { fill: #ffff00; stroke: #ffff00; }
        .node-circle.worker { fill: #00ff00; stroke: #00ff00; }
        .link-line {
            stroke: #00ffff33;
            stroke-width: 1;
        }
        .node-label {
            fill: #fff;
            font-size: 8px;
            text-anchor: middle;
            pointer-events: none;
        }

        /* Right Panel */
        .right-panel {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-width: 320px;
            max-width: 400px;
        }

        /* Sector Heatmap */
        .sector-panel {
            height: 200px;
            border-bottom: 1px solid #333;
            padding: 15px;
        }
        .sector-panel h3 {
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 10px;
        }
        .sector-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            grid-template-rows: repeat(2, 1fr);
            gap: 8px;
            height: calc(100% - 30px);
        }
        .sector {
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 4px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
        }
        .sector.hot { background: #ff000066; border-color: #ff0000; }
        .sector.warm { background: #ff880044; border-color: #ff8800; }
        .sector.active { background: #ffff0033; border-color: #ffff00; }
        .sector-num {
            font-size: 16px;
            font-weight: bold;
            color: #00ffff;
        }
        .sector-activity {
            font-size: 9px;
            color: #666;
        }

        /* Control Panel */
        .control-panel {
            padding: 15px;
            border-bottom: 1px solid #333;
        }
        .control-panel h3 {
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 10px;
        }
        .control-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
        }
        .ctrl-btn {
            background: #1a1a2e;
            border: 1px solid #333;
            color: #00ff00;
            padding: 10px 5px;
            border-radius: 4px;
            font-family: inherit;
            font-size: 9px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .ctrl-btn:hover {
            background: #2a2a4e;
            border-color: #00ffff;
            transform: translateY(-2px);
        }
        .ctrl-btn.danger {
            border-color: #ff0000;
            color: #ff0000;
        }
        .ctrl-btn.danger:hover {
            background: #ff000033;
        }

        /* Job Panel */
        .job-panel {
            padding: 15px;
            border-bottom: 1px solid #333;
        }
        .job-panel h3 {
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 10px;
        }
        .job-form {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .job-form select, .job-form input {
            background: #0a0a0f;
            border: 1px solid #333;
            color: #00ff00;
            padding: 8px;
            font-family: inherit;
            font-size: 11px;
            border-radius: 4px;
        }
        .job-form .row {
            display: flex;
            gap: 8px;
        }
        .job-form .row input {
            flex: 1;
        }
        .job-submit {
            background: linear-gradient(135deg, #00ffff 0%, #00ff00 100%);
            color: #0a0a0f;
            font-weight: bold;
        }

        /* Event Log */
        .event-panel {
            flex: 1;
            padding: 15px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        .event-panel h3 {
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 10px;
        }
        .event-list {
            flex: 1;
            overflow-y: auto;
            font-size: 10px;
        }
        .event-item {
            padding: 6px 8px;
            margin: 3px 0;
            background: #0f0f1a;
            border-radius: 3px;
            border-left: 2px solid #00ff00;
        }
        .event-item.alarm { border-color: #ff0000; }
        .event-item.election { border-color: #ff00ff; }
        .event-item.detection { border-color: #ffff00; }
        .event-item.job { border-color: #00ffff; }
        .event-time {
            color: #666;
            margin-right: 8px;
        }

        /* Packet Timeline */
        .timeline-panel {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 320px;
            height: 60px;
            background: #0a0a0f;
            border-top: 1px solid #333;
            padding: 5px 15px;
        }
        .timeline-panel h3 {
            color: #00ffff;
            font-size: 9px;
            margin-bottom: 5px;
        }
        #timeline-svg {
            width: 100%;
            height: 40px;
        }
        .timeline-bar {
            fill: #00ffff44;
        }

        /* Pulse animation */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .pulse { animation: pulse 1s infinite; }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0a0a0f; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }

        /* View Toggle */
        .view-toggle {
            position: absolute;
            top: 10px;
            right: 15px;
            z-index: 10;
            display: flex;
            gap: 5px;
        }
        .view-toggle button {
            background: #1a1a2e;
            border: 1px solid #333;
            color: #00ffff;
            padding: 5px 10px;
            font-size: 9px;
            cursor: pointer;
            border-radius: 3px;
        }
        .view-toggle button.active {
            background: #00ffff33;
            border-color: #00ffff;
        }

        /* Maze Grid */
        #maze-container {
            display: none;
            width: 100%;
            height: 100%;
            padding: 40px 20px 20px 20px;
        }
        #maze-container.active {
            display: block;
        }
        #topology-svg.hidden {
            display: none;
        }
        .maze-grid {
            display: grid;
            grid-template-columns: repeat(16, 1fr);
            grid-template-rows: repeat(16, 1fr);
            gap: 1px;
            width: 100%;
            height: calc(100% - 40px);
            max-width: 500px;
            max-height: 500px;
            margin: 0 auto;
        }
        .maze-cell {
            background: #1a1a2e;
            border-radius: 2px;
            transition: background 0.2s;
        }
        .maze-cell.wall { background: #333; }
        .maze-cell.explored { background: #00ff0044; }
        .maze-cell.path { background: #00ffff66; }
        .maze-cell.start { background: #00ff00; }
        .maze-cell.goal { background: #ff00ff; }
        .maze-cell.explorer {
            background: #ffff00;
            box-shadow: 0 0 8px #ffff00;
        }
        .maze-controls {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 10px;
        }
        .maze-status {
            text-align: center;
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 10px;
        }
        .maze-status.solved {
            color: #00ff00;
            font-weight: bold;
        }

        /* Terrain Grid */
        #terrain-container {
            display: none;
            width: 100%;
            height: 100%;
            padding: 40px 15px 15px 15px;
        }
        #terrain-container.active {
            display: block;
        }
        #terrain-canvas {
            width: 100%;
            height: calc(100% - 100px);
            max-width: 512px;
            max-height: 512px;
            margin: 0 auto;
            display: block;
            background: #0a0a0f;
            border: 1px solid #333;
        }
        .terrain-status {
            text-align: center;
            color: #00ffff;
            font-size: 11px;
            margin-bottom: 8px;
        }
        .terrain-controls {
            display: flex;
            gap: 8px;
            justify-content: center;
            margin-top: 8px;
            flex-wrap: wrap;
        }
        .terrain-strategy {
            display: flex;
            gap: 5px;
            justify-content: center;
            margin-top: 8px;
        }
        .terrain-strategy button {
            padding: 4px 8px;
            font-size: 9px;
            background: #1a1a2e;
            border: 1px solid #333;
            color: #00ff00;
            cursor: pointer;
        }
        .terrain-strategy button:hover {
            background: #252540;
            border-color: #00ff00;
        }
        .terrain-strategy button.active {
            background: #00ff0033;
            border-color: #00ff00;
        }
        .terrain-legend {
            display: flex;
            gap: 8px;
            justify-content: center;
            margin-top: 6px;
            font-size: 8px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 3px;
        }
        .legend-color {
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }
    </style>
</head>
<body>
    <!-- Top Stats Bar -->
    <div class="stats-bar">
        <div class="stat-item">
            <div class="stat-value" id="stat-nodes">0</div>
            <div class="stat-label">Nodes</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="stat-queen">--</div>
            <div class="stat-label">Queen</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="stat-pps">0</div>
            <div class="stat-label">Packets/s</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="stat-alerts">0</div>
            <div class="stat-label">Alerts</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="stat-jobs">0</div>
            <div class="stat-label">Jobs</div>
        </div>
    </div>

    <div class="main-container">
        <!-- Left: Topology / Maze -->
        <div class="topology-panel">
            <h3 id="left-panel-title">NETWORK TOPOLOGY</h3>
            <div class="view-toggle">
                <button id="btn-topology" class="active" onclick="showView('topology')">Topology</button>
                <button id="btn-maze" onclick="showView('maze')">Maze</button>
                <button id="btn-terrain" onclick="showView('terrain')" style="color:#ff8800;border-color:#ff8800">Terrain</button>
            </div>
            <svg id="topology-svg"></svg>
            <div id="maze-container">
                <div class="maze-status" id="maze-status">Click "Start Maze" to begin exploration</div>
                <div class="maze-grid" id="maze-grid"></div>
                <div class="maze-controls">
                    <button class="ctrl-btn" onclick="startMaze()">Start Maze</button>
                    <button class="ctrl-btn" onclick="simulateMaze()" style="color:#ffff00;border-color:#ffff00">Simulate</button>
                    <button class="ctrl-btn" onclick="resetMaze()">Reset</button>
                </div>
            </div>
            <div id="terrain-container">
                <div class="terrain-status" id="terrain-status">Click "Start Terrain" to begin tactical exploration</div>
                <canvas id="terrain-canvas" width="512" height="512"></canvas>
                <div class="terrain-legend">
                    <div class="legend-item"><div class="legend-color" style="background:#228B22"></div>Open</div>
                    <div class="legend-item"><div class="legend-color" style="background:#006400"></div>Forest</div>
                    <div class="legend-item"><div class="legend-color" style="background:#696969"></div>Urban</div>
                    <div class="legend-item"><div class="legend-color" style="background:#4169E1"></div>Water</div>
                    <div class="legend-item"><div class="legend-color" style="background:#8B4513"></div>Rocky</div>
                    <div class="legend-item"><div class="legend-color" style="background:#556B2F"></div>Marsh</div>
                    <div class="legend-item"><div class="legend-color" style="background:#D2691E"></div>Road</div>
                    <div class="legend-item"><div class="legend-color" style="background:#1C1C1C"></div>Wall</div>
                </div>
                <div class="terrain-controls">
                    <button class="ctrl-btn" onclick="startTerrain()" style="color:#ff8800;border-color:#ff8800">Start Terrain</button>
                    <button class="ctrl-btn" onclick="resetTerrain()">Reset</button>
                </div>
                <div class="terrain-strategy">
                    <button onclick="sendStrategy(2)" id="strat-spread" class="active">Spread</button>
                    <button onclick="sendStrategy(1)" id="strat-regroup">Regroup</button>
                    <button onclick="sendStrategy(3)" id="strat-patrol">Patrol</button>
                    <button onclick="sendStrategy(4)" id="strat-retreat">Retreat</button>
                    <button onclick="sendStrategy(5)" id="strat-advance">Advance</button>
                </div>
            </div>
        </div>

        <!-- Right: Controls & Events -->
        <div class="right-panel">
            <!-- Sector Heatmap -->
            <div class="sector-panel">
                <h3>SECTOR ACTIVITY</h3>
                <div class="sector-grid" id="sector-grid"></div>
            </div>

            <!-- Control Panel -->
            <div class="control-panel">
                <h3>SWARM CONTROL</h3>
                <div class="control-grid">
                    <button class="ctrl-btn" onclick="injectAlarm()">Alarm</button>
                    <button class="ctrl-btn" onclick="injectElection()">Election</button>
                    <button class="ctrl-btn" onclick="injectData()">Data</button>
                    <button class="ctrl-btn" onclick="injectThreat(0)">Threat S0</button>
                    <button class="ctrl-btn" onclick="injectThreat(4)">Threat S4</button>
                    <button class="ctrl-btn danger" onclick="killAll()">KILL ALL</button>
                </div>
            </div>

            <!-- ARM Control Panel -->
            <div class="control-panel">
                <h3>ARM SWARM CONTROL</h3>
                <div class="control-grid">
                    <button class="ctrl-btn" onclick="startArmMaze()" style="color:#00ffff;border-color:#00ffff">ARM Maze</button>
                    <button class="ctrl-btn" onclick="startArmTerrain()" style="color:#ff8800;border-color:#ff8800">ARM Terrain</button>
                    <button class="ctrl-btn danger" onclick="killArmSwarm()">KILL ARM</button>
                </div>
            </div>

            <!-- Job Submission -->
            <div class="job-panel">
                <h3>SUBMIT JOB</h3>
                <div class="job-form">
                    <select id="job-type">
                        <option value="1">Prime Search</option>
                        <option value="2">Monte Carlo Pi</option>
                        <option value="4">Parallel Sum</option>
                    </select>
                    <div class="row">
                        <input type="number" id="param1" value="1" placeholder="Start">
                        <input type="number" id="param2" value="10000" placeholder="End">
                    </div>
                    <button class="ctrl-btn job-submit" onclick="submitJob()">LAUNCH JOB</button>
                </div>
            </div>

            <!-- Event Log -->
            <div class="event-panel">
                <h3>EVENT LOG</h3>
                <div class="event-list" id="event-list"></div>
            </div>
        </div>
    </div>

    <!-- Timeline -->
    <div class="timeline-panel">
        <h3>PACKET TIMELINE (60s)</h3>
        <svg id="timeline-svg"></svg>
    </div>

    <script>
        // State
        let nodes = [];
        let links = [];
        let packetHistory = new Array(60).fill(0);
        let simulation = null;

        // Initialize D3 topology
        function initTopology() {
            const svg = d3.select('#topology-svg');
            const width = svg.node().getBoundingClientRect().width;
            const height = svg.node().getBoundingClientRect().height;

            svg.append('g').attr('class', 'links');
            svg.append('g').attr('class', 'nodes');

            simulation = d3.forceSimulation()
                .force('link', d3.forceLink().id(d => d.id).distance(80))
                .force('charge', d3.forceManyBody().strength(-200))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collision', d3.forceCollide().radius(30));
        }

        // Update topology visualization
        function updateTopology(nodeData) {
            const svg = d3.select('#topology-svg');
            const width = svg.node().getBoundingClientRect().width;
            const height = svg.node().getBoundingClientRect().height;

            // Convert node data to D3 format
            const newNodes = Object.values(nodeData).map(n => ({
                id: n.node_id,
                role: n.role.toLowerCase(),
                rx: n.rx,
                tx: n.tx,
                neighbors: n.neighbors
            }));

            // Generate links based on queen relationships
            const newLinks = [];
            const queenNode = newNodes.find(n => n.role === 'queen');
            if (queenNode) {
                newNodes.forEach(n => {
                    if (n.id !== queenNode.id) {
                        newLinks.push({ source: n.id, target: queenNode.id });
                    }
                });
            }

            // Update simulation
            nodes = newNodes;
            links = newLinks;

            // Links
            const link = svg.select('.links')
                .selectAll('line')
                .data(links, d => d.source.id + '-' + d.target.id);

            link.exit().remove();
            link.enter()
                .append('line')
                .attr('class', 'link-line');

            // Nodes
            const node = svg.select('.nodes')
                .selectAll('g')
                .data(nodes, d => d.id);

            node.exit().remove();

            const nodeEnter = node.enter()
                .append('g')
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));

            nodeEnter.append('circle')
                .attr('class', d => 'node-circle ' + d.role)
                .attr('r', d => d.role === 'queen' ? 18 : 12);

            nodeEnter.append('text')
                .attr('class', 'node-label')
                .attr('dy', 3)
                .text(d => d.id.slice(-4));

            // Update simulation
            simulation.nodes(nodes);
            simulation.force('link').links(links);
            simulation.alpha(0.3).restart();

            simulation.on('tick', () => {
                svg.select('.links').selectAll('line')
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                svg.select('.nodes').selectAll('g')
                    .attr('transform', d => `translate(${d.x},${d.y})`);
            });
        }

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        // Initialize sector grid
        function initSectors() {
            const grid = document.getElementById('sector-grid');
            for (let i = 0; i < 8; i++) {
                const sector = document.createElement('div');
                sector.className = 'sector';
                sector.id = `sector-${i}`;
                sector.innerHTML = `
                    <div class="sector-num">${i}</div>
                    <div class="sector-activity">0</div>
                `;
                grid.appendChild(sector);
            }
        }

        // Update sectors
        function updateSectors(activity) {
            for (let i = 0; i < 8; i++) {
                const sector = document.getElementById(`sector-${i}`);
                const val = activity[i] || 0;
                sector.querySelector('.sector-activity').textContent = val;
                sector.className = 'sector';
                if (val > 10) sector.classList.add('hot');
                else if (val > 5) sector.classList.add('warm');
                else if (val > 0) sector.classList.add('active');
            }
        }

        // Initialize timeline
        function initTimeline() {
            const svg = d3.select('#timeline-svg');
            const width = svg.node().getBoundingClientRect().width;
            svg.selectAll('rect')
                .data(packetHistory)
                .enter()
                .append('rect')
                .attr('class', 'timeline-bar')
                .attr('x', (d, i) => i * (width / 60))
                .attr('y', 35)
                .attr('width', width / 60 - 1)
                .attr('height', 0);
        }

        // Update timeline
        function updateTimeline(pps) {
            packetHistory.shift();
            packetHistory.push(pps);

            const svg = d3.select('#timeline-svg');
            const width = svg.node().getBoundingClientRect().width;
            const maxVal = Math.max(...packetHistory, 10);

            svg.selectAll('rect')
                .data(packetHistory)
                .attr('y', d => 35 - (d / maxVal) * 30)
                .attr('height', d => (d / maxVal) * 30);
        }

        // Update events
        function updateEvents(events) {
            const list = document.getElementById('event-list');
            const html = events.slice(-20).reverse().map(e => {
                const typeClass = e.type || '';
                const time = e.time || '--:--:--';
                return `<div class="event-item ${typeClass}">
                    <span class="event-time">${time.split('T').pop().split('.')[0]}</span>
                    ${e.message || ''}
                </div>`;
            }).join('');
            list.innerHTML = html || '<div style="color:#666">No events</div>';
        }

        // Fetch state
        async function fetchState() {
            try {
                const response = await fetch('/api/state');
                const state = await response.json();

                // Update stats
                const nodeCount = Object.keys(state.nodes).length;
                document.getElementById('stat-nodes').textContent = nodeCount;
                document.getElementById('stat-queen').textContent = state.queen_id ? state.queen_id.slice(-4) : '--';
                document.getElementById('stat-pps').textContent = state.packets_per_second || 0;
                document.getElementById('stat-alerts').textContent = state.active_alerts || 0;
                document.getElementById('stat-jobs').textContent = Object.keys(state.jobs || {}).length;

                // Update visualizations
                updateTopology(state.nodes);
                updateSectors(state.sector_activity || []);
                updateTimeline(state.packets_per_second || 0);
                updateEvents(state.events || []);

            } catch (e) {
                console.error('Fetch error:', e);
            }
        }

        // Control functions
        async function injectAlarm() {
            await fetch('/api/inject/alarm', { method: 'POST' });
        }

        async function injectElection() {
            await fetch('/api/inject/election', { method: 'POST' });
        }

        async function injectData() {
            await fetch('/api/inject/data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'Dashboard ping ' + Date.now() })
            });
        }

        async function injectThreat(sector) {
            await fetch('/api/inject/threat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sector: sector, type: 1, intensity: 200 })
            });
        }

        async function killAll() {
            if (confirm('Kill all swarm nodes?')) {
                await fetch('/api/inject/die', { method: 'POST' });
            }
        }

        async function submitJob() {
            const jobType = document.getElementById('job-type').value;
            const param1 = document.getElementById('param1').value;
            const param2 = document.getElementById('param2').value;

            await fetch('/api/job/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: parseInt(jobType),
                    param1: parseInt(param1),
                    param2: parseInt(param2),
                    chunks: 4
                })
            });
        }

        // ========== VIEW TOGGLE ==========
        let currentView = 'topology';

        function showView(view) {
            currentView = view;
            document.getElementById('btn-topology').classList.toggle('active', view === 'topology');
            document.getElementById('btn-maze').classList.toggle('active', view === 'maze');
            document.getElementById('btn-terrain').classList.toggle('active', view === 'terrain');
            document.getElementById('topology-svg').classList.toggle('hidden', view !== 'topology');
            document.getElementById('maze-container').classList.toggle('active', view === 'maze');
            document.getElementById('terrain-container').classList.toggle('active', view === 'terrain');
            const titles = {
                'topology': 'NETWORK TOPOLOGY',
                'maze': 'MAZE EXPLORATION',
                'terrain': 'TACTICAL TERRAIN'
            };
            document.getElementById('left-panel-title').textContent = titles[view] || 'NETWORK TOPOLOGY';
        }

        // ========== MAZE FUNCTIONS ==========

        function initMazeGrid() {
            const grid = document.getElementById('maze-grid');
            grid.innerHTML = '';
            for (let y = 0; y < 16; y++) {
                for (let x = 0; x < 16; x++) {
                    const cell = document.createElement('div');
                    cell.className = 'maze-cell';
                    cell.id = `maze-${x}-${y}`;
                    grid.appendChild(cell);
                }
            }
        }

        function updateMaze(mazeState) {
            if (!mazeState) return;

            const statusEl = document.getElementById('maze-status');
            if (mazeState.solved) {
                statusEl.textContent = 'MAZE SOLVED!';
                statusEl.className = 'maze-status solved';
            } else if (mazeState.active) {
                const explorerCount = Object.keys(mazeState.explorers || {}).length;
                statusEl.textContent = `Exploring... ${explorerCount} explorer(s) active`;
                statusEl.className = 'maze-status';
            } else {
                statusEl.textContent = 'Click "Start Maze" to begin exploration';
                statusEl.className = 'maze-status';
            }

            // Update grid cells
            const grid = mazeState.grid || [];
            for (let y = 0; y < 16; y++) {
                for (let x = 0; x < 16; x++) {
                    const cell = document.getElementById(`maze-${x}-${y}`);
                    if (!cell) continue;

                    cell.className = 'maze-cell';
                    const value = grid[y] ? grid[y][x] : 0;

                    if (value === 0xFF) cell.classList.add('wall');
                    else if (value === 0x10) cell.classList.add('start');
                    else if (value === 0x20) cell.classList.add('goal');
                    else if (value === 0x02) cell.classList.add('path');
                    else if (value === 0x01) cell.classList.add('explored');
                }
            }

            // Mark explorer positions
            const explorers = mazeState.explorers || {};
            for (const [nodeId, pos] of Object.entries(explorers)) {
                if (pos.x !== undefined && pos.y !== undefined) {
                    const cell = document.getElementById(`maze-${pos.x}-${pos.y}`);
                    if (cell) cell.classList.add('explorer');
                }
            }
        }

        async function startMaze() {
            await fetch('/api/maze/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ difficulty: 'medium' })
            });
            showView('maze');
        }

        async function resetMaze() {
            await fetch('/api/maze/reset', { method: 'POST' });
        }

        async function simulateMaze() {
            await fetch('/api/maze/simulate', { method: 'POST' });
        }

        // ========== TERRAIN FUNCTIONS ==========
        const TERRAIN_COLORS = [
            '#228B22', // OPEN - Forest Green
            '#006400', // FOREST - Dark Green
            '#696969', // URBAN - Dim Gray
            '#4169E1', // WATER - Royal Blue
            '#8B4513', // ROCKY - Saddle Brown
            '#556B2F', // MARSH - Dark Olive Green
            '#D2691E', // ROAD - Chocolate
            '#1C1C1C'  // IMPASSABLE - Very Dark Gray
        ];

        const THREAT_COLORS = [
            null,       // NONE
            '#333',     // UNKNOWN
            '#ff880033', // SUSPECTED
            '#ff880066', // DETECTED
            '#ff000066', // CONFIRMED
            '#ff0000aa', // ACTIVE
            '#ff0000'   // CRITICAL
        ];

        function drawTerrain(terrainState) {
            const canvas = document.getElementById('terrain-canvas');
            const ctx = canvas.getContext('2d');
            const cellSize = canvas.width / 32;

            ctx.clearRect(0, 0, canvas.width, canvas.height);

            if (!terrainState || !terrainState.grid) return;

            // Draw terrain cells
            for (let y = 0; y < 32; y++) {
                for (let x = 0; x < 32; x++) {
                    const cell = terrainState.grid[y] ? terrainState.grid[y][x] : null;
                    if (!cell) continue;

                    const terrainType = cell.base & 0x07;
                    const elevation = (cell.base >> 3) & 0x07;
                    const explored = cell.meta & 0x01;
                    const threat = (cell.meta >> 5) & 0x07;

                    // Base terrain color
                    ctx.fillStyle = TERRAIN_COLORS[terrainType] || '#333';

                    // Dim if not explored (fog of war)
                    if (!explored) {
                        ctx.fillStyle = '#0a0a0f';
                    }

                    ctx.fillRect(x * cellSize, y * cellSize, cellSize - 1, cellSize - 1);

                    // Elevation shading
                    if (explored && elevation > 3) {
                        ctx.fillStyle = 'rgba(255,255,255,0.15)';
                        ctx.fillRect(x * cellSize, y * cellSize, cellSize - 1, cellSize - 1);
                    }

                    // Threat overlay
                    if (explored && threat > 1 && THREAT_COLORS[threat]) {
                        ctx.fillStyle = THREAT_COLORS[threat];
                        ctx.fillRect(x * cellSize, y * cellSize, cellSize - 1, cellSize - 1);
                    }
                }
            }

            // Draw threats
            (terrainState.threats || []).forEach(t => {
                ctx.fillStyle = '#ff0000';
                ctx.beginPath();
                ctx.arc(t.x * cellSize + cellSize/2, t.y * cellSize + cellSize/2, 4, 0, Math.PI * 2);
                ctx.fill();
                ctx.strokeStyle = '#ff000066';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(t.x * cellSize + cellSize/2, t.y * cellSize + cellSize/2, 8, 0, Math.PI * 2);
                ctx.stroke();
            });

            // Draw objectives
            (terrainState.objectives || []).forEach(obj => {
                ctx.fillStyle = '#ff00ff';
                ctx.beginPath();
                ctx.moveTo(obj.x * cellSize + cellSize/2, obj.y * cellSize);
                ctx.lineTo(obj.x * cellSize + cellSize, obj.y * cellSize + cellSize);
                ctx.lineTo(obj.x * cellSize, obj.y * cellSize + cellSize);
                ctx.closePath();
                ctx.fill();
            });

            // Draw explorers
            const explorers = terrainState.explorers || {};
            const explorerColors = ['#00ff00', '#ffff00', '#00ffff', '#ff00ff', '#ff8800', '#88ff00', '#0088ff', '#ff0088'];
            let idx = 0;
            for (const [nodeId, exp] of Object.entries(explorers)) {
                if (exp.x === undefined || exp.y === undefined) continue;

                const color = explorerColors[idx % explorerColors.length];
                ctx.fillStyle = color;

                // Draw explorer dot
                ctx.beginPath();
                ctx.arc(exp.x * cellSize + cellSize/2, exp.y * cellSize + cellSize/2, 5, 0, Math.PI * 2);
                ctx.fill();

                // Draw sensor range circle
                const range = exp.sensor_range || 3;
                ctx.strokeStyle = color + '44';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.arc(exp.x * cellSize + cellSize/2, exp.y * cellSize + cellSize/2, range * cellSize, 0, Math.PI * 2);
                ctx.stroke();

                // Draw heading indicator
                const headings = [[0,-1],[1,-1],[1,0],[1,1],[0,1],[-1,1],[-1,0],[-1,-1]];
                const h = headings[exp.heading || 0] || [0,-1];
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(exp.x * cellSize + cellSize/2, exp.y * cellSize + cellSize/2);
                ctx.lineTo(exp.x * cellSize + cellSize/2 + h[0]*8, exp.y * cellSize + cellSize/2 + h[1]*8);
                ctx.stroke();

                idx++;
            }
        }

        function updateTerrain(terrainState) {
            if (!terrainState) return;

            const statusEl = document.getElementById('terrain-status');
            if (terrainState.active) {
                const explorerCount = Object.keys(terrainState.explorers || {}).length;
                const cellsExplored = terrainState.cells_explored || 0;
                statusEl.textContent = `Exploring: ${explorerCount} explorer(s), ${cellsExplored} cells discovered`;
            } else {
                statusEl.textContent = 'Click "Start Terrain" to begin tactical exploration';
            }

            // Update strategy buttons
            const strategies = ['hold', 'regroup', 'spread', 'patrol', 'retreat', 'advance'];
            strategies.forEach((s, i) => {
                const btn = document.getElementById('strat-' + s);
                if (btn) {
                    btn.classList.toggle('active', terrainState.current_strategy === i);
                }
            });

            drawTerrain(terrainState);
        }

        async function startTerrain() {
            await fetch('/api/terrain/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            showView('terrain');
        }

        async function resetTerrain() {
            await fetch('/api/terrain/reset', { method: 'POST' });
        }

        async function sendStrategy(cmd) {
            await fetch('/api/terrain/strategy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: cmd })
            });
        }

        // ========== ARM SWARM FUNCTIONS ==========
        async function startArmMaze() {
            await fetch('/api/arm/maze/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ start_x: 1, start_y: 1, goal_x: 14, goal_y: 14 })
            });
            addEvent('ARM maze exploration started', 'job');
        }

        async function startArmTerrain() {
            await fetch('/api/arm/terrain/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ start_x: 16, start_y: 16 })
            });
            addEvent('ARM terrain exploration started', 'job');
        }

        async function killArmSwarm() {
            await fetch('/api/arm/kill', { method: 'POST' });
            addEvent('ARM swarm kill signal sent', 'alarm');
        }

        // Update fetchState to include maze and terrain
        const originalFetchState = fetchState;
        fetchState = async function() {
            try {
                const response = await fetch('/api/state');
                const state = await response.json();

                // Update stats
                const nodeCount = Object.keys(state.nodes).length;
                document.getElementById('stat-nodes').textContent = nodeCount;
                document.getElementById('stat-queen').textContent = state.queen_id ? state.queen_id.slice(-4) : '--';
                document.getElementById('stat-pps').textContent = state.packets_per_second || 0;
                document.getElementById('stat-alerts').textContent = state.active_alerts || 0;
                document.getElementById('stat-jobs').textContent = Object.keys(state.jobs || {}).length;

                // Update visualizations
                updateTopology(state.nodes);
                updateSectors(state.sector_activity || []);
                updateTimeline(state.packets_per_second || 0);
                updateEvents(state.events || []);

                // Update maze
                if (state.maze) {
                    updateMaze(state.maze);
                }

                // Update terrain
                if (state.terrain) {
                    updateTerrain(state.terrain);
                }

            } catch (e) {
                console.error('Fetch error:', e);
            }
        };

        // Initialize
        initTopology();
        initSectors();
        initTimeline();
        initMazeGrid();
        drawTerrain(null);  // Initialize empty terrain canvas
        setInterval(fetchState, 1000);
        fetchState();
    </script>
</body>
</html>
'''

def main():
    parser = argparse.ArgumentParser(description='NanOS Swarm Orchestrator')
    parser.add_argument('--port', type=int, default=8080, help='HTTP server port')
    parser.add_argument('--log-dir', default='/tmp', help='Directory containing nanos_node_*.log files')
    args = parser.parse_args()

    if os.name == 'nt':
        possible_dirs = [args.log_dir, os.environ.get('TEMP', ''), os.environ.get('TMP', ''), 'C:\\Temp', '.']
        for d in possible_dirs:
            if d and os.path.isdir(d):
                args.log_dir = d
                break

    print(f"")
    print(f"  NanOS Tactical Command v0.5")
    print(f"  ============================")
    print(f"")
    print(f"  Log directory: {args.log_dir}")
    print(f"  Dashboard:     http://localhost:{args.port}")
    print(f"")
    print(f"  Features:")
    print(f"    - D3.js network topology visualization")
    print(f"    - Sector activity heatmap")
    print(f"    - Tactical threat injection")
    print(f"    - MapReduce-style computation")
    print(f"")
    print(f"  Press Ctrl+C to stop")
    print(f"")

    # Initialize multicast
    init_multicast()

    # Start log monitor thread
    monitor_thread = threading.Thread(target=monitor_logs, args=(args.log_dir,), daemon=True)
    monitor_thread.start()

    # Start HTTP server
    server = HTTPServer(('', args.port), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()

if __name__ == '__main__':
    main()
