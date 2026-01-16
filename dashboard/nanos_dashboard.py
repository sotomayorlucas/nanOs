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
    'job_counter': 0
}
state_lock = threading.Lock()

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
    """Parse a [METRICS] log line into a dict"""
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
            'last_seen': time.time()
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

    return events

def monitor_logs(log_dir):
    """Background thread to monitor log files"""
    global swarm_state

    file_positions = {}

    while True:
        try:
            log_files = glob.glob(os.path.join(log_dir, 'nanos_node_*.log'))

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
                            metrics = parse_metrics_line(line)
                            if metrics:
                                swarm_state['nodes'][metrics['node_id']] = metrics
                                swarm_state['last_update'] = time.time()

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

            # Clean up stale nodes
            with state_lock:
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
        else:
            self.send_error(404)

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
    <title>NanOS Swarm Orchestrator</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff00;
            padding: 20px;
            min-height: 100vh;
        }
        h1 {
            text-align: center;
            color: #00ffff;
            margin-bottom: 20px;
            text-shadow: 0 0 20px #00ffff;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
            font-size: 12px;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: rgba(26, 26, 46, 0.8);
            border: 1px solid #333;
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        .card h2 {
            color: #00ffff;
            font-size: 14px;
            margin-bottom: 15px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card h2::before {
            content: '';
            width: 8px;
            height: 8px;
            background: #00ffff;
            border-radius: 50%;
            box-shadow: 0 0 10px #00ffff;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }
        .stat {
            text-align: center;
            padding: 15px;
            background: rgba(0, 255, 255, 0.05);
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 255, 0.2);
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }
        .stat-label {
            font-size: 10px;
            color: #888;
            margin-top: 5px;
            text-transform: uppercase;
        }

        /* Job Submission Form */
        .job-form {
            display: grid;
            gap: 15px;
        }
        .form-row {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .form-row label {
            color: #888;
            min-width: 80px;
            font-size: 12px;
        }
        select, input[type="number"] {
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff00;
            padding: 10px;
            border-radius: 4px;
            font-family: inherit;
            flex: 1;
        }
        select:focus, input:focus {
            outline: none;
            border-color: #00ffff;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
        }
        button {
            background: linear-gradient(135deg, #00ffff 0%, #00ff00 100%);
            border: none;
            color: #0a0a0a;
            padding: 12px 24px;
            border-radius: 4px;
            font-family: inherit;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 255, 255, 0.4);
        }
        button.secondary {
            background: #333;
            color: #fff;
        }

        /* Jobs List */
        .job-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .job-item {
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.3);
            border-left: 3px solid #00ff00;
        }
        .job-item.running { border-left-color: #ffff00; animation: pulse 1s infinite; }
        .job-item.completed { border-left-color: #00ff00; }
        .job-item.cancelled { border-left-color: #ff0000; opacity: 0.5; }
        .job-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .job-id { color: #00ffff; font-weight: bold; }
        .job-type { color: #888; font-size: 11px; }
        .job-progress {
            height: 6px;
            background: #333;
            border-radius: 3px;
            overflow: hidden;
        }
        .job-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #00ffff, #00ff00);
            transition: width 0.3s;
        }
        .job-result {
            margin-top: 8px;
            color: #00ff00;
            font-size: 12px;
        }

        /* Nodes */
        .node {
            display: inline-block;
            margin: 5px;
            padding: 12px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            border-left: 3px solid #00ff00;
            min-width: 120px;
        }
        .node.queen { border-left-color: #ff00ff; box-shadow: 0 0 15px rgba(255, 0, 255, 0.3); }
        .node.sentinel { border-left-color: #ff0000; }
        .node.explorer { border-left-color: #ffff00; }
        .node-id { font-weight: bold; color: #00ffff; }
        .node-role { font-size: 10px; color: #888; }
        .node-stats { font-size: 11px; margin-top: 5px; color: #666; }

        /* Events */
        .events {
            max-height: 250px;
            overflow-y: auto;
        }
        .event {
            padding: 8px;
            margin: 4px 0;
            border-radius: 4px;
            font-size: 11px;
            background: rgba(0, 0, 0, 0.2);
        }
        .event.alarm { border-left: 2px solid #ff0000; }
        .event.election { border-left: 2px solid #ff00ff; }
        .event.kv { border-left: 2px solid #00ffff; }
        .event.task { border-left: 2px solid #ffff00; }
        .event.job { border-left: 2px solid #00ff00; }

        /* Status Bar */
        .status-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(10, 10, 10, 0.95);
            padding: 12px 20px;
            border-top: 1px solid #333;
            font-size: 12px;
            display: flex;
            justify-content: space-between;
            backdrop-filter: blur(10px);
        }
        .pulse { animation: pulse 1s infinite; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Compute Power Visualization */
        .compute-viz {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100px;
            position: relative;
        }
        .compute-core {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: radial-gradient(circle, #00ffff 0%, transparent 70%);
            position: absolute;
            animation: computePulse 2s infinite;
        }
        .compute-ring {
            width: 100px;
            height: 100px;
            border: 2px solid rgba(0, 255, 255, 0.3);
            border-radius: 50%;
            position: absolute;
            animation: ringPulse 2s infinite;
        }
        @keyframes computePulse {
            0%, 100% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.2); opacity: 1; }
        }
        @keyframes ringPulse {
            0% { transform: scale(1); opacity: 0.5; }
            100% { transform: scale(2); opacity: 0; }
        }
        .compute-power {
            font-size: 24px;
            font-weight: bold;
            color: #00ffff;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>NanOS SWARM ORCHESTRATOR</h1>
        <p class="subtitle">Global Distributed Computing Dashboard v0.4</p>

        <div class="stat-grid" style="margin-bottom: 20px;">
            <div class="stat">
                <div class="stat-value" id="node-count">0</div>
                <div class="stat-label">Active Nodes</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="compute-power">0</div>
                <div class="stat-label">GFLOPS (est.)</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="jobs-running">0</div>
                <div class="stat-label">Jobs Running</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="jobs-completed">0</div>
                <div class="stat-label">Jobs Completed</div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>SUBMIT COMPUTE JOB</h2>
                <div class="job-form">
                    <div class="form-row">
                        <label>Job Type:</label>
                        <select id="job-type">
                            <option value="1">Prime Search - Find primes in range</option>
                            <option value="2">Monte Carlo Pi - Estimate Pi</option>
                            <option value="4">Parallel Sum - Sum numbers in range</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>Range Start:</label>
                        <input type="number" id="param1" value="1" min="1">
                    </div>
                    <div class="form-row">
                        <label>Range End:</label>
                        <input type="number" id="param2" value="10000" min="1">
                    </div>
                    <div class="form-row">
                        <label>Chunks:</label>
                        <input type="number" id="chunks" value="4" min="1" max="16">
                    </div>
                    <button onclick="submitJob()">LAUNCH JOB</button>
                </div>
            </div>

            <div class="card">
                <h2>ACTIVE JOBS</h2>
                <div class="job-list" id="job-list"></div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>SWARM NODES</h2>
                <div id="nodes"></div>
            </div>

            <div class="card">
                <h2>EVENT LOG</h2>
                <div class="events" id="events"></div>
            </div>
        </div>
    </div>

    <div class="status-bar">
        <span>NanOS Swarm Orchestrator v0.4</span>
        <span id="status" class="pulse">Connecting...</span>
        <span id="last-update">--</span>
    </div>

    <script>
        async function fetchState() {
            try {
                const response = await fetch('/api/state');
                const state = await response.json();
                updateDashboard(state);
                document.getElementById('status').textContent = 'Connected';
                document.getElementById('status').className = '';
            } catch (e) {
                document.getElementById('status').textContent = 'Disconnected';
                document.getElementById('status').className = 'pulse';
            }
        }

        function updateDashboard(state) {
            const nodes = Object.values(state.nodes);
            const jobs = Object.values(state.jobs || {});

            // Stats
            document.getElementById('node-count').textContent = nodes.length;
            document.getElementById('compute-power').textContent = (nodes.length * 0.5).toFixed(1);
            document.getElementById('jobs-running').textContent = jobs.filter(j => j.status === 'running').length;
            document.getElementById('jobs-completed').textContent = jobs.filter(j => j.status === 'completed').length;

            // Last update
            if (state.last_update > 0) {
                const ago = Math.round((Date.now() / 1000) - state.last_update);
                document.getElementById('last-update').textContent = `Updated ${ago}s ago`;
            }

            // Nodes
            const nodesHtml = nodes.map(n => {
                const roleClass = n.role.toLowerCase();
                return `
                    <div class="node ${roleClass}">
                        <div class="node-id">${n.node_id.slice(-4)}</div>
                        <div class="node-role">${n.role}</div>
                        <div class="node-stats">RX:${n.rx} TX:${n.tx}</div>
                    </div>
                `;
            }).join('');
            document.getElementById('nodes').innerHTML = nodesHtml || '<div style="color:#666">No nodes detected</div>';

            // Jobs
            const jobsHtml = jobs.slice(-10).reverse().map(j => {
                const progress = j.chunks_total > 0 ? (j.chunks_done / j.chunks_total * 100) : 0;
                return `
                    <div class="job-item ${j.status}">
                        <div class="job-header">
                            <span class="job-id">Job #${j.id}</span>
                            <span class="job-type">${j.type_name}</span>
                        </div>
                        <div class="job-progress">
                            <div class="job-progress-bar" style="width: ${progress}%"></div>
                        </div>
                        <div class="job-result">
                            ${j.status === 'completed' ? 'Result: ' + j.result :
                              j.status === 'running' ? `Progress: ${j.chunks_done}/${j.chunks_total} chunks` :
                              j.status}
                        </div>
                    </div>
                `;
            }).join('');
            document.getElementById('job-list').innerHTML = jobsHtml || '<div style="color:#666">No jobs submitted</div>';

            // Events
            const eventsHtml = state.events.slice(-15).reverse().map(e => {
                return `<div class="event ${e.type}">[${e.node}] ${e.message}</div>`;
            }).join('');
            document.getElementById('events').innerHTML = eventsHtml || '<div style="color:#666">No events</div>';
        }

        async function submitJob() {
            const jobType = document.getElementById('job-type').value;
            const param1 = document.getElementById('param1').value;
            const param2 = document.getElementById('param2').value;
            const chunks = document.getElementById('chunks').value;

            try {
                const response = await fetch('/api/job/submit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: parseInt(jobType),
                        param1: parseInt(param1),
                        param2: parseInt(param2),
                        chunks: parseInt(chunks)
                    })
                });
                const result = await response.json();
                if (result.success) {
                    console.log('Job submitted:', result.job_id);
                }
            } catch (e) {
                console.error('Failed to submit job:', e);
            }
        }

        // Poll every second
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
    print(f"  NanOS Swarm Orchestrator v0.4")
    print(f"  ==============================")
    print(f"")
    print(f"  Log directory: {args.log_dir}")
    print(f"  Dashboard:     http://localhost:{args.port}")
    print(f"")
    print(f"  Features:")
    print(f"    - Real-time swarm monitoring")
    print(f"    - Distributed job submission")
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
