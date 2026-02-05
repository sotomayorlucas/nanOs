# Getting Started with NanOS

Welcome to NanOS! This guide will help you get up and running with your first swarm.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Your First Swarm](#your-first-swarm)
5. [Understanding the Output](#understanding-the-output)
6. [Next Steps](#next-steps)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

**Want to see NanOS in action immediately?** If you're on a Linux system with Docker:

```bash
# Clone the repository
git clone https://github.com/sotomayorlucas/nanOs.git
cd nanOs

# Build and run (requires QEMU)
make
make run
```

In another terminal:

```bash
# Launch the tactical dashboard
cd nanOs
make dashboard
```

Open your browser to `http://localhost:8080` and watch your swarm come alive!

---

## Prerequisites

### Operating System

NanOS development works best on:
- **Linux** (Ubuntu 20.04+, Debian, Fedora, Arch)
- **macOS** (with Homebrew)
- **Windows** (with WSL2)

### Required Tools

#### For x86 Development

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential qemu-system-x86 grub-pc-bin xorriso mtools
```

**macOS:**
```bash
brew install qemu grub xorriso
brew tap nativeos/i386-elf-toolchain
brew install i386-elf-binutils i386-elf-gcc
```

**Fedora:**
```bash
sudo dnf install gcc make qemu grub2 xorriso
```

#### For ARM Development

```bash
# Ubuntu/Debian
sudo apt-get install gcc-arm-none-eabi qemu-system-arm

# macOS
brew install arm-none-eabi-gcc qemu
```

#### For ESP32 Development

```bash
# Install ESP-IDF
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
source export.sh

# Or use PlatformIO
pip install platformio
```

#### For Dashboard

```bash
# Python 3.7+
pip install flask flask-cors
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/sotomayorlucas/nanOs.git
cd nanOs
```

### 2. Verify Prerequisites

```bash
# Check for required tools
which i686-elf-gcc  # or gcc
which qemu-system-i386
which grub-mkrescue
```

If any are missing, install them using the instructions above.

### 3. Build NanOS

```bash
# Build x86 version
make

# Should produce: nanos-x86.iso
```

Expected output:
```
Compiling boot/boot.asm...
Compiling kernel/kernel.c...
Compiling drivers/e1000_minimal.c...
Linking kernel...
Creating ISO image...
Build complete: nanos-x86.iso
```

### 4. Test the Build

```bash
# Run single node
make run
```

You should see the NanOS boot message and heartbeat output.

---

## Your First Swarm

### Single Node

Test with a single node first:

```bash
make run
```

**What you'll see:**
```
NanOS v0.3 - Node #12345 (Worker)
Heartbeat...
Heartbeat...
```

Press `Ctrl+C` to stop.

### Multi-Node Swarm

Now launch a 3-node swarm:

```bash
make swarm
```

**What happens:**
- Three QEMU instances launch in the background
- Each node gets a random ID and role
- Nodes discover each other via multicast
- Heartbeats and messages propagate through the swarm

**View output:**

```bash
# Terminal 1
tail -f logs/node1.log

# Terminal 2
tail -f logs/node2.log

# Terminal 3
tail -f logs/node3.log
```

### Using the Dashboard

The easiest way to visualize your swarm:

```bash
# In a new terminal
make dashboard
```

Open browser to: `http://localhost:8080`

**You'll see:**
- **Network Graph**: Nodes and their connections
- **Role Distribution**: Queen, Workers, Explorers, Sentinels
- **Packet Timeline**: Message flow through the swarm
- **Controls**: Inject commands and start modules

### Stopping the Swarm

```bash
# Stop all QEMU instances
make stop-swarm

# Or manually
pkill -f qemu-system
```

---

## Understanding the Output

### Boot Sequence

```
NanOS v0.3 Initializing...
[+] Hardware initialized
[+] Network initialized (e1000)
[+] Node ID: 0x4A2F1C3B
[+] Role assigned: Worker
[+] Heartbeat: 1000ms
Ready. Entering reactive loop...
```

**What this means:**
- Hardware (NIC, timers) initialized
- Random node ID generated
- Role randomly assigned based on probabilities
- Node is now listening for packets

### Heartbeat Messages

```
[HELLO] From: 0x4A2F1C3B (Worker) TTL:16
[HELLO] From: 0x7B1E9A3C (Explorer) TTL:15
[HELLO] From: 0x9C4D2E1F (Sentinel) TTL:16
```

**Interpretation:**
- Each node broadcasts heartbeats
- Format: `[TYPE] From: ID (Role) TTL:remaining_hops`
- Explorers heartbeat more frequently (0.5s vs 1.0s)

### Packet Relay

```
[RX] HELLO from 0x7B1E9A3C
[GOSSIP] First seen, relaying...
[TX] HELLO TTL:15 -> multicast
```

**What's happening:**
1. Packet received from node `7B1E9A3C`
2. Gossip protocol checks if duplicate
3. Not seen before, so relay with TTL-1

### Gossip Deduplication

```
[RX] ALARM from 0x4A2F1C3B
[GOSSIP] Duplicate (seen 234ms ago), dropping
```

**Protection against broadcast storms:**
- Packet already seen 234ms ago
- Within immunity window (500ms)
- Don't relay again

### Role-Based Behavior

**Queen Command:**
```
[RX] QUEEN_CMD from 0x1F3E9A2D (Queen)
[AUTH] Verifying HMAC...
[AUTH] Valid! Executing command...
```

**Unauthorized Command:**
```
[RX] DIE from 0x4A2F1C3B (Worker)
[AUTH] Not authenticated or wrong role
[SECURITY] Command rejected
```

---

## Next Steps

### 1. Explore the Dashboard

Try these experiments:

**Inject an Alarm:**
- Click "Inject Alarm" in the dashboard
- Watch it propagate through all nodes
- Observe gossip deduplication

**Start Maze Exploration:**
- Click "Start x86 Maze"
- Watch nodes collaboratively explore
- See pheromone trails in the visualization

**Monitor Topology:**
- Observe node discovery
- Watch edges form as nodes communicate
- See the network graph evolve

### 2. Try ARM Swarm

```bash
# Build ARM version
make arm

# Launch ARM swarm
make swarm-arm3

# Start terrain exploration via dashboard
# Click "Start ARM Terrain"
```

### 3. Experiment with Code

**Change heartbeat interval** (kernel/kernel.c):
```c
// Make Workers heartbeat faster
if (role == ROLE_WORKER) {
    heartbeat_interval = 500;  // Was 1000
}
```

Rebuild and observe the difference:
```bash
make clean
make
make swarm
```

### 4. Add Custom Pheromone Type

**Define new type** (include/nanos.h):
```c
#define PHEROMONE_CUSTOM  0x90
```

**Handle it** (kernel/kernel.c):
```c
case PHEROMONE_CUSTOM:
    handle_custom_pheromone(pkt);
    break;
```

**Broadcast it:**
```c
void send_custom_message(void) {
    pheromone_t pkt = {0};
    pkt.type = PHEROMONE_CUSTOM;
    // ... fill in other fields
    send_packet(&pkt);
}
```

### 5. Learn the Architecture

Read the detailed documentation:

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [API.md](API.md) - Programming interface
- [docs/manual/NanOS_Technical_Manual.pdf](docs/manual/NanOS_Technical_Manual.pdf) - Complete guide

### 6. Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Code style
- Testing procedures
- Submitting pull requests

---

## Troubleshooting

### Build Fails: "i686-elf-gcc not found"

**Problem:** Cross-compiler not installed

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install gcc

# macOS - use native gcc or install cross-compiler
brew tap nativeos/i386-elf-toolchain
brew install i386-elf-gcc
```

**Alternative:** Edit Makefile to use system gcc:
```makefile
CC = gcc
CFLAGS += -m32
```

### QEMU Doesn't Start

**Problem:** QEMU not installed or wrong version

**Check installation:**
```bash
which qemu-system-i386
qemu-system-i386 --version
```

**Install:**
```bash
# Ubuntu/Debian
sudo apt-get install qemu-system-x86

# macOS
brew install qemu
```

### Nodes Don't See Each Other

**Problem:** Multicast not working

**Symptoms:**
- Each node only sees its own heartbeats
- No packet relay
- Empty network graph in dashboard

**Solutions:**

1. **Check firewall:**
   ```bash
   # Allow multicast
   sudo ufw allow from 230.0.0.0/4
   ```

2. **Verify multicast routing:**
   ```bash
   route -n | grep 224.0.0.0
   ```

3. **Use alternative network backend:**
   Edit Makefile, change to socket UDP:
   ```makefile
   -netdev socket,id=net0,mcast=230.0.0.1:1234
   # to
   -netdev socket,id=net0,listen=:1234
   ```

### Dashboard Won't Start

**Problem:** Python dependencies missing

**Solution:**
```bash
pip install flask flask-cors

# Or use venv
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors
```

**Check it's running:**
```bash
curl http://localhost:8080/api/state
```

### Kernel Hangs on Boot

**Problem:** Network initialization stuck

**Debug:**
```bash
# Run with serial console
qemu-system-i386 -cdrom nanos-x86.iso -serial stdio
```

**Common causes:**
- e1000 driver issue (check PCI enumeration)
- Incorrect MAC address
- Missing network device in QEMU

### High Memory Usage

**Expected behavior:** Nodes trigger apoptosis at 90% heap

**Monitor:**
```bash
# Check logs for:
grep "APOPTOSIS" logs/*.log
```

**If too frequent:**
- Reduce number of neighbors tracked
- Decrease gossip cache size
- Optimize packet processing

---

## Performance Tuning

### For Development (More Logging)

```c
// kernel/kernel.c
#define DEBUG_VERBOSE 1
```

### For Production (Less Overhead)

```c
// include/nanos.h
#define DEBUG_VERBOSE 0
#define HEARTBEAT_INTERVAL 2000  // Slower heartbeats
#define GOSSIP_CACHE_SIZE 16     // Smaller cache
```

---

## Further Resources

### Documentation

- [README.md](README.md) - Project overview
- [README.es.md](README.es.md) - Documentación en español
- [EMBEDDED.md](EMBEDDED.md) - Embedded platforms
- [CHANGELOG.md](CHANGELOG.md) - Version history

### Protocol Details

- [docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md) - NERT protocol
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) - Security analysis
- [docs/RFC-NERT-001.txt](docs/RFC-NERT-001.txt) - NERT RFC

### Community

- GitHub Issues: Report bugs, request features
- Pull Requests: Contribute code
- Discussions: Ask questions, share ideas

---

## What's Next?

Now that you have NanOS running:

1. **Experiment**: Try different swarm sizes, roles, commands
2. **Build**: Create your own modules and applications
3. **Learn**: Read the architecture and protocol docs
4. **Contribute**: Share your improvements with the community

Welcome to the swarm!

---

*"The journey of a thousand nodes begins with a single `make run`."*
