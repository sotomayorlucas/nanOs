# NanOS v0.3

**A Reactive Unikernel for Swarm Intelligence - Multi-Architecture**

NanOS is a minimal bare-metal operating system designed to run on thousands of disposable nodes that communicate via broadcast protocols to form a collective hive mind. Now supports x86, ARM Cortex-M3, and ESP32.

## What's New in v0.3

- **ARM Cortex-M3 Support**: Run swarms on QEMU ARM (lm3s6965evb Stellaris)
- **Modular Architecture**: Maze and terrain exploration as separate modules
- **Tactical Dashboard**: Web-based command center with ARM swarm control
- **ESP32 Support**: PlatformIO project for real hardware swarms
- **24-byte Compact Protocol**: Optimized packet format for embedded devices

## Supported Platforms

| Platform | Architecture | Network | Status |
|----------|-------------|---------|--------|
| x86 QEMU | i386 | e1000 NIC | Production |
| ARM QEMU | Cortex-M3 | Stellaris Ethernet | Production |
| ESP32 | Xtensa | WiFi/ESP-NOW | Experimental |

## Philosophy

- **Biology over Bureaucracy**: No scheduler, no userspace, no permissions, no filesystem. The kernel is a cell reacting to stimuli.
- **Organized Chaos**: No static IPs, no TCP connections. Everything is broadcast/multicast.
- **Ephemeral**: Memory is volatile. State is maintained by message recirculation (gossip), not disk storage.
- **Silent by Default**: If there are no events, the CPU sleeps (`hlt` / `wfi`).
- **Immune System**: Authenticate before you trust. Verify before you obey.

## Architecture

```
nanOs/
├── boot/
│   └── boot.asm              # x86 Multiboot2 header + entry point
├── kernel/
│   └── kernel.c              # Main x86 reactive loop (modular)
├── arch/
│   └── arm-qemu/
│       ├── startup.c         # ARM Cortex-M3 vector table & startup
│       ├── nanos_arm.c       # ARM kernel with ethernet
│       ├── modules.h         # Shared module interfaces
│       ├── maze_arm.c        # Maze exploration module
│       ├── terrain_arm.c     # Terrain exploration module
│       └── lm3s6965.ld       # ARM linker script
├── platformio/
│   └── nanos_swarm/          # ESP32 PlatformIO project
├── drivers/
│   └── e1000_minimal.c       # Intel e1000 NIC driver
├── include/
│   ├── nanos.h               # Core types, security, gossip
│   ├── io.h                  # Port I/O functions
│   └── e1000.h               # NIC driver header
├── dashboard/
│   └── nanos_dashboard.py    # Web-based tactical command center
├── tools/
│   └── swarm_observer.py     # CLI swarm visualization
├── linker.ld                 # x86 linker script
└── Makefile                  # Build system
```

## The Pheromone Protocol

### x86 Format (64 bytes)
```c
struct nanos_pheromone {
    uint32_t magic;       // 0x4E414E4F ("NANO")
    uint32_t node_id;     // Random ID assigned at boot
    uint8_t  type;        // Message type
    uint8_t  ttl;         // Hops remaining
    uint8_t  flags;       // Bit 0: authenticated, Bits 1-3: role
    uint8_t  version;     // Protocol version (0x02)
    uint32_t seq;         // Sequence number
    uint8_t  hmac[8];     // Truncated HMAC
    uint8_t  payload[40]; // Data
};
```

### ARM Compact Format (24 bytes)
```c
typedef struct __attribute__((packed)) {
    uint8_t  magic;       // 0xAA
    uint16_t node_id;     // 16-bit node ID
    uint8_t  type;        // Message type
    uint8_t  ttl_flags;   // TTL (4 bits) + flags (4 bits)
    uint8_t  seq;         // Sequence number
    uint16_t dest_id;     // Destination (0xFFFF = broadcast)
    uint8_t  dist_hop;    // Distance/hop count
    uint8_t  payload[8];  // Compact payload
    uint8_t  hmac[4];     // 4-byte HMAC
    uint8_t  reserved[3]; // Padding
} arm_packet_t;
```

## Pheromone Types

| Type | Code | Description | Auth Required |
|------|------|-------------|---------------|
| HELLO | 0x01 | Heartbeat | No |
| DATA | 0x02 | Information | No |
| ALARM | 0x03 | Danger alert | No |
| ECHO | 0x04 | Acknowledgment | No |
| QUEEN_CMD | 0x10 | Queen command | **Yes** |
| MAZE_INIT | 0x70 | Start maze exploration | No |
| MAZE_MOVE | 0x71 | Maze movement | No |
| MAZE_SOLVED | 0x73 | Maze solved | No |
| TERRAIN_INIT | 0x80 | Start terrain exploration | No |
| TERRAIN_REPORT | 0x81 | Terrain discovery | No |
| TERRAIN_THREAT | 0x82 | Threat detected | No |
| REBIRTH | 0xFE | Cell death | **Yes** |
| DIE | 0xFF | Kill command | **Yes** |

## Cell Roles

| Role | Probability | Heartbeat | Behavior |
|------|-------------|-----------|----------|
| **WORKER** | ~75% | 1.0s | Process data, relay messages |
| **EXPLORER** | ~12.5% | 0.5s | Fast discovery, frequent heartbeats |
| **SENTINEL** | ~12.5% | 2.0s | Monitor anomalies, log contacts |
| **QUEEN** | ~0.4% | 3.0s | Issue authenticated commands |

## Building & Running

### x86 QEMU Swarm
```bash
# Build ISO
make

# Run single node
make run

# Launch 3-node swarm
make swarm

# Launch 5-node swarm
make swarm5
```

### ARM QEMU Swarm
```bash
# Build ARM kernel (requires arm-none-eabi-gcc)
make arm

# Launch 3-node ARM swarm
make swarm-arm3

# Launch 5-node ARM swarm
make swarm-arm5
```

### ESP32 (PlatformIO)
```bash
cd platformio/nanos_swarm

# Build
pio run

# Upload to ESP32
pio run -t upload

# Monitor serial
pio device monitor
```

## Tactical Dashboard

The web-based dashboard provides real-time swarm control:

```bash
# Start dashboard (opens http://localhost:8080)
make dashboard
```

**Features:**
- Network topology visualization
- Maze exploration view
- Terrain exploration with fog-of-war
- x86 swarm injection (Alarm, Election, Threats)
- ARM swarm control (Start Maze, Start Terrain, Kill)
- Event log and packet timeline

### Dashboard API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/state` | GET | Current swarm state |
| `/api/maze/start` | POST | Start x86 maze |
| `/api/terrain/start` | POST | Start x86 terrain |
| `/api/arm/maze/start` | POST | Start ARM maze exploration |
| `/api/arm/terrain/start` | POST | Start ARM terrain exploration |
| `/api/arm/kill` | POST | Terminate ARM QEMU nodes |
| `/api/inject/alarm` | POST | Inject alarm pheromone |
| `/api/inject/election` | POST | Trigger election |

## ARM Modules

The ARM kernel supports modular exploration systems:

### Maze Module (`maze_arm.c`)
- Collaborative pathfinding
- Direction scoring with pheromone trails
- Wall detection and sharing
- Solved state propagation

### Terrain Module (`terrain_arm.c`)
- Procedural terrain generation
- Fog-of-war exploration
- Threat detection and reporting
- Strategic movement commands

Modules are activated via dashboard commands, not auto-start.

## Memory Model

### x86
- **Stack**: 16KB
- **Heap**: 64KB (apoptosis at 90%)
- **RX Buffers**: 64KB
- **TX Queue**: 2KB
- **Total**: ~150KB

### ARM Cortex-M3
- **Stack**: 4KB
- **Heap**: 16KB
- **Neighbors**: 512B
- **Total**: ~24KB

## Network Configuration

### x86 QEMU
Uses e1000 NIC with multicast:
```
-netdev socket,id=net0,mcast=230.0.0.1:1234
-device e1000,netdev=net0,mac=52:54:00:XX:XX:XX
```

### ARM QEMU
Uses Stellaris Ethernet with socket multicast:
```
-net nic,macaddr=52:54:00:XX:XX:XX
-net socket,mcast=230.0.0.1:1234
```

## Security (Immune System)

Critical commands require:
1. **FLAG_AUTHENTICATED** bit set
2. **Valid HMAC** with shared swarm secret
3. **Role verification** (Queens only for DIE)

## Gossip Protocol

Prevents broadcast storms:
1. **Deduplication Cache**: 32-entry circular buffer
2. **Immunity Window**: 500ms ignore after first seen
3. **Probabilistic Decay**: 20% decrease per duplicate
4. **Max Echoes**: Stop after 5 copies

## Apoptosis

Cells die and rebirth when:
- Heap exceeds 90%
- Lifetime exceeds 1 hour

On death: emit REBIRTH, reset heap, new ID, re-roll role.

## License

Public domain. Use it, break it, evolve it.

---

*"In the swarm, no cell is special. Every cell is essential."*
