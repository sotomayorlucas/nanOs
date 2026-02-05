# NanOS Architecture

**Version:** 0.4
**Last Updated:** 2026-02-05

## Table of Contents

1. [Overview](#overview)
2. [Design Philosophy](#design-philosophy)
3. [System Architecture](#system-architecture)
4. [Core Components](#core-components)
5. [Platform Abstraction](#platform-abstraction)
6. [Protocol Stack](#protocol-stack)
7. [Memory Architecture](#memory-architecture)
8. [Security Architecture](#security-architecture)
9. [Module System](#module-system)

---

## Overview

NanOS is a **unikernel operating system** designed for swarm intelligence applications. It runs on bare metal without userspace separation, filesystems, or traditional OS abstractions. The system is optimized for:

- **Minimal footprint**: ~24KB RAM on ARM, ~150KB on x86
- **Real-time responsiveness**: Event-driven, no scheduler overhead
- **Security**: Built-in cryptographic authentication and encryption
- **Resilience**: Distributed state, self-healing through apoptosis

### Key Characteristics

| Property | Implementation |
|----------|----------------|
| **Paradigm** | Reactive, event-driven |
| **Memory Model** | Volatile only, no persistence |
| **Networking** | Broadcast/multicast only, no TCP |
| **Execution Model** | Single-threaded, non-preemptive |
| **State Management** | Gossip protocol, message recirculation |
| **Security Model** | Immune system (authentication before trust) |

---

## Design Philosophy

### Biology over Bureaucracy

NanOS models itself after biological systems rather than traditional computing:

```
Traditional OS        →  NanOS Swarm
─────────────────────────────────────────
Process               →  Cell (Node)
Scheduler             →  Reactive loop
IPC                   →  Pheromones (Packets)
Filesystem            →  Volatile state
Authentication        →  Immune system
Load balancing        →  Role assignment
Fault tolerance       →  Apoptosis/Rebirth
```

### Core Principles

1. **Organized Chaos**: No central coordinator, emergent behavior
2. **Ephemeral State**: Memory is volatile, state lives in message circulation
3. **Silent by Default**: CPU sleeps when idle (`hlt`/`wfi`)
4. **Authenticate Before Trust**: All commands require verification
5. **Sacrificial Nodes**: Nodes are disposable, swarm is immortal

---

## System Architecture

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  APPLICATION LAYER                        │
│  ┌──────────┐ ┌──────────┐ ┌────────────┐               │
│  │  Maze    │ │ Terrain  │ │  Custom    │               │
│  │ Explorer │ │ Explorer │ │  Modules   │               │
│  └──────────┘ └──────────┘ └────────────┘               │
├──────────────────────────────────────────────────────────┤
│                   KERNEL LAYER                            │
│  ┌──────────────┐ ┌─────────────┐ ┌──────────────┐     │
│  │   Genetic    │ │  Collective │ │  Task        │     │
│  │ Configuration│ │ Intelligence│ │  Handler     │     │
│  └──────────────┘ └─────────────┘ └──────────────┘     │
├──────────────────────────────────────────────────────────┤
│                  SECURITY LAYER                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │   AIS    │ │  Judas   │ │ Blackbox │ │   HMAC   │   │
│  │ Anomaly  │ │ Honeypot │ │ Forensics│ │   Auth   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
├──────────────────────────────────────────────────────────┤
│                  PROTOCOL LAYER                           │
│  ┌────────────────────┐ ┌─────────────────────┐         │
│  │   Gossip Protocol  │ │   NERT (Reliable)   │         │
│  │   Deduplication    │ │   Encryption        │         │
│  │   Bloom Filter     │ │   Key Rotation      │         │
│  └────────────────────┘ └─────────────────────┘         │
├──────────────────────────────────────────────────────────┤
│                    HAL LAYER                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │   x86    │ │   ARM    │ │  ESP32   │ │   ...    │   │
│  │ e1000 NIC│ │Stellaris │ │  WiFi    │ │          │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└──────────────────────────────────────────────────────────┘
```

### Directory Structure

```
nanOs/
├── boot/               # x86 bootloader
│   └── boot.asm       # Multiboot2 entry
│
├── kernel/            # Core kernel
│   ├── kernel.c       # x86 reactive loop
│   ├── collective.c   # Swarm intelligence
│   ├── genetic_receiver.c  # Configuration
│   ├── task_handler.c # Async operations
│   ├── blackbox.c     # Forensics
│   ├── judas.c        # Honeypot
│   ├── protocol/      # Network protocols
│   │   ├── hmac.c
│   │   ├── nert_*.c   # NERT implementation
│   │   └── chacha8_poly1305.c
│   └── covert/        # Covert channels
│       ├── covert_optical.c
│       └── covert_manchester.c
│
├── arch/              # Platform-specific
│   ├── x86/
│   │   ├── hal_x86.c
│   │   ├── console_vga.c
│   │   └── serial_com.c
│   ├── arm-qemu/
│   │   ├── nanos_arm.c
│   │   ├── startup.c
│   │   ├── maze_arm.c
│   │   ├── terrain_arm.c
│   │   └── modules.h
│   ├── arm64/
│   │   └── hal_arm64.c
│   └── esp32/
│       └── hal_esp32.c
│
├── drivers/           # Hardware drivers
│   └── e1000_minimal.c
│
├── include/           # Public headers
│   ├── nanos.h        # Core types
│   ├── io.h           # I/O functions
│   └── e1000.h        # NIC driver
│
├── lib/               # Utilities
│   └── string.c       # String functions
│
├── dashboard/         # Web interface
│   └── nanos_dashboard.py
│
├── tools/            # Utilities
│   └── swarm_observer.py
│
└── docs/             # Documentation
    ├── manual/       # LaTeX manual
    ├── THREAT_MODEL.md
    └── PROTOCOL_*.md
```

---

## Core Components

### 1. Reactive Loop (Kernel)

The kernel is a simple event loop that processes incoming packets:

```c
void kernel_main(void) {
    // Initialize
    hal_init();
    role_init();
    network_init();
    
    // Reactive loop
    while (1) {
        // Process received packets
        while (packet_available()) {
            packet_t* pkt = receive_packet();
            process_packet(pkt);
        }
        
        // Handle periodic tasks
        if (time_for_heartbeat()) {
            send_heartbeat();
        }
        
        if (memory_critical()) {
            apoptosis();
        }
        
        // Sleep until next event
        hal_sleep_idle();
    }
}
```

### 2. Role System

Each node is assigned a role at boot (with re-roll on rebirth):

| Role | Probability | Heartbeat | Behavior |
|------|-------------|-----------|----------|
| **WORKER** | 75% | 1.0s | Process data, relay messages |
| **EXPLORER** | 12.5% | 0.5s | Fast discovery, frequent heartbeats |
| **SENTINEL** | 12.5% | 2.0s | Monitor anomalies, log contacts |
| **QUEEN** | 0.4% | 3.0s | Issue authenticated commands |

```c
typedef enum {
    ROLE_WORKER    = 0,  // 0b00
    ROLE_EXPLORER  = 1,  // 0b01
    ROLE_SENTINEL  = 2,  // 0b10
    ROLE_QUEEN     = 3   // 0b11
} node_role_t;
```

### 3. Gossip Protocol

Prevents broadcast storms through:

- **Deduplication Cache**: 32-entry circular buffer
- **Immunity Window**: 500ms ignore period
- **Probabilistic Decay**: 20% decrease per duplicate
- **Max Echo Limit**: Stop after 5 copies

```c
typedef struct {
    uint32_t packet_id;      // Hash of packet
    uint32_t first_seen_ms;  // Timestamp
    uint8_t  echo_count;     // Number of times seen
} gossip_entry_t;
```

### 4. Apoptosis (Cell Death)

Cells die and rebirth when:
- Heap usage > 90%
- Lifetime > 1 hour
- Manual DIE command (authenticated)

Process:
1. Emit REBIRTH pheromone
2. Reset heap
3. Generate new node ID
4. Re-roll role
5. Continue operation

---

## Platform Abstraction

### HAL (Hardware Abstraction Layer)

Each platform implements the HAL interface:

```c
// Core HAL functions
void     hal_init(void);
uint32_t hal_get_ticks(void);
uint32_t hal_random(void);
void     hal_print(const char* str);
void     hal_sleep_idle(void);

// Network HAL
void     hal_net_init(void);
void     hal_net_send(const uint8_t* data, size_t len);
int      hal_net_recv(uint8_t* buffer, size_t max_len);
```

### Platform-Specific Details

#### x86 (QEMU)

- **Boot**: Multiboot2 via GRUB
- **NIC**: Intel e1000 (PCI)
- **Network**: Multicast UDP on 230.0.0.1:1234
- **Console**: VGA text mode
- **Memory**: ~150KB total

#### ARM Cortex-M3 (QEMU Stellaris)

- **Boot**: Vector table + startup code
- **NIC**: Stellaris Ethernet controller
- **Network**: Socket multicast
- **Console**: UART
- **Memory**: ~24KB total

#### ESP32 (Real Hardware)

- **Boot**: ESP-IDF bootloader
- **Network**: WiFi with ESP-NOW
- **Console**: UART over USB
- **Memory**: ~18KB for NanOS

---

## Protocol Stack

### Packet Formats

#### Standard Format (x86) - 64 bytes

```c
struct nanos_pheromone {
    uint32_t magic;       // 0x4E414E4F ("NANO")
    uint32_t node_id;     // Random ID
    uint8_t  type;        // Pheromone type
    uint8_t  ttl;         // Time-to-live
    uint8_t  flags;       // AUTH | ROLE
    uint8_t  version;     // Protocol version
    uint32_t seq;         // Sequence number
    uint8_t  hmac[8];     // Authentication
    uint8_t  payload[40]; // Data
};
```

#### Compact Format (ARM/ESP32) - 24 bytes

```c
typedef struct __attribute__((packed)) {
    uint8_t  magic;       // 0xAA
    uint16_t node_id;     // 16-bit ID
    uint8_t  type;        // Type
    uint8_t  ttl_flags;   // TTL(4) | Flags(4)
    uint8_t  seq;         // Sequence
    uint16_t dest_id;     // Destination
    uint8_t  dist_hop;    // Distance(4) | Hop(4)
    uint8_t  payload[8];  // Data
    uint8_t  hmac[4];     // Auth
    uint8_t  reserved[3]; // Padding
} arm_packet_t;
```

### NERT (NanOS Ephemeral Reliable Transport)

Optional reliable transport layer with:

- **Encryption**: ChaCha8-Poly1305
- **Authentication**: Poly1305 MAC
- **Reliability**: SACK + retransmission
- **Forward Secrecy**: Per-epoch key derivation
- **FEC**: XOR parity for packet recovery

---

## Memory Architecture

### x86 Memory Map

```
0x00100000  ┌──────────────────┐
            │   Kernel Code    │  ~30KB
            ├──────────────────┤
            │   Kernel Data    │  ~10KB
            ├──────────────────┤
            │   Stack          │  16KB
            ├──────────────────┤
            │   Heap           │  64KB
            ├──────────────────┤
            │   RX Buffers     │  64KB
            ├──────────────────┤
            │   TX Queue       │  2KB
            └──────────────────┘
            Total: ~150KB
```

### ARM Memory Map

```
0x20000000  ┌──────────────────┐
            │   .data/.bss     │  ~4KB
            ├──────────────────┤
            │   Stack          │  4KB
            ├──────────────────┤
            │   Heap           │  16KB
            ├──────────────────┤
            │   Neighbor Table │  512B
            └──────────────────┘
            Total: ~24KB
```

### Memory Management

- **Allocation**: Simple bump allocator or dlmalloc
- **No Free**: Most allocations are permanent
- **Apoptosis**: Reset entire heap when >90% full
- **Stack**: Fixed size, no overflow detection

---

## Security Architecture

### Defense in Depth

1. **Cryptographic Layer**
   - ChaCha8-Poly1305 encryption (optional)
   - HMAC-SHA256 authentication (mandatory for commands)
   - Key derivation with forward secrecy

2. **Protocol Layer**
   - Rate limiting per node
   - Replay protection (nonce tracking)
   - Behavioral blacklist

3. **Application Layer**
   - AIS (Artificial Immune System) anomaly detection
   - Judas honeypot nodes
   - Blackbox forensic recording

### Authentication Flow

```
Sender                          Receiver
  │                                │
  ├─► Generate HMAC ───────────────►
  │   HMAC = SHA256(key, packet)   │
  │                                │
  │   ┌─────────────────────┐      │
  │   │ Verify HMAC         │◄─────┤
  │   │ Check role          │      │
  │   │ Validate command    │      │
  │   └─────────────────────┘      │
  │                                │
  ◄──────── Execute/Reject ────────┤
```

### Command Authorization

| Command | Auth Required | Role Required |
|---------|---------------|---------------|
| HELLO | No | Any |
| DATA | No | Any |
| ALARM | No | Any |
| QUEEN_CMD | **Yes** | Queen |
| REBIRTH | **Yes** | Any (self) |
| DIE | **Yes** | Queen |

---

## Module System

### Module Architecture

Modules are self-contained exploration or application subsystems:

```c
typedef struct {
    const char* name;
    void (*init)(void);
    void (*process)(const uint8_t* payload);
    void (*tick)(void);
} module_t;
```

### Built-in Modules

#### Maze Explorer

- Collaborative pathfinding
- Pheromone trail scoring
- Wall detection sharing
- Solved state propagation

#### Terrain Explorer

- Procedural terrain generation
- Fog-of-war exploration
- Threat detection
- Strategic movement

### Module Registration

```c
// In modules.h
extern module_t maze_module;
extern module_t terrain_module;

// In kernel initialization
register_module(&maze_module);
register_module(&terrain_module);
```

---

## Performance Characteristics

### Latency

| Operation | Typical | Worst Case |
|-----------|---------|------------|
| Packet RX | 50μs | 200μs |
| HMAC Verify | 100μs | 500μs |
| Packet TX | 100μs | 1ms |
| Gossip Check | 20μs | 100μs |

### Throughput

| Platform | Packets/sec |
|----------|-------------|
| x86 | ~10,000 |
| ARM Cortex-M3 | ~1,000 |
| ESP32 | ~500 |

### Scalability

Tested with:
- **Local swarms**: Up to 50 nodes
- **Network topology**: Full mesh (multicast)
- **Gossip overhead**: O(N) per broadcast

---

## Build System

### Makefile Targets

```bash
make              # Build x86 ISO
make run          # Single x86 node
make swarm        # 3-node x86 swarm
make swarm5       # 5-node x86 swarm

make arm          # Build ARM binary
make swarm-arm3   # 3-node ARM swarm
make swarm-arm5   # 5-node ARM swarm

make dashboard    # Launch web dashboard
make clean        # Clean build artifacts
```

### Cross-Compilation

```bash
# x86
i686-elf-gcc -ffreestanding -nostdlib ...

# ARM
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb ...

# ESP32
xtensa-esp32-elf-gcc ...
```

---

## Future Architecture

### Planned Enhancements

- [ ] More hardware platforms (RP2040, STM32, nRF52)
- [ ] LoRa support for long-range swarms
- [ ] Multi-hop gradient routing optimization
- [ ] Dynamic role migration
- [ ] Swarm partitioning detection
- [ ] Enhanced forensics with timeline reconstruction

---

## References

- [README.md](README.md) - Getting started
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md) - NERT spec
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) - Security analysis
- [docs/manual/](docs/manual/) - Technical manual (LaTeX)

---

*"The architecture of emergence: simple rules, complex behavior."*
