# NanOS v0.4 - Secure Mesh Networking Framework

**From Operating System to Security Framework**

NanOS v0.4 represents a fundamental architectural shift: transforming from a monolithic unikernel into a **portable security framework** for IoT mesh networking. The NERT (NanOS Ephemeral Reliable Transport) protocol is now a standalone library that can be integrated into any embedded project.

## 🆕 What's New in v0.4

### Framework Architecture
- **🔌 Pluggable HAL**: Hardware abstraction layer allows NERT to run on any platform
- **⚙️ Configuration API**: Inject node identity, keys, and callbacks at runtime
- **📡 Pub/Sub Messaging**: Register handlers for specific message types
- **🔄 Virtual PHY**: UDP multicast implementation for testing without hardware

### Security Enhancements
- **🛡️ Input Validation**: Defensive payload checking prevents buffer overflows
- **🔐 Enhanced Key Management**: Foundation for dynamic key rotation (PHEROMONE_REKEY)
- **📊 Security Telemetry**: Callbacks for security events (bad MAC, replay attacks)
- **🧹 Key Wiping**: Secure memory cleanup during apoptosis

### Development Tools
- **🐍 Security Tester**: Python-based attack toolkit (`attacker.py`)
  - Replay attacks
  - Payload fuzzing
  - Fake Queen election
  - DoS flooding
- **🔧 Virtual Swarm**: Run complete mesh networks on localhost
- **🧪 Automated Testing**: End-to-end security test suite

## Architecture Evolution

### v0.3 (Monolithic)
```
┌─────────────────────────┐
│   Kernel (kernel.c)     │
│  ┌──────────────────┐   │
│  │  NERT Protocol   │   │
│  │  HAL (x86/ARM)   │   │
│  │  Security        │   │
│  └──────────────────┘   │
└─────────────────────────┘
```

### v0.4 (Framework)
```
┌──────────────────────────────────────┐
│         Your Application             │
│  ┌────────────────────────────────┐  │
│  │   Callbacks & Handlers         │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│      NERT Framework (lib/nert)       │
│  ┌────────────────────────────────┐  │
│  │  Protocol Core (nert.c)        │  │
│  │  Security (nert_security.c)    │  │
│  │  Config (nert_config.c)        │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│       HAL Interface (pluggable)      │
│  ┌──────────┬──────────┬──────────┐  │
│  │  x86     │   ARM    │  Virtual │  │
│  │  ESP32   │  Custom  │   ...    │  │
│  └──────────┴──────────┴──────────┘  │
└──────────────────────────────────────┘
```

## Project Structure

```
nanOs/
├── lib/nert/                    # 🆕 Framework library
│   ├── nert_phy_if.h           # HAL interface definition
│   ├── nert_config.h           # Configuration API
│   ├── nert_security.h         # Security extensions
│   ├── nert_config.c           # Config helpers
│   ├── nert_security.c         # Security implementation
│   ├── hal/
│   │   └── hal_virtual.c       # UDP multicast HAL
│   ├── examples/
│   │   └── demo_node.c         # Framework usage example
│   └── Makefile                # Framework build system
├── kernel/                      # Original NanOS kernel
│   └── protocol/               # Core protocol (to be migrated)
│       ├── nert.c
│       ├── bloom.c
│       ├── gossip.c
│       └── hmac.c
├── tools/
│   ├── attacker.py             # 🆕 Security testing toolkit
│   ├── run_swarm.sh            # 🆕 Virtual swarm launcher
│   └── run_security_test.sh    # 🆕 Automated test suite
└── docs/                        # Technical documentation
```

## Quick Start

### 1. Build the Framework

```bash
cd lib/nert
make demo
```

### 2. Run a Virtual Swarm

```bash
# Terminal 1: Start 3 nodes
../../tools/run_swarm.sh --nodes 3

# Terminal 2: Run security tests
../../tools/run_security_test.sh
```

### 3. Manual Attack Testing

```bash
# Start nodes
./examples/demo_node 1001 &
./examples/demo_node 1002 &
./examples/demo_node 1003 &

# Launch attacks
python3 ../../tools/attacker.py --attack replay --capture 5
python3 ../../tools/attacker.py --attack fuzzing --count 20
python3 ../../tools/attacker.py --attack fake-queen --duration 10
```

## Framework API Example

```c
#include "nert_phy_if.h"
#include "nert_config.h"
#include "nert_security.h"

// Message handler (pub/sub pattern)
void handle_alarm(uint16_t sender_id, uint8_t msg_type,
                 const void *data, uint8_t len, void *ctx) {
    printf("ALARM from %04X: %.*s\n", sender_id, len, (char*)data);
}

int main(void) {
    // 1. Create virtual PHY (or use platform-specific HAL)
    struct nert_phy_interface *phy =
        nert_phy_virtual_create(5555, "239.255.0.1");

    // 2. Initialize configuration
    struct nert_config config;
    uint8_t master_key[32] = {/* your key */};
    nert_config_init(&config, 0x1234, master_key, phy);

    // 3. Register message handlers
    nert_config_add_handler(&config, PHEROMONE_ALARM,
                           handle_alarm, NULL);

    // 4. Enable security features
    config.security.enable_replay_protection = 1;
    config.security.enable_key_rotation = 1;

    // 5. Initialize NERT
    nert_init_ex(&config);  // New in v0.4

    // 6. Main loop
    while (running) {
        nert_process_incoming();
        nert_timer_tick();

        // Send data
        nert_send_unreliable(0, PHEROMONE_DATA, "hello", 5);
    }

    // 7. Cleanup
    nert_security_wipe_keys();
    nert_phy_virtual_destroy(phy);
}
```

## Security Testing

### Replay Attack Detection

```bash
$ python3 tools/attacker.py --attack replay --capture 3 --count 10

[ATTACK] Replay Attack - replaying 10 packets
  Replaying packet 1/10: node_id=1001, seq=142
  Replaying packet 2/10: node_id=1002, seq=98
  ...

# Expected Result:
[Node 1001] Security Event: REPLAY_BLOCKED from 1002
[Node 1002] Security Event: REPLAY_BLOCKED from 1001
```

### Payload Fuzzing

```bash
$ python3 tools/attacker.py --attack fuzzing --count 20

[ATTACK] Fuzzing Attack - sending 20 malformed packets
  Fuzz 1: Oversized payload (actual 300, claimed 255)
  Fuzz 2: Undersized payload (actual 1, claimed 50)
  Fuzz 3: Invalid magic (0x7F)
  ...

# Expected Result:
[Node 1001] Security Event: INVALID_PAYLOAD from DEAD
[Node 1002] Security Event: BAD_MAC from DEAD
```

### Fake Queen Election

```bash
$ python3 tools/attacker.py --attack fake-queen --duration 10

[ATTACK] Fake Queen Attack - duration 10s
  Announcing fake Queen (ID=0xFFFF, priority=MAX)
  ...

# Expected Result:
Nodes should reject unauthenticated election messages
```

## Security Improvements (v0.3 → v0.4)

| Feature | v0.3 | v0.4 | Impact |
|---------|------|------|--------|
| **Hardcoded Keys** | ✗ | ✓ Configurable | Prevents key extraction |
| **Payload Validation** | ✗ | ✓ Defensive checks | Prevents buffer overflows |
| **Security Callbacks** | ✗ | ✓ Event hooks | Real-time attack detection |
| **Key Rotation** | ⚠️ Basic | ✓ Enhanced | Forward secrecy foundation |
| **Replay Protection** | ✓ | ✓ Enhanced | Per-connection bitmaps |
| **Virtual Testing** | ✗ | ✓ UDP multicast | Test without hardware |

## NERT Protocol Specification

### Header Format (x86 Full Mode)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic     | Ver + Class   |           Node ID             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Dest ID             |          Sequence             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          ACK Number           |     Flags     |  Payload Len  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Timestamp            |      TTL      |   Hop Count   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Nonce Counter                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Payload (variable)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Poly1305 MAC (8 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Reliability Classes

| Class | Code | Features | Use Case |
|-------|------|----------|----------|
| **Fire & Forget** | 0x00 | No ACK, no retry | Telemetry streams |
| **Best Effort** | 0x01 | Retry without ACK | Sensor updates |
| **Reliable** | 0x02 | ACK + retransmit | Commands |
| **Critical** | 0x03 | Reliable + FEC + multipath | Vital control |

### Security Features

- **ChaCha8**: Lightweight stream cipher (optimized for embedded)
- **Poly1305**: Authenticated encryption (8-byte MAC)
- **Epoch Keys**: Time-based key derivation (3600s rotation)
- **Grace Window**: 30s tolerance for clock drift
- **Replay Protection**: 64-bit sliding window bitmap

## Performance Characteristics

| Metric | x86 (e1000) | ARM (Cortex-M3) | ESP32 (ESP-NOW) |
|--------|-------------|-----------------|-----------------|
| **Throughput** | 10 Mbps | 100 Kbps | 250 Kbps |
| **Latency** | <1ms | <10ms | <20ms |
| **RAM Usage** | 32 KB | 8 KB | 16 KB |
| **Encryption** | ~500 KB/s | ~50 KB/s | ~100 KB/s |
| **Max Nodes** | 1000+ | 100+ | 250+ |

## Roadmap

### v0.4.1 (Current)
- [x] Framework architecture
- [x] Virtual PHY for testing
- [x] Security testing toolkit
- [x] Input validation
- [ ] Full key rotation implementation

### v0.5 (Planned)
- [ ] Complete PHEROMONE_REKEY protocol
- [ ] Reputation-based Queen election
- [ ] FEC (Forward Error Correction) completion
- [ ] Rust bindings
- [ ] Python bindings via CFFI

### v1.0 (Future)
- [ ] Formal security audit
- [ ] Performance optimization
- [ ] LoRa PHY implementation
- [ ] Zigbee PHY implementation
- [ ] RIOT-OS integration

## Use Cases

### 1. Industrial IoT Sensor Networks
- Deploy hundreds of disposable sensors
- Automatic mesh formation
- No infrastructure required
- Resilient to node failures

### 2. Edge Computing Swarms
- Distributed computation on low-power devices
- Ephemeral workload distribution
- Built-in security

### 3. Research & Education
- Protocol security research
- Mesh networking studies
- CTF challenges
- Embedded systems teaching

### 4. Security Testing
- Penetration testing of IoT devices
- Red team exercises
- Honeypot deployment

## Contributing

NanOS v0.4 is designed for security research and educational purposes. Contributions welcome:

1. **New HAL implementations**: Add support for your platform
2. **Security improvements**: Attack vectors, defenses
3. **Protocol extensions**: New pheromone types
4. **Testing**: More attack scenarios

## License

MIT License - See LICENSE file

## Citation

If you use NanOS in academic work:

```bibtex
@software{nanos2026,
  title = {NanOS: A Secure Mesh Networking Framework for IoT},
  author = {NanOS Project},
  year = {2026},
  version = {0.4},
  url = {https://github.com/sotomayorlucas/nanos}
}
```

## Acknowledgments

Inspired by:
- **Biological Systems**: Ant colonies, immune systems
- **Research**: Moving Target Defense, ephemeral computing
- **Protocols**: ZeroMQ, MQTT, CoAP

---

**⚠️ Security Notice**: NanOS v0.4 is experimental software. The cryptographic implementations are simplified for embedded systems and have not undergone formal security audits. Do not use in production systems without thorough review.

**🔬 Research Use**: Ideal for authorized security testing, CTF challenges, and academic research on mesh networking protocols.
