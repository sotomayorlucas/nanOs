# NanOS Documentation Index

**Complete guide to all NanOS documentation resources**

---

## 📚 Quick Navigation

| Category | Document | Description |
|----------|----------|-------------|
| **Getting Started** | [GETTING_STARTED.md](GETTING_STARTED.md) | Step-by-step tutorial for new users |
| **Overview** | [README.md](README.md) | Project overview and quick reference |
| **Spanish** | [README.es.md](README.es.md) | Documentación en español |
| **Embedded** | [EMBEDDED.md](EMBEDDED.md) | ESP32, RP2040, LoRa support |

---

## 🏗️ Architecture & Design

### System Architecture
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Complete system architecture
  - Design philosophy (Biology over Bureaucracy)
  - Component breakdown (Kernel, HAL, Protocol, Security)
  - Memory architecture (x86, ARM, ESP32)
  - Module system
  - Performance characteristics

### API Reference
- **[API.md](API.md)** - Complete API documentation
  - Core API (roles, identity, lifecycle)
  - Network API (packet transmission/reception)
  - Security API (HMAC, encryption, key management)
  - HAL API (hardware abstraction)
  - Protocol API (gossip, NERT)
  - Module API
  - Dashboard API
  - Code examples

---

## 🔐 Security & Protocols

### Security Documentation
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** - Security threat analysis
  - Attack surface analysis
  - Threat enumeration
  - Defense layers (AIS, Judas, Blackbox)
  - Security testing procedures

- **[docs/SECURITY_FIX_FORWARD_SECRECY.md](docs/SECURITY_FIX_FORWARD_SECRECY.md)** - Forward secrecy implementation
  - Vulnerability analysis
  - Fix implementation
  - Key rotation mechanism

### Protocol Specifications
- **[docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md)** - NERT Protocol
  - Protocol overview and motivation
  - Packet format specifications
  - Cryptography (ChaCha8, Poly1305)
  - Reliability mechanisms (SACK, retransmission)
  - Forward Error Correction (FEC)
  - Multi-path transmission

- **[docs/RFC-NERT-001.txt](docs/RFC-NERT-001.txt)** - Formal NERT RFC
  - Formal protocol specification
  - Implementation requirements
  - Security considerations

---

## 🤝 Contributing

### Development Guides
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
  - Development process and workflow
  - Coding standards and style guide
  - Testing guidelines
  - Pull request process
  - Areas for contribution

- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** - Community guidelines
  - Behavior standards
  - Enforcement policies
  - The NanOS Way

### Version History
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
  - v0.4.0: NERT Protocol, encryption, task handler
  - v0.3.0: ARM support, modular architecture, dashboard
  - v0.2.0: Role system, gossip, security
  - v0.1.0: Initial x86 unikernel

- **[docs/MIGRATION_v0.4.md](docs/MIGRATION_v0.4.md)** - Migration guide
  - Upgrading from v0.3 to v0.4
  - Breaking changes
  - New features

---

## 📖 Technical Manual

### Complete Manual (LaTeX)
- **[docs/manual/NanOS_Technical_Manual.pdf](docs/manual/NanOS_Technical_Manual.pdf)** - Comprehensive manual
  - Part I: NanOS Core (philosophy, architecture, roles, protocol)
  - Part II: NERT Protocol (encryption, reliability, FEC)
  - Part III: Implementation Guide (compilation, API, debugging)
  - Appendices (configuration, glossary)
  - 4400+ lines of LaTeX with TikZ diagrams

- **[docs/manual/README.txt](docs/manual/README.txt)** - Manual build instructions
  - Prerequisites (TeX Live, packages)
  - Compilation steps
  - Manual structure overview

---

## 🛠️ Platform-Specific

### x86 (QEMU)
- **Platform**: i386 architecture
- **Network**: Intel e1000 NIC with multicast
- **Memory**: ~150KB total
- **Build**: `make && make run`
- **Swarm**: `make swarm` (3 nodes), `make swarm5` (5 nodes)

### ARM Cortex-M3 (QEMU Stellaris)
- **Platform**: ARM Cortex-M3
- **Network**: Stellaris Ethernet controller
- **Memory**: ~24KB total
- **Build**: `make arm`
- **Swarm**: `make swarm-arm3` (3 nodes), `make swarm-arm5` (5 nodes)
- **Modules**: Maze explorer, terrain explorer

### ESP32 (Real Hardware)
- **Platform**: Xtensa LX6
- **Network**: WiFi with ESP-NOW
- **Memory**: ~18KB for NanOS
- **Build**: `cd platformio/nanos_swarm && pio run`
- **Upload**: `pio run -t upload`

---

## 📝 Documentation by Topic

### For New Users
1. Start with [GETTING_STARTED.md](GETTING_STARTED.md)
2. Read [README.md](README.md) for overview
3. Try examples in [GETTING_STARTED.md](GETTING_STARTED.md)
4. Explore with [Dashboard](README.md#tactical-dashboard)

### For Developers
1. Read [ARCHITECTURE.md](ARCHITECTURE.md) for system design
2. Study [API.md](API.md) for programming interface
3. Review [CONTRIBUTING.md](CONTRIBUTING.md) for standards
4. Check [CHANGELOG.md](CHANGELOG.md) for recent changes

### For Security Researchers
1. Review [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
2. Study [docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md)
3. Examine [docs/SECURITY_FIX_FORWARD_SECRECY.md](docs/SECURITY_FIX_FORWARD_SECRECY.md)
4. Test with [Security Testing](docs/THREAT_MODEL.md#10-security-testing)

### For Embedded Developers
1. Read [EMBEDDED.md](EMBEDDED.md) for platform support
2. Check [HAL API](API.md#hal-api) for porting
3. Review compact packet format (24 bytes)
4. Explore ESP32 implementation

### For Protocol Designers
1. Study [docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md)
2. Read [docs/RFC-NERT-001.txt](docs/RFC-NERT-001.txt)
3. Review [Gossip Protocol](API.md#gossip-protocol)
4. Examine packet formats in [README.md](README.md#the-pheromone-protocol)

---

## 🎯 Common Tasks

### Building
```bash
make              # Build x86 ISO
make arm          # Build ARM binary
make clean        # Clean build artifacts
```

### Running
```bash
make run          # Single x86 node
make swarm        # 3-node x86 swarm
make swarm-arm3   # 3-node ARM swarm
make dashboard    # Launch web dashboard
```

### Documentation
```bash
cd docs/manual
make              # Build LaTeX manual
make view         # Open PDF
```

### Testing
```bash
# Manual testing
make run          # Test single node
make swarm        # Test multi-node
make dashboard    # Test visualization

# Monitor logs
tail -f logs/node1.log

# Use observer
python3 tools/swarm_observer.py
```

---

## 📊 Documentation Statistics

| Document | Lines | Words | Topics |
|----------|-------|-------|--------|
| GETTING_STARTED.md | 400+ | 4,000+ | Tutorials, troubleshooting |
| ARCHITECTURE.md | 600+ | 6,000+ | Design, components, memory |
| API.md | 700+ | 7,000+ | Functions, examples, usage |
| CONTRIBUTING.md | 350+ | 3,500+ | Standards, workflow, testing |
| THREAT_MODEL.md | 500+ | 5,000+ | Security, threats, mitigations |
| PROTOCOL_*.md | 1000+ | 10,000+ | NERT spec, crypto, reliability |
| Technical Manual | 4400+ | 20,000+ | Complete reference |
| **Total** | **~8,000** | **~56,000** | **All aspects** |

---

## 🔍 Finding Information

### Search Documentation
```bash
# Search all markdown files
grep -r "keyword" *.md docs/*.md

# Search code comments
grep -r "keyword" --include="*.c" --include="*.h"

# Search manual
cd docs/manual
grep "keyword" NanOS_Technical_Manual.tex
```

### Browse by File Type

**Markdown Documentation:**
```
.
├── README.md                   # Main overview
├── README.es.md                # Spanish version
├── GETTING_STARTED.md          # Tutorial
├── ARCHITECTURE.md             # System design
├── API.md                      # API reference
├── CONTRIBUTING.md             # Development guide
├── CHANGELOG.md                # Version history
├── CODE_OF_CONDUCT.md          # Community rules
├── EMBEDDED.md                 # Embedded platforms
└── docs/
    ├── THREAT_MODEL.md         # Security
    ├── PROTOCOL_*.md           # Protocols
    ├── MIGRATION_*.md          # Upgrades
    └── RFC-NERT-001.txt        # RFC
```

**Source Code:**
```
.
├── kernel/
│   ├── kernel.c                # Main x86 kernel
│   ├── collective.c            # Swarm intelligence
│   ├── task_handler.c          # Async tasks
│   └── protocol/
│       ├── hmac.c              # Authentication
│       └── nert_*.c            # NERT protocol
├── arch/
│   ├── x86/                    # x86 HAL
│   ├── arm-qemu/               # ARM HAL
│   └── esp32/                  # ESP32 HAL
└── include/
    └── nanos.h                 # Core types
```

---

## 🌐 External Resources

### Tools
- **Dashboard**: Web-based swarm control (`make dashboard`)
- **Observer**: CLI visualization (`python3 tools/swarm_observer.py`)
- **QEMU**: Virtual machine for testing
- **PlatformIO**: ESP32 development environment

### References
- **GitHub Repository**: [sotomayorlucas/nanOs](https://github.com/sotomayorlucas/nanOs)
- **Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Discussions**: Community Q&A

---

## 📚 Recommended Reading Order

### Beginner Path
1. [README.md](README.md) - Overview (10 min)
2. [GETTING_STARTED.md](GETTING_STARTED.md) - Tutorial (30 min)
3. Practice with dashboard (30 min)
4. [ARCHITECTURE.md](ARCHITECTURE.md) - System design (20 min)
5. [API.md](API.md) - Reference (as needed)

### Advanced Path
1. [ARCHITECTURE.md](ARCHITECTURE.md) - Deep dive (45 min)
2. [API.md](API.md) - Complete API (60 min)
3. [docs/manual/NanOS_Technical_Manual.pdf](docs/manual/NanOS_Technical_Manual.pdf) - Full manual (2-3 hours)
4. [docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md) - NERT (45 min)
5. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) - Security (30 min)

### Contributor Path
1. [CONTRIBUTING.md](CONTRIBUTING.md) - Guidelines (20 min)
2. [ARCHITECTURE.md](ARCHITECTURE.md) - System design (45 min)
3. [API.md](API.md) - API reference (60 min)
4. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community (5 min)
5. Source code exploration (variable)

---

## 💡 Documentation Philosophy

### The NanOS Documentation Way

- **Complete but Concise**: Cover everything, waste no words
- **Examples First**: Show, then explain
- **Multiple Formats**: Markdown for quick reference, LaTeX for deep dives
- **Multi-Lingual**: English primary, Spanish available
- **Living Documents**: Updated with each release

### Documentation Goals

1. **Accessible**: Beginners can start immediately
2. **Comprehensive**: Experts can find all details
3. **Accurate**: Code and docs stay synchronized
4. **Visual**: Diagrams explain complex concepts
5. **Searchable**: Easy to find information

---

## 🤔 Need Help?

### Can't Find What You Need?

1. **Search this index** for keywords
2. **Check the [GETTING_STARTED.md](GETTING_STARTED.md) troubleshooting** section
3. **Browse [API.md](API.md)** for function reference
4. **Review [ARCHITECTURE.md](ARCHITECTURE.md)** for design concepts
5. **Open a GitHub issue** if documentation is missing or unclear

### Want to Improve Documentation?

See [CONTRIBUTING.md](CONTRIBUTING.md) section on documentation:
- Fix typos or errors (pull request welcome!)
- Add examples or clarifications
- Translate to other languages
- Create tutorials or guides

---

*"Documentation is the roadmap to the swarm."*
