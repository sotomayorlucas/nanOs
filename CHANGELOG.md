# Changelog

All notable changes to NanOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CONTRIBUTING.md with contribution guidelines
- CHANGELOG.md for version tracking
- Enhanced documentation structure

## [0.4.0] - 2026-01-26

### Added
- **NERT Protocol**: Ephemeral Reliable Transport with forward secrecy
- ChaCha8-Poly1305 encryption for packet confidentiality
- Per-epoch key derivation with automatic rotation
- SACK (Selective Acknowledgment) for reliability
- Forward Error Correction (FEC) with XOR parity
- Multi-path transmission capability
- Task handler system for asynchronous operations
- Blackbox forensic system for post-mortem analysis
- Enhanced threat model documentation
- Security fix documentation for forward secrecy

### Changed
- Improved key rotation mechanism with grace windows
- Enhanced HMAC verification with constant-time comparison
- Optimized packet processing pipeline
- Refactored protocol layer for modularity

### Security
- Fixed forward secrecy implementation (CVE reference: RFC-NERT-001)
- Added behavioral blacklist for anomaly detection
- Implemented rate limiting for command packets
- Enhanced replay protection with nonce tracking

## [0.3.0] - 2025-12

### Added
- **ARM Cortex-M3 Support**: Run on QEMU ARM (lm3s6965evb Stellaris)
- **Modular Architecture**: Maze and terrain exploration as separate modules
- **Tactical Dashboard**: Web-based command center (Python Flask)
- **ESP32 Support**: PlatformIO project for real hardware swarms
- **Compact Protocol**: 24-byte packet format for embedded devices
- ARM swarm launch scripts (`make swarm-arm3`, `make swarm-arm5`)
- Terrain exploration module with fog-of-war
- Maze exploration module with collaborative pathfinding

### Changed
- Split kernel into platform-specific implementations
- Reorganized directory structure with `arch/` for platforms
- Improved Makefile with ARM targets
- Enhanced dashboard with ARM swarm control

### Platform Support
- x86 QEMU (i386, e1000 NIC) - Production
- ARM QEMU (Cortex-M3, Stellaris Ethernet) - Production
- ESP32 (Xtensa, WiFi/ESP-NOW) - Experimental

## [0.2.0] - 2025-11

### Added
- **Role System**: Queen, Worker, Explorer, Sentinel roles
- **Gossip Protocol**: Deduplication cache with immunity window
- **Apoptosis**: Cell death and rebirth mechanism
- **HMAC Authentication**: SHA256-based packet verification
- **Gradient Routing**: Distance-based message propagation
- **Bloom Filter**: Efficient membership testing
- Dashboard API endpoints
- Swarm observer CLI tool

### Changed
- Enhanced pheromone protocol (64-byte format)
- Improved security with role-based command restrictions
- Better memory management with heap monitoring
- Optimized multicast networking

### Security
- Added HMAC for authenticated commands
- Implemented role verification for QUEEN_CMD
- Added authentication flag in packet header
- Shared secret key for swarm security

## [0.1.0] - 2025-10

### Added
- **Initial Release**: Bare-metal x86 kernel
- Multiboot2 bootloader support
- e1000 NIC driver (Intel Gigabit Ethernet)
- Basic pheromone protocol
- Broadcast networking on multicast (230.0.0.1:1234)
- Random node ID assignment
- Heartbeat mechanism
- Basic packet types (HELLO, DATA, ALARM, ECHO)
- QEMU support with e1000 networking
- Multi-node swarm capability
- Makefile build system

### Architecture
- Unikernel design (no userspace, no filesystem)
- Event-driven reactive loop
- Volatile memory only (no persistence)
- Silent-by-default (CPU sleeps when idle)

### Philosophy
- Biology over bureaucracy
- Organized chaos
- Ephemeral state
- Immune system security

## Version History Summary

| Version | Date | Key Feature |
|---------|------|-------------|
| 0.1.0 | 2025-10 | Initial x86 unikernel |
| 0.2.0 | 2025-11 | Role system & security |
| 0.3.0 | 2025-12 | ARM support & dashboard |
| 0.4.0 | 2026-01 | NERT protocol & encryption |

## Migration Guides

- [Migrating from v0.3 to v0.4](docs/MIGRATION_v0.4.md)

## Security Advisories

- [NERT Forward Secrecy Fix](docs/SECURITY_FIX_FORWARD_SECRECY.md)
- [Threat Model](docs/THREAT_MODEL.md)

## Documentation

- [README](README.md) - Current version overview
- [EMBEDDED](EMBEDDED.md) - Embedded platform support
- [Technical Manual](docs/manual/NanOS_Technical_Manual.pdf) - Comprehensive guide
- [Protocol Specification](docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md)
- [RFC-NERT-001](docs/RFC-NERT-001.txt) - NERT protocol RFC

---

## Legend

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements and fixes

---

*"In the swarm, evolution never stops."*
