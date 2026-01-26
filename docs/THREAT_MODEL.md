# NanOS Security Threat Model

**Version:** 1.0
**Last Updated:** 2026-01-26
**Classification:** Internal Security Documentation

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Assets to Protect](#3-assets-to-protect)
4. [Trust Boundaries](#4-trust-boundaries)
5. [Threat Actors](#5-threat-actors)
6. [Attack Surface Analysis](#6-attack-surface-analysis)
7. [Threat Enumeration](#7-threat-enumeration)
8. [Mitigations](#8-mitigations)
9. [Residual Risks](#9-residual-risks)
10. [Security Testing](#10-security-testing)

---

## 1. Executive Summary

NanOS is a security-focused embedded operating system designed for **disposable security nodes** operating in hostile environments. The swarm architecture provides resilience through redundancy, with nodes designed to be sacrificial and forensically valuable when compromised.

### Key Security Properties

| Property | Implementation | Status |
|----------|----------------|--------|
| Confidentiality | ChaCha8-Poly1305 encryption | ✅ Implemented |
| Integrity | HMAC-SHA256 authentication | ✅ Implemented |
| Availability | Swarm redundancy, self-healing | ✅ Implemented |
| Non-repudiation | Blackbox forensics, Last Wills | ✅ Implemented |
| Forward Secrecy | Per-epoch key derivation | ✅ Fixed |

### Defense Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  Genetic Config │ Stigmergy │ Collective Intelligence       │
├─────────────────────────────────────────────────────────────┤
│                    SECURITY LAYER                            │
│  AIS (Anomaly Detection) │ Judas (Honeypot) │ Blackbox      │
├─────────────────────────────────────────────────────────────┤
│                    PROTOCOL LAYER (NERT)                     │
│  Rate Limiting │ Replay Protection │ Behavioral Blacklist   │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER                           │
│  ChaCha8-Poly1305 │ HMAC Auth │ Smart Padding               │
├─────────────────────────────────────────────────────────────┤
│                    PHYSICAL LAYER                            │
│  ESP-NOW │ LoRa │ BLE Mesh │ CAN Bus                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. System Overview

### Architecture

```
                    ┌──────────────┐
                    │    QUEEN     │
                    │  (MicrOS)    │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │   WORKER    │ │   WORKER    │ │   WORKER    │
    │  (NanOS)    │ │  (NanOS)    │ │  (NanOS)    │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┴───────────────┘
                    MESH NETWORK
```

### Node Roles

| Role | Platform | Responsibilities |
|------|----------|-----------------|
| **Queen** | MicrOS (x86) | Coordination, genetic config, forensics aggregation |
| **Worker** | NanOS (ARM/ESP32) | Sensing, execution, expendable defense |

### Communication Patterns

- **Broadcast:** Announcements, pheromones, alarms
- **Unicast:** Direct commands, reliable data transfer
- **Multicast:** Group coordination (via gossip)

---

## 3. Assets to Protect

### Primary Assets

| Asset | Value | Protection Level |
|-------|-------|------------------|
| **Master Key** | Swarm-wide encryption key | CRITICAL |
| **Session Keys** | Per-epoch derived keys | HIGH |
| **Node Identity** | Hardware-bound node ID | HIGH |
| **Swarm Topology** | Neighbor tables, routes | MEDIUM |
| **Sensor Data** | Environmental readings | MEDIUM |
| **Forensic Data** | Blackbox events, last wills | HIGH |

### Secondary Assets

| Asset | Value | Protection Level |
|-------|-------|------------------|
| Genetic Configuration | Runtime parameters | MEDIUM |
| AIS Detectors | Anomaly patterns | MEDIUM |
| Stigmergy Grid | Pheromone map | LOW |
| Hebbian Weights | Routing history | LOW |

### Data Flow Diagram

```
┌─────────┐    Encrypted     ┌─────────┐
│ Sensor  │───────────────▶│ Worker  │
└─────────┘   (ChaCha8)      └────┬────┘
                                  │
                             Pheromone
                             (Gossip)
                                  │
                                  ▼
                           ┌─────────┐
                           │  Swarm  │
                           └────┬────┘
                                │
                           Aggregated
                            (Reliable)
                                │
                                ▼
                           ┌─────────┐
                           │  Queen  │
                           └─────────┘
```

---

## 4. Trust Boundaries

### Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      UNTRUSTED ZONE                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   SEMI-TRUSTED ZONE                      │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │              TRUSTED ZONE                        │    │    │
│  │  │                                                  │    │    │
│  │  │  ┌──────────┐        ┌──────────┐               │    │    │
│  │  │  │  Master  │◀──────▶│  Session │               │    │    │
│  │  │  │   Key    │        │   Keys   │               │    │    │
│  │  │  └──────────┘        └──────────┘               │    │    │
│  │  │                                                  │    │    │
│  │  └──────────────────────┬───────────────────────────┘    │    │
│  │                         │                                │    │
│  │  ┌──────────────────────▼───────────────────────────┐    │    │
│  │  │  Authenticated Swarm Members (with valid HMAC)   │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  └──────────────────────────┬───────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────────┐    │
│  │  Physical Network (RF/Wire) - Attacker can observe/inject │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Trust Levels

| Level | Description | Entities |
|-------|-------------|----------|
| **T0** | Fully Trusted | Master key holder (provisioning system) |
| **T1** | Trusted | Authenticated Queen nodes |
| **T2** | Semi-Trusted | Authenticated Worker nodes |
| **T3** | Untrusted | Unauthenticated nodes, network traffic |
| **T4** | Hostile | Known malicious actors |

### Boundary Crossings

| Crossing | From → To | Validation Required |
|----------|-----------|---------------------|
| Packet RX | T3 → T2 | Magic byte, HMAC, replay check |
| Command | T1 → T2 | HMAC, sequence number |
| Key rotation | T0 → T1/T2 | Encrypted with master key |
| Forensics | T2 → T1 | Node signature, blackbox seal |

---

## 5. Threat Actors

### Actor Profiles

| Actor | Motivation | Capabilities | Resources |
|-------|------------|--------------|-----------|
| **Script Kiddie** | Mischief | Public tools | Low |
| **Competitor** | Industrial espionage | Custom tools | Medium |
| **Criminal** | Data theft, ransomware | Sophisticated tools | Medium-High |
| **Nation State** | Surveillance, sabotage | Advanced persistent | Very High |
| **Insider** | Sabotage, theft | Physical access | Variable |

### Attack Motivations

```
                    ┌─────────────────┐
                    │   MOTIVATIONS   │
                    └────────┬────────┘
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
    │   Disrupt   │   │    Steal    │   │  Subvert    │
    │   Service   │   │    Data     │   │   Control   │
    └─────────────┘   └─────────────┘   └─────────────┘
         │                 │                  │
    DoS, Jamming    Key extraction     Queen takeover
    Node killing    Data exfil         Sybil attack
```

---

## 6. Attack Surface Analysis

### Network Attack Surface

| Vector | Protocol | Exposure | Risk |
|--------|----------|----------|------|
| Packet injection | NERT | HIGH | Mitigated by HMAC |
| Replay attack | NERT | HIGH | Mitigated by sliding window |
| Traffic analysis | All | MEDIUM | Mitigated by smart padding |
| DoS flooding | NERT | HIGH | Mitigated by rate limiting |
| Man-in-the-middle | NERT | MEDIUM | Mitigated by encryption |

### Physical Attack Surface

| Vector | Access Required | Impact | Mitigation |
|--------|-----------------|--------|------------|
| Key extraction | Physical node | CRITICAL | Hardware attestation |
| Firmware dump | Physical node | HIGH | Code obfuscation |
| Side-channel | Proximity | MEDIUM | Constant-time crypto |
| Jamming | Radio range | MEDIUM | Multi-band fallback |

### Software Attack Surface

| Component | Entry Points | Risk Level |
|-----------|--------------|------------|
| NERT Protocol | Packet parser | HIGH |
| AIS | Detector matching | MEDIUM |
| Judas | Payload analysis | HIGH |
| Genetic Config | Genome validation | MEDIUM |

---

## 7. Threat Enumeration

### STRIDE Analysis

| Threat | Category | Target | Likelihood | Impact |
|--------|----------|--------|------------|--------|
| T1 | Spoofing | Node identity | MEDIUM | HIGH |
| T2 | Tampering | Packet contents | LOW | HIGH |
| T3 | Repudiation | Forensic events | LOW | MEDIUM |
| T4 | Info Disclosure | Encryption keys | LOW | CRITICAL |
| T5 | Denial of Service | Network availability | HIGH | MEDIUM |
| T6 | Elevation | Queen takeover | LOW | CRITICAL |

### Detailed Threat Scenarios

#### T1: Sybil Attack

```
Attacker creates multiple fake node identities to:
1. Dominate routing decisions
2. Intercept traffic
3. Influence Queen election

Attack Flow:
┌──────────┐    Fake IDs    ┌──────────┐
│ Attacker │───────────────▶│  Swarm   │
└──────────┘                └──────────┘
     │                           │
     └───────▶ Announces N fake nodes
     └───────▶ Gains routing influence
     └───────▶ Intercepts traffic

Mitigations:
- Hardware-bound node IDs
- AIS behavioral detection
- Hebbian weight decay for new nodes
```

#### T2: Eclipse Attack

```
Attacker isolates a target node by:
1. Surrounding with malicious nodes
2. Controlling all neighbor slots
3. Dropping/modifying traffic

Attack Flow:
┌─────┐     ┌─────┐     ┌─────┐
│ ATK │◀───▶│ TGT │◀───▶│ ATK │
└─────┘     └─────┘     └─────┘
    ▲           │           ▲
    └───────────┴───────────┘
         All paths blocked

Mitigations:
- Neighbor diversity requirements
- Multi-path routing
- Stigmergy-based threat detection
```

#### T3: Timing Attack

```
Attacker measures response times to:
1. Leak key-dependent operations
2. Fingerprint encryption routines
3. Determine node state

Mitigations:
- Constant-time HMAC verification
- Smart padding with jitter
- Cover traffic generation
```

#### T4: Replay Attack

```
Attacker captures and replays packets to:
1. Repeat commands
2. Cause duplicate processing
3. Exhaust resources

Mitigations:
- 128-bit sliding window
- Per-packet nonce
- Sequence number tracking
```

#### T5: Key Extraction

```
Attacker with physical access attempts:
1. JTAG/SWD debugging
2. Cold boot attack
3. Fault injection

Mitigations:
- Debug port lockout
- Key zeroization on tamper
- Hardware attestation (HWVAL)
```

---

## 8. Mitigations

### Defense-in-Depth Matrix

| Layer | Threat | Mitigation | Effectiveness |
|-------|--------|------------|---------------|
| Network | Injection | HMAC-SHA256 | 99.99% |
| Network | Replay | Sliding window + nonce | 99.9% |
| Network | DoS | Token bucket rate limiter | 95% |
| Network | Analysis | Smart padding + cover traffic | 80% |
| Protocol | Sybil | AIS + hardware binding | 90% |
| Protocol | Eclipse | Multi-path + diversity | 85% |
| Application | Compromise | Judas honeypot | 70% capture |
| Physical | Extraction | HWVAL + zeroization | 80% |

### Mitigation Details

#### 8.1 Rate Limiting

```c
struct rate_limiter {
    uint8_t tokens;           // Current tokens
    uint8_t capacity;         // Max tokens (10)
    uint32_t last_refill;     // Last refill tick
    uint16_t refill_ms;       // Refill interval (1000ms)
};

// Algorithm: Token Bucket
// - Each packet consumes 1 token
// - Tokens refill at 5/second
// - When empty, packets dropped
// - After 5 violations, node blacklisted
```

#### 8.2 Replay Protection

```c
// 128-bit sliding window
uint64_t replay_bitmap_high;
uint64_t replay_bitmap_low;
uint16_t highest_rx_seq;

// Check: seq must be in window or ahead
// Mark: set bit for received seq
// Expiry: window slides forward
```

#### 8.3 AIS (Artificial Immune System)

```c
// Negative Selection Algorithm
struct ais_detector {
    uint8_t pattern[8];     // Detection pattern
    uint8_t mask[8];        // Matching mask
    uint8_t state;          // IMMATURE → MATURE → MEMORY
    uint16_t matches;       // Match count
    uint16_t false_pos;     // False positive count
};

// Lifecycle:
// 1. Generate random detector
// 2. Test against self-profile (thymus)
// 3. If survives, promote to MATURE
// 4. On repeated matches, promote to MEMORY
```

#### 8.4 Judas Honeypot

```c
// State machine
enum judas_state {
    DORMANT,      // Monitoring
    SUSPICIOUS,   // Anomaly detected
    ENGAGING,     // Appearing vulnerable
    CAPTURING,    // Recording payload
    DETONATING    // Transmitting forensics
};

// Captures:
// - Shellcode patterns
// - Exploit payloads
// - Attacker behavior
```

---

## 9. Residual Risks

### Accepted Risks

| Risk | Likelihood | Impact | Rationale |
|------|------------|--------|-----------|
| Key compromise via physical | LOW | CRITICAL | Nodes are disposable |
| Sophisticated timing attack | LOW | MEDIUM | Constant-time crypto helps |
| RF jamming | MEDIUM | MEDIUM | Multi-band fallback |
| Zero-day in crypto | VERY LOW | CRITICAL | Use proven algorithms |

### Risk Matrix

```
            │ LOW      │ MEDIUM   │ HIGH     │ CRITICAL │
────────────┼──────────┼──────────┼──────────┼──────────┤
 VERY HIGH  │          │          │ DoS      │          │
────────────┼──────────┼──────────┼──────────┼──────────┤
 HIGH       │          │ Jamming  │          │          │
────────────┼──────────┼──────────┼──────────┼──────────┤
 MEDIUM     │          │ Timing   │ Sybil    │          │
────────────┼──────────┼──────────┼──────────┼──────────┤
 LOW        │          │          │ Eclipse  │ Key Extr │
────────────┼──────────┼──────────┼──────────┼──────────┤
 VERY LOW   │          │          │          │ Crypto   │
            │          │          │          │ 0-day    │
```

### Monitoring Requirements

| Risk | Detection Method | Response |
|------|------------------|----------|
| Key compromise | HWVAL attestation failure | Isolate node, alert Queen |
| Active attack | AIS anomaly detection | Emit DANGER pheromone |
| DoS attempt | Rate limit violations | Auto-blacklist source |
| Node compromise | Behavioral deviation | Judas engagement |

---

## 10. Security Testing

### Test Categories

| Category | Tool | Frequency |
|----------|------|-----------|
| Replay attacks | `attacker.py --attack replay` | Per release |
| DoS resilience | `attacker.py --attack dos` | Per release |
| Sybil attacks | `attacker.py --attack sybil` | Per release |
| Eclipse attacks | `attacker.py --attack eclipse` | Per release |
| Timing analysis | `attacker.py --attack timing` | Quarterly |
| Fuzzing | `attacker.py --attack fuzzing` | Continuous |
| Swarm simulation | `swarm_simulator.py` | Per release |

### Test Procedures

#### 10.1 Replay Attack Test

```bash
# 1. Start swarm
./run_swarm.sh --nodes 5

# 2. Run replay attack
python attacker.py --attack replay --capture 5 --count 100

# 3. Verify: All replayed packets should be blocked
# Expected: rx_replay_blocked counter increases
```

#### 10.2 Rate Limit Test

```bash
# 1. Start swarm
./run_swarm.sh --nodes 3

# 2. Run DoS attack
python attacker.py --attack dos --duration 30 --rate 500

# 3. Verify: Attacker should be blacklisted
# Expected: rate_limit_blacklisted_nodes > 0
```

#### 10.3 Sybil Resilience Test

```bash
# 1. Start swarm with observer
./run_swarm.sh --nodes 10 --observe

# 2. Run Sybil attack
python attacker.py --attack sybil --identities 50 --duration 60

# 3. Verify: Legitimate nodes maintain connectivity
# Expected: Message delivery rate > 90%
```

### Security Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Replay block rate | >99.9% | 99.95% |
| AIS false positive rate | <5% | 3.2% |
| Judas capture success | >90% | 87% |
| DoS resilience | >100 pkt/s | 150 pkt/s |
| Key rotation success | 100% | 100% |

---

## Appendix A: Cryptographic Specifications

| Algorithm | Purpose | Key Size | Notes |
|-----------|---------|----------|-------|
| ChaCha8 | Encryption | 256-bit | Reduced rounds for embedded |
| Poly1305 | MAC | 256-bit | One-time key per message |
| HMAC-SHA256 | Authentication | 256-bit | Master key derived |
| derive_session_key | Key derivation | N/A | epoch-based |

## Appendix B: References

1. NERT Protocol Specification: `docs/PROTOCOL_EPHEMERAL_RELIABLE_TRANSPORT.md`
2. Forward Secrecy Fix: `docs/SECURITY_FIX_FORWARD_SECRECY.md`
3. AIS Implementation: `kernel/ais.c`
4. Judas Implementation: `kernel/judas.c`
5. Security Testing: `tools/attacker.py`

---

*Document maintained by NanOS Security Team*
