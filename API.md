# NanOS API Documentation

**Version:** 0.4
**Last Updated:** 2026-02-05

## Table of Contents

1. [Core API](#core-api)
2. [Network API](#network-api)
3. [Security API](#security-api)
4. [HAL API](#hal-api)
5. [Protocol API](#protocol-api)
6. [Module API](#module-api)
7. [Dashboard API](#dashboard-api)

---

## Core API

### Role Management

#### `role_init()`

Initialize the role system and assign a random role to the node.

```c
void role_init(void);
```

**Behavior:**
- Assigns role based on probability distribution
- Sets heartbeat interval based on role
- Initializes role-specific state

**Role Distribution:**
- WORKER: 75%
- EXPLORER: 12.5%
- SENTINEL: 12.5%
- QUEEN: 0.4%

#### `get_role()`

Get the current node's role.

```c
node_role_t get_role(void);
```

**Returns:** Current role (ROLE_WORKER, ROLE_EXPLORER, ROLE_SENTINEL, or ROLE_QUEEN)

#### `get_role_name()`

Get human-readable role name.

```c
const char* get_role_name(node_role_t role);
```

**Parameters:**
- `role` - Role to get name for

**Returns:** String constant ("Worker", "Explorer", "Sentinel", or "Queen")

#### `set_role()`

Manually set the node's role (typically only used during rebirth).

```c
void set_role(node_role_t new_role);
```

**Parameters:**
- `new_role` - New role to assign

---

### Node Identity

#### `get_node_id()`

Get the current node's unique identifier.

```c
uint32_t get_node_id(void);  // x86
uint16_t get_node_id(void);  // ARM
```

**Returns:** Node ID (assigned at boot or rebirth)

**Note:** Node IDs are randomly generated and not guaranteed to be unique in very large swarms.

#### `regenerate_node_id()`

Generate a new random node ID (called during rebirth).

```c
void regenerate_node_id(void);
```

---

### Lifecycle Management

#### `apoptosis()`

Trigger cell death and rebirth.

```c
void apoptosis(void);
```

**Behavior:**
1. Emit REBIRTH pheromone
2. Reset heap allocator
3. Generate new node ID
4. Re-roll role assignment
5. Reset statistics
6. Continue execution

**Triggers:**
- Heap usage > 90%
- Lifetime > 1 hour
- Authenticated DIE command from Queen
- Manual call

---

## Network API

### Packet Transmission

#### `send_packet()`

Send a pheromone packet to the swarm.

```c
void send_packet(const pheromone_t* pkt);
```

**Parameters:**
- `pkt` - Pointer to initialized packet structure

**Example:**
```c
pheromone_t pkt = {0};
pkt.magic = PHEROMONE_MAGIC;
pkt.node_id = get_node_id();
pkt.type = PHEROMONE_HELLO;
pkt.ttl = 16;
pkt.flags = 0;
pkt.version = PROTOCOL_VERSION;
pkt.seq = get_next_seq();

send_packet(&pkt);
```

#### `broadcast_pheromone()`

High-level function to broadcast a typed pheromone.

```c
void broadcast_pheromone(uint8_t type, const uint8_t* payload, size_t payload_len);
```

**Parameters:**
- `type` - Pheromone type (PHEROMONE_HELLO, etc.)
- `payload` - Optional payload data (can be NULL)
- `payload_len` - Length of payload (0 if NULL)

**Example:**
```c
struct alarm_payload {
    uint8_t severity;
    uint32_t threat_id;
} alarm = {
    .severity = 5,
    .threat_id = 0x12345678
};

broadcast_pheromone(PHEROMONE_ALARM, (uint8_t*)&alarm, sizeof(alarm));
```

### Packet Reception

#### `receive_packet()`

Receive a packet from the network.

```c
pheromone_t* receive_packet(void);
```

**Returns:** Pointer to received packet, or NULL if none available

**Note:** Packet buffer is reused, copy data if needed beyond immediate use.

#### `packet_available()`

Check if packets are available.

```c
bool packet_available(void);
```

**Returns:** true if packets waiting, false otherwise

---

### Pheromone Types

```c
// Basic types
#define PHEROMONE_HELLO         0x01  // Heartbeat
#define PHEROMONE_DATA          0x02  // General data
#define PHEROMONE_ALARM         0x03  // Alert/warning
#define PHEROMONE_ECHO          0x04  // Acknowledgment

// Command types (require authentication)
#define PHEROMONE_QUEEN_CMD     0x10  // Queen command
#define PHEROMONE_REBIRTH       0xFE  // Cell rebirth
#define PHEROMONE_DIE           0xFF  // Kill command

// Maze exploration
#define PHEROMONE_MAZE_INIT     0x70  // Start maze
#define PHEROMONE_MAZE_MOVE     0x71  // Movement
#define PHEROMONE_MAZE_SOLVED   0x73  // Solved

// Terrain exploration
#define PHEROMONE_TERRAIN_INIT  0x80  // Start terrain
#define PHEROMONE_TERRAIN_REPORT 0x81 // Discovery
#define PHEROMONE_TERRAIN_THREAT 0x82 // Threat detected
```

---

## Security API

### HMAC Authentication

#### `hmac_sha256()`

Compute HMAC-SHA256 for authentication.

```c
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* output);
```

**Parameters:**
- `key` - Shared secret key
- `key_len` - Length of key in bytes
- `data` - Data to authenticate
- `data_len` - Length of data
- `output` - Buffer for 32-byte HMAC output

**Example:**
```c
uint8_t hmac[32];
hmac_sha256(swarm_key, 32, packet_data, packet_len, hmac);

// Use first 8 bytes for packet
memcpy(pkt.hmac, hmac, 8);
```

#### `verify_hmac()`

Verify HMAC of received packet.

```c
bool verify_hmac(const pheromone_t* pkt);
```

**Parameters:**
- `pkt` - Packet to verify

**Returns:** true if HMAC is valid, false otherwise

**Note:** Uses constant-time comparison to prevent timing attacks.

### Encryption (NERT)

#### `chacha8_poly1305_encrypt()`

Encrypt data with ChaCha8-Poly1305.

```c
void chacha8_poly1305_encrypt(const uint8_t* key,
                              const uint8_t* nonce,
                              const uint8_t* plaintext,
                              size_t len,
                              uint8_t* ciphertext,
                              uint8_t* tag);
```

**Parameters:**
- `key` - 32-byte encryption key
- `nonce` - 12-byte nonce (must be unique)
- `plaintext` - Data to encrypt
- `len` - Length of plaintext
- `ciphertext` - Output buffer (same size as plaintext)
- `tag` - Output buffer for 16-byte authentication tag

#### `chacha8_poly1305_decrypt()`

Decrypt and verify data.

```c
bool chacha8_poly1305_decrypt(const uint8_t* key,
                              const uint8_t* nonce,
                              const uint8_t* ciphertext,
                              size_t len,
                              const uint8_t* tag,
                              uint8_t* plaintext);
```

**Parameters:**
- `key` - 32-byte decryption key
- `nonce` - 12-byte nonce
- `ciphertext` - Encrypted data
- `len` - Length of ciphertext
- `tag` - 16-byte authentication tag
- `plaintext` - Output buffer

**Returns:** true if decryption and verification succeeded, false if authentication failed

---

### Key Management

#### `derive_epoch_key()`

Derive epoch-specific key for forward secrecy.

```c
void derive_epoch_key(const uint8_t* master_key,
                     uint32_t epoch,
                     uint8_t* epoch_key);
```

**Parameters:**
- `master_key` - 32-byte master secret
- `epoch` - Epoch number (increments periodically)
- `epoch_key` - Output buffer for 32-byte derived key

**Algorithm:** `epoch_key = HMAC-SHA256(master_key, "EPOCH" || epoch)`

---

## HAL API

### Hardware Abstraction Layer

All platforms must implement these functions.

#### `hal_init()`

Initialize hardware (serial, timers, network).

```c
void hal_init(void);
```

**Platform-specific behavior:**
- x86: Initialize VGA, serial, PIT, PIC, e1000
- ARM: Initialize UART, SysTick, Ethernet controller
- ESP32: Initialize WiFi, ESP-NOW, system timers

#### `hal_get_ticks()`

Get millisecond tick counter.

```c
uint32_t hal_get_ticks(void);
```

**Returns:** Milliseconds since boot (wraps at ~49 days)

**Note:** Must be monotonic and reasonably accurate (±10% acceptable)

#### `hal_random()`

Get random 32-bit value.

```c
uint32_t hal_random(void);
```

**Returns:** Pseudo-random or hardware random number

**Note:** Used for node ID, role assignment, jitter. Does not need to be cryptographically secure.

#### `hal_print()`

Print string to console/serial.

```c
void hal_print(const char* str);
```

**Parameters:**
- `str` - Null-terminated string to print

#### `hal_sleep_idle()`

Sleep CPU until next event.

```c
void hal_sleep_idle(void);
```

**Behavior:**
- x86: Execute `hlt` instruction
- ARM: Execute `wfi` instruction
- ESP32: Light sleep or `vTaskDelay(1)`

---

### Network HAL

#### `hal_net_init()`

Initialize network interface.

```c
void hal_net_init(void);
```

#### `hal_net_send()`

Send packet on network.

```c
void hal_net_send(const uint8_t* data, size_t len);
```

**Parameters:**
- `data` - Packet data
- `len` - Packet length

**Note:** Should use multicast/broadcast. Non-blocking preferred.

#### `hal_net_recv()`

Receive packet from network.

```c
int hal_net_recv(uint8_t* buffer, size_t max_len);
```

**Parameters:**
- `buffer` - Buffer to receive into
- `max_len` - Maximum bytes to receive

**Returns:** Number of bytes received, or 0 if none available

---

## Protocol API

### Gossip Protocol

#### `gossip_init()`

Initialize gossip deduplication cache.

```c
void gossip_init(void);
```

#### `gossip_should_relay()`

Check if packet should be relayed.

```c
bool gossip_should_relay(const pheromone_t* pkt);
```

**Parameters:**
- `pkt` - Packet to check

**Returns:** true if should relay, false if duplicate/expired

**Algorithm:**
1. Compute packet hash
2. Check if in cache (seen recently)
3. Apply immunity window (500ms)
4. Apply probabilistic decay (20% per duplicate)
5. Check echo count limit (max 5)

#### `gossip_record()`

Record packet in gossip cache.

```c
void gossip_record(const pheromone_t* pkt);
```

**Parameters:**
- `pkt` - Packet to record

---

### NERT Protocol

#### `nert_init()`

Initialize NERT reliable transport.

```c
void nert_init(void);
```

#### `nert_send_reliable()`

Send data with reliability and encryption.

```c
bool nert_send_reliable(uint32_t dest_id,
                       const uint8_t* data,
                       size_t len,
                       nert_reliability_t reliability);
```

**Parameters:**
- `dest_id` - Destination node ID (0xFFFFFFFF for broadcast)
- `data` - Data to send
- `len` - Data length
- `reliability` - Reliability class (NERT_UNRELIABLE, NERT_RELIABLE, NERT_GUARANTEED)

**Returns:** true if queued successfully, false if queue full

#### `nert_poll()`

Process NERT protocol (retransmissions, ACKs).

```c
void nert_poll(void);
```

**Note:** Should be called periodically (every 10-100ms)

---

## Module API

### Module Structure

```c
typedef struct {
    const char* name;              // Module name
    void (*init)(void);            // Initialize module
    void (*process)(const uint8_t* payload, size_t len);  // Process packet
    void (*tick)(void);            // Periodic update
} module_t;
```

### Module Registration

#### `register_module()`

Register a module with the kernel.

```c
void register_module(const module_t* module);
```

**Parameters:**
- `module` - Pointer to module structure

**Example:**
```c
void my_module_init(void) {
    // Initialize module state
}

void my_module_process(const uint8_t* payload, size_t len) {
    // Handle received packets
}

void my_module_tick(void) {
    // Periodic processing
}

const module_t my_module = {
    .name = "MyModule",
    .init = my_module_init,
    .process = my_module_process,
    .tick = my_module_tick
};

// In kernel init
register_module(&my_module);
```

---

## Dashboard API

The tactical dashboard exposes a REST API on `http://localhost:8080`.

### Endpoints

#### `GET /api/state`

Get current swarm state.

**Response:**
```json
{
    "nodes": [
        {
            "id": 12345,
            "role": "Worker",
            "last_seen": 1234567890,
            "position": {"x": 10, "y": 20}
        }
    ],
    "edges": [
        {"from": 12345, "to": 67890}
    ],
    "maze": { ... },
    "terrain": { ... }
}
```

#### `POST /api/inject/alarm`

Inject alarm pheromone into x86 swarm.

**Request:**
```json
{
    "severity": 5
}
```

**Response:**
```json
{
    "success": true,
    "message": "Alarm injected"
}
```

#### `POST /api/arm/maze/start`

Start maze exploration on ARM swarm.

**Request:** (empty)

**Response:**
```json
{
    "success": true,
    "message": "Maze exploration started"
}
```

#### `POST /api/arm/terrain/start`

Start terrain exploration on ARM swarm.

**Request:** (empty)

**Response:**
```json
{
    "success": true,
    "message": "Terrain exploration started"
}
```

#### `POST /api/arm/kill`

Terminate ARM QEMU nodes.

**Request:** (empty)

**Response:**
```json
{
    "success": true,
    "message": "ARM nodes terminated"
}
```

---

## Code Examples

### Example 1: Send Heartbeat

```c
void send_heartbeat(void) {
    pheromone_t pkt = {0};
    
    pkt.magic = PHEROMONE_MAGIC;
    pkt.node_id = get_node_id();
    pkt.type = PHEROMONE_HELLO;
    pkt.ttl = 16;
    pkt.flags = (get_role() << 1);
    pkt.version = PROTOCOL_VERSION;
    pkt.seq = get_next_seq();
    
    // Add timestamp to payload
    uint32_t* ts = (uint32_t*)pkt.payload;
    *ts = hal_get_ticks();
    
    send_packet(&pkt);
}
```

### Example 2: Process Received Packet

```c
void process_packet(const pheromone_t* pkt) {
    // Validate magic
    if (pkt->magic != PHEROMONE_MAGIC) {
        return;
    }
    
    // Check if we should relay
    if (!gossip_should_relay(pkt)) {
        return;  // Duplicate or expired
    }
    
    // Record in gossip cache
    gossip_record(pkt);
    
    // Handle based on type
    switch (pkt->type) {
        case PHEROMONE_HELLO:
            handle_hello(pkt);
            break;
        case PHEROMONE_ALARM:
            handle_alarm(pkt);
            break;
        case PHEROMONE_DIE:
            if (verify_hmac(pkt)) {
                apoptosis();
            }
            break;
        // ...
    }
    
    // Relay if TTL remaining
    if (pkt->ttl > 0) {
        pheromone_t relay = *pkt;
        relay.ttl--;
        send_packet(&relay);
    }
}
```

### Example 3: Authenticated Command

```c
void send_die_command(void) {
    if (get_role() != ROLE_QUEEN) {
        return;  // Only Queens can kill
    }
    
    pheromone_t pkt = {0};
    pkt.magic = PHEROMONE_MAGIC;
    pkt.node_id = get_node_id();
    pkt.type = PHEROMONE_DIE;
    pkt.ttl = 16;
    pkt.flags = FLAG_AUTHENTICATED | (ROLE_QUEEN << 1);
    pkt.version = PROTOCOL_VERSION;
    pkt.seq = get_next_seq();
    
    // Compute HMAC
    uint8_t hmac[32];
    hmac_sha256(swarm_key, 32, (uint8_t*)&pkt, 
                offsetof(pheromone_t, hmac), hmac);
    memcpy(pkt.hmac, hmac, 8);
    
    send_packet(&pkt);
}
```

---

## Error Handling

NanOS uses minimal error handling:

- **Network errors**: Silently dropped, rely on redundancy
- **Memory exhaustion**: Trigger apoptosis
- **Invalid packets**: Ignored or logged
- **Authentication failure**: Command rejected

**Philosophy:** The swarm is resilient. Individual nodes can fail without bringing down the system.

---

## Performance Tips

1. **Minimize allocations**: Use stack or static buffers when possible
2. **Batch operations**: Process multiple packets per iteration
3. **Optimize hot paths**: Gossip check is called frequently
4. **Use const**: Helps compiler optimize
5. **Avoid printf in hot paths**: Use counters instead

---

## Testing

```bash
# Test single node
make run

# Test swarm behavior
make swarm

# Monitor with observer
python3 tools/swarm_observer.py

# Use dashboard
make dashboard
```

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guide
- [docs/manual/](docs/manual/) - Complete technical manual

---

*"Simple APIs, emergent complexity."*
