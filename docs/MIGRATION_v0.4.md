# Migration Guide: v0.3 → v0.4

This guide helps you migrate from NanOS v0.3 (monolithic kernel) to v0.4 (framework architecture).

## Overview of Changes

### Architectural Shift

**v0.3**: Tightly coupled kernel with embedded protocol
**v0.4**: Modular framework with pluggable components

### Key Differences

| Aspect | v0.3 | v0.4 |
|--------|------|------|
| **Initialization** | `nert_init()` | `nert_init_ex(&config)` |
| **Node ID** | Random at boot | Injected via config |
| **Master Key** | Hardcoded | Injected via config |
| **Message Handling** | Monolithic switch | Pub/Sub callbacks |
| **HAL** | Platform-specific files | Interface + implementations |
| **Testing** | Hardware required | Virtual PHY available |

## Migration Steps

### 1. Update Initialization Code

#### Before (v0.3)
```c
#include "nert.h"

int main(void) {
    // Node ID was auto-generated
    nert_init();

    // Master key was hardcoded in nert.c
    // No way to override

    while (1) {
        nert_process_incoming();
        nert_timer_tick();
    }
}
```

#### After (v0.4)
```c
#include "nert_phy_if.h"
#include "nert_config.h"

int main(void) {
    // Create PHY interface
    struct nert_phy_interface *phy = nert_phy_x86_get();
    // or: nert_phy_virtual_create(5555, "239.255.0.1");

    // Setup configuration
    struct nert_config config;
    uint8_t master_key[32] = {/* your key */};
    nert_config_init(&config, 0x1234, master_key, phy);

    // Initialize with config
    nert_init_ex(&config);

    while (1) {
        nert_process_incoming();
        nert_timer_tick();
    }
}
```

### 2. Convert Message Handlers

#### Before (v0.3)
```c
// In kernel.c
void process_pheromone(struct nanos_pheromone *pkt) {
    switch (pkt->type) {
        case PHEROMONE_ALARM:
            handle_alarm(pkt);
            break;
        case PHEROMONE_DATA:
            handle_data(pkt);
            break;
        // ... many more cases
    }
}
```

#### After (v0.4)
```c
// Separate handlers with callbacks
void handle_alarm(uint16_t sender_id, uint8_t msg_type,
                 const void *data, uint8_t len, void *ctx) {
    // Handle alarm
}

void handle_data(uint16_t sender_id, uint8_t msg_type,
                const void *data, uint8_t len, void *ctx) {
    // Handle data
}

// In main()
nert_config_add_handler(&config, PHEROMONE_ALARM, handle_alarm, NULL);
nert_config_add_handler(&config, PHEROMONE_DATA, handle_data, NULL);
```

### 3. Implement Custom HAL

If you have a custom platform (not x86/ARM/ESP32):

#### Before (v0.3)
```c
// Create nert_hal_myplatform.c
int nert_hal_send(const void *data, uint16_t len) {
    // Platform-specific send
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
    // Platform-specific receive
}

// ... other HAL functions
```

#### After (v0.4)
```c
#include "nert_phy_if.h"

static int my_send(const void *data, uint16_t len, void *ctx) {
    // Platform-specific send
}

static int my_receive(void *buffer, uint16_t max_len, void *ctx) {
    // Platform-specific receive
}

static uint32_t my_get_ticks(void *ctx) {
    // Return milliseconds since boot
}

static uint32_t my_random(void *ctx) {
    // Return random number
}

struct nert_phy_interface* nert_phy_myplatform_get(void) {
    static struct nert_phy_interface phy = {
        .send = my_send,
        .receive = my_receive,
        .get_ticks = my_get_ticks,
        .random = my_random,
        .context = NULL  // Or platform-specific context
    };
    return &phy;
}
```

### 4. Enable Security Features

#### New in v0.4
```c
// Enable replay protection
config.security.enable_replay_protection = 1;

// Enable key rotation
config.security.enable_key_rotation = 1;
config.security.key_rotation_period_sec = 3600;

// Register security event callback
config.security_callback = on_security_event;

void on_security_event(uint8_t event_type, uint16_t peer_id,
                       const char *details, void *ctx) {
    switch (event_type) {
        case NERT_SEC_EVENT_BAD_MAC:
            printf("Bad MAC from %04X\n", peer_id);
            break;
        case NERT_SEC_EVENT_REPLAY_BLOCKED:
            printf("Replay attack blocked from %04X\n", peer_id);
            break;
        // ... handle other events
    }
}
```

### 5. Add Payload Validation

#### New in v0.4
```c
// Register constraints for custom message types
nert_security_register_constraints(
    PHEROMONE_MY_CUSTOM,
    4,      // min_len
    32,     // max_len
    0       // variable size (not fixed)
);

// Payloads are automatically validated before delivery
```

## Build System Changes

### v0.3 Makefile
```makefile
nanos.bin: kernel.o nert.o ...
    ld -o $@ $^
```

### v0.4 Makefile
```makefile
# Option 1: Build as part of NanOS kernel
include lib/nert/Makefile

# Option 2: Build standalone application
demo_node: demo_node.c
    cd lib/nert && make demo
```

## Testing Changes

### v0.3: Hardware Required
```bash
# Could only test on real hardware or QEMU with networking
./qemu-arm.sh
```

### v0.4: Virtual Testing Available
```bash
# Test on localhost without QEMU
cd lib/nert
make demo

# Run virtual swarm
../../tools/run_swarm.sh --nodes 3

# Run security tests
../../tools/run_security_test.sh
```

## Backwards Compatibility

### Legacy API (v0.3)
The old API still works if you don't use the new config system:

```c
// Still supported in v0.4
nert_init();  // Uses defaults
nert_set_master_key(key);
nert_set_receive_callback(callback);
```

### Deprecated Functions
- `nert_hal_send()` → Use PHY interface
- `nert_hal_receive()` → Use PHY interface
- `nert_hal_get_node_id()` → Use config.node_id
- Global `receive_callback` → Use config handlers

## Common Migration Issues

### Issue 1: Undefined Reference to HAL Functions

**Problem:**
```
undefined reference to `nert_hal_send'
```

**Solution:**
Link with the appropriate HAL implementation:
```makefile
# Add HAL object to linker
LDFLAGS += lib/nert/hal/hal_virtual.o
```

### Issue 2: Callback Not Called

**Problem:**
Message handlers not receiving packets.

**Solution:**
Ensure handlers are registered BEFORE `nert_init_ex()`:
```c
nert_config_add_handler(&config, PHEROMONE_DATA, handler, NULL);
nert_init_ex(&config);  // Must be after handler registration
```

### Issue 3: Virtual PHY Socket Error

**Problem:**
```
Failed to create virtual PHY: Address already in use
```

**Solution:**
Another process is using the port. Either:
```bash
# Kill existing process
killall demo_node

# Or use different port
./demo_node --port 5556
```

## Performance Considerations

### v0.4 Overhead

The framework adds minimal overhead:
- **Callback dispatch**: ~10 CPU cycles
- **Configuration**: Zero runtime cost (initialization only)
- **HAL abstraction**: 1 function pointer dereference

### Memory Usage

- **v0.3**: Fixed allocations
- **v0.4**: Slightly more flexible (config structs)

Typical increase: 512 bytes for config structures

## Migration Checklist

- [ ] Update `#include` statements
- [ ] Create PHY interface (or use existing)
- [ ] Initialize `nert_config` structure
- [ ] Convert message handlers to callbacks
- [ ] Register handlers with `nert_config_add_handler()`
- [ ] Replace `nert_init()` with `nert_init_ex()`
- [ ] Update Makefile to link HAL
- [ ] Test with virtual PHY first
- [ ] Add security callbacks (optional)
- [ ] Register custom payload constraints (optional)

## Next Steps

1. **Read**: `README_v0.4.md` for full feature overview
2. **Study**: `lib/nert/examples/demo_node.c` for complete example
3. **Test**: Run `tools/run_security_test.sh` to verify
4. **Extend**: Implement custom HAL for your platform

## Getting Help

- **Issues**: File on GitHub
- **Questions**: See `docs/` directory
- **Examples**: Check `lib/nert/examples/`

---

**Note**: v0.3 code will continue to work, but new features require v0.4 API.
