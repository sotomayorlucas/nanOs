# NanOS Embedded Support

NanOS now supports ultra-low-cost microcontrollers for IoT, robotics, and sensor networks.

## Supported Platforms

| Platform | MCU | RAM | Network | Status |
|----------|-----|-----|---------|--------|
| ESP32 | Xtensa LX6 | 520KB | WiFi/ESP-NOW/BLE | Ready |
| RP2040 | ARM Cortex-M0+ | 264KB | SPI Radio | Planned |
| STM32F4 | ARM Cortex-M4 | 192KB | SPI/CAN | Planned |
| nRF52840 | ARM Cortex-M4 | 256KB | BLE Mesh/Thread | Planned |
| LoRa Generic | Various | 32KB+ | LoRa (SX127x) | Planned |

## Build Profiles

### Full (x86/QEMU)
- All features enabled
- 64KB heap, large tables
- For development and testing

### Standard (ESP32, RP2040)
- Core features + tactical
- 16KB heap
- WiFi/ESP-NOW networking

### Lite (LoRa nodes)
- Heartbeat + gossip only
- 4KB heap
- Compact 24-byte packets

### Minimal (ATmega class)
- Bare essentials
- 1KB heap
- Extreme power saving

## ESP32 Quick Start

### Prerequisites
```bash
# Install ESP-IDF (v5.0+)
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh
source export.sh
```

### Build
```bash
cd nanOs/arch/esp32
idf.py create-project nanos_swarm
cp -r . components/nanos/
idf.py build
idf.py flash monitor
```

### Wiring (ESP32 DevKit)

| Function | Pin |
|----------|-----|
| LED | GPIO 2 |
| Button | GPIO 0 |
| I2C SDA | GPIO 21 |
| I2C SCL | GPIO 22 |

## Network Options

### ESP-NOW (Default for ESP32)
- Range: ~200m outdoor
- Latency: <10ms
- No infrastructure needed
- Encrypted peer-to-peer

### LoRa (Long Range)
- Range: 2-15km
- Low bandwidth (50kbps)
- License-free ISM band
- Use compact packets

### BLE Mesh
- Range: ~100m
- Low power
- Good for indoor IoT

## Compact Packet Format

For LoRa and other low-bandwidth radios:

```
Standard: 64 bytes
Compact:  24 bytes (62% smaller)

Byte  Field        Size
0     magic        1     (0xAA)
1-2   node_id      2     (16-bit)
3     type         1
4     ttl_flags    1     (4+4 bits)
5     seq          1
6-7   dest_id      2
8     dist_hop     1     (4+4 bits)
9-16  payload      8
17-20 hmac         4     (truncated)
21-23 reserved     3
```

## Power Management

For battery-powered nodes:

```c
// Configuration in nanos_config.h
#define NANOS_DEEP_SLEEP        1
#define HEARTBEAT_INTERVAL_MS   5000   // 5s between heartbeats
#define NANOS_SLEEP_IDLE_MS     100    // Light sleep between ticks
```

Estimated battery life:
- 1000mAh + ESP32 + ESP-NOW: ~2 weeks
- 1000mAh + LoRa + deep sleep: ~6 months

## Application Examples

### Distributed Sensor Network
```c
// Read temperature every minute, share with swarm
void sensor_task(void) {
    int16_t temp = read_temperature();

    nanos_packet_t pkt;
    pkt.type = PHEROMONE_SENSOR;
    struct compact_sensor* s = (void*)pkt.payload;
    s->sensor_type = SENSOR_TEMPERATURE;
    s->value = temp;

    hal_net_send(&pkt, sizeof(pkt));
}
```

### Swarm Robotics
```c
// Share position with other robots
void broadcast_position(int16_t x, int16_t y, uint8_t heading) {
    nanos_packet_t pkt;
    pkt.type = PHEROMONE_ROBOT_POS;

    struct compact_robot_pos* pos = (void*)pkt.payload;
    pos->pos_x = x;
    pos->pos_y = y;
    pos->heading = heading;
    pos->battery = hal_battery_level();

    hal_net_send(&pkt, sizeof(pkt));
}
```

### Threat Detection Grid
```c
// Report detection to swarm
void report_detection(uint8_t type, uint8_t confidence,
                      int16_t x, int16_t y) {
    nanos_packet_t pkt;
    pkt.type = PHEROMONE_DETECT;

    struct compact_detect* det = (void*)pkt.payload;
    det->detect_type = type;
    det->confidence = confidence;
    det->pos_x = x;
    det->pos_y = y;

    hal_net_send(&pkt, sizeof(pkt));
}
```

## Memory Usage

| Profile | State RAM | Heap | Total |
|---------|-----------|------|-------|
| Full | ~8KB | 64KB | 72KB |
| Standard | ~2KB | 16KB | 18KB |
| Lite | ~512B | 4KB | 4.5KB |
| Minimal | ~256B | 1KB | 1.3KB |

## HAL Porting Guide

To port to a new platform:

1. Create `arch/yourplatform/hal_yourplatform.c`
2. Implement required functions:
   - `hal_init()` - Hardware setup
   - `hal_get_ticks()` - Millisecond counter
   - `hal_random()` - Random number
   - `hal_print()` - Console output
   - `hal_net_init/send/recv()` - Network
3. Add platform define to `nanos_config.h`
4. Build with `-DNANOS_PLATFORM_YOURPLATFORM`

## License

Same as NanOS core - MIT/Apache-2.0 dual license.
