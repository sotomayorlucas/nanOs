/*
 * NanOS Configuration Header
 * Compile-time options for different platforms and resource constraints
 *
 * Usage: Define NANOS_PLATFORM before including this header
 *   -DNANOS_PLATFORM_X86       - Full PC/QEMU build (default)
 *   -DNANOS_PLATFORM_ESP32     - ESP32 with ESP-NOW/WiFi
 *   -DNANOS_PLATFORM_RP2040    - Raspberry Pi Pico
 *   -DNANOS_PLATFORM_STM32     - STM32F4 series
 *   -DNANOS_PLATFORM_NRF52     - Nordic nRF52840 (BLE)
 *   -DNANOS_PLATFORM_LORA      - Generic LoRa node
 *   -DNANOS_PLATFORM_MINIMAL   - Bare minimum (ATmega class)
 */
#ifndef NANOS_CONFIG_H
#define NANOS_CONFIG_H

/* ==========================================================================
 * Platform Detection & Defaults
 * ========================================================================== */

/* Default to x86 if no platform specified */
#if !defined(NANOS_PLATFORM_X86) && \
    !defined(NANOS_PLATFORM_ESP32) && \
    !defined(NANOS_PLATFORM_RP2040) && \
    !defined(NANOS_PLATFORM_STM32) && \
    !defined(NANOS_PLATFORM_NRF52) && \
    !defined(NANOS_PLATFORM_LORA) && \
    !defined(NANOS_PLATFORM_MINIMAL)
#define NANOS_PLATFORM_X86
#endif

/* ==========================================================================
 * Platform Profiles
 * ========================================================================== */

#if defined(NANOS_PLATFORM_X86)
/*
 * Full x86 build - QEMU/bare metal PC
 * RAM: Unlimited  Flash: Unlimited  Network: Ethernet
 */
#define NANOS_PROFILE_FULL
#define NANOS_HAS_VGA           1
#define NANOS_HAS_KEYBOARD      1
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_ETHERNET      1
#define NANOS_HAS_TIMER_PIT     1
#define NANOS_TICK_MS           10

#elif defined(NANOS_PLATFORM_ESP32)
/*
 * ESP32 - WiFi/BLE MCU
 * RAM: 520KB  Flash: 4MB  Network: WiFi/ESP-NOW/BLE
 */
#define NANOS_PROFILE_STANDARD
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_WIFI          1
#define NANOS_HAS_ESPNOW        1
#define NANOS_HAS_BLE           1
#define NANOS_HAS_NVS           1       /* Non-volatile storage */
#define NANOS_HAS_FREERTOS      1
#define NANOS_TICK_MS           10
#define NANOS_DEEP_SLEEP        1       /* Power saving support */

#elif defined(NANOS_PLATFORM_RP2040)
/*
 * Raspberry Pi Pico
 * RAM: 264KB  Flash: 2MB  Network: External (SPI)
 */
#define NANOS_PROFILE_STANDARD
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_SPI_RADIO     1       /* For LoRa/nRF24L01 */
#define NANOS_HAS_FLASH         1
#define NANOS_TICK_MS           10

#elif defined(NANOS_PLATFORM_STM32)
/*
 * STM32F4 series
 * RAM: 192KB  Flash: 1MB  Network: External
 */
#define NANOS_PROFILE_STANDARD
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_SPI_RADIO     1
#define NANOS_HAS_CAN           1       /* CAN bus for industrial */
#define NANOS_TICK_MS           10

#elif defined(NANOS_PLATFORM_NRF52)
/*
 * Nordic nRF52840 - BLE/Thread/Zigbee
 * RAM: 256KB  Flash: 1MB  Network: BLE Mesh/Thread
 */
#define NANOS_PROFILE_STANDARD
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_BLE_MESH      1
#define NANOS_HAS_THREAD        1
#define NANOS_HAS_FLASH         1
#define NANOS_TICK_MS           10
#define NANOS_DEEP_SLEEP        1

#elif defined(NANOS_PLATFORM_LORA)
/*
 * Generic LoRa node (SX1276/SX1262)
 * Optimized for long range, low bandwidth
 */
#define NANOS_PROFILE_LITE
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_LORA          1
#define NANOS_HAS_FLASH         1
#define NANOS_TICK_MS           100     /* Slower tick for power saving */
#define NANOS_DEEP_SLEEP        1
#define NANOS_COMPACT_PACKETS   1       /* Use smaller packet format */

#elif defined(NANOS_PLATFORM_MINIMAL)
/*
 * Minimal build - ATmega/small ARM Cortex-M0
 * RAM: 8-32KB  Flash: 64-256KB
 */
#define NANOS_PROFILE_MINIMAL
#define NANOS_HAS_SERIAL        1
#define NANOS_HAS_SPI_RADIO     1
#define NANOS_TICK_MS           100
#define NANOS_COMPACT_PACKETS   1
#define NANOS_NO_FLOAT          1       /* No floating point */

#endif

/* ==========================================================================
 * Profile-Based Feature Configuration
 * ========================================================================== */

#if defined(NANOS_PROFILE_FULL)
/* Full build - all features enabled */
#define NEIGHBOR_TABLE_SIZE     16
#define ROUTE_CACHE_SIZE        32
#define KV_STORE_SIZE           16
#define KV_KEY_SIZE             16
#define KV_VALUE_SIZE           32
#define MAX_PENDING_TASKS       8
#define MAX_ACTIVE_JOBS         4
#define MAX_JOB_CHUNKS          16
#define GOSSIP_CACHE_SIZE       64
#define BLOOM_FILTER_SIZE       256
#define MAX_ACTIVE_EVENTS       8
#define MAZE_SIZE               32
#define TERRAIN_SIZE            64
#define VISITED_HISTORY_SIZE    256
#define HEAP_SIZE               (64 * 1024)

/* Feature flags */
#define NANOS_FEATURE_TERRAIN   1
#define NANOS_FEATURE_MAZE      1
#define NANOS_FEATURE_COMPUTE   1
#define NANOS_FEATURE_TACTICAL  1
#define NANOS_FEATURE_KV        1
#define NANOS_FEATURE_TASKS     1

#elif defined(NANOS_PROFILE_STANDARD)
/* Standard MCU build - reduced but functional */
#define NEIGHBOR_TABLE_SIZE     8
#define ROUTE_CACHE_SIZE        16
#define KV_STORE_SIZE           8
#define KV_KEY_SIZE             8
#define KV_VALUE_SIZE           16
#define MAX_PENDING_TASKS       4
#define MAX_ACTIVE_JOBS         2
#define MAX_JOB_CHUNKS          8
#define GOSSIP_CACHE_SIZE       32
#define BLOOM_FILTER_SIZE       128
#define MAX_ACTIVE_EVENTS       4
#define MAZE_SIZE               16
#define TERRAIN_SIZE            32
#define VISITED_HISTORY_SIZE    64
#define HEAP_SIZE               (16 * 1024)

/* Feature flags - terrain/maze optional */
#define NANOS_FEATURE_TERRAIN   0
#define NANOS_FEATURE_MAZE      0
#define NANOS_FEATURE_COMPUTE   1
#define NANOS_FEATURE_TACTICAL  1
#define NANOS_FEATURE_KV        1
#define NANOS_FEATURE_TASKS     1

#elif defined(NANOS_PROFILE_LITE)
/* Lite build - for constrained devices */
#define NEIGHBOR_TABLE_SIZE     4
#define ROUTE_CACHE_SIZE        8
#define KV_STORE_SIZE           4
#define KV_KEY_SIZE             8
#define KV_VALUE_SIZE           8
#define MAX_PENDING_TASKS       2
#define MAX_ACTIVE_JOBS         1
#define MAX_JOB_CHUNKS          4
#define GOSSIP_CACHE_SIZE       16
#define BLOOM_FILTER_SIZE       64
#define MAX_ACTIVE_EVENTS       2
#define MAZE_SIZE               0       /* Disabled */
#define TERRAIN_SIZE            0       /* Disabled */
#define VISITED_HISTORY_SIZE    0
#define HEAP_SIZE               (4 * 1024)

/* Feature flags - minimal set */
#define NANOS_FEATURE_TERRAIN   0
#define NANOS_FEATURE_MAZE      0
#define NANOS_FEATURE_COMPUTE   0
#define NANOS_FEATURE_TACTICAL  1
#define NANOS_FEATURE_KV        1
#define NANOS_FEATURE_TASKS     0

#elif defined(NANOS_PROFILE_MINIMAL)
/* Minimal build - bare essentials only */
#define NEIGHBOR_TABLE_SIZE     2
#define ROUTE_CACHE_SIZE        4
#define KV_STORE_SIZE           2
#define KV_KEY_SIZE             4
#define KV_VALUE_SIZE           4
#define MAX_PENDING_TASKS       0
#define MAX_ACTIVE_JOBS         0
#define MAX_JOB_CHUNKS          0
#define GOSSIP_CACHE_SIZE       8
#define BLOOM_FILTER_SIZE       32
#define MAX_ACTIVE_EVENTS       0
#define MAZE_SIZE               0
#define TERRAIN_SIZE            0
#define VISITED_HISTORY_SIZE    0
#define HEAP_SIZE               (1 * 1024)

/* Feature flags - heartbeat and gossip only */
#define NANOS_FEATURE_TERRAIN   0
#define NANOS_FEATURE_MAZE      0
#define NANOS_FEATURE_COMPUTE   0
#define NANOS_FEATURE_TACTICAL  0
#define NANOS_FEATURE_KV        0
#define NANOS_FEATURE_TASKS     0

#endif

/* ==========================================================================
 * Packet Format Configuration
 * ========================================================================== */

#ifdef NANOS_COMPACT_PACKETS
/*
 * Compact packet format for low-bandwidth radios (LoRa, 802.15.4)
 * Total: 24 bytes (vs 64 standard)
 */
#define NANOS_PKT_PAYLOAD_SIZE  8
#define NANOS_PKT_TOTAL_SIZE    24
#define NANOS_HMAC_SIZE         4       /* Truncated HMAC */
#else
/*
 * Standard packet format (Ethernet, WiFi, ESP-NOW)
 * Total: 64 bytes
 */
#define NANOS_PKT_PAYLOAD_SIZE  32
#define NANOS_PKT_TOTAL_SIZE    64
#define NANOS_HMAC_SIZE         8
#endif

/* ==========================================================================
 * Timing Configuration
 * ========================================================================== */

/* Heartbeat interval (ms) - longer for battery devices */
#ifdef NANOS_DEEP_SLEEP
#define HEARTBEAT_INTERVAL_MS   5000    /* 5 seconds for battery */
#define HELLO_INTERVAL_MS       15000   /* 15 seconds */
#define QUORUM_CHECK_MS         30000   /* 30 seconds */
#else
#define HEARTBEAT_INTERVAL_MS   1000    /* 1 second for powered */
#define HELLO_INTERVAL_MS       5000    /* 5 seconds */
#define QUORUM_CHECK_MS         10000   /* 10 seconds */
#endif

/* Timeouts */
#define NEIGHBOR_TIMEOUT_MS     (HEARTBEAT_INTERVAL_MS * 5)
#define QUEEN_TIMEOUT_MS        (HEARTBEAT_INTERVAL_MS * 10)
#define ELECTION_TIMEOUT_MS     (HEARTBEAT_INTERVAL_MS * 3)

/* ==========================================================================
 * Power Management
 * ========================================================================== */

#ifdef NANOS_DEEP_SLEEP
#define NANOS_SLEEP_IDLE_MS     100     /* Sleep between ticks */
#define NANOS_SLEEP_DEEP_MS     1000    /* Deep sleep when no activity */
#define NANOS_WAKE_ON_RADIO     1       /* Wake on radio interrupt */
#endif

/* ==========================================================================
 * Sensor Configuration (for IoT applications)
 * ========================================================================== */

#ifndef NANOS_MAX_SENSORS
#define NANOS_MAX_SENSORS       4
#endif

/* Sensor types */
#define SENSOR_NONE             0
#define SENSOR_TEMPERATURE      1
#define SENSOR_HUMIDITY         2
#define SENSOR_PRESSURE         3
#define SENSOR_LIGHT            4
#define SENSOR_MOTION           5
#define SENSOR_DISTANCE         6
#define SENSOR_VOLTAGE          7
#define SENSOR_CURRENT          8
#define SENSOR_GPS              9
#define SENSOR_ACCELEROMETER    10
#define SENSOR_GYROSCOPE        11

/* ==========================================================================
 * Robot/Vehicle Configuration (for swarm robotics)
 * ========================================================================== */

#ifdef NANOS_ROBOT_MODE
#define NANOS_HAS_MOTORS        1
#define NANOS_HAS_ENCODERS      1
#define NANOS_HAS_IMU           1
#define NANOS_COLLISION_AVOID   1

/* Robot-specific pheromones */
#define PHEROMONE_ROBOT_POS     0x90
#define PHEROMONE_ROBOT_TASK    0x91
#define PHEROMONE_ROBOT_AVOID   0x92
#define PHEROMONE_ROBOT_BATTERY 0x93
#define PHEROMONE_ROBOT_CARGO   0x94
#endif

/* ==========================================================================
 * Debug Configuration
 * ========================================================================== */

#ifndef NANOS_DEBUG
#ifdef NANOS_PROFILE_FULL
#define NANOS_DEBUG             1
#else
#define NANOS_DEBUG             0
#endif
#endif

#if NANOS_DEBUG
#define NANOS_LOG_PACKETS       1
#define NANOS_LOG_STATE         1
#define NANOS_ASSERT_ENABLED    1
#else
#define NANOS_LOG_PACKETS       0
#define NANOS_LOG_STATE         0
#define NANOS_ASSERT_ENABLED    0
#endif

/* ==========================================================================
 * Utility Macros
 * ========================================================================== */

#if NANOS_ASSERT_ENABLED
#define NANOS_ASSERT(cond) do { if (!(cond)) nanos_panic(__FILE__, __LINE__); } while(0)
#else
#define NANOS_ASSERT(cond) ((void)0)
#endif

/* Compile-time feature check */
#define NANOS_HAS_FEATURE(f) (NANOS_FEATURE_##f)

/* Memory size check at compile time */
#define NANOS_STATIC_ASSERT(cond, msg) typedef char static_assert_##msg[(cond)?1:-1]

/* Packed struct for compact packets */
#define NANOS_PACKED __attribute__((packed))

#endif /* NANOS_CONFIG_H */
