/*
 * NERT HAL Implementation for nRF52840
 *
 * Supports BLE Mesh and Thread for swarm communication
 * Targets Nordic nRF52840 DK and compatible boards
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>

#if defined(NRF52840_XXAA) || defined(NANOS_PLATFORM_NRF52)

#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "nrf_drv_rng.h"
#include "nrf_drv_clock.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "nrf_nvmc.h"

/* BLE includes */
#include "ble.h"
#include "ble_hci.h"
#include "ble_srv_common.h"
#include "ble_advdata.h"
#include "ble_conn_params.h"

/* Mesh includes (if available) */
#ifdef MESH_FEATURE_ENABLED
#include "mesh_stack.h"
#include "mesh_softdevice_init.h"
#include "access.h"
#include "device_state_manager.h"
#endif

/* Thread includes (if available) */
#ifdef OPENTHREAD_ENABLED
#include <openthread/instance.h>
#include <openthread/thread.h>
#include <openthread/udp.h>
#include <openthread/platform/radio.h>
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define NERT_NRF_USE_BLE            1   /* Use BLE advertising/scanning */
#define NERT_NRF_USE_MESH           0   /* Use BLE Mesh (requires mesh SDK) */
#define NERT_NRF_USE_THREAD         0   /* Use Thread (requires OpenThread) */

#define NERT_RX_QUEUE_SIZE          8
#define NERT_MAX_FRAME_SIZE         100

/* BLE Configuration */
#define APP_BLE_CONN_CFG_TAG        1
#define APP_BLE_OBSERVER_PRIO       3

/* NERT Service UUID: 4E455254-0001-1000-8000-00805F9B34FB */
#define NERT_SERVICE_UUID_BASE      {0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, \
                                     0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
#define NERT_SERVICE_UUID           0x4E52
#define NERT_CHAR_TX_UUID           0x4E54  /* TX characteristic */
#define NERT_CHAR_RX_UUID           0x4E52  /* RX characteristic */

/* Advertising parameters */
#define ADV_INTERVAL_MIN            MSEC_TO_UNITS(100, UNIT_0_625_MS)
#define ADV_INTERVAL_MAX            MSEC_TO_UNITS(200, UNIT_0_625_MS)
#define ADV_DURATION                0  /* Continuous */

/* Scan parameters */
#define SCAN_INTERVAL               MSEC_TO_UNITS(100, UNIT_0_625_MS)
#define SCAN_WINDOW                 MSEC_TO_UNITS(50, UNIT_0_625_MS)
#define SCAN_DURATION               0  /* Continuous */

/* ============================================================================
 * NVS (Non-Volatile Storage) Configuration
 * ============================================================================ */

#define NERT_NVS_PAGE_ADDR          0x000FF000  /* Last page before bootloader */
#define NERT_NVS_MAGIC              0x4E455254  /* "NERT" */

struct nert_nvs_config {
    uint32_t magic;
    uint16_t node_id;
    uint8_t  tx_power;
    uint8_t  reserved;
    uint8_t  master_key[32];
    uint32_t crc;
};

/* ============================================================================
 * Local State
 * ============================================================================ */

static uint16_t local_node_id = 0;
static uint32_t boot_tick = 0;

/* RX queue */
struct rx_entry {
    uint8_t data[NERT_MAX_FRAME_SIZE];
    uint16_t len;
    int8_t rssi;
};

static struct rx_entry rx_queue[NERT_RX_QUEUE_SIZE];
static volatile uint8_t rx_head = 0;
static volatile uint8_t rx_tail = 0;

/* BLE state */
static uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID;
static ble_uuid_t m_adv_uuids[] = {{NERT_SERVICE_UUID, BLE_UUID_TYPE_VENDOR_BEGIN}};
static uint8_t m_adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
static bool m_advertising = false;
static bool m_scanning = false;

/* GATT handles */
static uint16_t m_service_handle;
static ble_gatts_char_handles_t m_tx_handles;
static ble_gatts_char_handles_t m_rx_handles;

/* Manufacturer data for advertising NERT packets */
#define MANUFACTURER_ID             0xFFFF  /* Test/development ID */
static uint8_t m_adv_data[31];
static uint8_t m_scan_rsp_data[31];

#ifdef OPENTHREAD_ENABLED
static otInstance *m_ot_instance = NULL;
static otUdpSocket m_ot_socket;
static const uint16_t NERT_THREAD_PORT = 0x4E52;  /* "NR" */
#endif

/* ============================================================================
 * NVS Functions
 * ============================================================================ */

static int nvs_read_config(struct nert_nvs_config *config) {
    memcpy(config, (void*)NERT_NVS_PAGE_ADDR, sizeof(*config));
    if (config->magic != NERT_NVS_MAGIC) {
        return -1;
    }
    return 0;
}

static int nvs_write_config(const struct nert_nvs_config *config) {
    /* Erase page */
    nrf_nvmc_page_erase(NERT_NVS_PAGE_ADDR);

    /* Write data */
    nrf_nvmc_write_bytes(NERT_NVS_PAGE_ADDR, (const uint8_t*)config, sizeof(*config));

    return 0;
}

/* ============================================================================
 * BLE Advertising
 * ============================================================================ */

#if NERT_NRF_USE_BLE

static void advertising_init(void) {
    ble_gap_adv_params_t adv_params;
    ble_gap_adv_data_t adv_data;

    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.primary_phy = BLE_GAP_PHY_1MBPS;
    adv_params.duration = ADV_DURATION;
    adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    adv_params.p_peer_addr = NULL;
    adv_params.filter_policy = BLE_GAP_ADV_FP_ANY;
    adv_params.interval = ADV_INTERVAL_MIN;

    /* Build advertising data with NERT info */
    ble_advdata_t advdata;
    memset(&advdata, 0, sizeof(advdata));
    advdata.name_type = BLE_ADVDATA_NO_NAME;
    advdata.include_appearance = false;
    advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    advdata.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    advdata.uuids_complete.p_uuids = m_adv_uuids;

    /* Encode advertising data */
    uint8_t encoded_advdata[BLE_GAP_ADV_SET_DATA_SIZE_MAX];
    uint16_t encoded_advdata_len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
    ble_advdata_encode(&advdata, encoded_advdata, &encoded_advdata_len);

    memset(&adv_data, 0, sizeof(adv_data));
    adv_data.adv_data.p_data = encoded_advdata;
    adv_data.adv_data.len = encoded_advdata_len;

    sd_ble_gap_adv_set_configure(&m_adv_handle, &adv_data, &adv_params);
}

static void advertising_start(void) {
    if (!m_advertising) {
        sd_ble_gap_adv_start(m_adv_handle, APP_BLE_CONN_CFG_TAG);
        m_advertising = true;
    }
}

static void advertising_stop(void) {
    if (m_advertising) {
        sd_ble_gap_adv_stop(m_adv_handle);
        m_advertising = false;
    }
}

/* ============================================================================
 * BLE Scanning
 * ============================================================================ */

static ble_gap_scan_params_t m_scan_params = {
    .extended = 0,
    .active = 0,  /* Passive scanning */
    .interval = SCAN_INTERVAL,
    .window = SCAN_WINDOW,
    .timeout = SCAN_DURATION,
    .scan_phys = BLE_GAP_PHY_1MBPS,
    .filter_policy = BLE_GAP_SCAN_FP_ACCEPT_ALL,
};

static ble_data_t m_scan_buffer = {
    .p_data = m_adv_data,
    .len = sizeof(m_adv_data)
};

static void scan_start(void) {
    if (!m_scanning) {
        sd_ble_gap_scan_start(&m_scan_params, &m_scan_buffer);
        m_scanning = true;
    }
}

static void scan_stop(void) {
    if (m_scanning) {
        sd_ble_gap_scan_stop();
        m_scanning = false;
    }
}

/* ============================================================================
 * GATT Service
 * ============================================================================ */

static void services_init(void) {
    ble_uuid128_t base_uuid = {NERT_SERVICE_UUID_BASE};
    uint8_t uuid_type;

    sd_ble_uuid_vs_add(&base_uuid, &uuid_type);

    /* Add service */
    ble_uuid_t service_uuid;
    service_uuid.type = uuid_type;
    service_uuid.uuid = NERT_SERVICE_UUID;

    sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &service_uuid, &m_service_handle);

    /* Add TX characteristic (for sending NERT packets) */
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t attr_char_value;
    ble_uuid_t char_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.write = 1;
    char_md.char_props.write_wo_resp = 1;
    char_md.p_char_user_desc = NULL;
    char_md.p_char_pf = NULL;
    char_md.p_user_desc_md = NULL;
    char_md.p_cccd_md = NULL;
    char_md.p_sccd_md = NULL;

    char_uuid.type = uuid_type;
    char_uuid.uuid = NERT_CHAR_TX_UUID;

    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 0;
    attr_md.vlen = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid = &char_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len = 0;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len = NERT_MAX_FRAME_SIZE;

    sd_ble_gatts_characteristic_add(m_service_handle, &char_md, &attr_char_value, &m_tx_handles);

    /* Add RX characteristic (for receiving NERT packets via notification) */
    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.notify = 1;
    char_md.char_props.read = 1;

    ble_gatts_attr_md_t cccd_md;
    memset(&cccd_md, 0, sizeof(cccd_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
    cccd_md.vloc = BLE_GATTS_VLOC_STACK;
    char_md.p_cccd_md = &cccd_md;

    char_uuid.uuid = NERT_CHAR_RX_UUID;

    sd_ble_gatts_characteristic_add(m_service_handle, &char_md, &attr_char_value, &m_rx_handles);
}

/* ============================================================================
 * BLE Event Handler
 * ============================================================================ */

static void ble_evt_handler(ble_evt_t const *p_ble_evt, void *p_context) {
    (void)p_context;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            scan_stop();  /* Stop scanning when connected */
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            advertising_start();
            scan_start();
            break;

        case BLE_GAP_EVT_ADV_REPORT: {
            /* Received advertisement - check for NERT packets */
            const ble_gap_evt_adv_report_t *p_adv = &p_ble_evt->evt.gap_evt.params.adv_report;

            /* Look for manufacturer data with NERT magic */
            uint8_t *p_data = (uint8_t*)p_adv->data.p_data;
            uint16_t len = p_adv->data.len;

            for (uint16_t i = 0; i < len - 4; i++) {
                /* Check for manufacturer specific data type (0xFF) */
                if (p_data[i] >= 3 && p_data[i+1] == 0xFF) {
                    uint16_t mfg_id = p_data[i+2] | (p_data[i+3] << 8);
                    if (mfg_id == MANUFACTURER_ID) {
                        /* Check NERT magic */
                        if (i + 4 < len && p_data[i+4] == 0x4E) {
                            /* NERT packet found - add to queue */
                            uint8_t pkt_len = p_data[i] - 3;  /* Subtract mfg header */
                            if (pkt_len <= NERT_MAX_FRAME_SIZE) {
                                uint8_t next = (rx_head + 1) % NERT_RX_QUEUE_SIZE;
                                if (next != rx_tail) {
                                    memcpy(rx_queue[rx_head].data, &p_data[i+4], pkt_len);
                                    rx_queue[rx_head].len = pkt_len;
                                    rx_queue[rx_head].rssi = p_adv->rssi;
                                    rx_head = next;
                                }
                            }
                        }
                    }
                    break;
                }
            }

            /* Continue scanning */
            sd_ble_gap_scan_start(NULL, &m_scan_buffer);
            break;
        }

        case BLE_GATTS_EVT_WRITE: {
            /* Data written to TX characteristic */
            const ble_gatts_evt_write_t *p_write = &p_ble_evt->evt.gatts_evt.params.write;

            if (p_write->handle == m_tx_handles.value_handle) {
                /* NERT packet received via GATT */
                if (p_write->len > 0 && p_write->len <= NERT_MAX_FRAME_SIZE) {
                    /* Check NERT magic */
                    if (p_write->data[0] == 0x4E) {
                        uint8_t next = (rx_head + 1) % NERT_RX_QUEUE_SIZE;
                        if (next != rx_tail) {
                            memcpy(rx_queue[rx_head].data, p_write->data, p_write->len);
                            rx_queue[rx_head].len = p_write->len;
                            rx_queue[rx_head].rssi = 0;  /* Unknown RSSI for GATT */
                            rx_head = next;
                        }
                    }
                }
            }
            break;
        }

        default:
            break;
    }
}

NRF_SDH_BLE_OBSERVER(m_ble_observer, APP_BLE_OBSERVER_PRIO, ble_evt_handler, NULL);

/* ============================================================================
 * BLE Initialization
 * ============================================================================ */

static int ble_stack_init(void) {
    /* Enable SoftDevice */
    nrf_sdh_enable_request();

    /* Configure BLE stack */
    uint32_t ram_start = 0;
    nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start);
    nrf_sdh_ble_enable(&ram_start);

    /* Set TX power */
    sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_adv_handle, 0);

    return 0;
}

#endif /* NERT_NRF_USE_BLE */

/* ============================================================================
 * Thread Support
 * ============================================================================ */

#ifdef OPENTHREAD_ENABLED

static void ot_udp_receive_callback(void *aContext, otMessage *aMessage,
                                     const otMessageInfo *aMessageInfo) {
    (void)aContext;
    (void)aMessageInfo;

    uint16_t len = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    if (len > NERT_MAX_FRAME_SIZE) len = NERT_MAX_FRAME_SIZE;

    uint8_t next = (rx_head + 1) % NERT_RX_QUEUE_SIZE;
    if (next != rx_tail) {
        otMessageRead(aMessage, otMessageGetOffset(aMessage),
                      rx_queue[rx_head].data, len);
        rx_queue[rx_head].len = len;
        rx_queue[rx_head].rssi = 0;
        rx_head = next;
    }
}

static int thread_init(void) {
    m_ot_instance = otInstanceInitSingle();
    if (m_ot_instance == NULL) {
        return -1;
    }

    /* Configure Thread network */
    otLinkSetPanId(m_ot_instance, 0x4E52);  /* "NR" */
    otThreadSetEnabled(m_ot_instance, true);

    /* Open UDP socket */
    otUdpOpen(m_ot_instance, &m_ot_socket, ot_udp_receive_callback, NULL);

    otSockAddr sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.mPort = NERT_THREAD_PORT;
    otUdpBind(m_ot_instance, &m_ot_socket, &sockaddr, OT_NETIF_THREAD);

    return 0;
}

static int thread_send(const uint8_t *data, uint16_t len) {
    otMessage *message = otUdpNewMessage(m_ot_instance, NULL);
    if (message == NULL) {
        return -1;
    }

    if (otMessageAppend(message, data, len) != OT_ERROR_NONE) {
        otMessageFree(message);
        return -1;
    }

    /* Send to all-nodes multicast */
    otMessageInfo messageInfo;
    memset(&messageInfo, 0, sizeof(messageInfo));
    otIp6AddressFromString("ff03::1", &messageInfo.mPeerAddr);
    messageInfo.mPeerPort = NERT_THREAD_PORT;

    if (otUdpSend(m_ot_instance, &m_ot_socket, message, &messageInfo) != OT_ERROR_NONE) {
        otMessageFree(message);
        return -1;
    }

    return 0;
}

#endif /* OPENTHREAD_ENABLED */

/* ============================================================================
 * HAL Implementation
 * ============================================================================ */

int nert_hal_send(const void *data, uint16_t len) {
    if (len > NERT_MAX_FRAME_SIZE) return -1;

#ifdef OPENTHREAD_ENABLED
    #if NERT_NRF_USE_THREAD
        return thread_send((const uint8_t*)data, len);
    #endif
#endif

#if NERT_NRF_USE_BLE
    /* Send via BLE advertising (manufacturer data) */
    uint8_t adv_data[31];
    uint8_t adv_len = 0;

    /* Flags */
    adv_data[adv_len++] = 2;
    adv_data[adv_len++] = BLE_GAP_AD_TYPE_FLAGS;
    adv_data[adv_len++] = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;

    /* Manufacturer specific data */
    uint8_t mfg_len = len + 2;  /* +2 for manufacturer ID */
    if (adv_len + 2 + mfg_len > 31) {
        mfg_len = 31 - adv_len - 2;
    }

    adv_data[adv_len++] = mfg_len + 1;
    adv_data[adv_len++] = BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA;
    adv_data[adv_len++] = MANUFACTURER_ID & 0xFF;
    adv_data[adv_len++] = (MANUFACTURER_ID >> 8) & 0xFF;
    memcpy(&adv_data[adv_len], data, mfg_len - 2);
    adv_len += mfg_len - 2;

    /* Update advertising data */
    ble_gap_adv_data_t gap_adv_data;
    memset(&gap_adv_data, 0, sizeof(gap_adv_data));
    gap_adv_data.adv_data.p_data = adv_data;
    gap_adv_data.adv_data.len = adv_len;

    advertising_stop();
    sd_ble_gap_adv_set_configure(&m_adv_handle, &gap_adv_data, NULL);
    advertising_start();

    /* Also send via GATT notification if connected */
    if (m_conn_handle != BLE_CONN_HANDLE_INVALID) {
        ble_gatts_hvx_params_t hvx_params;
        uint16_t hvx_len = len;

        memset(&hvx_params, 0, sizeof(hvx_params));
        hvx_params.handle = m_rx_handles.value_handle;
        hvx_params.type = BLE_GATT_HVX_NOTIFICATION;
        hvx_params.offset = 0;
        hvx_params.p_len = &hvx_len;
        hvx_params.p_data = (uint8_t*)data;

        sd_ble_gatts_hvx(m_conn_handle, &hvx_params);
    }

    return 0;
#else
    return -1;
#endif
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
#ifdef OPENTHREAD_ENABLED
    otTaskletsProcess(m_ot_instance);
#endif

    /* Check queue */
    if (rx_head != rx_tail) {
        uint16_t len = rx_queue[rx_tail].len;
        if (len > max_len) len = max_len;
        memcpy(buffer, rx_queue[rx_tail].data, len);
        rx_tail = (rx_tail + 1) % NERT_RX_QUEUE_SIZE;
        return len;
    }

    return 0;
}

uint32_t nert_hal_get_ticks(void) {
    /* Use RTC or app_timer */
    return (NRF_RTC1->COUNTER * 1000) / 32768 - boot_tick;
}

uint32_t nert_hal_random(void) {
    uint8_t random_bytes[4];
    uint8_t available = 0;

    nrf_drv_rng_bytes_available(&available);
    if (available >= 4) {
        nrf_drv_rng_rand(random_bytes, 4);
        return (random_bytes[0] << 24) | (random_bytes[1] << 16) |
               (random_bytes[2] << 8) | random_bytes[3];
    }

    /* Fallback */
    static uint32_t seed = 0x12345678;
    seed = seed * 1103515245 + 12345;
    return seed;
}

uint16_t nert_hal_get_node_id(void) {
    if (local_node_id == 0) {
        /* Try NVS */
        struct nert_nvs_config config;
        if (nvs_read_config(&config) == 0 && config.node_id != 0) {
            local_node_id = config.node_id;
        } else {
            /* Generate from device ID */
            local_node_id = (uint16_t)(NRF_FICR->DEVICEID[0] ^ NRF_FICR->DEVICEID[1]);
            if (local_node_id == 0) {
                local_node_id = (uint16_t)nert_hal_random();
            }
        }
    }
    return local_node_id;
}

/* ============================================================================
 * Power Management
 * ============================================================================ */

void nert_hal_enter_system_off(void) {
    /* Lowest power mode - only wakes on reset or GPIO */
    nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_SYSOFF);
}

void nert_hal_enter_low_power(uint32_t duration_ms) {
    /* System ON sleep - preserves RAM, wakes on RTC */
    (void)duration_ms;  /* TODO: Configure RTC wakeup */
    nrf_pwr_mgmt_run();
}

void nert_hal_set_tx_power(int8_t power_dbm) {
    /* Valid values: -40, -20, -16, -12, -8, -4, 0, +3, +4 dBm */
    int8_t valid_powers[] = {-40, -20, -16, -12, -8, -4, 0, 3, 4};
    int8_t closest = 0;
    int8_t min_diff = 127;

    for (int i = 0; i < sizeof(valid_powers); i++) {
        int8_t diff = power_dbm - valid_powers[i];
        if (diff < 0) diff = -diff;
        if (diff < min_diff) {
            min_diff = diff;
            closest = valid_powers[i];
        }
    }

    sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_adv_handle, closest);
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void nert_hal_init(void) {
    boot_tick = (NRF_RTC1->COUNTER * 1000) / 32768;

    /* Initialize clock */
    nrf_drv_clock_init();
    nrf_drv_clock_lfclk_request(NULL);

    /* Initialize RNG */
    nrf_drv_rng_init(NULL);

    /* Initialize power management */
    nrf_pwr_mgmt_init();

#if NERT_NRF_USE_BLE
    /* Initialize BLE stack */
    ble_stack_init();

    /* Initialize services */
    services_init();

    /* Initialize advertising */
    advertising_init();

    /* Start advertising and scanning */
    advertising_start();
    scan_start();
#endif

#ifdef OPENTHREAD_ENABLED
    #if NERT_NRF_USE_THREAD
        thread_init();
    #endif
#endif

    /* Pre-compute node ID */
    nert_hal_get_node_id();
}

/* ============================================================================
 * PHY Interface
 * ============================================================================ */

static int nrf52_phy_send(const void *data, uint16_t len, void *ctx) {
    (void)ctx;
    return nert_hal_send(data, len);
}

static int nrf52_phy_receive(void *buffer, uint16_t max_len, void *ctx) {
    (void)ctx;
    return nert_hal_receive(buffer, max_len);
}

static uint32_t nrf52_phy_get_ticks(void *ctx) {
    (void)ctx;
    return nert_hal_get_ticks();
}

static uint32_t nrf52_phy_random(void *ctx) {
    (void)ctx;
    return nert_hal_random();
}

static struct nert_phy_interface nrf52_phy = {
    .send = nrf52_phy_send,
    .receive = nrf52_phy_receive,
    .get_ticks = nrf52_phy_get_ticks,
    .random = nrf52_phy_random,
    .context = NULL
};

struct nert_phy_interface* nert_phy_nrf52_get(void) {
    return &nrf52_phy;
}

#endif /* NRF52840_XXAA || NANOS_PLATFORM_NRF52 */
