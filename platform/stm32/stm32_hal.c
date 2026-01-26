/*
 * NERT HAL Implementation for STM32F4
 *
 * Supports CAN bus and LoRa (SX1276) for communication
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>

#if defined(STM32F4) || defined(NANOS_PLATFORM_STM32)

#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_can.h"
#include "stm32f4xx_hal_spi.h"
#include "stm32f4xx_hal_rng.h"
#include "stm32f4xx_hal_rtc.h"
#include "stm32f4xx_hal_pwr.h"
#include "stm32f4xx_hal_flash.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define NERT_STM32_USE_CAN          1   /* Use CAN bus (1) or LoRa (0) */
#define NERT_STM32_USE_LORA         1   /* Enable LoRa as fallback/alternate */
#define NERT_RX_QUEUE_SIZE          8
#define NERT_MAX_FRAME_SIZE         100 /* Compact mode */

/* CAN Configuration */
#define NERT_CAN_BITRATE            500000  /* 500 kbps */
#define NERT_CAN_FILTER_ID          0x4E52  /* "NR" - NERT */
#define NERT_CAN_FILTER_MASK        0xFFFF

/* LoRa Configuration (SX1276) */
#define LORA_FREQUENCY              915000000   /* 915 MHz (US) */
#define LORA_BANDWIDTH              125000      /* 125 kHz */
#define LORA_SPREADING_FACTOR       7
#define LORA_CODING_RATE            5           /* 4/5 */
#define LORA_PREAMBLE_LENGTH        8
#define LORA_TX_POWER               14          /* dBm */

/* SX1276 Registers */
#define REG_FIFO                    0x00
#define REG_OP_MODE                 0x01
#define REG_FRF_MSB                 0x06
#define REG_FRF_MID                 0x07
#define REG_FRF_LSB                 0x08
#define REG_PA_CONFIG               0x09
#define REG_FIFO_ADDR_PTR           0x0D
#define REG_FIFO_TX_BASE_ADDR       0x0E
#define REG_FIFO_RX_BASE_ADDR       0x0F
#define REG_FIFO_RX_CURRENT_ADDR    0x10
#define REG_IRQ_FLAGS               0x12
#define REG_RX_NB_BYTES             0x13
#define REG_MODEM_CONFIG_1          0x1D
#define REG_MODEM_CONFIG_2          0x1E
#define REG_PREAMBLE_MSB            0x20
#define REG_PREAMBLE_LSB            0x21
#define REG_PAYLOAD_LENGTH          0x22
#define REG_MODEM_CONFIG_3          0x26
#define REG_DIO_MAPPING_1           0x40
#define REG_VERSION                 0x42
#define REG_PA_DAC                  0x4D

/* SX1276 Modes */
#define MODE_LONG_RANGE             0x80
#define MODE_SLEEP                  0x00
#define MODE_STDBY                  0x01
#define MODE_TX                     0x03
#define MODE_RX_CONTINUOUS          0x05
#define MODE_RX_SINGLE              0x06

/* IRQ Flags */
#define IRQ_TX_DONE                 0x08
#define IRQ_RX_DONE                 0x40
#define IRQ_PAYLOAD_CRC_ERROR       0x20

/* ============================================================================
 * Hardware Handles (defined in main.c or board init)
 * ============================================================================ */

extern CAN_HandleTypeDef hcan1;
extern SPI_HandleTypeDef hspi1;      /* For LoRa */
extern RNG_HandleTypeDef hrng;
extern RTC_HandleTypeDef hrtc;

/* LoRa NSS (Chip Select) Pin */
#define LORA_NSS_PORT               GPIOA
#define LORA_NSS_PIN                GPIO_PIN_4
#define LORA_RESET_PORT             GPIOB
#define LORA_RESET_PIN              GPIO_PIN_0
#define LORA_DIO0_PORT              GPIOB
#define LORA_DIO0_PIN               GPIO_PIN_1

/* ============================================================================
 * Local State
 * ============================================================================ */

static uint16_t local_node_id = 0;
static uint32_t boot_tick = 0;

/* RX queue */
struct rx_entry {
    uint8_t data[NERT_MAX_FRAME_SIZE];
    uint16_t len;
};

static struct rx_entry rx_queue[NERT_RX_QUEUE_SIZE];
static volatile uint8_t rx_head = 0;
static volatile uint8_t rx_tail = 0;

/* Transport mode */
static uint8_t use_lora = 0;  /* 0 = CAN, 1 = LoRa */

/* ============================================================================
 * Flash Storage for Configuration
 * ============================================================================ */

/* Store config in last sector of flash */
#define CONFIG_FLASH_ADDR           0x080E0000  /* Sector 11 on STM32F407 */
#define CONFIG_MAGIC                0x4E455254  /* "NERT" */

struct nert_flash_config {
    uint32_t magic;
    uint16_t node_id;
    uint8_t  lora_enabled;
    uint8_t  tx_power;
    uint32_t frequency;
    uint8_t  master_key[32];
    uint32_t crc;
};

static int flash_read_config(struct nert_flash_config *config) {
    memcpy(config, (void*)CONFIG_FLASH_ADDR, sizeof(*config));
    if (config->magic != CONFIG_MAGIC) {
        return -1;
    }
    /* TODO: Verify CRC */
    return 0;
}

static int flash_write_config(const struct nert_flash_config *config) {
    HAL_FLASH_Unlock();

    /* Erase sector */
    FLASH_EraseInitTypeDef erase;
    erase.TypeErase = FLASH_TYPEERASE_SECTORS;
    erase.Sector = FLASH_SECTOR_11;
    erase.NbSectors = 1;
    erase.VoltageRange = FLASH_VOLTAGE_RANGE_3;

    uint32_t error;
    if (HAL_FLASHEx_Erase(&erase, &error) != HAL_OK) {
        HAL_FLASH_Lock();
        return -1;
    }

    /* Write config word by word */
    uint32_t *src = (uint32_t*)config;
    uint32_t addr = CONFIG_FLASH_ADDR;
    for (size_t i = 0; i < sizeof(*config) / 4; i++) {
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr, src[i]) != HAL_OK) {
            HAL_FLASH_Lock();
            return -1;
        }
        addr += 4;
    }

    HAL_FLASH_Lock();
    return 0;
}

/* ============================================================================
 * SX1276 LoRa Driver
 * ============================================================================ */

#if NERT_STM32_USE_LORA

static void lora_nss_low(void) {
    HAL_GPIO_WritePin(LORA_NSS_PORT, LORA_NSS_PIN, GPIO_PIN_RESET);
}

static void lora_nss_high(void) {
    HAL_GPIO_WritePin(LORA_NSS_PORT, LORA_NSS_PIN, GPIO_PIN_SET);
}

static uint8_t lora_read_reg(uint8_t reg) {
    uint8_t tx[2] = { reg & 0x7F, 0x00 };
    uint8_t rx[2];

    lora_nss_low();
    HAL_SPI_TransmitReceive(&hspi1, tx, rx, 2, 100);
    lora_nss_high();

    return rx[1];
}

static void lora_write_reg(uint8_t reg, uint8_t value) {
    uint8_t tx[2] = { reg | 0x80, value };

    lora_nss_low();
    HAL_SPI_Transmit(&hspi1, tx, 2, 100);
    lora_nss_high();
}

static void lora_write_fifo(const uint8_t *data, uint8_t len) {
    lora_nss_low();

    uint8_t cmd = REG_FIFO | 0x80;
    HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
    HAL_SPI_Transmit(&hspi1, (uint8_t*)data, len, 100);

    lora_nss_high();
}

static void lora_read_fifo(uint8_t *data, uint8_t len) {
    lora_nss_low();

    uint8_t cmd = REG_FIFO;
    HAL_SPI_Transmit(&hspi1, &cmd, 1, 100);
    HAL_SPI_Receive(&hspi1, data, len, 100);

    lora_nss_high();
}

static void lora_set_mode(uint8_t mode) {
    lora_write_reg(REG_OP_MODE, MODE_LONG_RANGE | mode);
}

static void lora_set_frequency(uint32_t freq) {
    uint64_t frf = ((uint64_t)freq << 19) / 32000000;
    lora_write_reg(REG_FRF_MSB, (uint8_t)(frf >> 16));
    lora_write_reg(REG_FRF_MID, (uint8_t)(frf >> 8));
    lora_write_reg(REG_FRF_LSB, (uint8_t)(frf >> 0));
}

static int lora_init(void) {
    /* Reset the module */
    HAL_GPIO_WritePin(LORA_RESET_PORT, LORA_RESET_PIN, GPIO_PIN_RESET);
    HAL_Delay(10);
    HAL_GPIO_WritePin(LORA_RESET_PORT, LORA_RESET_PIN, GPIO_PIN_SET);
    HAL_Delay(10);

    /* Check version */
    uint8_t version = lora_read_reg(REG_VERSION);
    if (version != 0x12) {
        return -1;  /* Not SX1276 */
    }

    /* Sleep mode for configuration */
    lora_set_mode(MODE_SLEEP);
    HAL_Delay(10);

    /* Set frequency */
    lora_set_frequency(LORA_FREQUENCY);

    /* Configure modem */
    /* Bandwidth 125kHz, CR 4/5, Explicit header */
    lora_write_reg(REG_MODEM_CONFIG_1, 0x72);
    /* SF7, CRC on */
    lora_write_reg(REG_MODEM_CONFIG_2, 0x74);
    /* LNA gain auto, Low data rate optimize off */
    lora_write_reg(REG_MODEM_CONFIG_3, 0x04);

    /* Preamble length */
    lora_write_reg(REG_PREAMBLE_MSB, 0x00);
    lora_write_reg(REG_PREAMBLE_LSB, LORA_PREAMBLE_LENGTH);

    /* TX power */
    lora_write_reg(REG_PA_CONFIG, 0x8F);  /* PA_BOOST, max power */
    lora_write_reg(REG_PA_DAC, 0x87);     /* High power mode */

    /* FIFO pointers */
    lora_write_reg(REG_FIFO_TX_BASE_ADDR, 0x00);
    lora_write_reg(REG_FIFO_RX_BASE_ADDR, 0x00);

    /* DIO0 = RxDone */
    lora_write_reg(REG_DIO_MAPPING_1, 0x00);

    /* Standby mode */
    lora_set_mode(MODE_STDBY);

    return 0;
}

static int lora_send(const uint8_t *data, uint8_t len) {
    /* Standby mode */
    lora_set_mode(MODE_STDBY);

    /* Set FIFO pointer to TX base */
    lora_write_reg(REG_FIFO_ADDR_PTR, 0x00);

    /* Write data to FIFO */
    lora_write_fifo(data, len);

    /* Set payload length */
    lora_write_reg(REG_PAYLOAD_LENGTH, len);

    /* Start TX */
    lora_set_mode(MODE_TX);

    /* Wait for TX done (with timeout) */
    uint32_t start = HAL_GetTick();
    while ((lora_read_reg(REG_IRQ_FLAGS) & IRQ_TX_DONE) == 0) {
        if (HAL_GetTick() - start > 1000) {
            lora_set_mode(MODE_STDBY);
            return -1;  /* Timeout */
        }
    }

    /* Clear IRQ flags */
    lora_write_reg(REG_IRQ_FLAGS, 0xFF);

    /* Back to RX mode */
    lora_set_mode(MODE_RX_CONTINUOUS);

    return 0;
}

static int lora_receive(uint8_t *buffer, uint8_t max_len) {
    /* Check IRQ flags */
    uint8_t irq = lora_read_reg(REG_IRQ_FLAGS);

    if (irq & IRQ_RX_DONE) {
        /* Clear flags */
        lora_write_reg(REG_IRQ_FLAGS, 0xFF);

        /* Check CRC */
        if (irq & IRQ_PAYLOAD_CRC_ERROR) {
            lora_set_mode(MODE_RX_CONTINUOUS);
            return 0;
        }

        /* Get packet length */
        uint8_t len = lora_read_reg(REG_RX_NB_BYTES);
        if (len > max_len) len = max_len;

        /* Set FIFO pointer to current RX address */
        lora_write_reg(REG_FIFO_ADDR_PTR,
                       lora_read_reg(REG_FIFO_RX_CURRENT_ADDR));

        /* Read FIFO */
        lora_read_fifo(buffer, len);

        /* Back to RX mode */
        lora_set_mode(MODE_RX_CONTINUOUS);

        return len;
    }

    return 0;
}

static void lora_start_rx(void) {
    lora_set_mode(MODE_RX_CONTINUOUS);
}

#endif /* NERT_STM32_USE_LORA */

/* ============================================================================
 * CAN Bus Driver
 * ============================================================================ */

#if NERT_STM32_USE_CAN

static CAN_TxHeaderTypeDef can_tx_header;
static CAN_RxHeaderTypeDef can_rx_header;

static int can_init(void) {
    /* Configure filter */
    CAN_FilterTypeDef filter;
    filter.FilterBank = 0;
    filter.FilterMode = CAN_FILTERMODE_IDMASK;
    filter.FilterScale = CAN_FILTERSCALE_32BIT;
    filter.FilterIdHigh = (NERT_CAN_FILTER_ID << 5);
    filter.FilterIdLow = 0x0000;
    filter.FilterMaskIdHigh = (NERT_CAN_FILTER_MASK << 5);
    filter.FilterMaskIdLow = 0x0000;
    filter.FilterFIFOAssignment = CAN_RX_FIFO0;
    filter.FilterActivation = ENABLE;
    filter.SlaveStartFilterBank = 14;

    if (HAL_CAN_ConfigFilter(&hcan1, &filter) != HAL_OK) {
        return -1;
    }

    /* Start CAN */
    if (HAL_CAN_Start(&hcan1) != HAL_OK) {
        return -1;
    }

    /* Activate RX notification */
    if (HAL_CAN_ActivateNotification(&hcan1, CAN_IT_RX_FIFO0_MSG_PENDING) != HAL_OK) {
        return -1;
    }

    /* Setup TX header */
    can_tx_header.StdId = NERT_CAN_FILTER_ID;
    can_tx_header.ExtId = 0;
    can_tx_header.RTR = CAN_RTR_DATA;
    can_tx_header.IDE = CAN_ID_STD;
    can_tx_header.TransmitGlobalTime = DISABLE;

    return 0;
}

static int can_send(const uint8_t *data, uint16_t len) {
    /* CAN frames are max 8 bytes, need to fragment */
    uint32_t mailbox;
    uint16_t offset = 0;

    while (offset < len) {
        uint8_t chunk_len = (len - offset > 8) ? 8 : (len - offset);
        can_tx_header.DLC = chunk_len;

        /* Wait for free mailbox */
        uint32_t start = HAL_GetTick();
        while (HAL_CAN_GetTxMailboxesFreeLevel(&hcan1) == 0) {
            if (HAL_GetTick() - start > 100) {
                return -1;  /* Timeout */
            }
        }

        if (HAL_CAN_AddTxMessage(&hcan1, &can_tx_header, (uint8_t*)(data + offset), &mailbox) != HAL_OK) {
            return -1;
        }

        offset += chunk_len;
    }

    return 0;
}

static int can_receive(uint8_t *buffer, uint16_t max_len) {
    if (HAL_CAN_GetRxFifoFillLevel(&hcan1, CAN_RX_FIFO0) == 0) {
        return 0;
    }

    uint8_t data[8];
    if (HAL_CAN_GetRxMessage(&hcan1, CAN_RX_FIFO0, &can_rx_header, data) != HAL_OK) {
        return 0;
    }

    uint8_t len = can_rx_header.DLC;
    if (len > max_len) len = max_len;

    memcpy(buffer, data, len);
    return len;
}

/* CAN RX Interrupt callback */
void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan) {
    uint8_t data[8];
    if (HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &can_rx_header, data) == HAL_OK) {
        /* Add to queue */
        uint8_t next = (rx_head + 1) % NERT_RX_QUEUE_SIZE;
        if (next != rx_tail) {
            memcpy(rx_queue[rx_head].data, data, can_rx_header.DLC);
            rx_queue[rx_head].len = can_rx_header.DLC;
            rx_head = next;
        }
    }
}

#endif /* NERT_STM32_USE_CAN */

/* ============================================================================
 * HAL Implementation
 * ============================================================================ */

int nert_hal_send(const void *data, uint16_t len) {
    if (len > NERT_MAX_FRAME_SIZE) return -1;

#if NERT_STM32_USE_LORA
    if (use_lora) {
        return lora_send((const uint8_t*)data, len);
    }
#endif

#if NERT_STM32_USE_CAN
    return can_send((const uint8_t*)data, len);
#else
    return -1;
#endif
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
#if NERT_STM32_USE_LORA
    if (use_lora) {
        return lora_receive((uint8_t*)buffer, max_len);
    }
#endif

#if NERT_STM32_USE_CAN
    /* Check queue first */
    if (rx_head != rx_tail) {
        uint16_t len = rx_queue[rx_tail].len;
        if (len > max_len) len = max_len;
        memcpy(buffer, rx_queue[rx_tail].data, len);
        rx_tail = (rx_tail + 1) % NERT_RX_QUEUE_SIZE;
        return len;
    }

    return can_receive((uint8_t*)buffer, max_len);
#else
    return 0;
#endif
}

uint32_t nert_hal_get_ticks(void) {
    return HAL_GetTick() - boot_tick;
}

uint32_t nert_hal_random(void) {
    uint32_t random;
    if (HAL_RNG_GenerateRandomNumber(&hrng, &random) != HAL_OK) {
        /* Fallback to pseudo-random */
        static uint32_t seed = 0x12345678;
        seed = seed * 1103515245 + 12345;
        return seed;
    }
    return random;
}

uint16_t nert_hal_get_node_id(void) {
    if (local_node_id == 0) {
        /* Try to load from flash */
        struct nert_flash_config config;
        if (flash_read_config(&config) == 0 && config.node_id != 0) {
            local_node_id = config.node_id;
        } else {
            /* Generate from device unique ID */
            uint32_t uid0 = HAL_GetUIDw0();
            uint32_t uid1 = HAL_GetUIDw1();
            local_node_id = (uint16_t)((uid0 ^ uid1) & 0xFFFF);
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

void nert_hal_enter_stop_mode(uint32_t wakeup_ms) {
    /* Configure RTC wakeup timer */
    HAL_RTCEx_SetWakeUpTimer_IT(&hrtc, wakeup_ms * 2, RTC_WAKEUPCLOCK_RTCCLK_DIV16);

    /* Enter STOP mode */
    HAL_PWR_EnterSTOPMode(PWR_LOWPOWERREGULATOR_ON, PWR_STOPENTRY_WFI);

    /* Reconfigure clocks after wakeup */
    SystemClock_Config();

    /* Disable wakeup timer */
    HAL_RTCEx_DeactivateWakeUpTimer(&hrtc);
}

void nert_hal_enter_standby_mode(void) {
    /* Enter STANDBY mode (lowest power, loses RAM) */
    HAL_PWR_EnterSTANDBYMode();
}

void nert_hal_set_tx_power(int8_t power_dbm) {
#if NERT_STM32_USE_LORA
    if (use_lora) {
        /* Clamp to valid range */
        if (power_dbm < 2) power_dbm = 2;
        if (power_dbm > 17) power_dbm = 17;

        uint8_t pa_config = 0x80 | (power_dbm - 2);
        lora_write_reg(REG_PA_CONFIG, pa_config);
    }
#endif
    (void)power_dbm;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void nert_hal_init(void) {
    boot_tick = HAL_GetTick();

    /* Load configuration */
    struct nert_flash_config config;
    if (flash_read_config(&config) == 0) {
        use_lora = config.lora_enabled;
    }

    /* Initialize transport */
#if NERT_STM32_USE_CAN
    if (!use_lora) {
        can_init();
    }
#endif

#if NERT_STM32_USE_LORA
    if (use_lora || !NERT_STM32_USE_CAN) {
        if (lora_init() == 0) {
            lora_start_rx();
        } else {
            /* Fall back to CAN if LoRa init failed */
            use_lora = 0;
#if NERT_STM32_USE_CAN
            can_init();
#endif
        }
    }
#endif

    /* Pre-compute node ID */
    nert_hal_get_node_id();
}

/* ============================================================================
 * PHY Interface for NERT Protocol
 * ============================================================================ */

static int stm32_phy_send(const void *data, uint16_t len, void *ctx) {
    (void)ctx;
    return nert_hal_send(data, len);
}

static int stm32_phy_receive(void *buffer, uint16_t max_len, void *ctx) {
    (void)ctx;
    return nert_hal_receive(buffer, max_len);
}

static uint32_t stm32_phy_get_ticks(void *ctx) {
    (void)ctx;
    return nert_hal_get_ticks();
}

static uint32_t stm32_phy_random(void *ctx) {
    (void)ctx;
    return nert_hal_random();
}

static struct nert_phy_interface stm32_phy = {
    .send = stm32_phy_send,
    .receive = stm32_phy_receive,
    .get_ticks = stm32_phy_get_ticks,
    .random = stm32_phy_random,
    .context = NULL
};

struct nert_phy_interface* nert_phy_stm32_get(void) {
    return &stm32_phy;
}

#endif /* STM32F4 || NANOS_PLATFORM_STM32 */
