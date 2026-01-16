/*
 * NanOS - Intel e1000 (82540EM) Driver Header
 * The sensory organ for detecting pheromones
 */

#ifndef E1000_H
#define E1000_H

#include "nanos.h"  /* For types and structures */

/* ==========================================================================
 * PCI Configuration - Where to find our NIC
 * ========================================================================== */
#define PCI_CONFIG_ADDR     0xCF8
#define PCI_CONFIG_DATA     0xCFC

#define E1000_VENDOR_ID     0x8086  /* Intel */
#define E1000_DEVICE_ID     0x100E  /* 82540EM (QEMU default) */

/* ==========================================================================
 * e1000 Register Offsets - The NIC's control panel
 * ========================================================================== */
#define E1000_CTRL          0x0000  /* Device Control */
#define E1000_STATUS        0x0008  /* Device Status */
#define E1000_EERD          0x0014  /* EEPROM Read */
#define E1000_ICR           0x00C0  /* Interrupt Cause Read */
#define E1000_IMS           0x00D0  /* Interrupt Mask Set */
#define E1000_IMC           0x00D8  /* Interrupt Mask Clear */
#define E1000_RCTL          0x0100  /* Receive Control */
#define E1000_TCTL          0x0400  /* Transmit Control */
#define E1000_RDBAL         0x2800  /* RX Descriptor Base Low */
#define E1000_RDBAH         0x2804  /* RX Descriptor Base High */
#define E1000_RDLEN         0x2808  /* RX Descriptor Length */
#define E1000_RDH           0x2810  /* RX Descriptor Head */
#define E1000_RDT           0x2818  /* RX Descriptor Tail */
#define E1000_TDBAL         0x3800  /* TX Descriptor Base Low */
#define E1000_TDBAH         0x3804  /* TX Descriptor Base High */
#define E1000_TDLEN         0x3808  /* TX Descriptor Length */
#define E1000_TDH           0x3810  /* TX Descriptor Head */
#define E1000_TDT           0x3818  /* TX Descriptor Tail */
#define E1000_RAL           0x5400  /* Receive Address Low */
#define E1000_RAH           0x5404  /* Receive Address High */
#define E1000_MTA           0x5200  /* Multicast Table Array (128 entries) */

/* ==========================================================================
 * Control Register Bits
 * ========================================================================== */
#define E1000_CTRL_SLU      (1 << 6)    /* Set Link Up */
#define E1000_CTRL_RST      (1 << 26)   /* Device Reset */

/* ==========================================================================
 * Receive Control Bits - PROMISCUOUS MODE is key
 * ========================================================================== */
#define E1000_RCTL_EN       (1 << 1)    /* Receiver Enable */
#define E1000_RCTL_SBP      (1 << 2)    /* Store Bad Packets */
#define E1000_RCTL_UPE      (1 << 3)    /* Unicast Promiscuous Enable */
#define E1000_RCTL_MPE      (1 << 4)    /* Multicast Promiscuous Enable */
#define E1000_RCTL_BAM      (1 << 15)   /* Broadcast Accept Mode */
#define E1000_RCTL_BSIZE_2K (0 << 16)   /* Buffer Size 2048 */
#define E1000_RCTL_SECRC    (1 << 26)   /* Strip Ethernet CRC */

/* ==========================================================================
 * Transmit Control Bits
 * ========================================================================== */
#define E1000_TCTL_EN       (1 << 1)    /* Transmitter Enable */
#define E1000_TCTL_PSP      (1 << 3)    /* Pad Short Packets */
#define E1000_TCTL_CT_SHIFT 4           /* Collision Threshold shift */
#define E1000_TCTL_COLD_SHIFT 12        /* Collision Distance shift */

/* ==========================================================================
 * Descriptor Status Bits
 * ========================================================================== */
#define E1000_RXD_STAT_DD   (1 << 0)    /* Descriptor Done */
#define E1000_RXD_STAT_EOP  (1 << 1)    /* End of Packet */
#define E1000_TXD_STAT_DD   (1 << 0)    /* Descriptor Done */
#define E1000_TXD_CMD_EOP   (1 << 0)    /* End of Packet */
#define E1000_TXD_CMD_RS    (1 << 3)    /* Report Status */

/* ==========================================================================
 * Descriptor Ring Configuration
 * ========================================================================== */
#define E1000_NUM_RX_DESC   32      /* Small ring - we process fast */
#define E1000_NUM_TX_DESC   8       /* Tiny TX ring - we don't talk much */
#define E1000_RX_BUFFER_SIZE 2048   /* Per-packet buffer */

/* ==========================================================================
 * RX Descriptor - Hardware structure for receiving packets
 * ========================================================================== */
struct e1000_rx_desc {
    uint64_t addr;      /* Buffer address */
    uint16_t length;    /* Packet length */
    uint16_t checksum;  /* Hardware checksum */
    uint8_t  status;    /* Descriptor status */
    uint8_t  errors;    /* Error flags */
    uint16_t special;   /* VLAN tag */
} __attribute__((packed));

/* ==========================================================================
 * TX Descriptor - Hardware structure for transmitting packets
 * ========================================================================== */
struct e1000_tx_desc {
    uint64_t addr;      /* Buffer address */
    uint16_t length;    /* Packet length */
    uint8_t  cso;       /* Checksum offset */
    uint8_t  cmd;       /* Command field */
    uint8_t  status;    /* Descriptor status */
    uint8_t  css;       /* Checksum start */
    uint16_t special;   /* VLAN tag */
} __attribute__((packed));

/* ==========================================================================
 * Ethernet Frame Header
 * ========================================================================== */
#define ETH_ALEN            6       /* MAC address length */
#define ETH_TYPE_NANOS      0x4E4F  /* "NO" - NanOS protocol */

struct eth_header {
    uint8_t  dst[ETH_ALEN];     /* Destination MAC */
    uint8_t  src[ETH_ALEN];     /* Source MAC */
    uint16_t ethertype;         /* Protocol type */
} __attribute__((packed));

/* ==========================================================================
 * Driver Functions
 * ========================================================================== */
int  e1000_init(void);
void e1000_get_mac(uint8_t* mac);
int  e1000_send(void* data, uint16_t length);
int  e1000_receive(void* buffer, uint16_t max_length);
bool e1000_has_packet(void);

/* Non-blocking TX queue management */
void e1000_tx_drain(void);           /* Call from main loop to flush queue */
uint8_t e1000_tx_queue_depth(void);  /* Current queue depth */
uint32_t e1000_tx_dropped(void);     /* Packets dropped due to full queue */
bool e1000_tx_queue_available(void); /* Is there space in queue? */

#endif /* E1000_H */
