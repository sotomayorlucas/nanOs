/*
 * NanOS - Intel e1000 (82540EM) Minimal Driver
 * The cell's sensory and effector organ for pheromone transmission
 *
 * Key features:
 *   - PROMISCUOUS MODE: We capture ALL packets on the wire
 *   - No IP stack: Raw Ethernet frames only
 *   - Polling-based: No interrupts (keeps it simple)
 */

#include "../include/e1000.h"
#include "../include/io.h"

/* ==========================================================================
 * Driver State - Minimal, static allocation
 * ========================================================================== */
static uint32_t e1000_mmio_base = 0;    /* Memory-mapped I/O base address */
static uint8_t  e1000_mac[6];           /* Our MAC address */
static bool     e1000_initialized = false;

/* Descriptor rings - aligned to 16 bytes as required by hardware */
static struct e1000_rx_desc rx_descs[E1000_NUM_RX_DESC] __attribute__((aligned(16)));
static struct e1000_tx_desc tx_descs[E1000_NUM_TX_DESC] __attribute__((aligned(16)));

/* RX buffers */
static uint8_t rx_buffers[E1000_NUM_RX_DESC][E1000_RX_BUFFER_SIZE] __attribute__((aligned(16)));

/* TX buffer (single, we send one at a time) */
static uint8_t tx_buffer[E1000_RX_BUFFER_SIZE] __attribute__((aligned(16)));

/* Current descriptor indices */
static uint32_t rx_cur = 0;
static uint32_t tx_cur = 0;

/* ==========================================================================
 * Register Access Helpers
 * ========================================================================== */
static inline void e1000_write(uint32_t reg, uint32_t value) {
    mmio_write32(e1000_mmio_base + reg, value);
}

static inline uint32_t e1000_read(uint32_t reg) {
    return mmio_read32(e1000_mmio_base + reg);
}

/* ==========================================================================
 * PCI Configuration Space Access
 * Find our NIC on the PCI bus
 * ========================================================================== */
static uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1 << 31)           /* Enable bit */
                  | (bus << 16)
                  | (slot << 11)
                  | (func << 8)
                  | (offset & 0xFC);

    outl(PCI_CONFIG_ADDR, addr);
    return inl(PCI_CONFIG_DATA);
}

static void pci_write(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t addr = (1 << 31)
                  | (bus << 16)
                  | (slot << 11)
                  | (func << 8)
                  | (offset & 0xFC);

    outl(PCI_CONFIG_ADDR, addr);
    outl(PCI_CONFIG_DATA, value);
}

/* Scan PCI bus for e1000 NIC */
static int pci_find_e1000(uint8_t* bus_out, uint8_t* slot_out) {
    for (uint8_t bus = 0; bus < 256; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            uint32_t vendor_device = pci_read(bus, slot, 0, 0);
            uint16_t vendor = vendor_device & 0xFFFF;
            uint16_t device = vendor_device >> 16;

            if (vendor == E1000_VENDOR_ID && device == E1000_DEVICE_ID) {
                *bus_out = bus;
                *slot_out = slot;
                return 0;  /* Found */
            }
        }
    }
    return -1;  /* Not found */
}

/* ==========================================================================
 * EEPROM Access - Read MAC address from non-volatile memory
 * ========================================================================== */
static uint16_t eeprom_read(uint8_t addr) {
    /* Start read */
    e1000_write(E1000_EERD, (addr << 8) | 1);

    /* Wait for completion */
    uint32_t val;
    do {
        val = e1000_read(E1000_EERD);
    } while (!(val & (1 << 4)));  /* Bit 4 = done */

    return (val >> 16) & 0xFFFF;
}

static void read_mac_from_eeprom(void) {
    uint16_t word;

    word = eeprom_read(0);
    e1000_mac[0] = word & 0xFF;
    e1000_mac[1] = word >> 8;

    word = eeprom_read(1);
    e1000_mac[2] = word & 0xFF;
    e1000_mac[3] = word >> 8;

    word = eeprom_read(2);
    e1000_mac[4] = word & 0xFF;
    e1000_mac[5] = word >> 8;
}

/* ==========================================================================
 * RX Ring Initialization
 * ========================================================================== */
static void init_rx(void) {
    /* Setup RX descriptors */
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        rx_descs[i].addr   = (uint64_t)(uint32_t)rx_buffers[i];
        rx_descs[i].status = 0;
    }

    /* Set descriptor ring address */
    e1000_write(E1000_RDBAL, (uint32_t)rx_descs);
    e1000_write(E1000_RDBAH, 0);  /* 32-bit addressing */

    /* Set descriptor ring length (in bytes) */
    e1000_write(E1000_RDLEN, E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));

    /* Set head and tail pointers */
    e1000_write(E1000_RDH, 0);
    e1000_write(E1000_RDT, E1000_NUM_RX_DESC - 1);

    rx_cur = 0;

    /*
     * CRITICAL: Enable PROMISCUOUS MODE
     * This is the key to our swarm protocol - we hear EVERYTHING
     */
    uint32_t rctl = E1000_RCTL_EN        /* Receiver enable */
                  | E1000_RCTL_SBP       /* Store bad packets (for debugging) */
                  | E1000_RCTL_UPE       /* Unicast promiscuous */
                  | E1000_RCTL_MPE       /* Multicast promiscuous */
                  | E1000_RCTL_BAM       /* Accept broadcast */
                  | E1000_RCTL_BSIZE_2K  /* 2KB buffers */
                  | E1000_RCTL_SECRC;    /* Strip CRC */

    e1000_write(E1000_RCTL, rctl);
}

/* ==========================================================================
 * TX Ring Initialization
 * ========================================================================== */
static void init_tx(void) {
    /* Setup TX descriptors */
    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        tx_descs[i].addr   = 0;
        tx_descs[i].cmd    = 0;
        tx_descs[i].status = E1000_TXD_STAT_DD;  /* Mark as done */
    }

    /* Set descriptor ring address */
    e1000_write(E1000_TDBAL, (uint32_t)tx_descs);
    e1000_write(E1000_TDBAH, 0);

    /* Set descriptor ring length */
    e1000_write(E1000_TDLEN, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));

    /* Set head and tail pointers */
    e1000_write(E1000_TDH, 0);
    e1000_write(E1000_TDT, 0);

    tx_cur = 0;

    /* Enable transmitter with standard parameters */
    uint32_t tctl = E1000_TCTL_EN          /* Transmitter enable */
                  | E1000_TCTL_PSP         /* Pad short packets */
                  | (15 << E1000_TCTL_CT_SHIFT)    /* Collision threshold */
                  | (64 << E1000_TCTL_COLD_SHIFT); /* Collision distance */

    e1000_write(E1000_TCTL, tctl);
}

/* ==========================================================================
 * Main Initialization
 * ========================================================================== */
int e1000_init(void) {
    uint8_t bus, slot;

    /* Find the NIC on PCI bus */
    if (pci_find_e1000(&bus, &slot) != 0) {
        return -1;  /* NIC not found */
    }

    /* Get BAR0 (memory-mapped I/O base) */
    uint32_t bar0 = pci_read(bus, slot, 0, 0x10);
    if (bar0 & 1) {
        /* I/O space - not supported */
        return -2;
    }
    e1000_mmio_base = bar0 & ~0xF;  /* Mask lower 4 bits */

    /* Enable bus mastering and memory access */
    uint32_t cmd = pci_read(bus, slot, 0, 0x04);
    cmd |= (1 << 1) | (1 << 2);  /* Memory space + bus master */
    pci_write(bus, slot, 0, 0x04, cmd);

    /* Reset the device */
    e1000_write(E1000_CTRL, E1000_CTRL_RST);

    /* Wait for reset to complete (hardware clears RST bit) */
    while (e1000_read(E1000_CTRL) & E1000_CTRL_RST);

    /* Small delay after reset */
    for (volatile int i = 0; i < 100000; i++);

    /* Set link up */
    uint32_t ctrl = e1000_read(E1000_CTRL);
    ctrl |= E1000_CTRL_SLU;
    e1000_write(E1000_CTRL, ctrl);

    /* Read MAC address from EEPROM */
    read_mac_from_eeprom();

    /* Clear multicast table array */
    for (int i = 0; i < 128; i++) {
        e1000_write(E1000_MTA + (i * 4), 0);
    }

    /* Disable interrupts (we use polling) */
    e1000_write(E1000_IMC, 0xFFFFFFFF);

    /* Initialize RX and TX rings */
    init_rx();
    init_tx();

    e1000_initialized = true;
    return 0;
}

/* ==========================================================================
 * Get MAC Address
 * ========================================================================== */
void e1000_get_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = e1000_mac[i];
    }
}

/* ==========================================================================
 * Check for Pending Packet
 * ========================================================================== */
bool e1000_has_packet(void) {
    if (!e1000_initialized) return false;
    return (rx_descs[rx_cur].status & E1000_RXD_STAT_DD) != 0;
}

/* ==========================================================================
 * Receive a Packet
 * Returns packet length, or -1 if no packet available
 * ========================================================================== */
int e1000_receive(void* buffer, uint16_t max_length) {
    if (!e1000_initialized) return -1;

    /* Check if current descriptor has a packet */
    if (!(rx_descs[rx_cur].status & E1000_RXD_STAT_DD)) {
        return -1;  /* No packet */
    }

    uint16_t length = rx_descs[rx_cur].length;
    if (length > max_length) {
        length = max_length;
    }

    /* Copy packet data */
    uint8_t* src = rx_buffers[rx_cur];
    uint8_t* dst = (uint8_t*)buffer;
    for (uint16_t i = 0; i < length; i++) {
        dst[i] = src[i];
    }

    /* Reset descriptor for reuse */
    rx_descs[rx_cur].status = 0;

    /* Update tail pointer to return descriptor to hardware */
    uint32_t old_cur = rx_cur;
    rx_cur = (rx_cur + 1) % E1000_NUM_RX_DESC;
    e1000_write(E1000_RDT, old_cur);

    return length;
}

/* ==========================================================================
 * Send a Packet
 * Wraps data in Ethernet frame with broadcast destination
 * ========================================================================== */
int e1000_send(void* data, uint16_t length) {
    if (!e1000_initialized) return -1;

    /* Minimum Ethernet frame is 60 bytes (+ 4 CRC = 64) */
    uint16_t frame_length = sizeof(struct eth_header) + length;
    if (frame_length < 60) {
        frame_length = 60;
    }

    /* Build Ethernet frame in TX buffer */
    struct eth_header* eth = (struct eth_header*)tx_buffer;

    /* Broadcast destination (all nodes hear this) */
    eth->dst[0] = 0xFF;
    eth->dst[1] = 0xFF;
    eth->dst[2] = 0xFF;
    eth->dst[3] = 0xFF;
    eth->dst[4] = 0xFF;
    eth->dst[5] = 0xFF;

    /* Source is our MAC */
    for (int i = 0; i < 6; i++) {
        eth->src[i] = e1000_mac[i];
    }

    /* Custom ethertype for NanOS protocol */
    eth->ethertype = ETH_TYPE_NANOS;

    /* Copy payload */
    uint8_t* payload = tx_buffer + sizeof(struct eth_header);
    uint8_t* src = (uint8_t*)data;
    for (uint16_t i = 0; i < length; i++) {
        payload[i] = src[i];
    }

    /* Pad with zeros if needed */
    for (uint16_t i = sizeof(struct eth_header) + length; i < frame_length; i++) {
        tx_buffer[i] = 0;
    }

    /* Wait for previous transmission to complete */
    while (!(tx_descs[tx_cur].status & E1000_TXD_STAT_DD));

    /* Setup TX descriptor */
    tx_descs[tx_cur].addr   = (uint64_t)(uint32_t)tx_buffer;
    tx_descs[tx_cur].length = frame_length;
    tx_descs[tx_cur].cmd    = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
    tx_descs[tx_cur].status = 0;

    /* Advance tail pointer to trigger transmission */
    uint32_t old_cur = tx_cur;
    tx_cur = (tx_cur + 1) % E1000_NUM_TX_DESC;
    e1000_write(E1000_TDT, (old_cur + 1) % E1000_NUM_TX_DESC);

    return 0;
}
