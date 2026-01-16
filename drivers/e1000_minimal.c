/*
 * NanOS - Intel e1000 (82540EM) Driver v0.2
 * The cell's sensory and effector organ for pheromone transmission
 *
 * v0.2 Improvements:
 *   - Non-blocking TX with software queue
 *   - Exponential backoff on congestion
 *   - TX queue drain in main loop
 */

#include "../include/e1000.h"
#include "../include/io.h"

/* ==========================================================================
 * Software TX Queue - Non-blocking transmission
 * ========================================================================== */
#define TX_QUEUE_SIZE       16      /* Software queue depth */
#define TX_BACKOFF_INIT     1       /* Initial backoff (ticks) */
#define TX_BACKOFF_MAX      32      /* Maximum backoff */

struct tx_queue_entry {
    uint8_t  data[128];     /* Packet data (max size for our protocol) */
    uint16_t length;        /* Packet length */
    uint8_t  used;          /* Slot in use? */
};

static struct tx_queue_entry tx_queue[TX_QUEUE_SIZE];
static uint8_t tx_queue_head = 0;   /* Next slot to dequeue */
static uint8_t tx_queue_tail = 0;   /* Next slot to enqueue */
static uint8_t tx_queue_count = 0;  /* Items in queue */
static uint8_t tx_backoff = 0;      /* Current backoff counter */
static uint32_t tx_dropped = 0;     /* Packets dropped due to full queue */

/* ==========================================================================
 * Driver State - Minimal, static allocation
 * ========================================================================== */
static uint32_t e1000_mmio_base = 0;
static uint8_t  e1000_mac[6];
static bool     e1000_initialized = false;

/* Descriptor rings - aligned to 16 bytes as required by hardware */
static struct e1000_rx_desc rx_descs[E1000_NUM_RX_DESC] __attribute__((aligned(16)));
static struct e1000_tx_desc tx_descs[E1000_NUM_TX_DESC] __attribute__((aligned(16)));

/* RX buffers */
static uint8_t rx_buffers[E1000_NUM_RX_DESC][E1000_RX_BUFFER_SIZE] __attribute__((aligned(16)));

/* TX buffers - one per hardware descriptor now */
static uint8_t tx_buffers[E1000_NUM_TX_DESC][256] __attribute__((aligned(16)));

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
 * ========================================================================== */
static uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1 << 31)
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

static int pci_find_e1000(uint8_t* bus_out, uint8_t* slot_out) {
    for (uint8_t bus = 0; bus < 255; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            uint32_t vendor_device = pci_read(bus, slot, 0, 0);
            uint16_t vendor = vendor_device & 0xFFFF;
            uint16_t device = vendor_device >> 16;

            if (vendor == E1000_VENDOR_ID && device == E1000_DEVICE_ID) {
                *bus_out = bus;
                *slot_out = slot;
                return 0;
            }
        }
    }
    return -1;
}

/* ==========================================================================
 * EEPROM Access
 * ========================================================================== */
static uint16_t eeprom_read(uint8_t addr) {
    e1000_write(E1000_EERD, (addr << 8) | 1);

    uint32_t val;
    do {
        val = e1000_read(E1000_EERD);
    } while (!(val & (1 << 4)));

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
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        rx_descs[i].addr   = (uint64_t)(uint32_t)rx_buffers[i];
        rx_descs[i].status = 0;
    }

    e1000_write(E1000_RDBAL, (uint32_t)rx_descs);
    e1000_write(E1000_RDBAH, 0);
    e1000_write(E1000_RDLEN, E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));
    e1000_write(E1000_RDH, 0);
    e1000_write(E1000_RDT, E1000_NUM_RX_DESC - 1);

    rx_cur = 0;

    /* PROMISCUOUS MODE - we hear everything */
    uint32_t rctl = E1000_RCTL_EN
                  | E1000_RCTL_SBP
                  | E1000_RCTL_UPE
                  | E1000_RCTL_MPE
                  | E1000_RCTL_BAM
                  | E1000_RCTL_BSIZE_2K
                  | E1000_RCTL_SECRC;

    e1000_write(E1000_RCTL, rctl);
}

/* ==========================================================================
 * TX Ring Initialization
 * ========================================================================== */
static void init_tx(void) {
    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        tx_descs[i].addr   = (uint64_t)(uint32_t)tx_buffers[i];
        tx_descs[i].cmd    = 0;
        tx_descs[i].status = E1000_TXD_STAT_DD;
    }

    e1000_write(E1000_TDBAL, (uint32_t)tx_descs);
    e1000_write(E1000_TDBAH, 0);
    e1000_write(E1000_TDLEN, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    e1000_write(E1000_TDH, 0);
    e1000_write(E1000_TDT, 0);

    tx_cur = 0;

    uint32_t tctl = E1000_TCTL_EN
                  | E1000_TCTL_PSP
                  | (15 << E1000_TCTL_CT_SHIFT)
                  | (64 << E1000_TCTL_COLD_SHIFT);

    e1000_write(E1000_TCTL, tctl);

    /* Initialize software queue */
    for (int i = 0; i < TX_QUEUE_SIZE; i++) {
        tx_queue[i].used = 0;
    }
    tx_queue_head = 0;
    tx_queue_tail = 0;
    tx_queue_count = 0;
}

/* ==========================================================================
 * Main Initialization
 * ========================================================================== */
int e1000_init(void) {
    uint8_t bus, slot;

    if (pci_find_e1000(&bus, &slot) != 0) {
        return -1;
    }

    uint32_t bar0 = pci_read(bus, slot, 0, 0x10);
    if (bar0 & 1) {
        return -2;
    }
    e1000_mmio_base = bar0 & ~0xF;

    uint32_t cmd = pci_read(bus, slot, 0, 0x04);
    cmd |= (1 << 1) | (1 << 2);
    pci_write(bus, slot, 0, 0x04, cmd);

    e1000_write(E1000_CTRL, E1000_CTRL_RST);
    while (e1000_read(E1000_CTRL) & E1000_CTRL_RST);

    for (volatile int i = 0; i < 100000; i++);

    uint32_t ctrl = e1000_read(E1000_CTRL);
    ctrl |= E1000_CTRL_SLU;
    e1000_write(E1000_CTRL, ctrl);

    read_mac_from_eeprom();

    for (int i = 0; i < 128; i++) {
        e1000_write(E1000_MTA + (i * 4), 0);
    }

    e1000_write(E1000_IMC, 0xFFFFFFFF);

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
 * ========================================================================== */
int e1000_receive(void* buffer, uint16_t max_length) {
    if (!e1000_initialized) return -1;

    if (!(rx_descs[rx_cur].status & E1000_RXD_STAT_DD)) {
        return -1;
    }

    uint16_t length = rx_descs[rx_cur].length;
    if (length > max_length) {
        length = max_length;
    }

    uint8_t* src = rx_buffers[rx_cur];
    uint8_t* dst = (uint8_t*)buffer;
    for (uint16_t i = 0; i < length; i++) {
        dst[i] = src[i];
    }

    rx_descs[rx_cur].status = 0;

    uint32_t old_cur = rx_cur;
    rx_cur = (rx_cur + 1) % E1000_NUM_RX_DESC;
    e1000_write(E1000_RDT, old_cur);

    return length;
}

/* ==========================================================================
 * Check if hardware TX is ready
 * ========================================================================== */
static bool tx_hw_ready(void) {
    return (tx_descs[tx_cur].status & E1000_TXD_STAT_DD) != 0;
}

/* ==========================================================================
 * Send directly to hardware (internal)
 * Returns 0 on success, -1 if hardware busy
 * ========================================================================== */
static int tx_hw_send(uint8_t* data, uint16_t length) {
    if (!tx_hw_ready()) {
        return -1;  /* Hardware busy */
    }

    /* Build Ethernet frame */
    uint8_t* buf = tx_buffers[tx_cur];
    struct eth_header* eth = (struct eth_header*)buf;

    /* Broadcast destination */
    eth->dst[0] = 0xFF; eth->dst[1] = 0xFF; eth->dst[2] = 0xFF;
    eth->dst[3] = 0xFF; eth->dst[4] = 0xFF; eth->dst[5] = 0xFF;

    /* Source MAC */
    for (int i = 0; i < 6; i++) {
        eth->src[i] = e1000_mac[i];
    }

    eth->ethertype = ETH_TYPE_NANOS;

    /* Copy payload */
    uint8_t* payload = buf + sizeof(struct eth_header);
    for (uint16_t i = 0; i < length; i++) {
        payload[i] = data[i];
    }

    /* Calculate frame length (min 60 bytes) */
    uint16_t frame_length = sizeof(struct eth_header) + length;
    if (frame_length < 60) {
        /* Pad with zeros */
        for (uint16_t i = frame_length; i < 60; i++) {
            buf[i] = 0;
        }
        frame_length = 60;
    }

    /* Setup descriptor */
    tx_descs[tx_cur].length = frame_length;
    tx_descs[tx_cur].cmd    = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
    tx_descs[tx_cur].status = 0;

    /* Trigger transmission */
    uint32_t old_cur = tx_cur;
    tx_cur = (tx_cur + 1) % E1000_NUM_TX_DESC;
    e1000_write(E1000_TDT, (old_cur + 1) % E1000_NUM_TX_DESC);

    tx_backoff = TX_BACKOFF_INIT;  /* Reset backoff on success */
    return 0;
}

/* ==========================================================================
 * Enqueue packet to software queue (non-blocking)
 * Returns 0 on success, -1 if queue full
 * ========================================================================== */
int e1000_send(void* data, uint16_t length) {
    if (!e1000_initialized) return -1;
    if (length > 128) return -2;  /* Too large */

    /* Try direct send first if queue empty and HW ready */
    if (tx_queue_count == 0 && tx_hw_ready()) {
        return tx_hw_send((uint8_t*)data, length);
    }

    /* Queue is not empty or HW busy - enqueue */
    if (tx_queue_count >= TX_QUEUE_SIZE) {
        tx_dropped++;
        return -3;  /* Queue full */
    }

    /* Copy to queue */
    struct tx_queue_entry* entry = &tx_queue[tx_queue_tail];
    uint8_t* src = (uint8_t*)data;
    for (uint16_t i = 0; i < length; i++) {
        entry->data[i] = src[i];
    }
    entry->length = length;
    entry->used = 1;

    tx_queue_tail = (tx_queue_tail + 1) % TX_QUEUE_SIZE;
    tx_queue_count++;

    return 0;
}

/* ==========================================================================
 * Drain TX Queue - Call this from main loop
 * Attempts to send one packet from queue per call (non-blocking)
 * ========================================================================== */
void e1000_tx_drain(void) {
    if (!e1000_initialized) return;
    if (tx_queue_count == 0) return;

    /* Backoff logic - wait if we had recent congestion */
    if (tx_backoff > 0) {
        tx_backoff--;
        return;
    }

    /* Try to send head of queue */
    if (!tx_hw_ready()) {
        /* Hardware still busy - apply exponential backoff */
        tx_backoff = (tx_backoff < TX_BACKOFF_MAX) ?
                     tx_backoff * 2 : TX_BACKOFF_MAX;
        if (tx_backoff == 0) tx_backoff = TX_BACKOFF_INIT;
        return;
    }

    /* Hardware ready - send from queue */
    struct tx_queue_entry* entry = &tx_queue[tx_queue_head];
    if (entry->used) {
        tx_hw_send(entry->data, entry->length);
        entry->used = 0;
        tx_queue_head = (tx_queue_head + 1) % TX_QUEUE_SIZE;
        tx_queue_count--;
    }
}

/* ==========================================================================
 * Get TX Queue Statistics
 * ========================================================================== */
uint8_t e1000_tx_queue_depth(void) {
    return tx_queue_count;
}

uint32_t e1000_tx_dropped(void) {
    return tx_dropped;
}

/* ==========================================================================
 * Check if TX queue has space
 * ========================================================================== */
bool e1000_tx_queue_available(void) {
    return tx_queue_count < TX_QUEUE_SIZE;
}
