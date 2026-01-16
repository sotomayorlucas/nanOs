/*
 * NanOS - VirtIO Network Driver
 * For QEMU virt machine (ARM64) and other VirtIO-capable platforms
 *
 * Implements VirtIO 1.0 (modern) over MMIO transport
 * Reference: https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.pdf
 */

#include "../include/hal.h"
#include "../include/nanos.h"

/* Only compile for non-x86 platforms */
#if !defined(ARCH_X86)

/* ==========================================================================
 * VirtIO MMIO Register Offsets
 * ========================================================================== */
#define VIRTIO_MMIO_MAGIC           0x000
#define VIRTIO_MMIO_VERSION         0x004
#define VIRTIO_MMIO_DEVICE_ID       0x008
#define VIRTIO_MMIO_VENDOR_ID       0x00C
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#define VIRTIO_MMIO_QUEUE_SEL       0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX   0x034
#define VIRTIO_MMIO_QUEUE_NUM       0x038
#define VIRTIO_MMIO_QUEUE_READY     0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY    0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK   0x064
#define VIRTIO_MMIO_STATUS          0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW  0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0A0
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0A4
#define VIRTIO_MMIO_CONFIG          0x100

/* VirtIO Magic */
#define VIRTIO_MAGIC                0x74726976  /* "virt" */

/* Device IDs */
#define VIRTIO_DEVICE_NET           1

/* Device Status Bits */
#define VIRTIO_STATUS_ACKNOWLEDGE   1
#define VIRTIO_STATUS_DRIVER        2
#define VIRTIO_STATUS_DRIVER_OK     4
#define VIRTIO_STATUS_FEATURES_OK   8
#define VIRTIO_STATUS_FAILED        128

/* VirtIO Net Feature Bits */
#define VIRTIO_NET_F_MAC            (1 << 5)
#define VIRTIO_NET_F_STATUS         (1 << 16)

/* ==========================================================================
 * VirtIO Ring Structures
 * ========================================================================== */
#define VIRTQ_DESC_F_NEXT           1
#define VIRTQ_DESC_F_WRITE          2

struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
} __attribute__((packed));

/* ==========================================================================
 * VirtIO Net Header
 * ========================================================================== */
struct virtio_net_hdr {
    uint8_t  flags;
    uint8_t  gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __attribute__((packed));

/* ==========================================================================
 * Queue Configuration
 * ========================================================================== */
#define RX_QUEUE        0
#define TX_QUEUE        1
#define QUEUE_SIZE      16
#define RX_BUFFER_SIZE  2048

/* ==========================================================================
 * Driver State
 * ========================================================================== */
static uintptr_t virtio_base = 0;
static bool virtio_initialized = false;
static uint8_t virtio_mac[6];

/* Descriptor rings (aligned to 16 bytes) */
static struct virtq_desc rx_descs[QUEUE_SIZE] __attribute__((aligned(16)));
static struct virtq_desc tx_descs[QUEUE_SIZE] __attribute__((aligned(16)));

/* Available rings */
static uint8_t rx_avail_mem[sizeof(struct virtq_avail) + QUEUE_SIZE * 2 + 2] __attribute__((aligned(2)));
static uint8_t tx_avail_mem[sizeof(struct virtq_avail) + QUEUE_SIZE * 2 + 2] __attribute__((aligned(2)));

/* Used rings (aligned to 4 bytes) */
static uint8_t rx_used_mem[sizeof(struct virtq_used) + QUEUE_SIZE * 8 + 2] __attribute__((aligned(4)));
static uint8_t tx_used_mem[sizeof(struct virtq_used) + QUEUE_SIZE * 8 + 2] __attribute__((aligned(4)));

/* Pointers to rings */
static struct virtq_avail* rx_avail;
static struct virtq_avail* tx_avail;
static struct virtq_used* rx_used;
static struct virtq_used* tx_used;

/* RX buffers */
static uint8_t rx_buffers[QUEUE_SIZE][RX_BUFFER_SIZE] __attribute__((aligned(16)));

/* TX buffer (single, we send one at a time) */
static uint8_t tx_buffer[RX_BUFFER_SIZE] __attribute__((aligned(16)));

/* Indices */
static uint16_t rx_last_used = 0;
static uint16_t tx_last_used = 0;
static uint16_t tx_cur = 0;

/* Software TX queue (like e1000) */
#define TX_SW_QUEUE_SIZE 16
struct tx_queue_entry {
    uint8_t data[128];
    uint16_t length;
    uint8_t used;
};
static struct tx_queue_entry tx_sw_queue[TX_SW_QUEUE_SIZE];
static uint8_t tx_sw_head = 0;
static uint8_t tx_sw_tail = 0;
static uint8_t tx_sw_count = 0;

/* ==========================================================================
 * MMIO Helpers
 * ========================================================================== */
static inline void vio_write32(uint32_t reg, uint32_t val) {
    mmio_write32(virtio_base + reg, val);
}

static inline uint32_t vio_read32(uint32_t reg) {
    return mmio_read32(virtio_base + reg);
}

/* ==========================================================================
 * Find VirtIO Network Device
 * ========================================================================== */
static uintptr_t find_virtio_net(void) {
    /* QEMU virt machine: VirtIO MMIO at 0x0A000000, 0x200 bytes each */
    for (int i = 0; i < 32; i++) {
        uintptr_t base = 0x0A000000 + i * 0x200;

        uint32_t magic = mmio_read32(base + VIRTIO_MMIO_MAGIC);
        if (magic != VIRTIO_MAGIC) continue;

        uint32_t device_id = mmio_read32(base + VIRTIO_MMIO_DEVICE_ID);
        if (device_id == VIRTIO_DEVICE_NET) {
            return base;
        }
    }
    return 0;
}

/* ==========================================================================
 * Initialize a VirtQueue
 * ========================================================================== */
static void init_virtq(int queue_idx, struct virtq_desc* descs,
                       struct virtq_avail* avail, struct virtq_used* used) {
    /* Select queue */
    vio_write32(VIRTIO_MMIO_QUEUE_SEL, queue_idx);
    dmb();

    /* Get max queue size */
    uint32_t max_size = vio_read32(VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0 || max_size < QUEUE_SIZE) {
        return;  /* Queue not available or too small */
    }

    /* Set our queue size */
    vio_write32(VIRTIO_MMIO_QUEUE_NUM, QUEUE_SIZE);

    /* Set descriptor table address */
    uint64_t desc_addr = (uint64_t)(uintptr_t)descs;
    vio_write32(VIRTIO_MMIO_QUEUE_DESC_LOW, (uint32_t)desc_addr);
    vio_write32(VIRTIO_MMIO_QUEUE_DESC_HIGH, (uint32_t)(desc_addr >> 32));

    /* Set available ring address */
    uint64_t avail_addr = (uint64_t)(uintptr_t)avail;
    vio_write32(VIRTIO_MMIO_QUEUE_DRIVER_LOW, (uint32_t)avail_addr);
    vio_write32(VIRTIO_MMIO_QUEUE_DRIVER_HIGH, (uint32_t)(avail_addr >> 32));

    /* Set used ring address */
    uint64_t used_addr = (uint64_t)(uintptr_t)used;
    vio_write32(VIRTIO_MMIO_QUEUE_DEVICE_LOW, (uint32_t)used_addr);
    vio_write32(VIRTIO_MMIO_QUEUE_DEVICE_HIGH, (uint32_t)(used_addr >> 32));

    /* Enable the queue */
    vio_write32(VIRTIO_MMIO_QUEUE_READY, 1);
    dmb();
}

/* ==========================================================================
 * Initialize RX Queue with Buffers
 * ========================================================================== */
static void setup_rx_buffers(void) {
    for (int i = 0; i < QUEUE_SIZE; i++) {
        rx_descs[i].addr = (uint64_t)(uintptr_t)rx_buffers[i];
        rx_descs[i].len = RX_BUFFER_SIZE;
        rx_descs[i].flags = VIRTQ_DESC_F_WRITE;
        rx_descs[i].next = 0;

        /* Add to available ring */
        rx_avail->ring[i] = i;
    }
    dmb();
    rx_avail->idx = QUEUE_SIZE;
    dmb();

    /* Notify device */
    vio_write32(VIRTIO_MMIO_QUEUE_NOTIFY, RX_QUEUE);
}

/* ==========================================================================
 * Read MAC Address from Device Config
 * ========================================================================== */
static void read_mac_address(void) {
    for (int i = 0; i < 6; i++) {
        virtio_mac[i] = mmio_read8(virtio_base + VIRTIO_MMIO_CONFIG + i);
    }
}

/* ==========================================================================
 * Initialize VirtIO Network Device
 * ========================================================================== */
int virtio_net_init(void) {
    /* Find the device */
    virtio_base = find_virtio_net();
    if (virtio_base == 0) {
        return -1;  /* Not found */
    }

    /* Reset device */
    vio_write32(VIRTIO_MMIO_STATUS, 0);
    dmb();

    /* Acknowledge */
    vio_write32(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    dmb();

    /* We know how to drive this device */
    vio_write32(VIRTIO_MMIO_STATUS,
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
    dmb();

    /* Read device features */
    vio_write32(VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
    uint32_t features = vio_read32(VIRTIO_MMIO_DEVICE_FEATURES);

    /* Accept MAC feature if available */
    uint32_t accepted = 0;
    if (features & VIRTIO_NET_F_MAC) {
        accepted |= VIRTIO_NET_F_MAC;
    }

    /* Write accepted features */
    vio_write32(VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    vio_write32(VIRTIO_MMIO_DRIVER_FEATURES, accepted);
    dmb();

    /* Features OK */
    vio_write32(VIRTIO_MMIO_STATUS,
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                VIRTIO_STATUS_FEATURES_OK);
    dmb();

    /* Check that device accepted our features */
    if (!(vio_read32(VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        vio_write32(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return -2;
    }

    /* Initialize ring pointers */
    rx_avail = (struct virtq_avail*)rx_avail_mem;
    tx_avail = (struct virtq_avail*)tx_avail_mem;
    rx_used = (struct virtq_used*)rx_used_mem;
    tx_used = (struct virtq_used*)tx_used_mem;

    /* Clear rings */
    rx_avail->flags = 0;
    rx_avail->idx = 0;
    tx_avail->flags = 0;
    tx_avail->idx = 0;

    /* Initialize queues */
    init_virtq(RX_QUEUE, rx_descs, rx_avail, rx_used);
    init_virtq(TX_QUEUE, tx_descs, tx_avail, tx_used);

    /* Read MAC address */
    read_mac_address();

    /* Setup RX buffers */
    setup_rx_buffers();

    /* Driver ready */
    vio_write32(VIRTIO_MMIO_STATUS,
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
    dmb();

    virtio_initialized = true;
    return 0;
}

/* ==========================================================================
 * Get MAC Address
 * ========================================================================== */
void virtio_net_get_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = virtio_mac[i];
    }
}

/* ==========================================================================
 * Check for Received Packet
 * ========================================================================== */
bool virtio_net_has_packet(void) {
    if (!virtio_initialized) return false;
    dmb();
    return rx_used->idx != rx_last_used;
}

/* ==========================================================================
 * Receive a Packet
 * ========================================================================== */
int virtio_net_receive(void* buffer, uint16_t max_length) {
    if (!virtio_initialized) return -1;

    dmb();
    if (rx_used->idx == rx_last_used) {
        return -1;  /* No packet */
    }

    /* Get used descriptor */
    uint16_t used_idx = rx_last_used % QUEUE_SIZE;
    uint32_t desc_idx = rx_used->ring[used_idx].id;
    uint32_t len = rx_used->ring[used_idx].len;

    /* Skip virtio header */
    uint32_t hdr_size = sizeof(struct virtio_net_hdr);
    if (len <= hdr_size) {
        len = 0;
    } else {
        len -= hdr_size;
    }

    if (len > max_length) {
        len = max_length;
    }

    /* Copy packet data (after virtio header) */
    uint8_t* src = rx_buffers[desc_idx] + hdr_size;
    uint8_t* dst = (uint8_t*)buffer;
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }

    rx_last_used++;

    /* Return buffer to available ring */
    uint16_t avail_idx = rx_avail->idx % QUEUE_SIZE;
    rx_avail->ring[avail_idx] = desc_idx;
    dmb();
    rx_avail->idx++;
    dmb();

    /* Notify device */
    vio_write32(VIRTIO_MMIO_QUEUE_NOTIFY, RX_QUEUE);

    return len;
}

/* ==========================================================================
 * Send a Packet (Internal)
 * ========================================================================== */
static int virtio_net_send_internal(void* data, uint16_t length) {
    if (!virtio_initialized) return -1;

    /* Check if TX is ready */
    dmb();

    /* Build packet with virtio header */
    struct virtio_net_hdr* hdr = (struct virtio_net_hdr*)tx_buffer;
    hdr->flags = 0;
    hdr->gso_type = 0;
    hdr->hdr_len = 0;
    hdr->gso_size = 0;
    hdr->csum_start = 0;
    hdr->csum_offset = 0;

    /* Copy data after header */
    uint8_t* dst = tx_buffer + sizeof(struct virtio_net_hdr);
    uint8_t* src = (uint8_t*)data;
    for (uint16_t i = 0; i < length; i++) {
        dst[i] = src[i];
    }

    /* Setup TX descriptor */
    uint16_t desc_idx = tx_cur % QUEUE_SIZE;
    tx_descs[desc_idx].addr = (uint64_t)(uintptr_t)tx_buffer;
    tx_descs[desc_idx].len = sizeof(struct virtio_net_hdr) + length;
    tx_descs[desc_idx].flags = 0;
    tx_descs[desc_idx].next = 0;

    /* Add to available ring */
    uint16_t avail_idx = tx_avail->idx % QUEUE_SIZE;
    tx_avail->ring[avail_idx] = desc_idx;
    dmb();
    tx_avail->idx++;
    dmb();

    /* Notify device */
    vio_write32(VIRTIO_MMIO_QUEUE_NOTIFY, TX_QUEUE);

    tx_cur++;
    return 0;
}

/* ==========================================================================
 * Send with Software Queue (non-blocking)
 * ========================================================================== */
int virtio_net_send(void* data, uint16_t length) {
    if (!virtio_initialized) return -1;
    if (length > 128) return -2;

    /* Try direct send if queue empty */
    if (tx_sw_count == 0) {
        return virtio_net_send_internal(data, length);
    }

    /* Enqueue */
    if (tx_sw_count >= TX_SW_QUEUE_SIZE) {
        return -3;  /* Queue full */
    }

    struct tx_queue_entry* entry = &tx_sw_queue[tx_sw_tail];
    uint8_t* src = (uint8_t*)data;
    for (uint16_t i = 0; i < length; i++) {
        entry->data[i] = src[i];
    }
    entry->length = length;
    entry->used = 1;

    tx_sw_tail = (tx_sw_tail + 1) % TX_SW_QUEUE_SIZE;
    tx_sw_count++;

    return 0;
}

/* ==========================================================================
 * Drain TX Queue
 * ========================================================================== */
void virtio_net_tx_drain(void) {
    if (!virtio_initialized) return;
    if (tx_sw_count == 0) return;

    struct tx_queue_entry* entry = &tx_sw_queue[tx_sw_head];
    if (entry->used) {
        virtio_net_send_internal(entry->data, entry->length);
        entry->used = 0;
        tx_sw_head = (tx_sw_head + 1) % TX_SW_QUEUE_SIZE;
        tx_sw_count--;
    }
}

uint8_t virtio_net_tx_queue_depth(void) {
    return tx_sw_count;
}

/* ==========================================================================
 * HAL Network Interface (redirects to VirtIO)
 * ========================================================================== */
static net_driver_t current_driver = NET_DRIVER_NONE;

int hal_net_init(void) {
    int ret = virtio_net_init();
    if (ret == 0) {
        current_driver = NET_DRIVER_VIRTIO;
    }
    return ret;
}

void hal_net_get_mac(uint8_t* mac) {
    virtio_net_get_mac(mac);
}

int hal_net_send(void* data, uint16_t length) {
    return virtio_net_send(data, length);
}

int hal_net_receive(void* buffer, uint16_t max_length) {
    return virtio_net_receive(buffer, max_length);
}

bool hal_net_has_packet(void) {
    return virtio_net_has_packet();
}

void hal_net_tx_drain(void) {
    virtio_net_tx_drain();
}

uint8_t hal_net_tx_queue_depth(void) {
    return virtio_net_tx_queue_depth();
}

net_driver_t hal_net_get_driver(void) {
    return current_driver;
}

#endif /* !ARCH_X86 */
