/*
 * NanOS ARM Cortex-M3 for QEMU
 * Target: lm3s6965evb (Stellaris LM3S6965)
 *
 * Run with:
 *   qemu-system-arm -M lm3s6965evb -kernel nanos-arm.elf -nographic
 */

#include <stdint.h>
#include <stddef.h>
#include "modules.h"

/* ==========================================================================
 * LM3S6965 Hardware Registers
 * ========================================================================== */

/* System Control */
#define SYSCTL_BASE     0x400FE000
#define SYSCTL_RCC      (*(volatile uint32_t*)(SYSCTL_BASE + 0x060))
#define SYSCTL_RCGC1    (*(volatile uint32_t*)(SYSCTL_BASE + 0x104))
#define SYSCTL_RCGC2    (*(volatile uint32_t*)(SYSCTL_BASE + 0x108))

/* SysTick Timer */
#define SYSTICK_CTRL    (*(volatile uint32_t*)0xE000E010)
#define SYSTICK_LOAD    (*(volatile uint32_t*)0xE000E014)
#define SYSTICK_VAL     (*(volatile uint32_t*)0xE000E018)
#define SYSTICK_ENABLE  (1 << 0)
#define SYSTICK_INT     (1 << 1)
#define SYSTICK_CLKSRC  (1 << 2)

/* NVIC */
#define NVIC_ISER0      (*(volatile uint32_t*)0xE000E100)
#define NVIC_ISER1      (*(volatile uint32_t*)0xE000E104)

/* UART0 */
#define UART0_BASE      0x4000C000
#define UART0_DR        (*(volatile uint32_t*)(UART0_BASE + 0x000))
#define UART0_FR        (*(volatile uint32_t*)(UART0_BASE + 0x018))
#define UART0_IBRD      (*(volatile uint32_t*)(UART0_BASE + 0x024))
#define UART0_FBRD      (*(volatile uint32_t*)(UART0_BASE + 0x028))
#define UART0_LCRH      (*(volatile uint32_t*)(UART0_BASE + 0x02C))
#define UART0_CTL       (*(volatile uint32_t*)(UART0_BASE + 0x030))
#define UART0_IM        (*(volatile uint32_t*)(UART0_BASE + 0x038))
#define UART0_ICR       (*(volatile uint32_t*)(UART0_BASE + 0x044))
#define UART_FR_TXFF    (1 << 5)
#define UART_FR_RXFE    (1 << 4)

/* GPIO Port A (UART pins) */
#define GPIOA_BASE      0x40004000
#define GPIOA_AFSEL     (*(volatile uint32_t*)(GPIOA_BASE + 0x420))
#define GPIOA_DEN       (*(volatile uint32_t*)(GPIOA_BASE + 0x51C))

/* GPIO Port F (LEDs on eval board) */
#define GPIOF_BASE      0x40025000
#define GPIOF_DIR       (*(volatile uint32_t*)(GPIOF_BASE + 0x400))
#define GPIOF_DEN       (*(volatile uint32_t*)(GPIOF_BASE + 0x51C))
#define GPIOF_DATA      (*(volatile uint32_t*)(GPIOF_BASE + 0x3FC))

/* Stellaris Ethernet */
#define ETH_BASE        0x40048000
#define MAC_RIS         (*(volatile uint32_t*)(ETH_BASE + 0x000))
#define MAC_IACK        (*(volatile uint32_t*)(ETH_BASE + 0x000))
#define MAC_IM          (*(volatile uint32_t*)(ETH_BASE + 0x004))
#define MAC_RCTL        (*(volatile uint32_t*)(ETH_BASE + 0x008))
#define MAC_TCTL        (*(volatile uint32_t*)(ETH_BASE + 0x00C))
#define MAC_DATA        (*(volatile uint32_t*)(ETH_BASE + 0x010))
#define MAC_IA0         (*(volatile uint32_t*)(ETH_BASE + 0x014))
#define MAC_IA1         (*(volatile uint32_t*)(ETH_BASE + 0x018))
#define MAC_NP          (*(volatile uint32_t*)(ETH_BASE + 0x034))
#define MAC_TR          (*(volatile uint32_t*)(ETH_BASE + 0x038))

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define CPU_FREQ        12000000    /* 12 MHz default */
#define TICK_HZ         100         /* 100 ticks/sec = 10ms */
#define HEARTBEAT_TICKS 100         /* 1 second */

#define MAX_NEIGHBORS   4
#define GOSSIP_SIZE     16
#define PKT_SIZE        24

/* Pheromone types */
#define PHEROMONE_HEARTBEAT 0x01
#define PHEROMONE_DATA      0x02
#define PHEROMONE_ALARM     0x03

/* Roles */
#define ROLE_WORKER     0
#define ROLE_EXPLORER   1
#define ROLE_SENTINEL   2
#define ROLE_QUEEN      3

/* ==========================================================================
 * Packet Structure (24 bytes - compact format)
 * ========================================================================== */

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint16_t node_id;
    uint8_t  type;
    uint8_t  ttl_flags;
    uint8_t  seq;
    uint16_t dest_id;
    uint8_t  dist_hop;
    uint8_t  payload[8];
    uint8_t  hmac[4];
    uint8_t  reserved[3];
} packet_t;

/* ==========================================================================
 * Global State
 * ========================================================================== */

/* Exported for modules */
volatile uint32_t ticks = 0;
static uint32_t seed = 0x12345678;

static struct {
    uint32_t node_id;
    uint8_t  role;
    uint8_t  mac[6];

    uint32_t packets_rx;
    uint32_t packets_tx;
    uint16_t seq;

    uint32_t last_heartbeat;

    struct {
        uint16_t id;
        uint8_t  role;
        uint32_t seen;
    } neighbors[MAX_NEIGHBORS];
    uint8_t neighbor_count;

    uint32_t gossip[GOSSIP_SIZE];
    uint8_t  gossip_idx;

    uint16_t queen_id;
    uint8_t  queen_dist;
    uint32_t queen_seen;
} state;

/* ==========================================================================
 * UART Functions
 * ========================================================================== */

static void uart_init(void) {
    /* Enable UART0 and GPIOA clocks */
    SYSCTL_RCGC1 |= (1 << 0);   /* UART0 */
    SYSCTL_RCGC2 |= (1 << 0);   /* GPIOA */

    /* Small delay for clock to stabilize */
    volatile int delay = 100;
    while (delay--);

    /* Disable UART */
    UART0_CTL = 0;

    /* Set baud rate: 115200 @ 12MHz */
    /* BRD = 12000000 / (16 * 115200) = 6.5104 */
    /* IBRD = 6, FBRD = 0.5104 * 64 = 33 */
    UART0_IBRD = 6;
    UART0_FBRD = 33;

    /* 8N1 */
    UART0_LCRH = (3 << 5);  /* 8 bits */

    /* Enable UART, TX, RX */
    UART0_CTL = (1 << 0) | (1 << 8) | (1 << 9);

    /* Configure PA0/PA1 for UART */
    GPIOA_AFSEL |= 0x03;
    GPIOA_DEN |= 0x03;
}

/* Exported for modules */
void uart_putc(char c) {
    while (UART0_FR & UART_FR_TXFF);
    UART0_DR = c;
}

void uart_puts(const char* s) {
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

void uart_put_hex(uint32_t n) {
    static const char hex[] = "0123456789ABCDEF";
    uart_putc('0'); uart_putc('x');
    for (int i = 28; i >= 0; i -= 4) {
        uart_putc(hex[(n >> i) & 0xF]);
    }
}

void uart_put_dec(uint32_t n) {
    char buf[12];
    int i = 0;
    if (n == 0) { uart_putc('0'); return; }
    while (n > 0) {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    }
    while (i > 0) uart_putc(buf[--i]);
}

/* ==========================================================================
 * Random Number Generator (exported for modules)
 * ========================================================================== */

uint32_t arm_random(void) {
    seed = seed * 1103515245 + 12345;
    return (seed >> 16) & 0x7FFF;
}

/* ==========================================================================
 * State Accessors (exported for modules)
 * ========================================================================== */

uint32_t arm_get_node_id(void) { return state.node_id; }
uint8_t  arm_get_role(void)    { return state.role; }
uint16_t arm_get_seq(void)     { return state.seq++; }

/* ==========================================================================
 * SysTick Handler
 * ========================================================================== */

void SysTick_Handler(void) {
    ticks++;
}

/* ==========================================================================
 * LED Functions (GPIO Port F on eval board)
 * ========================================================================== */

static void led_init(void) {
    SYSCTL_RCGC2 |= (1 << 5);  /* Enable GPIOF clock */
    volatile int delay = 100;
    while (delay--);
    GPIOF_DIR |= 0x01;         /* PF0 output */
    GPIOF_DEN |= 0x01;         /* Digital enable */
}

static void led_set(int on) {
    if (on) GPIOF_DATA |= 0x01;
    else    GPIOF_DATA &= ~0x01;
}

static void led_toggle(void) {
    GPIOF_DATA ^= 0x01;
}

/* ==========================================================================
 * Ethernet Functions (Stellaris MAC)
 * ========================================================================== */

static void eth_init(void) {
    /* Enable Ethernet clock */
    SYSCTL_RCGC2 |= (1 << 28) | (1 << 30);
    volatile int delay = 100;
    while (delay--);

    /* Read MAC address from hardware (set by QEMU -net nic,macaddr=...) */
    uint32_t ia0 = MAC_IA0;
    uint32_t ia1 = MAC_IA1;

    state.mac[0] = ia0 & 0xFF;
    state.mac[1] = (ia0 >> 8) & 0xFF;
    state.mac[2] = (ia0 >> 16) & 0xFF;
    state.mac[3] = (ia0 >> 24) & 0xFF;
    state.mac[4] = ia1 & 0xFF;
    state.mac[5] = (ia1 >> 8) & 0xFF;

    /* Generate unique node_id from MAC address */
    state.node_id = (state.mac[2] << 24) | (state.mac[3] << 16) |
                    (state.mac[4] << 8) | state.mac[5];
    state.role = state.node_id & 0x03;
    state.queen_dist = (state.role == ROLE_QUEEN) ? 0 : 15;

    /* Enable TX: TXEN=1, PADEN=1, CRC=1 */
    MAC_TCTL = (1 << 0) | (1 << 1) | (1 << 2);

    /* Enable RX: RXEN=1, BADCRC=0, PRMS=1 (promiscuous for broadcast) */
    MAC_RCTL = (1 << 0) | (1 << 4);

    uart_puts("[ETH] MAC=");
    for (int i = 0; i < 6; i++) {
        if (i > 0) uart_putc(':');
        uart_putc("0123456789ABCDEF"[(state.mac[i] >> 4) & 0xF]);
        uart_putc("0123456789ABCDEF"[state.mac[i] & 0xF]);
    }
    uart_puts("\n");
}

/* Build an ethernet frame with broadcast destination */
static uint8_t eth_frame[1518];

/* Exported for modules */
void eth_send(const void* data, uint16_t len) {
    /* Build ethernet frame: DST(6) + SRC(6) + Type(2) + Payload */
    uint8_t* frame = eth_frame;

    /* Broadcast destination */
    frame[0] = 0xFF; frame[1] = 0xFF; frame[2] = 0xFF;
    frame[3] = 0xFF; frame[4] = 0xFF; frame[5] = 0xFF;

    /* Source MAC */
    for (int i = 0; i < 6; i++) frame[6+i] = state.mac[i];

    /* EtherType: 0x88B5 (experimental) */
    frame[12] = 0x88;
    frame[13] = 0xB5;

    /* Payload */
    const uint8_t* payload = (const uint8_t*)data;
    for (uint16_t i = 0; i < len && i < 1500; i++) {
        frame[14+i] = payload[i];
    }

    uint16_t frame_len = 14 + len;
    if (frame_len < 60) frame_len = 60;  /* Minimum ethernet frame */

    /* Write frame length first (per Stellaris MAC spec) */
    MAC_DATA = frame_len - 14;

    /* Write frame data as 32-bit words */
    uint32_t words = (frame_len + 3) / 4;
    for (uint32_t i = 0; i < words; i++) {
        uint32_t word = frame[i*4];
        if (i*4+1 < frame_len) word |= frame[i*4+1] << 8;
        if (i*4+2 < frame_len) word |= frame[i*4+2] << 16;
        if (i*4+3 < frame_len) word |= frame[i*4+3] << 24;
        MAC_DATA = word;
    }

    /* Trigger transmit */
    MAC_TR = 1;
    state.packets_tx++;
}

static int eth_recv(void* buf, uint16_t maxlen) {
    /* Check if packets available */
    uint32_t np = MAC_NP;
    if ((np & 0x3F) == 0) return 0;

    /* Read first word (contains frame length) */
    uint32_t word = MAC_DATA;
    uint16_t frame_len = word & 0xFFFF;

    /* Sanity check frame length */
    if (frame_len == 0 || frame_len > 1518) {
        /* Drain FIFO on error */
        while ((MAC_NP & 0x3F) > 0) {
            (void)MAC_DATA;
        }
        return 0;
    }

    /* Read ethernet frame into temp buffer */
    uint8_t frame[1518];
    uint32_t total_words = (frame_len + 3) / 4;

    for (uint32_t i = 0; i < total_words && i < sizeof(frame)/4; i++) {
        word = MAC_DATA;
        frame[i*4+0] = word & 0xFF;
        frame[i*4+1] = (word >> 8) & 0xFF;
        frame[i*4+2] = (word >> 16) & 0xFF;
        frame[i*4+3] = (word >> 24) & 0xFF;
    }

    /* Skip ethernet header, extract payload */
    if (frame_len <= 14) return 0;

    uint16_t payload_len = frame_len - 14;
    if (payload_len > maxlen) payload_len = maxlen;

    uint8_t* dst = (uint8_t*)buf;
    for (uint16_t i = 0; i < payload_len; i++) {
        dst[i] = frame[14 + i];
    }

    return payload_len;
}

/* ==========================================================================
 * Gossip Deduplication
 * ========================================================================== */

static uint32_t pkt_hash(const packet_t* p) {
    uint32_t h = 0x811c9dc5;
    const uint8_t* d = (const uint8_t*)p;
    for (int i = 0; i < PKT_SIZE; i++) {
        h ^= d[i];
        h *= 0x01000193;
    }
    return h;
}

static int is_dup(const packet_t* p) {
    uint32_t h = pkt_hash(p);
    for (int i = 0; i < GOSSIP_SIZE; i++) {
        if (state.gossip[i] == h) return 1;
    }
    state.gossip[state.gossip_idx] = h;
    state.gossip_idx = (state.gossip_idx + 1) % GOSSIP_SIZE;
    return 0;
}

/* ==========================================================================
 * Role Names
 * ========================================================================== */

static const char* role_name(uint8_t r) {
    switch (r) {
        case ROLE_WORKER:   return "WORKER";
        case ROLE_EXPLORER: return "EXPLORER";
        case ROLE_SENTINEL: return "SENTINEL";
        case ROLE_QUEEN:    return "QUEEN";
        default:            return "?";
    }
}

/* ==========================================================================
 * Heartbeat
 * ========================================================================== */

static void send_heartbeat(void) {
    packet_t pkt = {0};
    pkt.magic = 0xAA;
    pkt.node_id = (uint16_t)(state.node_id & 0xFFFF);
    pkt.type = PHEROMONE_HEARTBEAT;
    pkt.ttl_flags = (15 << 4);
    pkt.seq = state.seq++;
    pkt.dist_hop = (state.queen_dist << 4);
    pkt.payload[0] = state.role;
    pkt.payload[1] = state.neighbor_count;

    eth_send(&pkt, PKT_SIZE);
    state.last_heartbeat = ticks;
    led_toggle();
}

/* ==========================================================================
 * Packet Processing
 * ========================================================================== */

static void update_neighbor(uint16_t id, uint8_t role) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (state.neighbors[i].id == id) {
            state.neighbors[i].seen = ticks;
            return;
        }
    }
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (state.neighbors[i].id == 0 || (ticks - state.neighbors[i].seen) > 3000) {
            state.neighbors[i].id = id;
            state.neighbors[i].role = role;
            state.neighbors[i].seen = ticks;
            state.neighbor_count = 0;
            for (int j = 0; j < MAX_NEIGHBORS; j++) {
                if (state.neighbors[j].id && (ticks - state.neighbors[j].seen) < 1000)
                    state.neighbor_count++;
            }
            return;
        }
    }
}

static void process_pkt(packet_t* pkt) {
    if (pkt->magic != 0xAA) return;
    if (pkt->node_id == (uint16_t)(state.node_id & 0xFFFF)) return;
    if (is_dup(pkt)) return;

    state.packets_rx++;

    switch (pkt->type) {
        case PHEROMONE_HEARTBEAT: {
            uint8_t role = pkt->payload[0];
            update_neighbor(pkt->node_id, role);

            if (role == ROLE_QUEEN) {
                uint8_t dist = (pkt->dist_hop >> 4) & 0x0F;
                if (dist < state.queen_dist || state.queen_id == 0) {
                    state.queen_id = pkt->node_id;
                    state.queen_dist = dist + 1;
                    state.queen_seen = ticks;
                }
            }
            break;
        }

        case PHEROMONE_ALARM:
            uart_puts("[ALARM] from ");
            uart_put_hex(pkt->node_id);
            uart_puts("!\n");
            for (int i = 0; i < 10; i++) {
                led_set(i & 1);
                for (volatile int d = 0; d < 50000; d++);
            }
            break;

        case PHEROMONE_DATA:
            uart_puts("[DATA] from ");
            uart_put_hex(pkt->node_id);
            uart_puts(": ");
            for (int i = 0; i < 8 && pkt->payload[i]; i++)
                uart_putc(pkt->payload[i]);
            uart_puts("\n");
            break;

        /* Maze packets */
        case PHEROMONE_MAZE_INIT:
        case PHEROMONE_MAZE_MOVE:
        case PHEROMONE_MAZE_WALL:
        case PHEROMONE_MAZE_SOLVED:
            maze_process_pkt((arm_packet_t*)pkt);
            break;

        /* Terrain packets */
        case PHEROMONE_TERRAIN_INIT:
        case PHEROMONE_TERRAIN_REPORT:
        case PHEROMONE_TERRAIN_THREAT:
        case PHEROMONE_TERRAIN_MOVE:
            terrain_process_pkt((arm_packet_t*)pkt);
            break;
    }
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(void) {
    /* Init UART first for debug output */
    uart_init();

    uart_puts("\n");
    uart_puts("========================================\n");
    uart_puts("  NanOS ARM Cortex-M3 (QEMU)\n");
    uart_puts("========================================\n");

    /* Init hardware - eth_init() reads MAC and generates node_id */
    led_init();
    eth_init();

    uart_puts("Node ID: ");
    uart_put_hex(state.node_id);
    uart_puts("\nRole:    ");
    uart_puts(role_name(state.role));
    uart_puts("\n");

    /* Setup SysTick for 10ms ticks */
    SYSTICK_LOAD = (CPU_FREQ / TICK_HZ) - 1;
    SYSTICK_VAL = 0;
    SYSTICK_CTRL = SYSTICK_ENABLE | SYSTICK_INT | SYSTICK_CLKSRC;

    uart_puts("========================================\n\n");

    /* Initialize modules */
    maze_init();
    terrain_init();

    /* Main loop */
    packet_t rx_pkt;
    uint32_t last_status = 0;
    uint8_t modules_started = 0;

    while (1) {
        /* Check for received packets */
        int len = eth_recv(&rx_pkt, PKT_SIZE);
        if (len >= PKT_SIZE) {
            process_pkt(&rx_pkt);
        }

        /* Periodic heartbeat */
        if ((ticks - state.last_heartbeat) >= HEARTBEAT_TICKS) {
            send_heartbeat();
        }

        /* Run module tick functions (only if active) */
        maze_tick();
        terrain_tick();

        /* Status every 5 seconds */
        if ((ticks - last_status) >= 500) {
            last_status = ticks;
            uart_puts("[STATUS] Node ");
            uart_put_hex(state.node_id);
            uart_puts(" [");
            uart_puts(role_name(state.role));
            uart_puts("] neighbors=");
            uart_put_dec(state.neighbor_count);
            uart_puts(" rx=");
            uart_put_dec(state.packets_rx);
            uart_puts(" tx=");
            uart_put_dec(state.packets_tx);
            uart_puts(" ticks=");
            uart_put_dec(ticks);
            uart_puts("\n");
        }

        /* Queen timeout - promote self after 30 seconds */
        if (state.role != ROLE_QUEEN && state.queen_id &&
            (ticks - state.queen_seen) > 3000) {
            uart_puts("[ELECTION] Queen timeout -> becoming QUEEN\n");
            state.role = ROLE_QUEEN;
            state.queen_dist = 0;
        }

        /* Idle loop - wait for next tick */
        __asm volatile ("wfi");  /* Wait for interrupt - saves power */
    }

    return 0;
}
