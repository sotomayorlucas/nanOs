# NanOS Ephemeral Reliable Transport (NERT) Protocol v1.2

## Overview

NERT es un protocolo híbrido UDP/TCP diseñado específicamente para la comunicación entre nodos desechables en NanOS. Combina la eficiencia de UDP con la confiabilidad selectiva de TCP, optimizado para nodos efímeros con vida máxima de 1 hora.

```
┌─────────────────────────────────────────────────────────────────┐
│                    NERT Protocol Stack                          │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer  │ Pheromones (HELLO, DATA, CMD, ELECTION)  │
├─────────────────────────────────────────────────────────────────┤
│  Security Layer     │ ChaCha8 Encryption + Poly1305 MAC        │
├─────────────────────────────────────────────────────────────────┤
│  Reliability Layer  │ Selective ACK + Forward Error Correction │
├─────────────────────────────────────────────────────────────────┤
│  Transport Layer    │ NERT (UDP-like base + TCP-like optional) │
├─────────────────────────────────────────────────────────────────┤
│  Network Layer      │ Multicast 230.0.0.1:1234 / Broadcast     │
├─────────────────────────────────────────────────────────────────┤
│  Link Layer         │ Ethernet (e1000) / WiFi (ESP32)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Filosofía de Diseño

### 1.1 Principios Core

| Principio | Descripción |
|-----------|-------------|
| **Ephemeral-First** | Diseñado para nodos que viven máximo 1 hora |
| **Memory-Bound** | Sin estado persistente, todo en RAM volátil |
| **Selective Reliability** | Solo garantiza entrega para mensajes críticos |
| **Crypto-Native** | Encriptación integrada, no opcional |
| **Swarm-Aware** | Optimizado para comunicación colectiva |

### 1.2 Clasificación de Mensajes

```c
/* Reliability Classes */
#define NERT_CLASS_FIRE_FORGET  0x00  /* UDP puro - no ACK */
#define NERT_CLASS_BEST_EFFORT  0x01  /* UDP + retry sin ACK */
#define NERT_CLASS_RELIABLE     0x02  /* TCP-like con ACK */
#define NERT_CLASS_CRITICAL     0x03  /* Reliable + FEC + Multi-path */
```

| Clase | Uso | ACK | Retry | FEC | Ejemplo |
|-------|-----|-----|-------|-----|---------|
| FIRE_FORGET | Telemetría frecuente | No | No | No | SENSOR, HELLO |
| BEST_EFFORT | Datos importantes | No | 2x | No | DATA, KV_SET |
| RELIABLE | Comandos | Sí | 5x | No | TASK, DETECT |
| CRITICAL | Control vital | Sí | 10x | Sí | QUEEN_CMD, DIE, CORONATION |

---

## 2. Estructura del Paquete NERT

### 2.1 Header Principal (20 bytes)

```c
struct nert_header {
    /* Byte 0-1: Magic + Version */
    uint8_t  magic;              /* 0xNE = 0x4E = 'N' */
    uint8_t  version_class;      /* [7:4]=version(1), [3:2]=class, [1:0]=reserved */

    /* Byte 2-5: Identificación */
    uint16_t node_id;            /* ID del remitente (truncado 16-bit) */
    uint16_t dest_id;            /* ID destino (0x0000 = broadcast) */

    /* Byte 6-9: Secuencia y Control */
    uint16_t seq_num;            /* Número de secuencia (0-65535) */
    uint16_t ack_num;            /* ACK number (piggyback) */

    /* Byte 10-11: Flags y Longitud */
    uint8_t  flags;              /* Ver flags abajo */
    uint8_t  payload_len;        /* Longitud del payload (0-255) */

    /* Byte 12-15: Timing */
    uint16_t timestamp;          /* Ticks desde boot (para RTT) */
    uint8_t  ttl;                /* Time-to-live (hops) */
    uint8_t  hop_count;          /* Hops viajados */

    /* Byte 16-19: Crypto */
    uint32_t nonce_counter;      /* Counter para ChaCha nonce */
};
```

### 2.2 Flags (8 bits)

```c
#define NERT_FLAG_SYN       0x01  /* Inicio de conexión confiable */
#define NERT_FLAG_ACK       0x02  /* Contiene ACK válido */
#define NERT_FLAG_FIN       0x04  /* Fin de stream */
#define NERT_FLAG_RST       0x08  /* Reset conexión */
#define NERT_FLAG_ENC       0x10  /* Payload encriptado */
#define NERT_FLAG_FEC       0x20  /* Incluye bloque FEC */
#define NERT_FLAG_FRAG      0x40  /* Paquete fragmentado */
#define NERT_FLAG_MPATH     0x80  /* Multi-path enabled */
```

### 2.3 Payload Encriptado

```c
struct nert_encrypted_payload {
    /* Encriptado con ChaCha8 */
    uint8_t  pheromone_type;     /* Tipo de mensaje NanOS */
    uint8_t  role_info;          /* [7:5]=sender_role, [4:0]=distance */
    uint8_t  data[payload_len-2]; /* Datos variables */
};
```

### 2.4 Authentication Tag (8 bytes)

```c
struct nert_auth_tag {
    uint8_t  poly1305_tag[8];    /* Truncated Poly1305 MAC */
};
```

### 2.5 Paquete Completo

```
┌────────────────────────────────────────────────────────────────┐
│ NERT Header (20 bytes) │ Encrypted Payload │ Auth Tag (8 bytes)│
├────────────────────────┼───────────────────┼───────────────────┤
│ magic, version, IDs,   │ ChaCha8 encrypted │ Poly1305 MAC      │
│ seq, ack, flags, ttl   │ pheromone data    │ (truncated 64-bit)│
└────────────────────────────────────────────────────────────────┘

Tamaño mínimo: 20 + 2 + 8 = 30 bytes
Tamaño máximo: 20 + 255 + 8 = 283 bytes
Tamaño típico: 20 + 32 + 8 = 60 bytes
```

---

## 3. Sistema de Encriptación

### 3.1 Algoritmo: ChaCha8-Poly1305 Lite

ChaCha8 ofrece un balance óptimo para microcontroladores:
- 8 rounds (vs 20 de ChaCha20) - suficiente seguridad para datos efímeros
- ~3x más rápido que ChaCha20
- Resistente a timing attacks (sin lookup tables)

### 3.2 Derivación de Claves

```c
/* Clave maestra del enjambre (256-bit) - Pre-compartida */
static const uint8_t SWARM_MASTER_KEY[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x8B, 0xAD, 0xF0, 0x0D, 0xFE, 0xED, 0xFA, 0xCE,
    0x13, 0x37, 0xC0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01,
    0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0
};

/* Derivación de clave de sesión por nodo */
void nert_derive_session_key(uint32_t node_id, uint32_t epoch_hour,
                              uint8_t session_key[32]) {
    uint8_t material[40];
    memcpy(material, SWARM_MASTER_KEY, 32);
    material[32] = (node_id >> 24) & 0xFF;
    material[33] = (node_id >> 16) & 0xFF;
    material[34] = (node_id >> 8) & 0xFF;
    material[35] = node_id & 0xFF;
    material[36] = (epoch_hour >> 24) & 0xFF;
    material[37] = (epoch_hour >> 16) & 0xFF;
    material[38] = (epoch_hour >> 8) & 0xFF;
    material[39] = epoch_hour & 0xFF;

    /* HKDF-like expansion usando ChaCha8 */
    chacha8_hash(material, 40, session_key);
}
```

### 3.3 Construcción del Nonce (96-bit)

```c
struct nert_nonce {
    uint32_t node_id;           /* Bytes 0-3: ID del sender */
    uint32_t nonce_counter;     /* Bytes 4-7: Counter del header */
    uint32_t epoch_second;      /* Bytes 8-11: Segundos desde boot */
};
```

### 3.4 Proceso de Encriptación

```c
int nert_encrypt(struct nert_packet *pkt, const uint8_t *plaintext,
                 uint8_t len, const uint8_t session_key[32]) {
    struct nert_nonce nonce;

    /* Construir nonce único */
    nonce.node_id = swarm_state.node_id;
    nonce.nonce_counter = pkt->header.nonce_counter;
    nonce.epoch_second = hal_timer_ticks() / 1000;

    /* Encriptar con ChaCha8 */
    chacha8_encrypt(session_key, (uint8_t*)&nonce, 12,
                    plaintext, len, pkt->payload);

    /* Generar Poly1305 MAC */
    poly1305_mac(session_key, pkt->payload, len,
                 (uint8_t*)&pkt->header, 20,  /* AAD = header */
                 pkt->auth_tag);

    pkt->header.flags |= NERT_FLAG_ENC;
    pkt->header.payload_len = len;

    return 0;
}
```

---

## 4. Mecanismo de Confiabilidad Selectiva

### 4.1 Estado de Conexión Lightweight

```c
#define NERT_MAX_CONNECTIONS    8   /* Conexiones simultáneas */
#define NERT_WINDOW_SIZE        4   /* Ventana de transmisión */
#define NERT_RETRY_TIMEOUT_MS   200 /* Timeout inicial */
#define NERT_MAX_RETRIES        5   /* Reintentos máximos */

struct nert_connection {
    uint16_t peer_id;               /* ID del peer */
    uint16_t send_seq;              /* Próximo seq a enviar */
    uint16_t recv_seq;              /* Próximo seq esperado */
    uint16_t ack_pending;           /* ACK pendiente de enviar */

    /* Ventana de retransmisión (solo para RELIABLE/CRITICAL) */
    struct {
        uint16_t seq;
        uint8_t  retries;
        uint16_t timeout_ms;
        uint8_t  data[64];
        uint8_t  len;
        uint8_t  active;
    } tx_window[NERT_WINDOW_SIZE];

    /* Estadísticas para RTT */
    uint16_t srtt;                  /* Smoothed RTT */
    uint16_t rttvar;                /* RTT variance */
    uint32_t last_activity;         /* Último tick de actividad */
};

static struct nert_connection connections[NERT_MAX_CONNECTIONS];
```

### 4.2 Selective ACK (SACK)

```c
struct nert_sack {
    uint16_t base_ack;              /* ACK acumulativo */
    uint8_t  bitmap;                /* Bitmap de 8 paquetes siguientes */
    /* Bit 0 = base_ack+1, Bit 1 = base_ack+2, ... */
};

/* Ejemplo: base_ack=100, bitmap=0b00101001
 * - Paquete 100: recibido (ACK base)
 * - Paquete 101: recibido (bit 0)
 * - Paquete 102: NO recibido
 * - Paquete 103: NO recibido
 * - Paquete 104: recibido (bit 3)
 * - Paquete 105: NO recibido
 * - Paquete 106: recibido (bit 5)
 * - Paquete 107-108: NO recibido
 */
```

### 4.3 Algoritmo de Retransmisión

```c
void nert_process_ack(struct nert_connection *conn, uint16_t ack_num,
                      uint8_t sack_bitmap) {
    /* Actualizar RTT si tenemos timestamp */
    uint16_t rtt = hal_timer_ticks() - conn->tx_window[0].sent_tick;
    conn->srtt = (conn->srtt * 7 + rtt) / 8;  /* EWMA */
    conn->rttvar = (conn->rttvar * 3 + abs(rtt - conn->srtt)) / 4;

    /* RTO = SRTT + 4*RTTVAR (similar a TCP) */
    uint16_t rto = conn->srtt + 4 * conn->rttvar;
    if (rto < 100) rto = 100;   /* Mínimo 100ms */
    if (rto > 2000) rto = 2000; /* Máximo 2s */

    /* Limpiar ventana para paquetes ACKed */
    for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
        if (conn->tx_window[i].active) {
            uint16_t seq = conn->tx_window[i].seq;

            /* ACK acumulativo */
            if (seq <= ack_num) {
                conn->tx_window[i].active = 0;
                continue;
            }

            /* SACK bitmap */
            int offset = seq - ack_num - 1;
            if (offset < 8 && (sack_bitmap & (1 << offset))) {
                conn->tx_window[i].active = 0;
            }
        }
    }
}

void nert_retransmit_check(struct nert_connection *conn) {
    uint32_t now = hal_timer_ticks();

    for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
        if (!conn->tx_window[i].active) continue;

        if (now - conn->tx_window[i].sent_tick > conn->tx_window[i].timeout_ms) {
            if (conn->tx_window[i].retries >= NERT_MAX_RETRIES) {
                /* Conexión considerada muerta */
                nert_connection_reset(conn);
                return;
            }

            /* Retransmitir con backoff exponencial */
            conn->tx_window[i].retries++;
            conn->tx_window[i].timeout_ms *= 2;
            conn->tx_window[i].sent_tick = now;

            nert_send_raw(conn->tx_window[i].data, conn->tx_window[i].len);
        }
    }
}
```

---

## 5. Forward Error Correction (FEC)

### 5.1 Reed-Solomon Lite (para CLASS_CRITICAL)

Para mensajes críticos, agregamos redundancia FEC que permite reconstruir paquetes perdidos sin retransmisión.

```c
#define FEC_DATA_SHARDS     4   /* Paquetes de datos */
#define FEC_PARITY_SHARDS   2   /* Paquetes de paridad */
#define FEC_SHARD_SIZE      32  /* Bytes por shard */

struct nert_fec_block {
    uint8_t  block_id;          /* ID del bloque FEC */
    uint8_t  shard_index;       /* 0-3=data, 4-5=parity */
    uint8_t  total_shards;      /* Total de shards en bloque */
    uint8_t  data[FEC_SHARD_SIZE];
};
```

### 5.2 XOR Parity Simple (bajo overhead)

Para un balance entre complejidad y protección:

```c
/* Genera 2 shards de paridad para 4 de datos */
void nert_fec_encode(uint8_t data[4][32], uint8_t parity[2][32]) {
    /* Parity 0: XOR de shards pares (0, 2) */
    for (int i = 0; i < 32; i++) {
        parity[0][i] = data[0][i] ^ data[2][i];
    }

    /* Parity 1: XOR de shards impares (1, 3) */
    for (int i = 0; i < 32; i++) {
        parity[1][i] = data[1][i] ^ data[3][i];
    }
}

/* Recupera shard perdido usando paridad */
int nert_fec_decode(uint8_t shards[6][32], uint8_t received_mask,
                    uint8_t recovered[4][32]) {
    int missing_count = 0;
    int missing[2] = {-1, -1};

    /* Identificar shards faltantes */
    for (int i = 0; i < 4; i++) {
        if (!(received_mask & (1 << i))) {
            if (missing_count >= 2) return -1; /* Irrecuperable */
            missing[missing_count++] = i;
        }
    }

    /* Copiar shards recibidos */
    for (int i = 0; i < 4; i++) {
        if (received_mask & (1 << i)) {
            memcpy(recovered[i], shards[i], 32);
        }
    }

    /* Recuperar con paridad */
    if (missing_count == 1) {
        int m = missing[0];
        int parity_idx = (m % 2);  /* 0,2 -> parity[0], 1,3 -> parity[1] */
        int pair = m ^ 2;          /* 0<->2, 1<->3 */

        for (int i = 0; i < 32; i++) {
            recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
        }
    } else if (missing_count == 2) {
        /* Requiere ambas paridades */
        if ((missing[0] % 2) == (missing[1] % 2)) return -1; /* Mismo grupo */

        for (int j = 0; j < 2; j++) {
            int m = missing[j];
            int parity_idx = (m % 2);
            int pair = m ^ 2;
            for (int i = 0; i < 32; i++) {
                recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
            }
        }
    }

    return 0;
}
```

---

## 6. Multi-Path Routing

### 6.1 Objetivo

Enviar copias del mensaje por múltiples rutas simultáneas para:
- Mayor probabilidad de entrega
- Menor latencia (el primero en llegar gana)
- Tolerancia a fallas de nodos intermedios

### 6.2 Estructura Multi-Path

```c
#define NERT_MAX_PATHS      3   /* Máximo de rutas paralelas */

struct nert_multipath_header {
    uint8_t  path_count;        /* Número de paths activos */
    uint8_t  path_index;        /* Índice de este path */
    uint16_t via_nodes[NERT_MAX_PATHS]; /* Primer hop de cada ruta */
};
```

### 6.3 Algoritmo de Selección de Rutas

```c
int nert_select_paths(uint16_t dest_id, uint16_t paths[NERT_MAX_PATHS]) {
    int path_count = 0;
    uint16_t excluded[NERT_MAX_PATHS] = {0};

    for (int p = 0; p < NERT_MAX_PATHS && path_count < NERT_MAX_PATHS; p++) {
        /* Buscar mejor vecino no excluido */
        struct neighbor_entry *best = NULL;
        uint8_t best_score = 255;

        for (int i = 0; i < neighbor_count; i++) {
            struct neighbor_entry *n = &neighbors[i];

            /* Saltar excluidos */
            int skip = 0;
            for (int e = 0; e < path_count; e++) {
                if (n->node_id == excluded[e]) { skip = 1; break; }
            }
            if (skip) continue;

            /* Score = distancia + (100 - packets_seen) */
            uint8_t score = n->distance;
            if (n->packets < 100) score += (100 - n->packets) / 10;

            if (score < best_score) {
                best_score = score;
                best = n;
            }
        }

        if (best) {
            paths[path_count] = best->node_id;
            excluded[path_count] = best->node_id;
            path_count++;
        }
    }

    return path_count;
}
```

### 6.4 Deduplicación en Destino

```c
#define NERT_DEDUP_CACHE_SIZE   16

struct nert_dedup_entry {
    uint16_t sender_id;
    uint16_t seq_num;
    uint32_t received_tick;
};

static struct nert_dedup_entry dedup_cache[NERT_DEDUP_CACHE_SIZE];
static uint8_t dedup_index = 0;

int nert_is_duplicate(uint16_t sender_id, uint16_t seq_num) {
    for (int i = 0; i < NERT_DEDUP_CACHE_SIZE; i++) {
        if (dedup_cache[i].sender_id == sender_id &&
            dedup_cache[i].seq_num == seq_num) {
            return 1; /* Duplicado */
        }
    }

    /* Agregar a caché (circular) */
    dedup_cache[dedup_index].sender_id = sender_id;
    dedup_cache[dedup_index].seq_num = seq_num;
    dedup_cache[dedup_index].received_tick = hal_timer_ticks();
    dedup_index = (dedup_index + 1) % NERT_DEDUP_CACHE_SIZE;

    return 0; /* Nuevo */
}
```

---

## 7. Enrutamiento Hebbiano (v0.5)

### 7.1 Inspiración Neurológica

> "Las neuronas que se disparan juntas, se conectan juntas" — Donald Hebb

NanOS v0.5 introduce **enrutamiento Hebbiano**, un sistema de aprendizaje inspirado en la plasticidad sináptica del cerebro. Cada conexión con un vecino tiene un "peso sináptico" que representa la confiabilidad aprendida de esa ruta.

### 7.2 Peso Sináptico

```c
/* Agregado a neighbor_entry */
struct neighbor_entry {
    uint32_t node_id;
    uint32_t last_seen;
    uint8_t  role;
    uint8_t  distance;
    uint16_t packets;
    uint8_t  synaptic_weight;  /* v0.5: 1-255, inicial: 128 */
};
```

| Constante | Valor | Descripción |
|-----------|-------|-------------|
| SYNAPSE_WEIGHT_MIN | 1 | Peso mínimo (conexión casi muerta) |
| SYNAPSE_WEIGHT_MAX | 255 | Peso máximo (conexión perfecta) |
| SYNAPSE_WEIGHT_INITIAL | 128 | Peso inicial neutral |
| SYNAPSE_WEIGHT_THRESHOLD | 32 | Umbral para ruta saludable |

### 7.3 Reglas de Aprendizaje

#### Long-Term Potentiation (LTP) - Recompensa

Cuando se recibe un ACK exitoso:
```c
weight = min(255, weight + 15);
```

#### Long-Term Depression (LTD) - Castigo

Cuando hay timeout o reintentos agotados:
```c
weight = max(1, weight - 40);
```

**Asimetría intencional**: El castigo es ~3x más severo que la recompensa para que el enjambre aprenda rápidamente a evitar nodos problemáticos.

#### Spike-Timing Dependent Plasticity (STDP)

Bonus adicional para respuestas rápidas (<100ms):
```c
if (response_ms < SYNAPSE_STDP_WINDOW_MS) {
    weight = min(255, weight + 5);
}
```

### 7.4 Fórmula de Costo Neural

El costo de ruta combina distancia física y confiabilidad aprendida:

```
Costo(j) = 10 × distancia_j + (255 - peso_j) / 8
```

| Distancia | Peso | Costo | Interpretación |
|-----------|------|-------|----------------|
| 1 hop | 255 (perfecto) | 10 + 0 = 10 | Mejor caso |
| 1 hop | 128 (neutral) | 10 + 15 = 25 | Conexión nueva |
| 1 hop | 1 (muerto) | 10 + 31 = 41 | Nodo problemático |
| 2 hops | 255 (perfecto) | 20 + 0 = 20 | Ruta alternativa viable |

**Insight clave**: Una ruta de 2 hops confiable (costo=20) es MEJOR que una ruta de 1 hop poco confiable (costo=41). El enjambre aprende a rodear nodos defectuosos.

### 7.5 Decaimiento Natural

Para evitar pesos permanentemente altos y permitir adaptación:

```c
/* Cada 5 segundos */
void nert_synapse_decay(void) {
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (neighbors[i].synaptic_weight > SYNAPSE_WEIGHT_INITIAL) {
            neighbors[i].synaptic_weight -= SYNAPSE_DECAY_AMOUNT;
        }
    }
}
```

### 7.6 Integración con Multi-Path

El enrutamiento multi-path (sección 6) ahora usa pesos sinápticos en la selección:

```c
int nert_select_paths(uint16_t dest_id, uint16_t paths[NERT_MAX_PATHS]) {
    for (int p = 0; p < NERT_MAX_PATHS; p++) {
        /* Score ahora incluye peso sináptico */
        uint8_t score = n->distance;
        score += (255 - n->synaptic_weight) / 8;  /* v0.5: factor de confiabilidad */

        if (score < best_score) {
            best_score = score;
            best = n;
        }
    }
}
```

---

## 8. Stigmergia: Feromonas Digitales (v0.5)

### 8.1 Concepto

Las hormigas no memorizan mapas; dejan **químicos que se evaporan**. Este mecanismo de coordinación indirecta se llama **stigmergia**. NanOS v0.5 implementa esto digitalmente.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Analogía Stigmergia                          │
├─────────────────────────────────────────────────────────────────┤
│  Hormiga real:          │  NanOS Digital:                       │
│  - Feromona química     │  - Feromona digital (4 bits)          │
│  - Se evapora con tiempo│  - Decae 1/segundo                    │
│  - Atrae o repele       │  - Modifica costo de movimiento       │
│  - Sin memoria central  │  - Sin coordinación central           │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Tipos de Feromonas

| Tipo | Código | Efecto en Costo | Uso |
|------|--------|-----------------|-----|
| DANGER | 0 | +8 × intensidad | Jamming, ataques, nodos maliciosos |
| QUEEN | 1 | -2 × intensidad | Camino hacia la reina (atracción) |
| RESOURCE | 2 | Neutral | Marcador de objetivos |
| AVOID | 3 | +4 × intensidad | Zonas subóptimas |

### 8.3 Estructura de Datos

```c
/* Almacenamiento eficiente: 4 tipos en 2 bytes por celda */
#define STIGMERGIA_SIZE     16   /* Grid 16x16 cubriendo terreno 32x32 */

struct {
    uint8_t data[2];  /* [DANGER:4|QUEEN:4], [RESOURCE:4|AVOID:4] */
} pheromones[STIGMERGIA_SIZE][STIGMERGIA_SIZE];

/* Total: 16 × 16 × 2 = 512 bytes */
```

### 8.4 Decaimiento Temporal

```c
#define STIGMERGIA_DECAY_INTERVAL_MS    1000    /* Cada 1 segundo */
#define STIGMERGIA_DECAY_AMOUNT         1       /* -1 intensidad */
#define STIGMERGIA_INTENSITY_MAX        15      /* Máximo (4 bits) */

void stigmergia_decay(void) {
    /* Cada segundo: todas las feromonas -1, mínimo 0 */
    for (int y = 0; y < STIGMERGIA_SIZE; y++) {
        for (int x = 0; x < STIGMERGIA_SIZE; x++) {
            for (int type = 0; type < 4; type++) {
                uint8_t intensity = stigmergia_get(x, y, type);
                if (intensity > 0) {
                    stigmergia_set(x, y, type, intensity - 1);
                }
            }
        }
    }
}
```

### 8.5 Modificación de Costo de Movimiento

```
Costo_total = Costo_base + 8×DANGER + 4×AVOID - 2×QUEEN
```

| Situación | Feromonas | Modificador | Costo Final |
|-----------|-----------|-------------|-------------|
| Celda normal | Ninguna | 0 | 10 |
| Zona peligrosa | DANGER=15 | +120 | 130 |
| Cerca de reina | QUEEN=10 | -20 | -10 (atracción) |
| Zona subóptima | AVOID=8 | +32 | 42 |

### 8.6 Propagación de Feromonas

Feromonas de alta intensidad se propagan a celdas vecinas con decremento:

```c
#define STIGMERGIA_PROPAGATE_THRESHOLD  6   /* Min para propagar */
#define STIGMERGIA_PROPAGATE_DECAY      3   /* -3 al propagar */

void stigmergia_propagate(void) {
    for (cada celda con intensidad >= threshold) {
        /* Propagar a vecinos con intensidad - 3 */
        propagar_a_vecinos(x, y, type, intensidad - STIGMERGIA_PROPAGATE_DECAY);
    }
}
```

### 8.7 Paquete de Feromona (PHEROMONE_STIGMERGIA = 0x88)

```c
struct stigmergia_payload {
    uint8_t  terrain_x;     /* Coordenada X (terreno) */
    uint8_t  terrain_y;     /* Coordenada Y (terreno) */
    uint8_t  type;          /* STIGMERGIA_* tipo */
    uint8_t  intensity;     /* 0-15 intensidad */
};
```

---

## 9. Black Box Distribuida: "El Último Aliento" (v0.5)

### 9.1 Problema

Cuando un nodo es comprometido y terminado, su evidencia forense se pierde. Un atacante inteligente podría comprometer un nodo, extraer información, y forzar su "suicidio" para eliminar rastros.

### 9.2 Solución

Antes de morir, cada nodo transmite un **testamento** (Last Will) a vecinos de confianza seleccionados por peso Hebbiano. La evidencia sobrevive en el enjambre.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Flujo Black Box                              │
├─────────────────────────────────────────────────────────────────┤
│  Operación Normal:                                              │
│    blackbox_record_event() → Almacena eventos de seguridad      │
│                                                                 │
│  Trigger de Muerte:                                             │
│    cell_apoptosis() → blackbox_emit_last_will()                 │
│                       → Envía a vecinos con mayor peso Hebbiano │
│                                                                 │
│  En Receptores:                                                 │
│    blackbox_process_last_will() → Almacena testamento           │
│                                                                 │
│  Consulta Forense:                                              │
│    blackbox_query_death(node_id) → Retorna evidencia            │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Razones de Muerte

```c
#define DEATH_NATURAL           0x00  /* Vejez/timeout normal */
#define DEATH_HEAP_EXHAUSTED    0x01  /* Sin memoria */
#define DEATH_CORRUPTION        0x02  /* Corrupción detectada */
#define DEATH_ATTACK_DETECTED   0x03  /* Ataque en progreso */
#define DEATH_QUEEN_ORDER       0x04  /* Orden de la reina */
#define DEATH_ISOLATION         0x05  /* Sin contacto con enjambre */
```

### 9.4 Tipos de Eventos de Seguridad

```c
#define EVENT_BAD_MAC           0x01  /* MAC inválido recibido */
#define EVENT_REPLAY            0x02  /* Intento de replay */
#define EVENT_RATE_LIMIT        0x03  /* Rate limit excedido */
#define EVENT_BLACKLIST         0x04  /* Nodo en blacklist */
#define EVENT_JAMMING           0x05  /* Jamming detectado */
#define EVENT_CORRUPTION        0x06  /* Corrupción de memoria */
```

### 9.5 Contenido del Testamento

```c
struct last_will_testament {
    uint32_t node_id;           /* ID del nodo que muere */
    uint8_t  death_reason;      /* DEATH_* código */
    uint8_t  uptime_hours;      /* Horas de vida */
    uint16_t bad_mac_count;     /* MACs inválidos recibidos */
    uint16_t replay_count;      /* Intentos de replay */
    uint16_t rate_limit_hits;   /* Veces rate limited */

    /* Últimos 8 eventos de seguridad */
    struct {
        uint8_t  type;          /* EVENT_* tipo */
        uint16_t source_node;   /* Nodo relacionado */
        uint32_t timestamp;     /* Cuando ocurrió */
    } events[8];
};
```

### 9.6 Selección de Receptores (Hebbiano)

El testamento se envía a los 3 vecinos con mayor peso sináptico:

```c
void blackbox_emit_last_will(uint8_t death_reason) {
    uint32_t recipients[3];
    uint32_t exclude_list[3] = {0};

    /* Seleccionar 3 vecinos más confiables */
    for (int i = 0; i < 3; i++) {
        recipients[i] = find_trusted_recipient(exclude_list);
        exclude_list[i] = recipients[i];

        if (recipients[i] != 0) {
            /* Enviar testamento */
            nert_send_reliable(recipients[i], PHEROMONE_LAST_WILL,
                              &testament, sizeof(testament));
        }
    }
}
```

### 9.7 Paquete de Testamento (PHEROMONE_LAST_WILL = 0x89)

```
┌────────────────────────────────────────────────────────────────┐
│ NERT Header (20 bytes) │ Last Will Payload │ Auth Tag (8 bytes)│
├────────────────────────┼───────────────────┼───────────────────┤
│ type=0x89, RELIABLE    │ node_id, reason,  │ Poly1305 MAC      │
│ class, encrypted       │ stats, events[8]  │                   │
└────────────────────────────────────────────────────────────────┘
```

### 9.8 Almacenamiento de Testamentos

```c
#define BLACKBOX_MAX_WILLS  8   /* Testamentos almacenados por nodo */

struct blackbox_storage {
    struct stored_will {
        uint32_t node_id;
        uint8_t  death_reason;
        uint8_t  uptime_hours;
        uint16_t bad_mac_count;
        uint8_t  priority;      /* Para relay y reemplazo */
        uint8_t  valid;
    } wills[BLACKBOX_MAX_WILLS];

    uint8_t count;
};
```

### 9.9 API de Black Box

```c
/* Inicializar sistema */
void blackbox_init(void);

/* Registrar evento de seguridad (durante operación normal) */
void blackbox_record_event(uint8_t event_type, uint16_t source_node);

/* Emitir testamento antes de morir */
void blackbox_emit_last_will(uint8_t death_reason);

/* Procesar testamento recibido */
void blackbox_process_last_will(struct nanos_pheromone* pkt);

/* Consultar muerte de un nodo específico */
int blackbox_query_death(uint32_t node_id,
                         uint8_t *death_reason,
                         uint16_t *bad_mac_count,
                         uint8_t *uptime_hours);

/* Imprimir resumen forense (debug) */
void blackbox_print_summary(void);
```

### 9.10 Supervivencia de Evidencia

Con 3 receptores de confianza y probabilidad de compromiso 10% por nodo:

```
P(evidencia perdida) = 0.1³ = 0.001 = 0.1%
P(evidencia sobrevive) = 1 - 0.001 = 99.9%
```

> "Los muertos hablan a través de los vivos."

---

## 10. Handshake de Conexión Reliable

### 10.1 Two-Way Handshake (simplificado)

A diferencia del 3-way handshake de TCP, usamos 2-way para conexiones efímeras (para más detalles sobre selección de rutas ver sección 7.6):

```
    Nodo A                         Nodo B
      |                              |
      |-------- SYN + DATA --------->|   (seq=X, ack=0)
      |                              |
      |<------- SYN+ACK + DATA ------|   (seq=Y, ack=X+1)
      |                              |
      |-------- DATA --------------->|   (seq=X+1, ack=Y+1)
      |                              |
      ... conexión establecida ...
```

### 10.2 Código de Handshake

```c
int nert_connect(uint16_t peer_id) {
    struct nert_connection *conn = nert_get_free_connection();
    if (!conn) return -1;

    conn->peer_id = peer_id;
    conn->send_seq = hal_rng_get() & 0xFFFF;
    conn->recv_seq = 0;
    conn->state = NERT_STATE_SYN_SENT;

    /* Enviar SYN */
    struct nert_packet pkt = {0};
    pkt.header.flags = NERT_FLAG_SYN | NERT_FLAG_ENC;
    pkt.header.seq_num = conn->send_seq;
    pkt.header.dest_id = peer_id;

    nert_send_reliable(conn, &pkt);

    return conn - connections; /* Connection ID */
}

void nert_handle_syn(struct nert_packet *pkt) {
    struct nert_connection *conn = nert_find_connection(pkt->header.node_id);

    if (!conn) {
        conn = nert_get_free_connection();
        if (!conn) return; /* Sin espacio */

        conn->peer_id = pkt->header.node_id;
        conn->recv_seq = pkt->header.seq_num + 1;
        conn->send_seq = hal_rng_get() & 0xFFFF;
    }

    /* Responder SYN+ACK */
    struct nert_packet resp = {0};
    resp.header.flags = NERT_FLAG_SYN | NERT_FLAG_ACK | NERT_FLAG_ENC;
    resp.header.seq_num = conn->send_seq;
    resp.header.ack_num = conn->recv_seq;
    resp.header.dest_id = conn->peer_id;

    nert_send(&resp);
    conn->state = NERT_STATE_ESTABLISHED;
}
```

---

## 11. API de Usuario

### 11.1 Funciones Principales

```c
/*
 * Inicializa el subsistema NERT
 * Deriva claves de sesión, inicializa estructuras
 */
void nert_init(void);

/*
 * Envía mensaje sin garantía de entrega (FIRE_FORGET)
 * Ideal para HELLO, SENSOR, datos frecuentes
 */
int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint8_t len);

/*
 * Envía mensaje con reintentos automáticos (BEST_EFFORT)
 * Ideal para DATA, KV operations
 */
int nert_send_best_effort(uint16_t dest_id, uint8_t pheromone_type,
                          const void *data, uint8_t len);

/*
 * Envía mensaje con ACK garantizado (RELIABLE)
 * Ideal para TASK, comandos
 */
int nert_send_reliable(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len);

/*
 * Envía mensaje crítico con FEC y multi-path (CRITICAL)
 * Ideal para QUEEN_CMD, DIE, CORONATION
 */
int nert_send_critical(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len);

/*
 * Procesa paquetes entrantes
 * Llamar desde el loop principal
 */
void nert_process_incoming(void);

/*
 * Timer tick - maneja retransmisiones
 * Llamar cada ~50ms
 */
void nert_timer_tick(void);

/*
 * Callback para paquetes recibidos
 */
typedef void (*nert_receive_callback)(uint16_t sender_id,
                                       uint8_t pheromone_type,
                                       const void *data, uint8_t len);
void nert_set_receive_callback(nert_receive_callback cb);
```

### 11.2 Ejemplo de Uso

```c
/* En kernel_main() */
void kernel_main(void) {
    hal_init();
    nert_init();
    nert_set_receive_callback(handle_pheromone);

    while (1) {
        nert_process_incoming();

        /* Enviar HELLO cada segundo (unreliable) */
        if (timer_expired(hello_timer)) {
            struct hello_payload hello = {
                .role = swarm_state.role,
                .distance = swarm_state.distance_to_queen
            };
            nert_send_unreliable(0x0000, PHEROMONE_HELLO,
                                 &hello, sizeof(hello));
        }

        /* Comando de reina (critical) */
        if (swarm_state.role == ROLE_QUEEN && pending_command) {
            nert_send_critical(target_node, PHEROMONE_QUEEN_CMD,
                              &command, sizeof(command));
        }

        nert_timer_tick();
        hal_cpu_idle();
    }
}

void handle_pheromone(uint16_t sender_id, uint8_t type,
                      const void *data, uint8_t len) {
    switch (type) {
        case PHEROMONE_HELLO:
            neighbor_update(sender_id, (struct hello_payload*)data);
            break;
        case PHEROMONE_QUEEN_CMD:
            execute_queen_command((struct queen_cmd*)data);
            break;
        /* ... otros tipos ... */
    }
}
```

---

## 12. Comparación con Protocolos Existentes

| Característica | TCP | UDP | QUIC | **NERT** |
|---------------|-----|-----|------|----------|
| Overhead mínimo | 20B | 8B | ~20B | **20B** |
| Encriptación | Opcional (TLS) | No | Obligatoria | **Obligatoria** |
| Handshake | 3-way | Ninguno | 1-RTT | **2-way** |
| Confiabilidad | Siempre | Nunca | Siempre | **Selectiva** |
| Multiplexing | Por conexión | Por puerto | Streams | **Por clase** |
| FEC | No | No | Opcional | **Para critical** |
| Multi-path | No | No | Parcial | **Sí** |
| Optimizado para efímeros | No | Parcial | No | **Sí** |
| RAM requerida | ~2KB/conn | ~0 | ~4KB/conn | **~100B/conn** |

---

## 13. Consideraciones de Seguridad

### 13.1 Modelo de Amenazas

| Amenaza | Mitigación |
|---------|------------|
| Eavesdropping | ChaCha8 encryption obligatoria |
| Replay attacks | Nonce único (node_id + counter + timestamp) |
| Tampering | Poly1305 MAC sobre header + payload |
| Impersonation | Clave pre-compartida del enjambre |
| DoS flooding | Bloom filter + gossip decay + rate limiting (v0.5) |
| Sybil/Eclipse attacks | Reputación Hebbiana: nodos maliciosos penalizados (v0.5) |
| Man-in-the-middle | Requiere conocer SWARM_MASTER_KEY |

### 13.2 Rotación de Claves con Ventana de Gracia

**Problema**: Sin sincronización de tiempo, nodos con relojes ligeramente desincronizados
podrían rechazar paquetes válidos justo en el cambio de época.

**Solución**: Mantener tres claves derivadas (anterior, actual, siguiente) y aceptar
cualquiera de ellas durante una ventana de gracia en los límites de época.

```
     Época N-1          │          Época N          │         Época N+1
                        │                           │
 ──────────────────────►│◄─────────────────────────►│◄──────────────────────
                        │                           │
              ┌─────────┼─────────┐       ┌─────────┼─────────┐
              │  Grace  │  Grace  │       │  Grace  │  Grace  │
              │ Window  │ Window  │       │ Window  │ Window  │
              │  (30s)  │  (30s)  │       │  (30s)  │  (30s)  │
              └─────────┼─────────┘       └─────────┼─────────┘
                        │                           │
  Acepta: key[N-1]      │ Acepta: key[N-1], key[N]  │ Acepta: key[N], key[N+1]
                        │                           │
```

```c
#define KEY_ROTATION_INTERVAL_SEC   3600    /* 1 hora */
#define GRACE_WINDOW_MS             30000   /* 30 segundos de gracia */

/* Claves para épocas adyacentes */
static uint8_t session_key[32];       /* Época actual */
static uint8_t prev_session_key[32];  /* Época anterior */
static uint8_t next_session_key[32];  /* Época siguiente (pre-calculada) */

void nert_check_key_rotation(void) {
    uint32_t current_epoch = hal_timer_ticks() / (1000 * KEY_ROTATION_INTERVAL_SEC);

    if (current_epoch != last_key_epoch) {
        /* Derivar las tres claves */
        derive_key_for_epoch(current_epoch - 1, prev_session_key);
        derive_key_for_epoch(current_epoch, session_key);
        derive_key_for_epoch(current_epoch + 1, next_session_key);
        last_key_epoch = current_epoch;
    }
}

/* En verificación de MAC: probar con claves válidas según posición en época */
uint8_t get_valid_key_mask(void) {
    uint32_t pos_in_epoch = hal_timer_ticks() % (KEY_ROTATION_INTERVAL_SEC * 1000);
    uint8_t mask = 0x01;  /* Clave actual siempre válida */

    if (pos_in_epoch < GRACE_WINDOW_MS)
        mask |= 0x02;  /* Aceptar clave anterior */

    if (pos_in_epoch > (KEY_ROTATION_INTERVAL_SEC * 1000 - GRACE_WINDOW_MS))
        mask |= 0x04;  /* Aceptar clave siguiente */

    return mask;
}
```

**Beneficios**:
- Tolera hasta 30 segundos de drift entre nodos
- Sin sincronización de tiempo requerida
- Overhead mínimo: 64 bytes extra de RAM para claves adicionales

### 13.3 Protección Anti-Replay

```c
/* Ventana anti-replay de 64 paquetes */
#define REPLAY_WINDOW_SIZE  64

struct replay_protection {
    uint16_t highest_seq;
    uint64_t bitmap;  /* Bits para [highest_seq-63, highest_seq] */
};

int nert_check_replay(struct replay_protection *rp, uint16_t seq) {
    if (seq > rp->highest_seq) {
        /* Nuevo máximo - desplazar ventana */
        int shift = seq - rp->highest_seq;
        if (shift >= 64) {
            rp->bitmap = 1;  /* Reset, solo este paquete */
        } else {
            rp->bitmap <<= shift;
            rp->bitmap |= 1;
        }
        rp->highest_seq = seq;
        return 0; /* Válido */
    }

    int offset = rp->highest_seq - seq;
    if (offset >= 64) {
        return -1; /* Muy antiguo */
    }

    if (rp->bitmap & (1ULL << offset)) {
        return -1; /* Replay detectado */
    }

    rp->bitmap |= (1ULL << offset);
    return 0; /* Válido */
}
```

---

## 14. Métricas y Debugging

### 14.1 Contadores de Estadísticas

```c
struct nert_stats {
    /* TX */
    uint32_t tx_packets;
    uint32_t tx_bytes;
    uint32_t tx_retransmits;
    uint32_t tx_fec_blocks;

    /* RX */
    uint32_t rx_packets;
    uint32_t rx_bytes;
    uint32_t rx_duplicates;
    uint32_t rx_recovered_fec;
    uint32_t rx_bad_mac;
    uint32_t rx_replay_blocked;

    /* Conexiones */
    uint32_t connections_opened;
    uint32_t connections_failed;

    /* Timing */
    uint16_t avg_rtt;
    uint16_t min_rtt;
    uint16_t max_rtt;
};

extern struct nert_stats nert_stats;
```

### 14.2 Debug Output

```c
#ifdef NERT_DEBUG
void nert_debug_packet(const char *prefix, struct nert_packet *pkt) {
    hal_debug_printf("[NERT] %s: src=%04X dst=%04X seq=%u ack=%u "
                    "flags=%02X len=%u\n",
                    prefix,
                    pkt->header.node_id,
                    pkt->header.dest_id,
                    pkt->header.seq_num,
                    pkt->header.ack_num,
                    pkt->header.flags,
                    pkt->header.payload_len);
}
#endif
```

---

## 15. Implementación por Plataforma

### 15.1 x86 (QEMU e1000)

```c
/* Usa infraestructura existente */
int nert_hal_send(const void *data, uint16_t len) {
    struct eth_header eth = {
        .dst = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, /* Multicast */
        .ethertype = htons(ETH_TYPE_NERT)  /* 0x4E52 = "NR" */
    };
    memcpy(eth.src, e1000_get_mac(), 6);

    return e1000_send_frame(&eth, data, len);
}
```

### 15.2 ARM Cortex-M3 (Stellaris)

```c
/* Formato compacto para MCU */
#define NERT_HEADER_COMPACT_SIZE  12

struct nert_header_compact {
    uint8_t  magic;              /* 0xAA */
    uint8_t  version_class;
    uint16_t node_id;
    uint16_t seq_num;
    uint8_t  flags;
    uint8_t  payload_len;
    uint32_t nonce_counter;
};
/* + 4 bytes auth tag = 16 bytes overhead total */
```

### 15.3 ESP32

```c
/* WiFi broadcast o ESP-NOW */
int nert_hal_send(const void *data, uint16_t len) {
    #ifdef USE_ESP_NOW
    return esp_now_send(BROADCAST_MAC, data, len);
    #else
    return udp_broadcast(NERT_PORT, data, len);
    #endif
}
```

---

## 16. Migración desde Protocolo Actual

### 16.1 Compatibilidad

NERT es compatible con el protocolo pheromone existente:
- Mismo puerto multicast (230.0.0.1:1234)
- Identificable por magic byte diferente (0x4E vs 0x4E414E4F)
- Fallback a protocolo legacy si NERT no disponible

### 16.2 Detección de Versión

```c
int nert_detect_protocol(const uint8_t *data, uint16_t len) {
    if (len >= 4 && *(uint32_t*)data == 0x4E414E4F) {
        return PROTOCOL_LEGACY;  /* "NANO" magic */
    }
    if (len >= 1 && data[0] == 0x4E) {
        return PROTOCOL_NERT;    /* NERT magic */
    }
    return PROTOCOL_UNKNOWN;
}
```

---

## 17. Resumen de Recursos

### 17.1 Uso de RAM

| Componente | Tamaño | Notas |
|------------|--------|-------|
| Conexiones | 8 × ~100B = 800B | 8 conexiones simultáneas |
| TX Buffers | 4 × 64B = 256B | Por conexión |
| RX Buffer | 512B | Buffer de recepción |
| Session Key | 32B | Clave derivada |
| Dedup Cache | 16 × 8B = 128B | Deduplicación |
| Stats | ~50B | Contadores |
| **Total** | **~1.8KB** | Sin FEC buffers |
| + FEC Buffers | +768B | Solo para CRITICAL |

### 17.2 Uso de CPU

| Operación | Ciclos (~ARM Cortex-M3) |
|-----------|-------------------------|
| ChaCha8 encrypt (32B) | ~2,000 |
| Poly1305 MAC | ~1,500 |
| FEC encode | ~500 |
| FEC decode | ~1,000 |
| Header parse | ~100 |

---

## Apéndice A: Constantes de Compilación

```c
/* nert_config.h */
#ifndef NERT_CONFIG_H
#define NERT_CONFIG_H

/* Plataforma */
#if defined(__arm__)
    #define NERT_COMPACT_HEADER    1
    #define NERT_MAX_CONNECTIONS   4
    #define NERT_WINDOW_SIZE       2
#else
    #define NERT_COMPACT_HEADER    0
    #define NERT_MAX_CONNECTIONS   8
    #define NERT_WINDOW_SIZE       4
#endif

/* Features */
#define NERT_ENABLE_FEC            1
#define NERT_ENABLE_MULTIPATH      1
#define NERT_ENABLE_DEBUG          0

/* Timing */
#define NERT_TICK_INTERVAL_MS      50
#define NERT_CONNECTION_TIMEOUT_MS 30000
#define NERT_KEY_ROTATION_SEC      3600

/* Crypto */
#define NERT_CHACHA_ROUNDS         8
#define NERT_MAC_SIZE              8

#endif /* NERT_CONFIG_H */
```

---

## Apéndice B: Diagrama de Estados

```
                    ┌──────────────────┐
                    │      CLOSED      │
                    └────────┬─────────┘
                             │ connect()
                             ▼
                    ┌──────────────────┐
          ┌─────────│    SYN_SENT      │
          │         └────────┬─────────┘
          │                  │ recv SYN+ACK
          │ timeout          ▼
          │         ┌──────────────────┐
          │         │   ESTABLISHED    │◄───────┐
          │         └────────┬─────────┘        │
          │                  │                   │
          │         ┌────────┴─────────┐        │
          │         ▼                  ▼        │
          │    send FIN           recv FIN      │
          │         │                  │        │
          │         ▼                  ▼        │
          │  ┌─────────────┐   ┌─────────────┐  │
          │  │  FIN_SENT   │   │ CLOSE_WAIT  │  │
          │  └──────┬──────┘   └──────┬──────┘  │
          │         │ recv ACK        │ send FIN│
          │         ▼                  ▼        │
          │  ┌─────────────┐   ┌─────────────┐  │
          │  │  TIME_WAIT  │   │ LAST_ACK    │  │
          │  └──────┬──────┘   └──────┬──────┘  │
          │         │ 2*RTT           │ recv ACK│
          │         ▼                  ▼        │
          │         └──────────┬───────┘        │
          │                    │                │
          └────────────────────┼────────────────┘
                               ▼
                      ┌──────────────────┐
                      │      CLOSED      │
                      └──────────────────┘
```

---

**Versión**: 1.2 (Stigmergia + Black Box)
**Autor**: Claude Code / NanOS Team
**Fecha**: 2026-01-18
**Licencia**: MIT

### Changelog
- **v1.2**: Agregadas secciones 8 (Stigmergia: Feromonas Digitales) y 9 (Black Box Distribuida: "El Último Aliento")
- **v1.1**: Agregado sección 7 (Enrutamiento Hebbiano), actualizado secciones de seguridad con protección contra ataques Sybil/Eclipse
- **v1.0**: Versión inicial del protocolo NERT
