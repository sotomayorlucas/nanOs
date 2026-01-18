# NERT Protocol Integration

## Arquitectura de Capas

NanOS v0.4 utiliza una arquitectura de capas limpia que separa la capa física (PHY) del protocolo NERT:

```
┌─────────────────────────────────────────────────────────┐
│          Application (demo_node.c)                      │
│   - Message handlers (pub/sub)                         │
│   - Security callbacks                                 │
│   - Business logic                                     │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│          NERT Protocol (kernel/protocol/nert.c)        │
│   - Packet formatting (20-byte header)                 │
│   - ChaCha8 encryption                                 │
│   - Poly1305 MAC authentication                        │
│   - Reliability classes (Fire & Forget, Reliable)      │
│   - Connection management                              │
│   - Retransmission logic                               │
│   - Key rotation                                       │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│          HAL Adapter (lib/nert/hal/hal_adapter.c)      │
│   - Bridges nert_phy_interface with nert_hal_*         │
│   - Maps send() → nert_hal_send()                      │
│   - Maps receive() → nert_hal_receive()                │
│   - Maps get_ticks() → nert_hal_get_ticks()            │
│   - Provides global state (ticks, g_state)             │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│          Physical Layer (lib/nert/hal/hal_virtual.c)   │
│   - UDP multicast sockets                              │
│   - Grupo: 239.255.0.1                                 │
│   - Puerto: 5555                                       │
│   - Non-blocking I/O                                   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
                  [Network / Wire]
```

## Flujo de Datos (TX)

Cuando la aplicación envía un mensaje:

```c
// Aplicación
nert_send_unreliable(0, PHEROMONE_ANNOUNCE, data, 6);

    ↓

// NERT Protocol (nert.c)
// 1. Construye header NERT (20 bytes)
struct nert_header {
    uint8_t  magic = 0x4E;           // 'N'
    uint8_t  version_class;
    uint16_t node_id;                 // De nert_hal_get_node_id()
    uint16_t dest_id = 0;             // Broadcast
    uint16_t seq_num;                 // Auto-incrementa
    uint16_t ack_num;
    uint8_t  flags = FLAG_ENC;        // Encrypted
    uint8_t  payload_len = 7;         // 6 data + 1 type
    uint16_t timestamp;               // De nert_hal_get_ticks()
    uint8_t  ttl = 15;
    uint8_t  hop_count = 0;
    uint32_t nonce_counter;
};

// 2. Cifra payload con ChaCha8
chacha8_encrypt(session_key, nonce, plain_payload, len, encrypted_payload);

// 3. Genera MAC con Poly1305
poly1305_mac(session_key, encrypted_payload, len, header, header_size, mac);

// 4. Construye paquete completo
[Header: 20 bytes] [Encrypted Payload: 7 bytes] [MAC: 8 bytes] = 35 bytes

    ↓

// HAL Adapter (hal_adapter.c)
nert_hal_send(packet, 35);

    ↓

// PHY Virtual (hal_virtual.c)
sendto(sock_fd, packet, 35, 0, &multicast_addr, sizeof(multicast_addr));

    ↓

[Network: UDP multicast to 239.255.0.1:5555]
```

## Flujo de Datos (RX)

Cuando llega un paquete de la red:

```
[Network: UDP multicast from 239.255.0.1:5555]

    ↓

// PHY Virtual (hal_virtual.c)
recvfrom(sock_fd, buffer, max_len, 0, &sender_addr, &addr_len);

    ↓

// HAL Adapter (hal_adapter.c)
nert_hal_receive(buffer, max_len);

    ↓

// NERT Protocol (nert.c)
nert_process_incoming() {
    // 1. Lee packet del PHY
    // 2. Valida magic number (0x4E)
    // 3. Extrae header y payload
    // 4. Verifica MAC con Poly1305 (previene modificación)
    if (poly1305_verify(session_key, payload, len, header, header_size, mac) != 0) {
        stats.rx_bad_mac++;  // Attack detected!
        return;
    }

    // 5. Descifra payload con ChaCha8
    chacha8_encrypt(session_key, nonce, encrypted_payload, len, plain_payload);

    // 6. Verifica replay protection (sliding window bitmap)
    if (is_duplicate(sender_id, seq_num)) {
        stats.rx_replay_blocked++;  // Replay attack detected!
        return;
    }

    // 7. Despacha a handler de aplicación
    if (receive_callback) {
        receive_callback(sender_id, pheromone_type, plain_payload, len);
    }
}

    ↓

// Aplicación
handle_data(sender_id, msg_type, data, len, user_ctx);
```

## Protección de Seguridad

### 1. Encryption (ChaCha8)
- **Todo el tráfico es cifrado** en la capa NERT
- UDP raw en PHY solo transporta bytes cifrados
- Un atacante capturando el tráfico solo ve:
  ```
  4E 10 12 34 00 00 00 2A ... [basura cifrada] ... A3 F2 01 E4
  ```

### 2. Authentication (Poly1305 MAC)
- Cada paquete tiene MAC de 8 bytes
- Previene modificación de paquetes
- Si el MAC no coincide → paquete rechazado silenciosamente

### 3. Replay Protection
- Sliding window bitmap de 64 bits
- Rechaza paquetes con sequence numbers antiguos
- Ejemplo:
  ```
  Seq 100: [Accept]
  Seq 101: [Accept]
  Seq 100: [REJECT - Replay attack!]
  ```

### 4. Key Rotation (Dynamic)
- Claves rotan cada 3600 segundos (1 hora)
- Grace window de 30 segundos para clock drift
- Forward secrecy: capturar nodo hoy ≠ descifrar tráfico de ayer

## Comparación: NERT vs UDP Raw

| Aspecto | UDP Raw (v0.3) | NERT Protocol (v0.4) |
|---------|----------------|----------------------|
| **Encryption** | ✗ None | ✅ ChaCha8 (todo el tráfico) |
| **Authentication** | ✗ None | ✅ Poly1305 MAC (cada paquete) |
| **Replay Protection** | ✗ None | ✅ Sliding window bitmap |
| **Reliability** | ✗ Fire & forget | ✅ 4 clases (unreliable → critical) |
| **Key Rotation** | ✗ Static | ✅ Dynamic (cada hora) |
| **Connection Management** | ✗ None | ✅ TCP-like states |
| **Retransmissions** | ✗ None | ✅ Exponential backoff |
| **Overhead** | 0 bytes | 28 bytes (20 header + 8 MAC) |

## Ejemplo de Uso

### Demo Node (Full NERT)

```c
#include "nert_phy_if.h"
#include "hal/hal_adapter.h"
#include "nert.h"

int main(void) {
    // 1. Crear PHY (UDP multicast)
    struct nert_phy_interface *phy =
        nert_phy_virtual_create(5555, "239.255.0.1");

    // 2. Inicializar HAL adapter
    nert_hal_adapter_init(phy, my_node_id);

    // 3. Inicializar NERT protocol
    nert_init();
    nert_set_master_key(demo_master_key);

    // 4. Main loop
    while (running) {
        nert_hal_update_ticks();      // Update global tick counter
        nert_process_incoming();       // Receive NERT packets
        nert_timer_tick();             // Handle retransmissions
        nert_check_key_rotation();     // Check if key rotation needed

        // 5. Send data via NERT (auto-encrypted)
        nert_send_unreliable(0, PHEROMONE_ANNOUNCE, data, len);
    }

    // 6. Cleanup
    nert_security_wipe_keys();
    nert_phy_virtual_destroy(phy);
}
```

## Archivos Clave

| Archivo | Propósito |
|---------|-----------|
| **kernel/protocol/nert.c** | Implementación core del protocolo NERT |
| **lib/nert/hal/hal_adapter.c** | Adapter entre PHY y NERT |
| **lib/nert/hal/hal_adapter.h** | API pública del adapter |
| **lib/nert/hal/hal_virtual.c** | PHY virtualizado (UDP multicast) |
| **lib/nert/examples/demo_node.c** | Ejemplo completo de uso |

## Verificación

Para verificar que NERT está funcionando correctamente:

```bash
# Terminal 1: Iniciar nodo
./demo_node 1001

# Expected output:
# [Node 1001] Initializing HAL adapter...
# [Node 1001] Initializing NERT stack...
# [Node 1001] READY - Using NERT protocol over UDP multicast
# [Node 1001] All traffic encrypted with ChaCha8+Poly1305

# Terminal 2: Capturar tráfico
tcpdump -i any -X host 239.255.0.1

# Expected: Paquetes UDP con datos cifrados
# 4E 10 12 34 ... [encrypted data] ... [8-byte MAC]
```

## Testing de Seguridad

El script `attacker.py` puede validar que NERT funciona correctamente:

```bash
# Test 1: Replay attack (debe ser bloqueado)
python3 tools/attacker.py --attack replay

# Expected: Nodes report "REPLAY_BLOCKED" events

# Test 2: Fuzzing (debe rechazar paquetes malformados)
python3 tools/attacker.py --attack fuzzing

# Expected: Nodes silently drop invalid packets
```

## Conclusión

Con la integración completa de NERT:

✅ **Todo el tráfico es cifrado** (no más UDP plaintext)
✅ **Autenticación garantizada** (Poly1305 MAC)
✅ **Protección contra replays** (sliding window)
✅ **Key rotation dinámica** (forward secrecy)
✅ **Arquitectura limpia** (PHY → Adapter → NERT → App)

La capa física (UDP) solo transporta bytes cifrados. El protocolo NERT maneja toda la seguridad, confiabilidad y gestión de conexiones.
