# NanOS v0.3

**Un Unikernel Reactivo para Inteligencia de Enjambre - Multi-Arquitectura**

NanOS es un sistema operativo mínimo de bare-metal diseñado para ejecutarse en miles de nodos desechables que se comunican mediante protocolos de difusión para formar una mente colectiva. Ahora soporta x86, ARM Cortex-M3 y ESP32.

## Novedades en v0.3

- **Soporte ARM Cortex-M3**: Ejecuta enjambres en QEMU ARM (lm3s6965evb Stellaris)
- **Arquitectura Modular**: Exploración de laberintos y terrenos como módulos separados
- **Panel Táctico**: Centro de comando basado en web con control de enjambre ARM
- **Soporte ESP32**: Proyecto PlatformIO para enjambres de hardware real
- **Protocolo Compacto de 24 bytes**: Formato de paquete optimizado para dispositivos embebidos

## Plataformas Soportadas

| Plataforma | Arquitectura | Red | Estado |
|----------|-------------|---------|--------|
| x86 QEMU | i386 | e1000 NIC | Producción |
| ARM QEMU | Cortex-M3 | Stellaris Ethernet | Producción |
| ESP32 | Xtensa | WiFi/ESP-NOW | Experimental |

## Filosofía

- **Biología sobre Burocracia**: Sin planificador, sin espacio de usuario, sin permisos, sin sistema de archivos. El kernel es una célula que reacciona a estímulos.
- **Caos Organizado**: Sin IPs estáticas, sin conexiones TCP. Todo es broadcast/multicast.
- **Efímero**: La memoria es volátil. El estado se mantiene mediante recirculación de mensajes (chisme), no almacenamiento en disco.
- **Silencioso por Defecto**: Si no hay eventos, la CPU duerme (`hlt` / `wfi`).
- **Sistema Inmunológico**: Autenticar antes de confiar. Verificar antes de obedecer.

## Arquitectura

```
nanOs/
├── boot/
│   └── boot.asm              # Encabezado Multiboot2 x86 + punto de entrada
├── kernel/
│   └── kernel.c              # Bucle reactivo x86 principal (modular)
├── arch/
│   └── arm-qemu/
│       ├── startup.c         # Tabla de vectores ARM Cortex-M3 y arranque
│       ├── nanos_arm.c       # Kernel ARM con ethernet
│       ├── modules.h         # Interfaces de módulos compartidos
│       ├── maze_arm.c        # Módulo de exploración de laberintos
│       ├── terrain_arm.c     # Módulo de exploración de terreno
│       └── lm3s6965.ld       # Script de enlazador ARM
├── platformio/
│   └── nanos_swarm/          # Proyecto PlatformIO ESP32
├── drivers/
│   └── e1000_minimal.c       # Controlador Intel e1000 NIC
├── include/
│   ├── nanos.h               # Tipos principales, seguridad, chisme
│   ├── io.h                  # Funciones de E/S de puerto
│   └── e1000.h               # Encabezado del controlador NIC
├── dashboard/
│   └── nanos_dashboard.py    # Centro de comando táctico basado en web
├── tools/
│   └── swarm_observer.py     # Visualización de enjambre CLI
├── linker.ld                 # Script de enlazador x86
└── Makefile                  # Sistema de compilación
```

## El Protocolo de Feromonas

### Formato x86 (64 bytes)
```c
struct nanos_pheromone {
    uint32_t magic;       // 0x4E414E4F ("NANO")
    uint32_t node_id;     // ID aleatorio asignado en el arranque
    uint8_t  type;        // Tipo de mensaje
    uint8_t  ttl;         // Saltos restantes
    uint8_t  flags;       // Bit 0: autenticado, Bits 1-3: rol
    uint8_t  version;     // Versión del protocolo (0x02)
    uint32_t seq;         // Número de secuencia
    uint8_t  hmac[8];     // HMAC truncado
    uint8_t  payload[40]; // Datos
};
```

### Formato Compacto ARM (24 bytes)
```c
typedef struct __attribute__((packed)) {
    uint8_t  magic;       // 0xAA
    uint16_t node_id;     // ID de nodo de 16 bits
    uint8_t  type;        // Tipo de mensaje
    uint8_t  ttl_flags;   // TTL (4 bits) + banderas (4 bits)
    uint8_t  seq;         // Número de secuencia
    uint16_t dest_id;     // Destino (0xFFFF = broadcast)
    uint8_t  dist_hop;    // Distancia/conteo de saltos
    uint8_t  payload[8];  // Carga útil compacta
    uint8_t  hmac[4];     // HMAC de 4 bytes
    uint8_t  reserved[3]; // Relleno
} arm_packet_t;
```

## Tipos de Feromonas

| Tipo | Código | Descripción | Autenticación Requerida |
|------|------|-------------|---------------|
| HELLO | 0x01 | Latido | No |
| DATA | 0x02 | Información | No |
| ALARM | 0x03 | Alerta de peligro | No |
| ECHO | 0x04 | Acuse de recibo | No |
| QUEEN_CMD | 0x10 | Comando de Reina | **Sí** |
| MAZE_INIT | 0x70 | Iniciar exploración de laberinto | No |
| MAZE_MOVE | 0x71 | Movimiento de laberinto | No |
| MAZE_SOLVED | 0x73 | Laberinto resuelto | No |
| TERRAIN_INIT | 0x80 | Iniciar exploración de terreno | No |
| TERRAIN_REPORT | 0x81 | Descubrimiento de terreno | No |
| TERRAIN_THREAT | 0x82 | Amenaza detectada | No |
| REBIRTH | 0xFE | Muerte celular | **Sí** |
| DIE | 0xFF | Comando de muerte | **Sí** |

## Roles de Células

| Rol | Probabilidad | Latido | Comportamiento |
|------|-------------|-----------|----------|
| **TRABAJADOR** | ~75% | 1.0s | Procesar datos, retransmitir mensajes |
| **EXPLORADOR** | ~12.5% | 0.5s | Descubrimiento rápido, latidos frecuentes |
| **CENTINELA** | ~12.5% | 2.0s | Monitorear anomalías, registrar contactos |
| **REINA** | ~0.4% | 3.0s | Emitir comandos autenticados |

## Compilación y Ejecución

### Enjambre x86 QEMU
```bash
# Compilar ISO
make

# Ejecutar un solo nodo
make run

# Lanzar enjambre de 3 nodos
make swarm

# Lanzar enjambre de 5 nodos
make swarm5
```

### Enjambre ARM QEMU
```bash
# Compilar kernel ARM (requiere arm-none-eabi-gcc)
make arm

# Lanzar enjambre ARM de 3 nodos
make swarm-arm3

# Lanzar enjambre ARM de 5 nodos
make swarm-arm5
```

### ESP32 (PlatformIO)
```bash
cd platformio/nanos_swarm

# Compilar
pio run

# Cargar en ESP32
pio run -t upload

# Monitorear puerto serie
pio device monitor
```

## Panel Táctico

El panel basado en web proporciona control de enjambre en tiempo real:

```bash
# Iniciar panel (abre http://localhost:8080)
make dashboard
```

**Características:**
- Visualización de topología de red
- Vista de exploración de laberintos
- Exploración de terreno con niebla de guerra
- Inyección de enjambre x86 (Alarma, Elección, Amenazas)
- Control de enjambre ARM (Iniciar Laberinto, Iniciar Terreno, Matar)
- Registro de eventos y línea de tiempo de paquetes

### API del Panel

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/state` | GET | Estado actual del enjambre |
| `/api/maze/start` | POST | Iniciar laberinto x86 |
| `/api/terrain/start` | POST | Iniciar terreno x86 |
| `/api/arm/maze/start` | POST | Iniciar exploración de laberinto ARM |
| `/api/arm/terrain/start` | POST | Iniciar exploración de terreno ARM |
| `/api/arm/kill` | POST | Terminar nodos QEMU ARM |
| `/api/inject/alarm` | POST | Inyectar feromona de alarma |
| `/api/inject/election` | POST | Activar elección |

## Módulos ARM

El kernel ARM soporta sistemas de exploración modulares:

### Módulo de Laberinto (`maze_arm.c`)
- Búsqueda de ruta colaborativa
- Puntuación de dirección con rastros de feromonas
- Detección y compartición de muros
- Propagación de estado resuelto

### Módulo de Terreno (`terrain_arm.c`)
- Generación de terreno procedural
- Exploración con niebla de guerra
- Detección y reporte de amenazas
- Comandos de movimiento estratégico

Los módulos se activan mediante comandos del panel, no auto-inicio.

## Modelo de Memoria

### x86
- **Pila**: 16KB
- **Heap**: 64KB (apoptosis al 90%)
- **Buffers RX**: 64KB
- **Cola TX**: 2KB
- **Total**: ~150KB

### ARM Cortex-M3
- **Pila**: 4KB
- **Heap**: 16KB
- **Vecinos**: 512B
- **Total**: ~24KB

## Configuración de Red

### x86 QEMU
Usa NIC e1000 con multicast:
```
-netdev socket,id=net0,mcast=230.0.0.1:1234
-device e1000,netdev=net0,mac=52:54:00:XX:XX:XX
```

### ARM QEMU
Usa Stellaris Ethernet con socket multicast:
```
-net nic,macaddr=52:54:00:XX:XX:XX
-net socket,mcast=230.0.0.1:1234
```

## Seguridad (Sistema Inmunológico)

Los comandos críticos requieren:
1. **FLAG_AUTHENTICATED** bit establecido
2. **HMAC válido** con secreto compartido del enjambre
3. **Verificación de rol** (solo Reinas para DIE)

## Protocolo de Chisme

Previene tormentas de broadcast:
1. **Caché de Deduplicación**: Buffer circular de 32 entradas
2. **Ventana de Inmunidad**: Ignorar 500ms después de la primera vez visto
3. **Decaimiento Probabilístico**: Disminución del 20% por duplicado
4. **Eco Máximo**: Detenerse después de 5 copias

## Apoptosis

Las células mueren y renacen cuando:
- El heap excede el 90%
- La vida útil excede 1 hora

Al morir: emitir REBIRTH, reiniciar heap, nuevo ID, reasignar rol.

## Documentación Adicional

- [CONTRIBUTING.md](CONTRIBUTING.md) - Guía para contribuidores
- [ARCHITECTURE.md](ARCHITECTURE.md) - Arquitectura del sistema
- [API.md](API.md) - Documentación de API
- [CHANGELOG.md](CHANGELOG.md) - Historial de versiones
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Código de conducta

## Licencia

Dominio público. Úsalo, rómpelo, evoluciónalo.

---

*"En el enjambre, ninguna célula es especial. Cada célula es esencial."*
