# NanOS ESP32 - PlatformIO Build

## Quick Start

### 1. Instalar PlatformIO
```bash
# Con pip
pip install platformio

# O con VSCode extension "PlatformIO IDE"
```

### 2. Compilar
```bash
cd platformio
pio run
```

### 3. Flashear
```bash
# Conecta el ESP32 via USB
pio run -t upload
```

### 4. Monitor Serial
```bash
pio device monitor
```

### Todo junto:
```bash
pio run -t upload && pio device monitor
```

## Boards Soportados

| Ambiente | Board | Comando |
|----------|-------|---------|
| esp32dev | ESP32 DevKit | `pio run -e esp32dev` |
| esp32c3 | ESP32-C3 | `pio run -e esp32c3` |
| esp32s3 | ESP32-S3 | `pio run -e esp32s3` |
| lora32 | TTGO LoRa32 | `pio run -e lora32` |

## Output Esperado

```
========================================
  NanOS ESP32 - The Swarm Awakens
========================================
Node ID:   A1B2C3D4
Role:      WORKER
MAC:       24:6F:28:XX:XX:XX
Free heap: 280000 bytes
========================================

I (1234) NanOS: Node A1B2C3D4 [WORKER] neighbors=0 rx=0 tx=1
I (2234) NanOS: Node A1B2C3D4 [WORKER] neighbors=2 rx=5 tx=2
```

## Comandos Utiles

```bash
# Limpiar build
pio run -t clean

# Ver dispositivos conectados
pio device list

# Compilar para board especifico
pio run -e esp32c3

# Upload + monitor
pio run -e esp32dev -t upload && pio device monitor
```

## Troubleshooting

**Error: No device found**
- Verifica cable USB (debe ser datos, no solo carga)
- Instala drivers CH340/CP210x si es necesario
- En Linux: `sudo usermod -a -G dialout $USER`

**Error: Failed to connect**
- Mantén presionado BOOT mientras conectas
- Prueba otro puerto USB

**Sin output en monitor**
- Verifica baudrate: 115200
- Reset manual del ESP32
