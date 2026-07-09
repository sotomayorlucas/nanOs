# Diseño: Unificación del espacio de tipos de pheromones (micrOs ↔ nanOs)

**Fecha:** 2026-07-08
**Estado:** Aprobado (brainstorming) — en implementación
**Repos:** micrOs (Queen) + nanOs (workers). micrOs compila con `-I ../nanOs/include`.

## Objetivo

Unificar el espacio de tipos de pheromones del **protocolo cross-repo** en una
sola fuente de verdad, eliminar el hazard de include-order y las colisiones, y
hacer higiene del EtherType — sin renumerar el namespace privado interno de nanOs
ni tocar el path ARM.

## Estado actual (verificado, post 6 fases NERT)

- **Dato decisivo:** el path **NERT cifrado ya usa numeración consistente** entre
  micrOs y nanOs (la "isla NERT": ANNOUNCE 0x01, DIE 0x13, CONFIG 0x14, TELEMETRY
  0x15, TASK 0xA0-0xA3; el `nert_message_handler` de nanOs hardcodea esos hex).
  Como tareas y discovery viven sobre NERT, **el interop vivo ya está alineado.**
- **4 fuentes de verdad:** micrOs `include/distributed/nert_service.h`; nanOs
  `include/nanos.h`, `include/nanos/task_handler.h`, `lib/nert/nert_config.h`.
  micrOs además re-#define 0x14/0x15 en `genetic_tuning.h`.
- **Hazard de include-order (nanOs):** mismos NOMBRES, valores distintos —
  `nanos.h` vs `nert_config.h`: ELECTION 0x05/0x02, ALARM 0x03/0x11, ECHO
  0x04/0x00, DATA 0x02/0x10, DIE 0xFF/0x13. Un `.c` obtiene un valor u otro según
  qué header incluya.
- **DIE partido en nanOs:** raw 0xFF (nanos.h, halt role-gated) vs NERT 0x13
  (hardcodeado en nert_message_handler). micrOs DIE=0x13.
- **Mismatches latentes** (no cruzan hoy): ELECTION 0x05↔0x02, ALARM 0x03↔0x11,
  COMMAND 0x12 ↔ QUEEN_CMD 0x10. Solo romperían si esos tipos se enviaran
  cross-repo, cosa que hoy no pasa.
- **EtherType:** x86 usa `0x4F4E` en TX y RX y el RX **filtra** (funciona).
  Constantes stale a `0x4E4F` (micrOs `nert_service.h:33`, nanOs `e1000.h:115`),
  el valor se redefine en ~5 sitios x86, y ARM usa `0x4E52` (`nert.h:43` + HALs
  ARM) — ARM no está en el build x86.
- **Namespace privado de nanOs** (raw, no cruza): CORONATION 0x06, QUERY 0x07, KV
  0x20-0x22, SENSOR 0x40, JOB 0x50-0x54, DETECT 0x60-0x63, MAZE 0x70-0x74, TERRAIN
  0x80-0x87, STIGMERGIA 0x88, AIS/HWVAL 0x8A-0x8D, REBIRTH 0xFE. No colisiona con
  la isla NERT (0x00-0x03, 0x10-0x18, 0xA0-0xB0).

## Enfoque (aprobado): header canónico compartido, foco cross-repo

Una sola fuente para los tipos del protocolo que cruzan micrOs↔nanOs (valores de
la isla NERT, que el path cifrado ya usa). El namespace privado interno de nanOs y
el path ARM quedan intactos. No hay renumeración masiva.

### Componentes

**1. Nuevo header canónico `nanOs/include/nert_proto.h`** — única fuente de:
```c
#define PHEROMONE_ECHO            0x00
#define PHEROMONE_ANNOUNCE        0x01   /* == nanOs HELLO (presence beacon) */
#define PHEROMONE_ELECTION        0x02
#define PHEROMONE_REKEY           0x03
#define PHEROMONE_DATA            0x10
#define PHEROMONE_ALARM           0x11
#define PHEROMONE_COMMAND         0x12
#define PHEROMONE_DIE             0x13
#define PHEROMONE_CONFIG_UPDATE   0x14
#define PHEROMONE_TELEMETRY_REPORT 0x15
#define PHEROMONE_JUDAS_ENGAGE    0x16
#define PHEROMONE_JUDAS_CAPTURE   0x17
#define PHEROMONE_JUDAS_FORENSICS 0x18
#define PHEROMONE_TASK_ASSIGN     0xA0
#define PHEROMONE_TASK_RESULT     0xA1
#define PHEROMONE_TASK_STATUS     0xA2
#define PHEROMONE_TASK_CANCEL     0xA3
#define PHEROMONE_APP_BASE        0xB0
/* Higiene de wire (x86): un solo EtherType canónico */
#define NERT_ETH_TYPE_WIRE        0x4F4E
```
Idempotente (`#ifndef` guards por macro) para tolerar co-inclusión con headers
que aún definan algún nombre alineado.

**2. micrOs** — sin cambio de VALORES (su set ya == canónico):
- `include/distributed/nert_service.h`: `#include <nert_proto.h>`, borra los 18
  `PHEROMONE_*` y la constante stale `NERT_ETH_TYPE 0x4E4F` (usa
  `NERT_ETH_TYPE_WIRE`).
- `include/distributed/genetic_tuning.h`: borra el re-#define de 0x14/0x15.
- Sitios de EtherType x86 (`nert_service.c` #undef/redefine, `nert_hal_micros.c`)
  referencian `NERT_ETH_TYPE_WIRE`.

**3. nanOs:**
- `kernel/kernel.c` `nert_message_handler`: reemplaza los hex `0x01/0x13/0x14/0xA0`
  por los nombres canónicos (legibilidad; sin cambio de wire).
- `lib/nert/nert_config.h`: borra sus `PHEROMONE_*` divergentes → incluye el
  canónico. **Mata el hazard de include-order (3ª tabla).**
- `include/nanos.h`:
  - Tipos compartidos ALINEADOS (ANNOUNCE/HELLO 0x01, CONFIG 0x14, TELEMETRY 0x15,
    TASK 0xA0-0xA3): tomados del canónico (mismo valor). `PHEROMONE_HELLO` se
    mantiene como alias de `PHEROMONE_ANNOUNCE` (0x01) para no tocar el código raw.
  - Tipos PRIVADOS de nanOs que DIVERGEN (DATA 0x02, ALARM 0x03, ECHO 0x04,
    ELECTION 0x05): renombrados a `NANOS_RAW_DATA/ALARM/ECHO/ELECTION` con el
    **mismo valor** (wire raw interno intacto). Así el canónico y `nanos.h`
    coexisten en un `.c` sin colisión de macros. Los que no tengan uso vivo se
    eliminan en vez de renombrar.
  - **DIE:** nanOs pasa a reconocer el **DIE canónico 0x13** en el path raw
    (además del NERT que ya lo usa), quedando consistente con micrOs. El 0xFF
    nativo se mantiene como `NANOS_RAW_DIE` (deprecado) SOLO si hay algún emisor
    interno; si no, se elimina. 0x13 está libre en el raw de nanOs.
  - **QUEEN_CMD (0x10 → COMMAND 0x12):** el handler de comando-de-la-Queen de
    nanOs (Queen→worker, `process_pheromone` ~kernel.c:1454) migra al **COMMAND
    canónico 0x12**, resolviendo el mismatch latente 0x12↔0x10 (micrOs COMMAND
    0x12 hoy sin emisores). El slot 0x10 pasa a ser DATA canónico (sin uso
    cross-repo). Verificar que ningún emisor interno de nanOs use 0x10 antes de
    liberarlo; si lo hay, renombrar a `NANOS_RAW_*`.
- Sitios de EtherType x86: `include/drivers/e1000.h` (`ETH_TYPE_NANOS 0x4E4F` →
  `NERT_ETH_TYPE_WIRE`), `nert_hal_x86.c`, `task_handler.c`, `e1000_minimal.c`
  (0x4F4E hardcodeado) referencian `NERT_ETH_TYPE_WIRE`.
- Código raw que usaba los tipos renombrados (`process_pheromone` cases, emisores)
  → nombres `NANOS_RAW_*`.

**4. Fuera de alcance (intactos, documentados):**
- Namespace privado interno de nanOs (KV/SENSOR/JOB/DETECT/MAZE/TERRAIN/etc.).
- Path ARM: `nert.h:43 NERT_ETH_TYPE 0x4E52` + HALs ARM (nert_hal_arm/nrf52/stm32)
  — no se buildea/testea acá; divergencia cross-arch documentada (a reconciliar si
  se revive ARM). El `0x88B5` de micrOs (protocolo legacy propio) tampoco se toca.

## Testing

- **Build limpio de ambos repos** SIN warnings/errores de redefinición de macros
  (el objetivo del hazard). nanOs con `-Werror`.
- **KATs del RFC 8439 siguen verdes** en boot (cripto no afectada).
- **Interop e2e:** `task prime N` cierra e2e (0x01/0xA0/0xA1 canónicos sin cambio →
  sigue andando); worker estable, sin crashes.
- **Anti-hazard:** un `.c` que incluya el canónico Y `nanos.h` compila sin
  conflicto de macros (verifica la separación de namespace).
- **DIE:** verificar que nanOs raw acepta 0x13 (opcional: inyección) sin romper el
  0xFF si se mantiene.
- **micrOs:** confirmar que los valores emitidos/manejados no cambiaron (solo se
  dedup-earon las defs).

## Riesgos y mitigación

- **Renombrar tipos raw de nanOs** toca `process_pheromone` + emisores (superficie
  moderada). Mitigación: `grep` de cada macro renombrada, actualización
  consistente; el build `-Werror` caza cualquier omisión (identificador no
  declarado).
- **DIE 0xFF:** antes de eliminarlo, verificar que ningún emisor interno lo use;
  si lo usa, mantener `NANOS_RAW_DIE` como alias deprecado.
- **micrOs es solo-dedup** (valores idénticos) → riesgo bajo.
- El path cifrado (interop vivo) usa valores YA canónicos → el interop no cambia.

## Fuera de alcance (explícito)

- Renumeración del namespace interno de nanOs. Reconciliación del EtherType ARM.
  El bug funcional de CONFIG_UPDATE (mandado RAW y truncado 36→32B, sin handler
  raw en nanOs) es un problema de transporte/handler, no de numeración — se
  documenta como pendiente aparte (el valor 0x14 sí queda canónico).
