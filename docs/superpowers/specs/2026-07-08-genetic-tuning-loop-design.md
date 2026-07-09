# Diseño: Revivir el loop de sintonización genética sobre NERT

**Fecha:** 2026-07-08
**Estado:** Aprobado (brainstorming) — en planificación
**Repos:** micrOs (Queen) + nanOs (workers). micrOs compila con `-I ../nanOs/include`.
**Rama:** `genetic-loop` (ambos repos).

## Objetivo

Hacer funcionar de punta a punta el ciclo de sintonización genética del enjambre,
que hoy es **código muerto en ambos repos** (no compilado, no cableado): la Queen
distribuye genomas de configuración NERT a los workers vía `PHEROMONE_CONFIG_UPDATE`
(0x14), los workers los aplican y reportan telemetría de fitness vía
`PHEROMONE_TELEMETRY_REPORT` (0x15), y la Queen evoluciona la población. Todo el
tráfico viaja por **NERT cifrado** (no por el path crudo, que trunca a 32B).

El disparador original ("bug de transporte de CONFIG_UPDATE") resultó ser un
síntoma: el envío crudo trunca los 36B a 32B (pierde `sample_count`+`checksum`),
pero además nada del subsistema genético está compilado ni cableado. Este diseño
revive el feature completo.

## Estado actual (verificado directamente en el código)

### Compatibilidad ya resuelta (NO tocar)
- `struct nert_genome` — idéntico campo por campo en
  `micrOs/include/distributed/genetic_tuning.h:58` y
  `nanOs/include/nanos/genetic_config.h:35`. Packed, 32B, con
  `_Static_assert(sizeof==32)` en micrOs.
- `struct config_update_payload` — idéntico (command, sub_swarm_id,
  apply_delay_ms, genome) = **36B** en ambos.
- `struct telemetry_report_payload` — idéntico = **26B** en ambos.
- **CRC16** — `crc16_update` byte-idéntico en
  `micrOs/distributed/genetic/genetic_algorithm.c:21` y
  `nanOs/kernel/genetic_receiver.c:45` (poly 0x1021, init 0xFFFF, MSB-first).
  micrOs computa sobre `offsetof(struct nert_genome, checksum)` = 30B; nanOs sobre
  `sizeof(nert_genome) - sizeof(uint16_t)` = 30B → mismo rango. Los checksums
  cruzan correctamente.
- `CONFIG_CMD_APPLY/TEST/REVERT/REPORT` (0x01-0x04) y `GENETIC_GENOME_VERSION` (1)
  idénticos.
- Tipos de pheromone 0x14/0x15 canónicos (`nert_proto.h`).

### Lo que está roto / muerto
- **micrOs `distributed/genetic/*.c` NO está en el Makefile** (`COMMON_C_SRCS`,
  Makefile:131+). No se compila. `daemon_genetic_tuning` nunca corre; ningún
  comando lo dispara.
- **micrOs envío trunca:** los 3 sitios (`genetic_distribute_genome:164`,
  `genetic_request_telemetry:212`, `genetic_cmd_apply_best:401`) mandan
  `config_update_payload` (36B) vía `nert_service_send_pheromone` →
  `send_nanos_pheromone` (`nert_service.c:436`), que hace `if(len>32)len=32`
  (línea 462) → pierde `sample_count`+`checksum`. El `nanos_pheromone.payload`
  crudo es de solo 32B (`nanos.h:390`).
- **nanOs `kernel/genetic_receiver.c` NO está en el Makefile** (`C_SRC`,
  Makefile:37-46). No se compila. `genetic_process_config_update` /
  `genetic_config_init` / `genetic_config_tick` / `genetic_send_telemetry_report`
  tienen **cero callers**.
- **nanOs dispatch NERT 0x14** (`kernel.c:129`): stub `/* TODO */` que solo loguea.
- **nanOs handler existente incompatible:** `genetic_process_config_update` toma un
  `struct nanos_pheromone *pkt` crudo (lee `pkt->flags` para el rol, `pkt->payload`),
  pero la entrega NERT es `(sender_id, msg_type, data, len)`. Además:
  - guard muerto `if (sizeof(struct config_update_payload) > 32) return;`
    (línea 373) — 36 > 32 → siempre retorna.
  - llama setters con **firmas viejas**:
    `nert_rate_limit_configure(cap, refill, ms)` pero el actual es
    `nert_rate_limit_configure(const struct nert_rate_limit_config*)`
    (`nert.h:512`); `nert_blacklist_configure(warn, ban)` pero el actual es
    `nert_blacklist_configure(const struct nert_behavior_config*)` (`nert.h:577`).
  - externa `struct nert_stats* nert_get_stats()` pero el actual devuelve
    `const struct nert_stats*`; `heap_usage_percent()` externado `uint8_t` pero
    devuelve `size_t`.
  - externa `extern uint8_t tx_queue_count;` pero es `static uint8_t tx_queue_count`
    en `nert.c:123` → **no linkea**.
- **nanOs telemetría cruda:** `genetic_send_telemetry_report` usa
  `route_send(queen, 0x15, ...)` (`collective.c:603`), que arma un
  `nanos_pheromone` crudo y trunca a 32B → no llega al dispatch NERT de la Queen.

### Infraestructura disponible
- `nert_send_unreliable(uint16_t dest, uint8_t type, const void *data, uint8_t len)`
  existe en ambos repos (nanOs `nert.c:3302`, micrOs extern `nert_service.c:243`).
  36B entra (NERT_MAX_PAYLOAD 200; HAL caps 280/300). nanOs ya lo usa para HELLO.
- `daemon_nert` (`nert_service.c:688`) es el **loop probado** que corre el interop
  NERT (RX/TX/task-distributor/announce cada 5s). Punto de enganche del engine.
- El dispatch NERT de la Queen `micros_nert_rx_dispatch` (`nert_service.c:252`)
  reparte **todos** los tipos al registro de callbacks
  (`type==0xFF || type==msg_type`) → 0x15 llega a `genetic_telemetry_callback` si
  está registrado.
- `genetic_tick(state)` (`genetic_daemon.c:242`) ya orquesta todo (asigna
  sub-swarms, distribuye, pide telemetría, evoluciona) auto-rate-limitado por ticks.
- API de shell ya existe: `genetic_cmd_status/enable/mode/force_evolve`,
  `genetic_get_state`.
- Setters nanOs presentes: `nert_set_jitter_params` (`nert.c:1224`),
  `nert_rate_limit_configure` (1781), `nert_blacklist_configure` (2022),
  `nert_cover_set_mode` (2436), `nert_get_stats` (3634),
  `heap_usage_percent` (`allocator.c:33`).

## Enfoque (aprobado)

Resucitar el feature end-to-end sobre NERT cifrado, manejando el engine desde
`daemon_nert` (no un segundo daemon). No se toca structs ni checksum.

### Flujo del loop

```
Queen (daemon_nert)                          Worker (nanos_loop)
startup: genetic_init + register 0x15 cb + enable
cada iter: genetic_tick():
  · asigna sub-swarms (tabla de nodos NERT)
  · distribuye genoma   ──0x14 APPLY (NERT)──▶ nert_message_handler 0x14
                                                 → genetic_process_config_nert()
                                                   sender==known_queen? CRC16?
                                                   → genetic_apply_genome()
  · pide telemetría     ──0x14 REPORT (NERT)─▶ → genetic_send_telemetry_report()
  genetic_telemetry_cb ◀──0x15 (NERT)────────   (nert_send_unreliable)
  → genetic_process_telemetry → fitness
  · con muestras: genetic_evolve_generation → nueva población → repite
```

### Componentes

**A. Transporte (ambos repos)**
- micrOs: en `nert_service_send_pheromone` (o helper), rutear **0x14** por
  `nert_send_unreliable` (sin truncar); el resto de tipos sigue por el path crudo.
- micrOs distribución: `genetic_distribute_genome` manda **1 vez por sub-swarm**
  (multicast; el worker filtra por `sub_swarm_id`) en vez de 1 vez por nodo, para
  no disparar el rate-limit del worker.
- nanOs: `genetic_send_telemetry_report` usa `nert_send_unreliable(queen, 0x15, ...)`
  en vez de `route_send`.

**B. micrOs (Queen)**
- Agregar `distributed/genetic/genetic_daemon.c`, `genetic_algorithm.c`,
  `genetic_fitness.c` a `COMMON_C_SRCS` en el Makefile.
- En `daemon_nert`: antes del loop, `genetic_init(&g_genetic_state)` +
  `nert_service_register_callback(PHEROMONE_TELEMETRY_REPORT, genetic_telemetry_callback)`
  + `genetic_enable(&g_genetic_state, true)`; dentro del loop,
  `genetic_tick(&g_genetic_state)` cada iteración. (Se expone un pequeño API
  init/pump en genetic_daemon.c para no acoplar `g_genetic_state` a nert_service.c.)

**C. nanOs (worker)**
- Agregar `kernel/genetic_receiver.c` a `C_SRC` (build x86) en el Makefile.
- `genetic_config_init()` en el bring-up (junto a los otros `*_init` en `kmain`);
  `genetic_config_tick()` en `nanos_loop` (junto a `task_handler_tick`).
- Reemplazar el stub NERT 0x14 (`kernel.c:129`) por
  `genetic_process_config_nert(sender_id, data, len)`:
  - valida `len >= sizeof(struct config_update_payload)`,
  - verifica `sender_id == g_state.known_queen_id` (si `known_queen_id==0`, acepta
    — la auth NERT ya prueba pertenencia al enjambre; reemplaza el rol `pkt->flags`),
  - conserva rate-limit + filtro `sub_swarm_id` + CRC16 + switch de comando,
  - **elimina** el guard `sizeof>32`.
  - Se refactoriza el núcleo de `genetic_process_config_update` a una función que
    opere sobre `const struct config_update_payload*` para compartir lógica.
- Arreglar la API vieja en genetic_receiver.c para compilar/linkear con `-Werror`:
  - construir `struct nert_rate_limit_config` (bucket_capacity, refill_tokens,
    refill_interval_ms, + resto con defaults sanos) y pasarla a
    `nert_rate_limit_configure`;
  - construir `struct nert_behavior_config` (warn_threshold, ban_threshold, +
    resto con defaults) y pasarla a `nert_blacklist_configure`;
  - `nert_get_stats()` como `const struct nert_stats*`;
  - `heap_usage_percent()` como `size_t` (cast a `uint8_t` al reportar);
  - agregar accessor `uint8_t nert_get_tx_queue_count(void)` en `nert.c` y usarlo
    en vez del `extern` al símbolo `static`.

## Cadencia vs rate-limit (resuelto)

`genetic_tick` distribuye cada 10s (6/min) y pide telemetría cada 30s; el worker
limita a `CONFIG_RATE_LIMIT_COUNT=3` configs/min. Sobre multicast + 1 envío por
sub-swarm, un worker recibe ~6 APPLY/min + 2 REPORT/min → excede 3/min.
**Resolución:** subir `CONFIG_RATE_LIMIT_COUNT` del worker de 3 → **10** por minuto
(coherente con ~6 APPLY/min de la Queen con margen) y contar hacia el límite **solo
APPLY/TEST** (REPORT no reconfigura, no debe consumir cupo). El plan implementa
exactamente estos dos cambios en `genetic_process_config_nert` / `genetic_config.h`.

## Testing (QEMU 2 nodos, `-netdev socket,mcast=230.0.0.1:1234`)

- **Build limpio** de ambos repos (nanOs `-Werror`), sin errores de link.
- **KATs RFC 8439** verdes en boot (cripto no afectada).
- **Downlink e2e:** la Queen distribuye un genoma → el worker imprime
  `[GENETIC] Applied genome 0x… gen=N`, checksum válido, y cambian sus parámetros
  (jitter/rate observables por serial).
- **Uplink e2e:** ante `CONFIG_CMD_REPORT`, el worker manda 0x15 por NERT y la Queen
  loguea la telemetría / procesa fitness.
- **Loop:** juntadas `min_samples`, la Queen corre `genetic_evolve_generation`
  (nueva generación visible por serial).
- **Regresión:** `task prime N` sigue cerrando e2e (0xA0/0xA1 intactos); worker
  estable sin crashes.

## Riesgos y mitigación

- **genetic_receiver.c contra API vieja** → superficie de reparación real (setters,
  símbolo static, return types). Mitigación: `-Werror` caza cada mismatch; el plan
  lista cada arreglo con la firma exacta.
- **sub-swarm assignment sin targets:** `genetic_assign_sub_swarms` debe alimentarse
  de la tabla de nodos NERT (poblada por discovery Phase 4). Verificar en el plan
  que lee `nert_service_get_node_count/id`; si no descubre nodos, no hay a quién
  distribuir.
- **Segundo daemon que no corre:** evitado — el engine cuelga de `daemon_nert`
  (probado), no de `daemon_genetic_tuning` vía `process_create`.
- **Rate-limit vs cadencia:** resuelto arriba (subir límite del worker + contar solo
  APPLY/TEST).

## Fuera de alcance (explícito)

- Fix del scheduler general de micrOs (los daemons no corren solos; usamos
  `daemon_nert`). Ver [[swarmos-scheduler-blocker]].
- Path ARM (fuera del build x86).
- Reúso de nonce al reboot (I1, mitigado en Phase 6).
