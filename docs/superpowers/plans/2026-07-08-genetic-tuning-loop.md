# Genetic Tuning Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Revive the swarm's genetic-tuning loop end-to-end over encrypted NERT: the micrOs Queen distributes NERT-config genomes to nanOs workers (CONFIG_UPDATE 0x14), workers apply them and report fitness telemetry (TELEMETRY_REPORT 0x15), and the Queen evolves the population.

**Architecture:** The genetic subsystem is dead code on both repos (uncompiled, unwired). We compile it on both sides, route CONFIG_UPDATE and TELEMETRY over encrypted NERT (`nert_send_unreliable`) instead of the raw 32B-truncating path, drive the Queen's engine from the already-running `daemon_nert` loop, and wire+repair the worker's `genetic_receiver.c` (stale API against the current NERT stack) so it actually applies genomes. Structs and the CRC16 checksum are already byte-compatible and are NOT touched.

**Tech Stack:** C (freestanding, x86-32 both kernels), GNU Make, QEMU (`qemu-system-i386`) with multicast socket networking, GRUB rescue ISO (`grub2-mkrescue` on Fedora).

## Global Constraints

- **No struct/checksum changes.** `struct nert_genome` (32B), `struct config_update_payload` (36B), `struct telemetry_report_payload` (26B) and the CRC16 (poly 0x1021, init 0xFFFF, over the first 30 bytes = `offsetof(nert_genome, checksum)`) are already identical across repos — do not modify them.
- **All genetic traffic rides encrypted NERT.** CONFIG_UPDATE (0x14) and TELEMETRY_REPORT (0x15) go via `nert_send_unreliable` (dest 0 = multicast broadcast), never the raw `send_nanos_pheromone` / `route_send` path (which caps payload to 32B and loses the genome checksum).
- **nanOs builds with `-Werror`** — every signature/type mismatch must be fixed, not silenced.
- **Do not touch the wire values** of any existing pheromone type; do not change task path (0xA0/0xA1) or discovery (0x01). `task prime N` must still close e2e.
- **Canonical pheromone types** come from `nanOs/include/nert_proto.h` (0x14 CONFIG_UPDATE, 0x15 TELEMETRY_REPORT) — already included by both repos.
- **Commit after each task.** Branch is `genetic-loop` on both repos. Do NOT push (the controller pushes only when the human asks).
- **QEMU runs require `dangerouslyDisableSandbox: true`** on the Bash call (the sandbox blocks multicast sockets); build the ISO with `grub2-mkrescue` (Fedora), and always rebuild the ISO before booting so changes aren't masked by a stale image.

---

## File Structure

**nanOs (worker):**
- `kernel/protocol/nert.c` — add 3 read-only accessors (`nert_get_tx_queue_count`, `nert_rate_limit_get_config`, `nert_blacklist_get_config`). [Task 1]
- `include/nert.h` — declare the 3 accessors. [Task 1]
- `kernel/genetic_receiver.c` — repair stale externs/calls; refactor config-apply core; add NERT entry point; telemetry over NERT; rate-limit bump. [Tasks 1, 2, 3]
- `include/nanos/genetic_config.h` — replace the raw handler declaration with the NERT one. [Task 2]
- `kernel/kernel.c` — wire NERT 0x14 dispatch → apply; `genetic_config_init()` at boot; `genetic_config_tick()` in loop. [Task 2]
- `Makefile` — add `kernel/genetic_receiver.c` to `C_SRC`. [Task 1]

**micrOs (Queen):**
- `Makefile` — add the three `distributed/genetic/*.c` to `COMMON_C_SRCS`. [Task 4]
- `distributed/nert/nert_service.c` — route 0x14 over NERT in `nert_service_send_pheromone`; start+pump the engine in `daemon_nert`. [Tasks 4, 5]
- `distributed/genetic/genetic_daemon.c` — distribute once per sub-swarm (multicast); add `genetic_engine_start()` / `genetic_engine_pump()`. [Tasks 4, 5]
- `include/distributed/genetic_tuning.h` — declare `genetic_engine_start` / `genetic_engine_pump`. [Task 5]

**Integration:** QEMU 2-node e2e. [Task 6]

---

### Task 1: nanOs — compile `genetic_receiver.c` and repair its stale NERT API

The worker's genetic receiver is not compiled and was written against an older NERT API (wrong setter signatures, a reference to a `static` symbol, wrong return types). Make it compile and link cleanly under `-Werror`, with the genome-apply path using the *current* config API via read-modify-write. This task does NOT wire it into dispatch yet (Task 2) — the deliverable is a clean build with the file compiled in.

**Files:**
- Modify: `nanOs/kernel/protocol/nert.c` (add accessors near the config statics, ~line 164 / 191, and the getter for `tx_queue_count` near line 123)
- Modify: `nanOs/include/nert.h` (declare accessors near the other `nert_rate_limit_*` / `nert_get_stats` prototypes)
- Modify: `nanOs/kernel/genetic_receiver.c` (externs block ~lines 21-29; `genetic_apply_genome` setters ~lines 179-191; `genetic_collect_metrics` ~lines 267-320)
- Modify: `nanOs/Makefile` (line 46 — end of x86 `C_SRC`)

**Interfaces:**
- Produces (nert.c, declared in nert.h):
  - `uint8_t nert_get_tx_queue_count(void);`
  - `const struct nert_rate_limit_config *nert_rate_limit_get_config(void);`
  - `const struct nert_behavior_config *nert_blacklist_get_config(void);`
- Consumes (already present in nert.c): `void nert_rate_limit_configure(const struct nert_rate_limit_config *config);`, `void nert_blacklist_configure(const struct nert_behavior_config *config);`, `void nert_set_jitter_params(uint16_t, uint16_t);`, `void nert_cover_set_mode(uint8_t);`, `const struct nert_stats* nert_get_stats(void);`, `size_t heap_usage_percent(void);`.

- [ ] **Step 1: Add the three accessors to `nert.c`**

Add near the top of the rate-limit section (after the `rate_limit_config`/`behavior_config` statics, e.g. after line 191). `tx_queue_count` is the `static uint8_t` at line 123 — the accessor must live in this same translation unit so it can read it:

```c
/* Read-only accessors for the genetic tuning receiver (kernel/genetic_receiver.c),
 * which does read-modify-write on the live config and reports queue depth. */
uint8_t nert_get_tx_queue_count(void) {
    return tx_queue_count;
}

const struct nert_rate_limit_config *nert_rate_limit_get_config(void) {
    return &rate_limit_config;
}

const struct nert_behavior_config *nert_blacklist_get_config(void) {
    return &behavior_config;
}
```

- [ ] **Step 2: Declare the accessors in `nert.h`**

Add near the existing `nert_rate_limit_configure` / `nert_blacklist_configure` / `nert_get_stats` prototypes:

```c
uint8_t nert_get_tx_queue_count(void);
const struct nert_rate_limit_config *nert_rate_limit_get_config(void);
const struct nert_behavior_config *nert_blacklist_get_config(void);
```

- [ ] **Step 3: Fix the externs block in `genetic_receiver.c`**

Replace the current extern declarations (lines ~21-29) with the correct signatures. Remove `extern uint8_t tx_queue_count;` (it is `static` in nert.c and cannot be externed). The struct types (`nert_stats`, `nert_rate_limit_config`, `nert_behavior_config`) come from `../include/nert.h`, already `#include`d at the top of the file. Result:

```c
/* External NERT functions (signatures must match kernel/protocol/nert.c) */
extern const struct nert_stats* nert_get_stats(void);
extern void nert_set_jitter_params(uint16_t min_ms, uint16_t max_ms);
extern void nert_rate_limit_configure(const struct nert_rate_limit_config *config);
extern void nert_blacklist_configure(const struct nert_behavior_config *config);
extern void nert_cover_set_mode(uint8_t mode);
extern int route_send(uint32_t dest_id, uint8_t type, const uint8_t *data, uint8_t len);
extern size_t heap_usage_percent(void);
extern uint8_t nert_get_tx_queue_count(void);
extern const struct nert_rate_limit_config *nert_rate_limit_get_config(void);
extern const struct nert_behavior_config *nert_blacklist_get_config(void);
```

- [ ] **Step 4: Fix the setter calls in `genetic_apply_genome` (read-modify-write)**

Replace the broken jitter/rate/blacklist/cover block (lines ~178-191) with calls that build the current config structs, override only the genome-controlled fields, and write them back:

```c
    /* Apply jitter parameters */
    nert_set_jitter_params(genome->jitter_min_ms, genome->jitter_max_ms);

    /* Apply rate limiting: read current config, override genome-controlled genes. */
    struct nert_rate_limit_config rl = *nert_rate_limit_get_config();
    rl.bucket_capacity     = genome->rate_bucket_capacity;
    rl.refill_tokens       = genome->rate_refill_tokens;
    rl.refill_interval_ms  = genome->rate_refill_ms;
    nert_rate_limit_configure(&rl);

    /* Apply behavioral blacklist thresholds: read current config, override genes. */
    struct nert_behavior_config bh = *nert_blacklist_get_config();
    bh.warn_threshold = genome->reputation_warn;
    bh.ban_threshold  = genome->reputation_ban;
    nert_blacklist_configure(&bh);

    /* Apply cover traffic mode */
    nert_cover_set_mode(genome->cover_mode);
```

- [ ] **Step 5: Fix the return-type mismatches in `genetic_collect_metrics`**

In `genetic_collect_metrics` (lines ~267-320): the local `struct nert_stats *stats = nert_get_stats();` must become `const`, and the two symbols that changed:

Change the stats local:
```c
    const struct nert_stats *stats = nert_get_stats();
```

Change the resource-metrics lines (were `report->heap_usage_pct = heap_usage_percent();` and `report->queue_depth = tx_queue_count;`):
```c
    report->heap_usage_pct = (uint8_t)heap_usage_percent();
    report->queue_depth = nert_get_tx_queue_count();
```

- [ ] **Step 6: Add `genetic_receiver.c` to the nanOs Makefile**

In `nanOs/Makefile`, x86 `C_SRC` (ends at line 46 with `drivers/e1000_minimal.c arch/x86/hal_x86.c`), append the receiver. Change line 45-46 region so the list includes it, e.g. add after `kernel/task_handler.c \` (line 41):

```make
                kernel/task_handler.c \
                kernel/genetic_receiver.c \
```

- [ ] **Step 7: Build nanOs and verify it compiles clean**

Run: `make -C /home/lkz/SwarmOS/nanOs clean && make -C /home/lkz/SwarmOS/nanOs`
Expected: build succeeds with no errors and no warnings (`-Werror`); `nanos-x86.elf` (or the configured kernel) is produced. In particular, no "conflicting types", no "undefined reference to `tx_queue_count`", no "too many arguments to function `nert_rate_limit_configure`".

- [ ] **Step 8: Commit**

```bash
git -C /home/lkz/SwarmOS/nanOs add kernel/protocol/nert.c include/nert.h kernel/genetic_receiver.c Makefile
git -C /home/lkz/SwarmOS/nanOs commit -m "nanOs: compile genetic_receiver.c, repair stale NERT config API"
```

---

### Task 2: nanOs — NERT CONFIG_UPDATE handler + boot/loop wiring + rate-limit

Give the worker a NERT-shaped entry point for CONFIG_UPDATE, wire the dispatch stub to it, initialize/tick the subsystem, and reconcile the config rate-limit with the Queen's distribution cadence.

**Files:**
- Modify: `nanOs/kernel/genetic_receiver.c` (refactor `genetic_process_config_update`; add `genetic_process_config_nert`; bump `CONFIG_RATE_LIMIT_COUNT` at line 36; rate-limit only APPLY/TEST)
- Modify: `nanOs/include/nanos/genetic_config.h` (line 148 — replace the raw handler prototype)
- Modify: `nanOs/kernel/kernel.c` (add include; case at line 129; init after line 2000; tick after line 1788)

**Interfaces:**
- Consumes: `g_state.known_queen_id` (set by the ANNOUNCE handler, kernel.c:151); `struct config_update_payload` (genetic_config.h); `genetic_apply_genome`, `genetic_verify_genome`, `genetic_send_telemetry_report`, `genetic_revert_to_default` (genetic_receiver.c).
- Produces: `void genetic_process_config_nert(uint16_t sender_id, const void *data, uint8_t len);` — the NERT dispatch entry for 0x14.

- [ ] **Step 1: Bump the config rate-limit constant**

In `genetic_receiver.c` line 36, change the per-minute cap from 3 to 10 (the Queen distributes ~6 APPLY/min; give margin):

```c
#define CONFIG_RATE_LIMIT_COUNT     10      /* Max config APPLY/TEST per minute */
```

- [ ] **Step 2: Refactor the command core out of `genetic_process_config_update`**

Replace the whole `genetic_process_config_update(struct nanos_pheromone *pkt)` function (lines ~350-423) with a payload-based static core plus the new NERT entry point. The core keeps rate-limit (APPLY/TEST only), sub-swarm filter, CRC verify, and the command switch; it drops the dead `sizeof>32` guard and the `pkt->flags` role check (the NERT layer authenticates the sender; the caller verifies it is the Queen):

```c
/* Shared command core. sender_id is the authenticated NERT sender (or the raw
 * pheromone node_id). Applies rate-limit to reconfiguring commands only. */
static void genetic_apply_config_payload(uint16_t sender_id,
                                         const struct config_update_payload *payload) {
    /* Sub-swarm targeting (0 = all) */
    if (payload->sub_swarm_id != 0 &&
        payload->sub_swarm_id != g_genetic_worker.sub_swarm_id) {
        return;  /* Not for us */
    }

    /* Rate limiting applies only to reconfiguring commands (APPLY/TEST). REPORT and
     * REVERT do not reconfigure and must not consume the budget. */
    if (payload->command == CONFIG_CMD_APPLY || payload->command == CONFIG_CMD_TEST) {
        uint32_t now = ticks;
        if (now - g_genetic_worker.last_config_tick < (CONFIG_RATE_LIMIT_MS / 10)) {
            g_genetic_worker.config_count++;
            if (g_genetic_worker.config_count > CONFIG_RATE_LIMIT_COUNT) {
                serial_puts("[GENETIC] Rate limited - too many config updates\n");
                return;
            }
        } else {
            g_genetic_worker.last_config_tick = now;
            g_genetic_worker.config_count = 1;
        }
    }

    switch (payload->command) {
        case CONFIG_CMD_APPLY:
            if (!genetic_verify_genome(&payload->genome)) {
                serial_puts("[GENETIC] Invalid genome checksum\n");
                blackbox_record_event(EVENT_CORRUPTION, sender_id);
                return;
            }
            genetic_apply_genome(&payload->genome, payload->apply_delay_ms, false);
            break;

        case CONFIG_CMD_TEST:
            if (!genetic_verify_genome(&payload->genome)) {
                serial_puts("[GENETIC] Invalid genome checksum\n");
                blackbox_record_event(EVENT_CORRUPTION, sender_id);
                return;
            }
            genetic_apply_genome(&payload->genome, payload->apply_delay_ms, true);
            break;

        case CONFIG_CMD_REVERT:
            genetic_revert_to_default();
            break;

        case CONFIG_CMD_REPORT:
            genetic_send_telemetry_report();
            break;

        default:
            serial_puts("[GENETIC] Unknown command: ");
            serial_put_hex(payload->command);
            serial_puts("\n");
            break;
    }
}

/* NERT dispatch entry for PHEROMONE_CONFIG_UPDATE (0x14). The decrypted payload is
 * delivered as (sender_id, data, len) -- NOT a nanos_pheromone. */
void genetic_process_config_nert(uint16_t sender_id, const void *data, uint8_t len) {
    if (data == NULL || len < sizeof(struct config_update_payload)) {
        serial_puts("[GENETIC] Config payload too short\n");
        return;
    }

    /* Accept only from the known Queen. If we have not yet learned the Queen's id
     * (known_queen_id == 0), accept: NERT authentication already proves the sender
     * is a swarm member holding the PSK. */
    uint16_t queen = (uint16_t)g_state.known_queen_id;
    if (queen != 0 && sender_id != queen) {
        serial_puts("[GENETIC] Rejected config from non-Queen\n");
        blackbox_record_event(EVENT_BAD_MAC, sender_id);
        return;
    }

    genetic_apply_config_payload(sender_id, (const struct config_update_payload *)data);
}
```

- [ ] **Step 3: Update the header prototype**

In `nanOs/include/nanos/genetic_config.h`, replace the raw handler declaration (line 148) and its doc comment:

```c
/**
 * Process a received CONFIG_UPDATE (0x14) delivered over encrypted NERT.
 * Called from nert_message_handler.
 *
 * @param sender_id  Authenticated NERT sender id
 * @param data       Decrypted payload (expects struct config_update_payload)
 * @param len        Payload length in bytes
 */
void genetic_process_config_nert(uint16_t sender_id, const void *data, uint8_t len);
```

- [ ] **Step 4: Wire the NERT dispatch in `kernel.c`**

Add the include near the other `<nanos/...>` includes at the top of `kernel.c`:

```c
#include <nanos/genetic_config.h>
```

Replace the CONFIG_UPDATE stub (kernel.c:129-134) with:

```c
        case PHEROMONE_CONFIG_UPDATE:  /* Genetic config from Queen (over NERT) */
            genetic_process_config_nert(sender_id, data, len);
            break;
```

- [ ] **Step 5: Initialize and tick the subsystem**

In `kmain`, after `blackbox_init();` (line 2000), add:

```c
    /* v0.7: Initialize genetic-config receiver (applies Queen-evolved NERT params) */
    genetic_config_init();
```

In `nanos_loop`, inside the `if (g_nert_enabled) { ... }` block, after `task_handler_tick();` (line 1788), add:

```c
            /* v0.7: genetic test-mode timeout handling */
            genetic_config_tick();
```

- [ ] **Step 6: Build nanOs and verify clean compile**

Run: `make -C /home/lkz/SwarmOS/nanOs clean && make -C /home/lkz/SwarmOS/nanOs`
Expected: builds clean under `-Werror`; no "implicit declaration of genetic_process_config_nert", no unused-function warning for `genetic_apply_config_payload`.

- [ ] **Step 7: Boot single node and verify init marker + stability**

Run (sandbox off; single node is enough to confirm no crash and the init marker):
```bash
make -C /home/lkz/SwarmOS/nanOs nanos-x86.iso
timeout 12 qemu-system-i386 -cdrom /home/lkz/SwarmOS/nanOs/nanos-x86.iso -m 32M -serial stdio -display none 2>&1 | tee /tmp/gl_t2.log
```
Expected in `/tmp/gl_t2.log`: `[GENETIC] Config receiver initialized`, `[BOOT] ... ready`, and the 5 RFC 8439 KATs pass; no panic/reset loop. (If `nanos-x86.iso` target is unavailable, use `make -C /home/lkz/SwarmOS/nanOs swarm NODES=1` which builds the ISO and writes serial to `/tmp/nanos_node_1.log`, then `pkill qemu`.)

- [ ] **Step 8: Commit**

```bash
git -C /home/lkz/SwarmOS/nanOs add kernel/genetic_receiver.c include/nanos/genetic_config.h kernel/kernel.c
git -C /home/lkz/SwarmOS/nanOs commit -m "nanOs: NERT CONFIG_UPDATE handler + boot/loop wiring + rate-limit"
```

---

### Task 3: nanOs — telemetry uplink over encrypted NERT

The worker's telemetry reply currently uses `route_send` (raw, truncates to 32B, never reaches the Queen's NERT dispatch). Send it over NERT so `micros_nert_rx_dispatch` fans it to the Queen's telemetry callback.

**Files:**
- Modify: `nanOs/kernel/genetic_receiver.c` (`genetic_send_telemetry_report`, lines ~323-344; externs block)

**Interfaces:**
- Consumes: `int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type, const void *data, uint8_t len);` (declared in `nert.h`, already included).
- Produces: (behavioral) 0x15 frames now ride encrypted NERT.

- [ ] **Step 1: Switch the telemetry send to NERT**

In `genetic_send_telemetry_report`, replace the `route_send(...)` call (line ~334) with `nert_send_unreliable`. `sizeof(report)` is 26 bytes (fits the `uint8_t len`):

```c
    int result = nert_send_unreliable(queen_id, PHEROMONE_TELEMETRY_REPORT,
                                      &report, sizeof(report));
```

- [ ] **Step 2: Drop the now-unused `route_send` extern (if genetic_receiver.c no longer uses it)**

Search the file: `grep -n route_send nanOs/kernel/genetic_receiver.c`. If the only remaining reference is the `extern` line, remove that `extern` line to avoid a dead declaration. If `route_send` is still used elsewhere in the file, leave it.

- [ ] **Step 3: Build nanOs and verify clean compile**

Run: `make -C /home/lkz/SwarmOS/nanOs clean && make -C /home/lkz/SwarmOS/nanOs`
Expected: clean build under `-Werror`; no unused-declaration warning; no implicit declaration of `nert_send_unreliable`.

- [ ] **Step 4: Commit**

```bash
git -C /home/lkz/SwarmOS/nanOs add kernel/genetic_receiver.c
git -C /home/lkz/SwarmOS/nanOs commit -m "nanOs: send genetic telemetry (0x15) over encrypted NERT"
```

---

### Task 4: micrOs — compile genetic subsystem + CONFIG_UPDATE over NERT + multicast distribution

Compile the Queen's genetic engine, route CONFIG_UPDATE over encrypted NERT (untruncated), and distribute each genome once per sub-swarm (multicast) instead of once per node.

**Files:**
- Modify: `micrOs/Makefile` (`COMMON_C_SRCS`, after line 182 `distributed/tasks/task_distributor.c \`)
- Modify: `micrOs/distributed/nert/nert_service.c` (`nert_service_send_pheromone`, lines ~996-1000)
- Modify: `micrOs/distributed/genetic/genetic_daemon.c` (`genetic_distribute_genome`, lines ~145-181)

**Interfaces:**
- Consumes: `int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type, const void *data, uint8_t len);` (externed at nert_service.c:243); `PHEROMONE_CONFIG_UPDATE` (0x14, via nert_proto.h).
- Produces: (behavioral) `nert_service_send_pheromone` sends 0x14 encrypted; `genetic_distribute_genome` sends one multicast frame per sub-swarm.

- [ ] **Step 1: Add the genetic sources to the micrOs Makefile**

In `COMMON_C_SRCS`, after `distributed/tasks/task_distributor.c \` (line 182), add:

```make
    distributed/tasks/task_distributor.c \
    distributed/genetic/genetic_algorithm.c \
    distributed/genetic/genetic_fitness.c \
    distributed/genetic/genetic_daemon.c \
    userland/shell.c
```

(That is: insert the three genetic files between `task_distributor.c` and the existing `userland/shell.c` — do not duplicate `userland/shell.c`.)

- [ ] **Step 2: Route CONFIG_UPDATE over NERT in `nert_service_send_pheromone`**

Replace the body of `nert_service_send_pheromone` (lines ~996-1000) so 0x14 goes encrypted (untruncated); all other types keep the raw path:

```c
int nert_service_send_pheromone(uint16_t dest_id, uint8_t pheromone_type,
                                 const void *data, uint8_t len) {
    /* Genetic config (0x14) must ride encrypted NERT: the 36B config_update_payload
     * exceeds the 32B raw pheromone payload (send_nanos_pheromone truncates it and
     * drops the genome checksum). NERT carries it intact and reaches the worker's
     * genetic_process_config_nert handler. */
    if (pheromone_type == PHEROMONE_CONFIG_UPDATE) {
        return nert_send_unreliable(dest_id, pheromone_type, data, len);
    }
    /* Use native NanOS packet format for compatibility */
    return send_nanos_pheromone(dest_id, pheromone_type, data, len);
}
```

- [ ] **Step 3: Distribute once per sub-swarm (multicast)**

In `genetic_distribute_genome` (lines ~161-180), replace the per-node send loop with a single broadcast send (the worker self-filters by `sub_swarm_id`; NERT is multicast, so one frame reaches all workers and sending per-node just risks the worker rate-limit):

```c
    /* Send ONCE as a multicast broadcast (dest 0). Workers filter by sub_swarm_id
     * in the payload; NERT frames are multicast, so a per-node loop would send the
     * same frame N times. Return the number of nodes this sub-swarm targets. */
    int result = nert_service_send_pheromone(
        0,
        PHEROMONE_CONFIG_UPDATE,
        &payload,
        sizeof(payload)
    );

    if (result < 0) {
        terminal_writestring("[GENETIC] Failed to distribute sub-swarm 0x");
        terminal_print_hex(sub_swarm_id);
        terminal_writestring("\n");
        return -1;
    }

    return assign->node_count;
```

(Delete the old `int sent = 0; for (...) { ... } return sent;` block that this replaces. Keep the payload-preparation block above it — lines 153-159 — unchanged.)

- [ ] **Step 4: Build micrOs and verify clean compile**

Run: `make -C /home/lkz/SwarmOS/micrOs clean && make -C /home/lkz/SwarmOS/micrOs`
Expected: builds successfully; the genetic objects compile and link (no "undefined reference to `genetic_init`/`genetic_tick`/`genetic_calc_checksum`"); `nert_service.c` compiles with `PHEROMONE_CONFIG_UPDATE` resolved.

- [ ] **Step 5: Commit**

```bash
git -C /home/lkz/SwarmOS/micrOs add Makefile distributed/nert/nert_service.c distributed/genetic/genetic_daemon.c
git -C /home/lkz/SwarmOS/micrOs commit -m "micrOs: compile genetic engine, route CONFIG_UPDATE over NERT, multicast distribution"
```

---

### Task 5: micrOs — drive the genetic engine from `daemon_nert`

The engine must run. Instead of spawning `daemon_genetic_tuning` as a second process (the scheduler may never run it), initialize it once and pump `genetic_tick` from `daemon_nert` — the proven loop that already drives all NERT interop.

**Files:**
- Modify: `micrOs/distributed/genetic/genetic_daemon.c` (add `genetic_engine_start` / `genetic_engine_pump` near the daemon entry point, ~line 340)
- Modify: `micrOs/include/distributed/genetic_tuning.h` (declare the two functions near `daemon_genetic_tuning`, ~line 413)
- Modify: `micrOs/distributed/nert/nert_service.c` (`daemon_nert`: extern decls near line 244; start before the loop ~line 694; pump inside the loop near `task_distributor_pump()` ~line 735)

**Interfaces:**
- Consumes: `genetic_init`, `genetic_enable`, `genetic_tick`, `genetic_print_status`, `genetic_telemetry_callback` (all in genetic_daemon.c); `nert_service_register_callback` (externed in genetic_daemon.c:24); `PHEROMONE_TELEMETRY_REPORT` (0x15).
- Produces:
  - `void genetic_engine_start(void);` — init engine + register 0x15 callback + enable.
  - `void genetic_engine_pump(void);` — one `genetic_tick(&g_genetic_state)` step.

- [ ] **Step 1: Add the start/pump API to `genetic_daemon.c`**

`genetic_telemetry_callback` is `static` in genetic_daemon.c, so registration must happen from this file. Add after `daemon_genetic_tuning` (~line 340):

```c
/* Drive the engine from daemon_nert (the proven-running loop) instead of a
 * separate process. Call genetic_engine_start() once before the loop, then
 * genetic_engine_pump() each iteration; genetic_tick self-rate-limits by ticks. */
void genetic_engine_start(void) {
    terminal_writestring("[GENETIC] Engine start (driven by nert daemon)\n");
    genetic_init(&g_genetic_state);
    nert_service_register_callback(PHEROMONE_TELEMETRY_REPORT,
                                    genetic_telemetry_callback);
    genetic_enable(&g_genetic_state, true);
    genetic_print_status(&g_genetic_state);
}

void genetic_engine_pump(void) {
    genetic_tick(&g_genetic_state);
}
```

- [ ] **Step 2: Declare the two functions in `genetic_tuning.h`**

Near `void daemon_genetic_tuning(void);` (~line 413):

```c
/**
 * Start the genetic engine (init + register telemetry callback + enable).
 * Call once from the NERT daemon before its main loop.
 */
void genetic_engine_start(void);

/**
 * Advance the genetic engine one step. Call each NERT daemon iteration.
 */
void genetic_engine_pump(void);
```

- [ ] **Step 3: Extern-declare and call them in `daemon_nert`**

In `nert_service.c`, add near the other shared externs (after line 244):

```c
extern void genetic_engine_start(void);
extern void genetic_engine_pump(void);
```

In `daemon_nert`, immediately after the startup banner (`terminal_writestring("[NERT] Hive Bridge daemon started (native mode)\n");`, line 694) and BEFORE `while (g_swarm_state.running) {`:

```c
    /* v0.7: start the genetic tuning engine on this (proven-running) loop. */
    genetic_engine_start();
```

Inside the loop, after `task_distributor_pump();` (line 735):

```c
        /* v0.7: advance the genetic tuning engine (self-rate-limited by ticks). */
        genetic_engine_pump();
```

- [ ] **Step 4: Build micrOs and verify clean compile**

Run: `make -C /home/lkz/SwarmOS/micrOs clean && make -C /home/lkz/SwarmOS/micrOs`
Expected: clean build; no "undefined reference to `genetic_engine_start`/`genetic_engine_pump`".

- [ ] **Step 5: Boot the Queen alone and verify the engine initializes**

Run (sandbox off). The micrOs ISO is `micros.iso`, built by `make iso`:
```bash
make -C /home/lkz/SwarmOS/micrOs iso
timeout 12 qemu-system-i386 -cdrom /home/lkz/SwarmOS/micrOs/micros.iso -m 64M \
  -device e1000,netdev=n0,mac=52:54:00:12:34:50 \
  -netdev socket,id=n0,mcast=230.0.0.1:1234 \
  -serial stdio -display none 2>&1 | tee /tmp/gl_t5.log
```
Expected in the log: `[NERT] Hive Bridge daemon started`, `[GENETIC] Engine start (driven by nert daemon)`, and the genetic status banner; `[GENETIC] No nodes available for sub-swarm assignment` is EXPECTED here (no worker present) and must not crash. No panic/reset loop.

- [ ] **Step 6: Commit**

```bash
git -C /home/lkz/SwarmOS/micrOs add distributed/genetic/genetic_daemon.c include/distributed/genetic_tuning.h distributed/nert/nert_service.c
git -C /home/lkz/SwarmOS/micrOs commit -m "micrOs: drive genetic engine from daemon_nert (start + pump)"
```

---

### Task 6: Integration — 2-node QEMU end-to-end (downlink apply + uplink telemetry + regression)

Boot the Queen and a worker on the same multicast group and verify the full loop: the Queen discovers the worker, distributes a genome, the worker applies it, replies with telemetry, and the Queen processes fitness. Then confirm the task path still works (regression).

**Files:** none (verification task). Uses both built ISOs.

**Interfaces:** none.

- [ ] **Step 1: Build both ISOs (Fedora `grub2-mkrescue`)**

Rebuild fresh so no stale ISO masks the changes. nanOs ISO = `nanos-x86.iso`; micrOs ISO = `micros.iso` (target `iso`):
```bash
make -C /home/lkz/SwarmOS/nanOs clean && make -C /home/lkz/SwarmOS/nanOs nanos-x86.iso
make -C /home/lkz/SwarmOS/micrOs clean && make -C /home/lkz/SwarmOS/micrOs iso
```
If `grub-mkrescue` fails on Fedora, build the ISO with `grub2-mkrescue -o <iso> <iso-staging-dir>` (see each Makefile's iso target for the staging layout). Confirm both ISO files (`nanOs/nanos-x86.iso`, `micrOs/micros.iso`) exist and are newer than the sources.

- [ ] **Step 2: Launch Queen + worker on the multicast group (sandbox OFF)**

Run each QEMU in the background with serial to a log; do NOT combine with `pkill` in the same command line. Use `dangerouslyDisableSandbox: true`.
```bash
# Queen (micrOs)
qemu-system-i386 -cdrom /home/lkz/SwarmOS/micrOs/micros.iso -m 64M \
  -device e1000,netdev=n0,mac=52:54:00:12:34:50 \
  -netdev socket,id=n0,mcast=230.0.0.1:1234 \
  -serial file:/tmp/gl_queen.log -display none &
# Worker (nanOs)
qemu-system-i386 -cdrom /home/lkz/SwarmOS/nanOs/nanos-x86.iso -m 32M \
  -device e1000,netdev=n0,mac=52:54:00:00:00:01 \
  -netdev socket,id=n0,mcast=230.0.0.1:1234 \
  -serial file:/tmp/gl_worker.log -display none &
```
Let them run ~40-60s (enough for discovery + at least one distribution at the 10s cadence + one telemetry request at 30s), then stop: `pkill -f qemu-system-i386`.

- [ ] **Step 3: Verify downlink (genome applied on the worker)**

Run: `grep -nE "GENETIC|Applied genome|Invalid genome" /tmp/gl_worker.log`
Expected: `[GENETIC] Config receiver initialized`, then `[GENETIC] Applied genome 0x... gen=...`. There must be NO `[GENETIC] Invalid genome checksum` (that would mean truncation/corruption) and NO `[GENETIC] Payload too short`.

- [ ] **Step 4: Verify the Queen assigned sub-swarms and distributed**

Run: `grep -nE "GENETIC|Assigned|Distribut" /tmp/gl_queen.log`
Expected: `[GENETIC] Engine start...`, `[GENETIC] Assigned 1 nodes to 1 sub-swarms` (once the worker is discovered), and `[GENETIC] Distributing genomes...` / `Distributed to N nodes`.

- [ ] **Step 5: Verify uplink (telemetry received + fitness processed at the Queen)**

The Queen requests telemetry every 30s (CONFIG_CMD_REPORT); the worker replies with 0x15 over NERT.
Run: `grep -nE "Telemetry|telemetry|fitness|Waiting for samples" /tmp/gl_queen.log /tmp/gl_worker.log`
Expected: worker log shows `[GENETIC] Telemetry sent: fitness metrics for genome 0x...`; Queen log shows telemetry being processed (fitness aggregation / `Waiting for samples (N/...)` — proving reports reach `genetic_process_telemetry` and feed the evolution gate). N must be > 0 and increase across successive requests.

- [ ] **Step 6: Regression — task path still closes**

With both nodes still bootable, verify the existing task path is unaffected. If the Queen has an interactive shell in this harness, `task prime 7` should complete `result=1, 0 faults` as before; otherwise confirm from the logs that task assignment/result traffic (0xA0/0xA1) and discovery (0x01) still flow and neither kernel panics. Record the outcome (pass / how verified) explicitly.

- [ ] **Step 7: Record results (no commit needed)**

Summarize in the task report: downlink applied (genome id, generation), checksum valid, uplink telemetry received and fitness sample count incrementing, regression outcome, and any anomaly. This task makes no code changes.

---

## Notes / Known limitations (documented, not blockers)

- **Sub-swarm A/B testing needs worker-side `sub_swarm_id` assignment.** Workers default to `sub_swarm_id = 0` and there is no message to assign them a non-zero sub-swarm, so only genomes broadcast with `sub_swarm_id == 0` reach workers. With a single worker (sub-swarm 0), the loop closes. True multi-sub-swarm A/B testing is a follow-up.
- **Full generation evolution** requires `population_size * GENETIC_MIN_SAMPLES` telemetry samples (8 × 3 = 24). With one worker reporting every 30s this accrues over minutes; the integration test verifies the sample counter increments (loop closed) rather than waiting for a full generation. Forcing evolution (`genetic_cmd_force_evolve`) is available but not shell-wired here.
- **Autonomy still rides `daemon_nert`.** The general micrOs scheduler blocker is unchanged and out of scope; the engine runs because it is pumped from the one loop that runs. See [[swarmos-scheduler-blocker]].
