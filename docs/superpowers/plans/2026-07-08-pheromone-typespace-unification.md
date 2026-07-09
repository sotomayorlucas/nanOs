# Pheromone Type-Space Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the 4 divergent pheromone-type sources into ONE canonical shared header for the cross-repo protocol, kill the include-order hazard + DIE split, and do EtherType hygiene — without renumbering nanOs's private raw namespace or touching ARM.

**Architecture:** New `nanOs/include/nert_proto.h` holds the canonical protocol types (NERT-island values, which the encrypted path on BOTH repos already uses) + the canonical x86 EtherType. micrOs and nanOs include it and drop their duplicate/divergent copies; nanOs's private raw types that collide are renamed `NANOS_RAW_*` (same values, wire unchanged). Verification is build-clean + RFC 8439 KATs + task interop (no framework; QEMU serial).

**Tech Stack:** C99 freestanding -m32; both repos build via `make`; micrOs compiles the shared tree with `-I ../nanOs/include`.

## Global Constraints

- Canonical protocol types (NERT-island; the encrypted path already uses these): ECHO 0x00, ANNOUNCE 0x01, ELECTION 0x02, REKEY 0x03, DATA 0x10, ALARM 0x11, COMMAND 0x12, DIE 0x13, CONFIG_UPDATE 0x14, TELEMETRY_REPORT 0x15, JUDAS_ENGAGE 0x16, JUDAS_CAPTURE 0x17, JUDAS_FORENSICS 0x18, TASK_ASSIGN 0xA0, TASK_RESULT 0xA1, TASK_STATUS 0xA2, TASK_CANCEL 0xA3, APP_BASE 0xB0.
- Canonical x86 EtherType: `NERT_ETH_TYPE_WIRE 0x4F4E`.
- micrOs pheromone VALUES do not change (its set already equals canonical) — this is dedup only.
- nanOs private raw divergent types keep their values, renamed: `PHEROMONE_DATA`0x02→`NANOS_RAW_DATA`, `PHEROMONE_ALARM`0x03→`NANOS_RAW_ALARM`, `PHEROMONE_ECHO`0x04→`NANOS_RAW_ECHO`, `PHEROMONE_ELECTION`0x05→`NANOS_RAW_ELECTION`. `PHEROMONE_HELLO`(0x01) becomes an alias of canonical `PHEROMONE_ANNOUNCE`.
- DIE canonical 0x13 recognized on nanOs raw path (in addition to the NERT path that already uses it); native 0xFF kept as `NANOS_RAW_DIE` only if an internal sender exists, else removed.
- QUEEN_CMD 0x10 → nanOs's queen-command handler migrates to canonical COMMAND 0x12 (resolves latent 0x12↔0x10; micrOs COMMAND has no senders today). Verify nothing internal still sends 0x10 before freeing it.
- Leave untouched: nanOs private namespace (CORONATION 0x06, QUERY 0x07, KV 0x20-0x22, legacy TASK 0x30/RESULT 0x31, SENSOR 0x40, JOB 0x50-0x54, DETECT 0x60-0x63, MAZE 0x70-0x74, TERRAIN 0x80-0x87, STIGMERGIA 0x88, AIS/HWVAL 0x8A-0x8D, REBIRTH 0xFE); the ARM path (`nanOs/include/nert.h:43 NERT_ETH_TYPE 0x4E52` + ARM HALs); micrOs `0x88B5` MICROS_ETHERTYPE.
- nanOs builds `-Werror -Wall -Wextra -Wno-unused-function -Wno-unused-but-set-variable`; micrOs no -Werror. No macro-redefinition warnings anywhere (the whole point).
- Test runner: `make` in each repo; nanOs KAT/interop via QEMU (sandbox DISABLED on the qemu Bash call). Recipes below.

---

## File Structure

- **Create** `nanOs/include/nert_proto.h` — canonical protocol types + `NERT_ETH_TYPE_WIRE`. One responsibility: the shared wire vocabulary. (T1)
- **Modify** micrOs `include/distributed/nert_service.h`, `include/distributed/genetic_tuning.h`, `distributed/nert/nert_service.c`, `distributed/nert/nert_hal_micros.c` — include canonical, drop dups, EtherType. (T2)
- **Modify** nanOs `include/nanos.h`, `include/nanos/task_handler.h`, `lib/nert/nert_config.h`, `kernel/kernel.c`, and every raw-path user of the renamed macros. (T3)
- **Modify** nanOs `include/drivers/e1000.h`, `kernel/protocol/nert_hal_x86.c`, `kernel/task_handler.c`, `drivers/e1000_minimal.c` — EtherType hygiene. (T4)

---

## Task 1: Canonical header `nert_proto.h`

**Files:** Create `nanOs/include/nert_proto.h`

**Interfaces:**
- Produces: the `PHEROMONE_*` macros (canonical values, Global Constraints) and `NERT_ETH_TYPE_WIRE 0x4F4E`.

- [ ] **Step 1: Create the header.**
```c
#ifndef NERT_PROTO_H
#define NERT_PROTO_H
/*
 * Canonical cross-repo pheromone protocol type space + wire EtherType.
 * SINGLE source of truth, shared by micrOs (Queen) and nanOs (workers). The
 * encrypted NERT path on both repos already dispatches with these values.
 * nanOs's private raw namespace (KV/SENSOR/TERRAIN/... and NANOS_RAW_*) is
 * separate and defined in nanos.h. Do not add nanOs-internal types here.
 */
#ifndef PHEROMONE_ECHO
#define PHEROMONE_ECHO             0x00
#endif
#ifndef PHEROMONE_ANNOUNCE
#define PHEROMONE_ANNOUNCE         0x01   /* presence beacon; nanOs HELLO == this */
#endif
#ifndef PHEROMONE_ELECTION
#define PHEROMONE_ELECTION         0x02
#endif
#ifndef PHEROMONE_REKEY
#define PHEROMONE_REKEY            0x03
#endif
#ifndef PHEROMONE_DATA
#define PHEROMONE_DATA             0x10
#endif
#ifndef PHEROMONE_ALARM
#define PHEROMONE_ALARM            0x11
#endif
#ifndef PHEROMONE_COMMAND
#define PHEROMONE_COMMAND          0x12
#endif
#ifndef PHEROMONE_DIE
#define PHEROMONE_DIE              0x13
#endif
#ifndef PHEROMONE_CONFIG_UPDATE
#define PHEROMONE_CONFIG_UPDATE    0x14
#endif
#ifndef PHEROMONE_TELEMETRY_REPORT
#define PHEROMONE_TELEMETRY_REPORT 0x15
#endif
#ifndef PHEROMONE_JUDAS_ENGAGE
#define PHEROMONE_JUDAS_ENGAGE     0x16
#endif
#ifndef PHEROMONE_JUDAS_CAPTURE
#define PHEROMONE_JUDAS_CAPTURE    0x17
#endif
#ifndef PHEROMONE_JUDAS_FORENSICS
#define PHEROMONE_JUDAS_FORENSICS  0x18
#endif
#ifndef PHEROMONE_TASK_ASSIGN
#define PHEROMONE_TASK_ASSIGN      0xA0
#endif
#ifndef PHEROMONE_TASK_RESULT
#define PHEROMONE_TASK_RESULT      0xA1
#endif
#ifndef PHEROMONE_TASK_STATUS
#define PHEROMONE_TASK_STATUS      0xA2
#endif
#ifndef PHEROMONE_TASK_CANCEL
#define PHEROMONE_TASK_CANCEL      0xA3
#endif
#ifndef PHEROMONE_APP_BASE
#define PHEROMONE_APP_BASE         0xB0
#endif
/* Canonical x86 wire EtherType (host reads it big-endian on the wire as 4F 4E). */
#ifndef NERT_ETH_TYPE_WIRE
#define NERT_ETH_TYPE_WIRE         0x4F4E
#endif
#endif /* NERT_PROTO_H */
```
The `#ifndef` per-macro guards let this co-exist with any header that still defines an ALIGNED name at the same value during the transition.

- [ ] **Step 2: Verify nanOs still builds (header is unused so far).**
Run: `cd /home/lkz/SwarmOS/nanOs && make 2>&1 | grep -iE "error|warning|\[OK\]"`
Expected: `[OK] Built nanos-x86.elf for x86`, no new warnings.

- [ ] **Step 3: Commit.**
```bash
cd /home/lkz/SwarmOS/nanOs && git add include/nert_proto.h
git commit -m "NERT: add canonical pheromone type + EtherType header (nert_proto.h)"
```

---

## Task 2: micrOs adopts the canonical header (dedup + EtherType)

**Files:**
- Modify: `micrOs/include/distributed/nert_service.h`, `micrOs/include/distributed/genetic_tuning.h`, `micrOs/distributed/nert/nert_service.c`, `micrOs/distributed/nert/nert_hal_micros.c`

**Interfaces:**
- Consumes: `nert_proto.h` (T1).

- [ ] **Step 1: Include canonical, drop micrOs's PHEROMONE_* defs.** In `nert_service.h`: add `#include <nert_proto.h>` near the top, and DELETE the 18 `#define PHEROMONE_*` lines (0x00-0xB0) it currently owns. Also delete its stale `#define NERT_ETH_TYPE 0x4E4F`. Keep everything else (structs, prototypes).

- [ ] **Step 2: Drop the genetic_tuning.h duplicate.** In `genetic_tuning.h`: delete its `#define PHEROMONE_CONFIG_UPDATE 0x14` and `#define PHEROMONE_TELEMETRY_REPORT 0x15` (they come from `nert_proto.h` via nert_service.h). If genetic_tuning.h is included without nert_service.h anywhere, add `#include <nert_proto.h>` there instead.

- [ ] **Step 3: Point the EtherType at the canonical constant.** In `nert_service.c`, the block that `#undef`s and redefines `NERT_ETH_TYPE` to `0x4F4E` (~line 27-28): replace the literal with `NERT_ETH_TYPE_WIRE` (from nert_proto.h, included via nert_service.h). In `nert_hal_micros.c`, change `#define NERT_ETH_TYPE_WIRE 0x4F4E` (line ~22) to `#include <nert_proto.h>` (drop the local define) OR leave the local (idempotent guard makes it harmless) — prefer including the canonical and removing the local literal.

- [ ] **Step 4: Build micrOs; confirm no value change and no redef warnings.**
Run: `cd /home/lkz/SwarmOS/micrOs && make 2>&1 | grep -iE "error|redefin|Build completado"`
Expected: `Build completado para x86: kernel.bin`, NO `redefinición`/`redefined` warnings, no errors.

- [ ] **Step 5: Commit.**
```bash
cd /home/lkz/SwarmOS/micrOs && git add include/distributed/nert_service.h include/distributed/genetic_tuning.h distributed/nert/nert_service.c distributed/nert/nert_hal_micros.c
git commit -m "NERT: micrOs sources pheromone types + EtherType from canonical nert_proto.h"
```

---

## Task 3: nanOs type unification (canonical adoption + namespace separation)

**Files:**
- Modify: `nanOs/include/nanos.h`, `nanOs/include/nanos/task_handler.h`, `nanOs/lib/nert/nert_config.h`, `nanOs/kernel/kernel.c`, and every raw-path user of the renamed macros (find via grep below).

**Interfaces:**
- Consumes: `nert_proto.h` (T1).
- Produces: `NANOS_RAW_DATA/ALARM/ECHO/ELECTION` (values 0x02/0x03/0x04/0x05); `PHEROMONE_HELLO` as alias of `PHEROMONE_ANNOUNCE`.

- [ ] **Step 1: Retire the third table.** In `lib/nert/nert_config.h`: DELETE its `#define PHEROMONE_ECHO/DATA/ALARM/ELECTION/DIE/...` block and add `#include <nert_proto.h>`. (Its values were already the NERT-island values, so this is value-neutral and removes the include-order hazard.)

- [ ] **Step 2: Canonicalize the task block.** In `include/nanos/task_handler.h`: replace its `#define PHEROMONE_TASK_ASSIGN 0xA0 .. TASK_CANCEL 0xA3` with `#include <nert_proto.h>` (same values). Keep the `struct task_payload`/`task_result_payload` etc.

- [ ] **Step 3: Separate namespaces in nanos.h.** In `include/nanos.h`:
  - Add `#include <nert_proto.h>` near the top.
  - DELETE the aligned defs that now come from canonical: `PHEROMONE_CONFIG_UPDATE 0x14`, `PHEROMONE_TELEMETRY_REPORT 0x15`, and `PHEROMONE_JUDAS_*` if present at 0x16-0x18.
  - Replace `#define PHEROMONE_HELLO 0x01` with `#define PHEROMONE_HELLO PHEROMONE_ANNOUNCE` (alias; value 0x01).
  - RENAME the divergent private types (keep values): `PHEROMONE_DATA 0x02`→`#define NANOS_RAW_DATA 0x02`; `PHEROMONE_ALARM 0x03`→`#define NANOS_RAW_ALARM 0x03`; `PHEROMONE_ECHO 0x04`→`#define NANOS_RAW_ECHO 0x04`; `PHEROMONE_ELECTION 0x05`→`#define NANOS_RAW_ELECTION 0x05`.
  - `PHEROMONE_QUEEN_CMD 0x10`: DELETE it (its handler migrates to canonical COMMAND 0x12 in Step 6). Do NOT keep 0x10 as a nanos name (0x10 is canonical DATA).
  - `PHEROMONE_DIE 0xFF`: rename to `#define NANOS_RAW_DIE 0xFF` (kept for the internal apoptosis path; the canonical `PHEROMONE_DIE` 0x13 comes from nert_proto.h).
  - Leave all other nanos.h private types unchanged (CORONATION 0x06, QUERY 0x07, KV, legacy TASK 0x30/RESULT 0x31, SENSOR, JOB, DETECT, MAZE, TERRAIN, STIGMERGIA, AIS, HWVAL, REBIRTH 0xFE).

- [ ] **Step 4: Find every raw-path user of the renamed macros.**
Run: `cd /home/lkz/SwarmOS/nanOs && grep -rn "PHEROMONE_DATA\|PHEROMONE_ALARM\|PHEROMONE_ECHO\|PHEROMONE_ELECTION\|PHEROMONE_QUEEN_CMD\|PHEROMONE_DIE\|PHEROMONE_HELLO" --include='*.c' --include='*.h' kernel/ lib/ include/`
For each hit in COMPILED code (kernel/, and lib/nert/nert_security.c; NOT the non-compiled lib/nert/{nert_auth,nert_batch,nert_buffer,crypto/entropy}.c — those already carry a "not compiled" NOTE): update `PHEROMONE_DATA→NANOS_RAW_DATA`, `PHEROMONE_ALARM→NANOS_RAW_ALARM`, `PHEROMONE_ECHO→NANOS_RAW_ECHO`, `PHEROMONE_ELECTION→NANOS_RAW_ELECTION`. `PHEROMONE_HELLO` stays valid (now an alias). Leave `PHEROMONE_CONFIG_UPDATE/TELEMETRY_REPORT/TASK_*` (canonical).

- [ ] **Step 5: NERT-path handler uses canonical names.** In `kernel/kernel.c` `nert_message_handler`, replace the hardcoded hex `case 0x01:`/`case 0x13:`/`case 0x14:`/`case 0xA0:` with `case PHEROMONE_ANNOUNCE:`/`case PHEROMONE_DIE:`/`case PHEROMONE_CONFIG_UPDATE:`/`case PHEROMONE_TASK_ASSIGN:` (same values; readability + single source). Add `#include <nert_proto.h>` if not already visible via nanos.h.

- [ ] **Step 6: DIE + QUEEN_CMD on the raw path (`process_pheromone`).**
  - DIE: the existing `case 0xFF:` (native DIE) — change to `case NANOS_RAW_DIE:` AND add `case PHEROMONE_DIE:` (0x13) with the same queen-authenticated halt handling (so nanOs raw accepts the canonical DIE from the Queen, consistent with its NERT path). If a single fallthrough is cleaner: `case NANOS_RAW_DIE: case PHEROMONE_DIE:`.
  - QUEEN_CMD: the existing queen-command `case 0x10:` (or `case PHEROMONE_QUEEN_CMD:`) — change to `case PHEROMONE_COMMAND:` (0x12). First confirm nothing in nanOs still SENDS 0x10: `grep -rn "PHEROMONE_QUEEN_CMD\|0x10" kernel/ | grep -i "send\|emit\|type ="` — if an internal sender exists, update it to `PHEROMONE_COMMAND` too.

- [ ] **Step 7: Build nanOs; confirm no macro-redef / undeclared-identifier.**
Run: `cd /home/lkz/SwarmOS/nanOs && make 2>&1 | grep -iE "error|redefin|undeclared|\[OK\]"`
Expected: `[OK] Built nanos-x86.elf`; NO `redefinición`/redefined, NO undeclared identifier (a miss in Step 4 shows here — fix and rebuild).

- [ ] **Step 8: Anti-hazard check.** Confirm a TU that includes both canonical and nanos.h compiles clean (kernel.c already does). Run: `grep -n "nert_proto.h\|nanos.h" kernel/kernel.c | head` and confirm the Step 7 build had zero macro warnings — that IS the co-include proof.

- [ ] **Step 9: Boot KAT + interop unaffected.** Build the ISO and boot one node (crypto KATs must still pass — types don't touch crypto):
```bash
cd /home/lkz/SwarmOS/nanOs && rm -rf iso_p3 && mkdir -p iso_p3/boot/grub && cp nanos-x86.elf iso_p3/boot/nanos.elf && printf 'set timeout=0\nset default=0\nmenuentry "NanOS" {\n    multiboot2 /boot/nanos.elf\n}\n' > iso_p3/boot/grub/grub.cfg && grub2-mkrescue -o nanos-x86.iso iso_p3 2>&1 | tail -1
cd /home/lkz/SwarmOS/nanOs && timeout 14 qemu-system-i386 -cdrom nanos-x86.iso -m 32M -serial file:/tmp/claude-1000/-home-lkz-SwarmOS/c87b13c5-38ce-42da-aebb-361c4c7f96da/scratchpad/ts-boot.log -display none ; grep -aE "KAT|ready" /tmp/claude-1000/-home-lkz-SwarmOS/c87b13c5-38ce-42da-aebb-361c4c7f96da/scratchpad/ts-boot.log
```
(QEMU Bash call: `dangerouslyDisableSandbox: true`.) Expect all `[KAT] ... OK` and `[BOOT] ... ready`.

- [ ] **Step 10: Commit.**
```bash
cd /home/lkz/SwarmOS/nanOs && git add include/nanos.h include/nanos/task_handler.h lib/nert/nert_config.h kernel/kernel.c $(git diff --name-only | tr '\n' ' ')
git commit -m "NERT: nanOs sources canonical pheromone types; rename divergent raw types NANOS_RAW_*; DIE 0x13 + COMMAND 0x12 on raw"
```
(Review `git status` before add; stage only source files you changed, not build artifacts.)

---

## Task 4: nanOs EtherType hygiene

**Files:**
- Modify: `nanOs/include/drivers/e1000.h`, `nanOs/kernel/protocol/nert_hal_x86.c`, `nanOs/kernel/task_handler.c`, `nanOs/drivers/e1000_minimal.c`

**Interfaces:**
- Consumes: `NERT_ETH_TYPE_WIRE` (T1).

- [ ] **Step 1: Fix the stale constant + reference the canonical.**
  - `include/drivers/e1000.h`: `#define ETH_TYPE_NANOS 0x4E4F` → `#define ETH_TYPE_NANOS NERT_ETH_TYPE_WIRE` (add `#include <nert_proto.h>` to e1000.h). This aligns the header with the real wire value (0x4F4E).
  - `kernel/protocol/nert_hal_x86.c`: the local `#define ETH_TYPE_NERT 0x4F4E` (or `NERT_ETH_TYPE 0x4F4E`) → use `NERT_ETH_TYPE_WIRE` (include nert_proto.h).
  - `kernel/task_handler.c`: the local `#define NERT_ETH_TYPE 0x4F4E` (line ~50) → `NERT_ETH_TYPE_WIRE`.
  - `drivers/e1000_minimal.c`: the hardcoded ethertype `0x4F4E` at the TX build site (~line 348) → `NERT_ETH_TYPE_WIRE` (include nert_proto.h). Keep the on-wire byte order identical (it already writes 0x4F then 0x4E).
  - Do NOT touch `include/nert.h:43 NERT_ETH_TYPE 0x4E52` or any ARM HAL — that is the (out-of-scope) ARM path.

- [ ] **Step 2: Build nanOs.**
Run: `cd /home/lkz/SwarmOS/nanOs && make 2>&1 | grep -iE "error|redefin|\[OK\]"`
Expected: `[OK] Built nanos-x86.elf`, no redef, no error.

- [ ] **Step 3: Interop still closes e2e** (EtherType value on the wire is unchanged — this is only constant hygiene; confirm nothing broke). Build both ISOs and run the task test:
```bash
cd /home/lkz/SwarmOS/nanOs && rm -rf iso_p3 && mkdir -p iso_p3/boot/grub && cp nanos-x86.elf iso_p3/boot/nanos.elf && printf 'set timeout=0\nset default=0\nmenuentry "NanOS" {\n    multiboot2 /boot/nanos.elf\n}\n' > iso_p3/boot/grub/grub.cfg && grub2-mkrescue -o nanos-x86.iso iso_p3 2>&1 | tail -1
cd /home/lkz/SwarmOS/micrOs && make 2>&1 | tail -1 && cp kernel.bin iso/boot/kernel.bin && grub2-mkrescue -o micros.iso iso 2>&1 | tail -1
bash /tmp/claude-1000/-home-lkz-SwarmOS/c87b13c5-38ce-42da-aebb-361c4c7f96da/scratchpad/p3.sh 2>&1 | grep -aE "completed|submitted="
```
(QEMU calls: `dangerouslyDisableSandbox: true`.) Expect `[TASK] Task 1 completed` and `completed=1`.

- [ ] **Step 4: Commit.**
```bash
cd /home/lkz/SwarmOS/nanOs && git add include/drivers/e1000.h kernel/protocol/nert_hal_x86.c kernel/task_handler.c drivers/e1000_minimal.c
git commit -m "NERT: nanOs EtherType hygiene — single NERT_ETH_TYPE_WIRE, fix stale 0x4E4F"
```

---

## Task 5: Integration verify + docs

**Files:** none (verification) + spec/plan docs.

- [ ] **Step 1: Clean builds, both repos, no macro-redef.**
```bash
cd /home/lkz/SwarmOS/nanOs && make clean >/dev/null 2>&1; make 2>&1 | grep -iE "error|redefin|redefined|\[OK\]"
cd /home/lkz/SwarmOS/micrOs && make clean >/dev/null 2>&1; make 2>&1 | grep -iE "error|redefin|redefined|Build completado"
```
Expected: nanOs `[OK]`, micrOs `Build completado`, ZERO redefinition lines.

- [ ] **Step 2: Sources-of-truth check.** Confirm the divergent duplicates are gone:
`grep -rn "define PHEROMONE_ELECTION\|define PHEROMONE_ALARM\|define PHEROMONE_DIE" /home/lkz/SwarmOS/micrOs /home/lkz/SwarmOS/nanOs --include='*.h'` → the ONLY hits are in `nanOs/include/nert_proto.h`. `NANOS_RAW_*` are defined once (nanos.h).

- [ ] **Step 3: Interop e2e** (already built in T4-S3, or rebuild): run `scratchpad/p3.sh`, expect `completed=1`, worker stable, 0 faults. Optionally `scratchpad/p4-2w.sh` (2 workers) — discovery over NERT still forms.

- [ ] **Step 4: Commit the design + plan docs.**
```bash
cd /home/lkz/SwarmOS/nanOs && git add docs/superpowers/specs/2026-07-08-pheromone-typespace-unification-design.md docs/superpowers/plans/2026-07-08-pheromone-typespace-unification.md
git commit -m "docs: pheromone type-space unification design + plan"
```

---

## Self-Review

- **Spec coverage:** canonical header (T1) ✓; retire 4 sources — micrOs dup (T2), nert_config.h + task_handler.h + nanos.h (T3) ✓; include-order hazard killed (T3-S1/S3, verified T3-S7/S8) ✓; NANOS_RAW_* rename (T3-S3/S4) ✓; DIE 0x13 on raw (T3-S6) ✓; QUEEN_CMD→COMMAND 0x12 (T3-S6) ✓; EtherType single constant + stale 0x4E4F fix, ARM untouched (T4) ✓; build-clean + KAT + interop (T3-S7/S9, T4, T5) ✓; nanOs private namespace + ARM out of scope (Global Constraints) ✓.
- **Placeholder scan:** the grep-driven "update each hit" steps name the EXACT old→new macro and the exact grep — actionable, not vague. The "confirm nothing sends 0x10 / keep 0xFF only if used" are explicit verify-then-act conditionals, not TODOs.
- **Type consistency:** `NERT_ETH_TYPE_WIRE`, `NANOS_RAW_DATA/ALARM/ECHO/ELECTION`, `NANOS_RAW_DIE`, `PHEROMONE_HELLO`(alias), and the canonical `PHEROMONE_*` names are used identically across T1-T5. micrOs values unchanged; nanOs raw values unchanged (renamed only); canonical DIE 0x13 / COMMAND 0x12 applied consistently on both nanOs paths.
