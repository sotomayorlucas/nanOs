# Diseño: Modelo formal de NERT en Coq/Rocq

**Fecha:** 2026-07-08
**Estado:** Aprobado (brainstorming) — en planificación
**Repo:** nanOs (dueño del `kernel/protocol/nert.c` compartido). micrOs no se toca.
**Rama:** `formal-nert` (nanOs, sacada de `main`).

## Objetivo

Un modelo **abstracto pero estructuralmente fiel** del *diseño* del protocolo NERT en
Coq/Rocq 9.2, que prueba mecánicamente 5 propiedades de seguridad/corrección. Es una
contribución autocontenida al repo (compila y chequea en esta máquina, solo stdlib).

**Tier (b), explícito:** el modelo prueba el DISEÑO/protocolo, **no** el C
(`nert.c`). No se conecta a la implementación (eso sería tier (c), fuera de alcance).
El valor: las 5 propiedades mapean a defectos reales y documentados de este proyecto
(ver [[swarmos-nert-crypto-bugs]] y `docs/THREAT_MODEL.md` / `docs/RFC-NERT-001.txt`),
así que el modelo caracteriza esos bugs como teoremas, no como comentarios.

## Toolchain, ubicación y build

- **Rocq 9.2** (`coqc`/`rocq`, ya instalado), **solo stdlib** — sin dependencias
  externas, reproducible acá.
- **Imports:** forma canónica sin deprecación en Rocq 9.x = `From Stdlib Require Import
  <Mod>.` (verificado por smoke-test: `Coq.*` y el bare compilan pero warnean
  `deprecated-since-9.0`). Todo `.v` usa `From Stdlib Require Import`.
- **Ubicación:** `nanOs/formal/nert/` con:
  - `_CoqProject` (lista los `.v` + flags), `Makefile` (generado con
    `coq_makefile -f _CoqProject -o Makefile` / `rocq makefile`), `README.md`.
  - `.v` por módulo (abajo).
  - `README.md` mapea cada teorema a su lugar en `kernel/protocol/nert.c` y a la
    cláusula del RFC/THREAT_MODEL que formaliza.
- **Higiene de pruebas:** **sin `Axiom` globales.** Las primitivas cripto son
  `Parameter`/`Variable` dentro de `Section`; sus propiedades de seguridad son
  `Hypothesis`. Los teoremas finales quedan condicionados a esos supuestos y
  `Print Assumptions <thm>` exhibe la base de confianza honesta (los puros — C/D/E —
  cierran con "Closed under the global context"). **Prohibido `admit`/`Admitted`.**

## Módulos (una responsabilidad por archivo)

| Archivo | Modela | Propiedad |
|---|---|---|
| `Bytes.v` | tipos base: byte/word como `N`, helpers de listas, `MAX_PAYLOAD` | — (base) |
| `Nonce.v` | generador de nonce `(node_id ‖ counter)`, seed por-boot, reboot | **A** |
| `Aead.v` | MAC/AEAD abstracto, `key_is_zero`, supuesto de infalsificabilidad | **B** |
| `Replay.v` | ventana deslizante de 64 bits (`check_and_update`) | **C** |
| `Demux.v` | clasificador por primer byte (0x4E NERT / 0x4F raw) | **D** |
| `Tlv.v` | reensamblado de fragmentos length-prefixed | **E** |

Cada módulo es independiente salvo su `From Stdlib Require`/`Require Import Bytes`.
Ninguno depende de otro módulo de propiedad (A..E son ortogonales).

## Propiedades (enunciados concretos)

### A — `Nonce.v` (unicidad de nonce; blocker I1)
Modelo: `NonceState := { node_id : N; counter : N }`. `next_nonce` incrementa el
counter y emite `nonce := (node_id, counter)`. `reboot seed` reinicia el counter a
`seed`.
- `nonce_gen_injective`: dentro de un boot, `step ↦ nonce_emitido` es inyectiva
  (counter estrictamente creciente) ⇒ sin reúso de `(key, nonce)` bajo key fija.
- `i1_reuse_reachable`: si el seed post-reboot es **constante** (sin entropía),
  **∃** dos boots que emiten el mismo nonce bajo la misma key — o sea
  `~ nonces_globally_unique`. Formaliza I1 (reset de `nonce_counter` al reboot).
- `entropy_seed_injective_unique`: si los seeds por-boot son inyectivos entre boots
  (supuesto Phase 6), ⇒ unicidad global de nonce. *Honestamente condicional a la
  hipótesis de entropía.*

### B — `Aead.v` (soundness de autenticación; auth-bypass de Phase 5)
Modelo: `Parameter mac : Key -> Msg -> Tag`. `verify k m t := tag_eqb (mac k m) t`.
`key_is_zero k := key_eqb k zero_key`.
- `Hypothesis mac_unforgeable`: sin conocer `k` (y `k ≠ 0`), no se puede producir
  `(m,t)` con `verify k m t = true` salvo derivándolo de un emisor poseedor de la key.
  (Modelado sobre una traza: el conjunto de tags válidos observables proviene solo de
  `send` de key-holders.)
- `auth_soundness`: `verify k f = true ∧ ¬ key_is_zero k ∧ [mac_unforgeable] ⇒ f fue
  emitido por un poseedor de la PSK`.
- `zero_key_forgeable`: modelando `mac zero_key m = zero_tag ∀ m` (la realidad de
  Poly1305 con clave todo-ceros), un adversario **sin** PSK produce un frame con tag
  todo-ceros que verifica ⇒ **soundness falla si se permite key cero** ⇒ el guard
  `key_is_zero` es **necesario** (teorema, no comentario).

### C — `Replay.v` (ventana de replay; mitigación T4 documentada)
Modelo: `Window := { top : N; bits : list bool (* 64 offsets bajo top *) }`.
`check_and_update : Window -> N (*seq*) -> option Window` (None = replay/viejo
rechazado; Some W' = aceptado + actualizado). Pruebas **puras** (sin supuestos cripto).
- `replay_no_double_accept`: en cualquier corrida (fold de `check_and_update`), un
  `seq` dado se acepta **a lo sumo una vez**.
- `replay_monotone`: `top` es no-decreciente a lo largo de la corrida.
- `replay_old_rejected`: `seq + 64 ≤ top ⇒ check_and_update = None`.

### D — `Demux.v` (demux por primer byte)
Modelo: `classify : byte -> FrameKind` con `FrameKind := Nert | Raw | Drop`.
- `demux_total`: `classify` es total (función total sobre `byte`; todo frame recibe
  una clasificación).
- `demux_unambiguous`: `classify 0x4E = Nert`, `classify 0x4F = Raw`, `Nert ≠ Raw`, y
  ningún byte cae en dos clases (determinismo de la función). Modesto por diseño.

### E — `Tlv.v` (reensamblado TLV; loop infinito de Phase 3)
Modelo: fragmentos como lista `[(offset, len, data)]` length-prefixed;
`reassemble : list Frag -> option (list byte)` definida por recursión estructural /
bien fundada sobre una medida **decreciente** (consume la entrada — modela la versión
ARREGLADA que desactiva la entrada, no el loop de Phase 3).
- `reassemble_terminates`: la definición como `Fixpoint`/`Function` con medida
  decreciente ES la prueba de terminación (definibilidad en Coq ⇒ terminación).
- `reassemble_bounded`: `length (salida) ≤ Σ len ≤ MAX_PAYLOAD`.

## Fidelidad y supuestos (la base de confianza del modelo)

Documentados en el README y como `Hypothesis`/comentarios:
1. Poly1305 es un MAC infalsificable (`mac_unforgeable`) — se asume, no se prueba.
2. `mac zero_key · = zero_tag` — fiel al bug real (Poly1305 con r=s=0 da tag cero).
3. nonce = `node_id ‖ counter` (96 bits) y el reboot resetea el counter — fiel a
   `nert.c`.
4. La ventana de replay es de 64 posiciones (fiel a `replay_bitmap`, un único
   bitmap de 64 bits; `NERT_REPLAY_WINDOW_SIZE = 64`).
El modelo **abstrae** bytes/keystream de ChaCha20 y **no** cubre: el C, unforgeability
real de Poly1305, ChaCha20 bit-exacto, timing, concurrencia/interrupciones, ARM.

## Testing / criterio de "hecho"

- `make` (en `nanOs/formal/nert/`) compila TODO sin error (las pruebas chequean).
  Ausencia de `admit`/`Admitted` verificada por (1) `grep -rn "admit\|Admitted" *.v` = 0
  y (2) `Print Assumptions` de cada teorema cabeza (abajo) — que expondría cualquier
  axioma residual de un `Admitted`.
- `Print Assumptions` de cada teorema cabeza (A1-3, B1-2, C1-3, D1-2, E1-2) exhibe una
  base de confianza limpia: los puros (C/D/E) cierran bajo el contexto global; los
  cripto (A entropía, B) solo dependen de sus `Hypothesis` nombradas.
- Los dos contraejemplos (`i1_reuse_reachable`, `zero_key_forgeable`) son teoremas
  probados (negaciones), no admitidos.
- Warnings de deprecación de imports = 0 (se usa `From Stdlib Require Import`).

## Fuera de alcance (explícito)

Conexión con el C (tier c); unforgeability real de Poly1305; ChaCha20 bit-exacto;
timing/side-channels; concurrencia/interrupciones; el path ARM. Estos se documentan
como supuestos/no-goals, no se prueban.
