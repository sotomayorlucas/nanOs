# Diseño: Reemplazar la cripto débil de NERT por ChaCha20-Poly1305 real (RFC 8439)

**Fecha:** 2026-07-08
**Estado:** Aprobado (brainstorming) — en implementación
**Repos:** micrOs (Queen) + nanOs (workers), acoplados; el core cripto vive en el
`nanOs/kernel/protocol/nert.c` compartido (micrOs lo compila como `nert_shared.o`).

## Objetivo

Reemplazar la cripto débil actual del canal NERT cifrado por **ChaCha20-Poly1305
real, byte-exacto según RFC 8439**, con self-tests contra los test vectors del RFC.

## Estado actual (verificado)

- **ChaCha8**: `chacha8_block` es un ChaCha correcto (constantes, quarterround,
  add-state, salida little-endian) salvo que hace **8 rounds** (4 double-rounds).
  Nonce de 12B, contador de 32 bits arrancando en 0. `chacha8_encrypt` es el
  stream cipher.
- **"Poly1305"**: NO es Poly1305. Es `acc = (acc*r)^s` por byte, truncado a 64
  bits, con r/s tomados directo de la key; produce tag de **8 bytes**
  (`NERT_MAC_SIZE=8`). Débil y falsificable (clave todo-ceros → tag todo-ceros).
- **Construcción AEAD**: cifra el payload con `session_key` (ChaCha8, counter 0) y
  "MAC" con la **misma** `session_key` directo (reúso de clave = inseguro). Tag de
  8B escrito en `payload+packed_len`; AAD = el header NERT de 20B.
- **Wire**: `[eth 14][NERT header 20][ciphertext padded a 64][tag 8]`.

## Enfoque (aprobado)

**AEAD RFC 8439 completo (byte-exacto)** con **ruptura limpia de wire** (sin
retrocompatibilidad; solo micrOs-x86 y nanOs-x86 hablan NERT y se reconstruyen
ambos). No se implementa soporte dual de formato.

## Arquitectura (capas aisladas, cada una con su KAT del RFC)

```
chacha20_block(key[8w], nonce[3w], counter) -> 64B                 [20 rounds]
chacha20_encrypt(key[32], nonce[12], counter_start, pt, len, ct)   [stream, counter inicial configurable]
poly1305_mac(otk[32], msg, msg_len, tag[16])                       [Poly1305 REAL 130-bit, 5x26-bit limbs]
poly1305_verify(otk[32], msg, msg_len, expected_tag[16]) -> 0/-1   [compare constante-en-tiempo]
nert_aead_encrypt(key[32], nonce[12], aad, aad_len, pt, pt_len, ct, tag[16])         [RFC 8439 seal]
nert_aead_decrypt(key[32], nonce[12], aad, aad_len, ct, ct_len, pt, tag[16]) -> 0/-1 [RFC 8439 open]
```

**AEAD seal (RFC 8439 §2.8):**
1. `otk = chacha20_block(key, nonce, counter=0)[0:32]`
2. `ct  = chacha20_encrypt(key, nonce, counter_start=1, pt)`
3. `mac_data = aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ le64(aad_len) ‖ le64(ct_len)`
4. `tag = poly1305_mac(otk, mac_data)`  (16 bytes)

**AEAD open:** recomputar `otk` y `tag`, comparar constante-en-tiempo contra el tag
recibido; si coincide, descifrar `ct` con `chacha20_encrypt(key,nonce,1,...)`.
Devuelve -1 sin descifrar si el tag no verifica. `pad16(x)` = ceros hasta múltiplo
de 16 (0 si ya es múltiplo).

La one-time-key deriva por mensaje del bloque 0 → **nunca se reutiliza la clave
Poly1305** (arregla el mal uso actual).

## Formato de wire (único cambio: tamaño del tag)

```
NERT payload: [ NERT header 20B (AAD) ][ ciphertext padded a bloques de 64 ][ TAG 16B ]
```
- `NERT_MAC_SIZE`: **8 → 16**. Propaga solo: tag en `payload+packed_len` (16B),
  `tag_ptr = raw+HEADER+payload_len` (16B), long. mínima `HEADER+1+MAC=37`, buffers
  `nert_packet.data[NERT_MAX_PAYLOAD+HEADER+MAC]` crecen +8. `auth.poly1305_tag[]`
  queda 16B pero sigue vestigial (no se usa en el cable).
- **Nonce 12B sin cambios**: `build_nonce(node_id, counter)` — único por clave
  (node_id distinto entre nodos, counter monótono por nodo). El AEAD usa counter 0
  (OTK) y 1+ (ciphertext).
- **AAD = header NERT de 20B** (como hoy).
- Tamaño: +8B/frame. Tarea 32B → 64+20+16 = 100B payload NERT + 14 eth = 114B; bajo
  los topes del HAL (nanOs 280 / micrOs 300) y e1000 (2048).

## Refactor de call-sites (dejan de manejar la clave Poly1305 a mano)

- `build_and_send` (TX tarea/announce): `chacha8_encrypt`+`poly1305_mac` →
  `nert_aead_encrypt(session_key, nonce, header, HEADER, plaintext, packed_len, pkt.payload, tag)`.
- `handle_received_packet` (RX): la cadena de gracia de 3 claves
  (session/prev/next + guard `key_is_zero`) prueba cada candidato con
  `nert_aead_decrypt`; se elimina el `chacha8_encrypt` de descifrado separado.
- Respuesta SYN+ACK: `nert_aead_encrypt`.
- `derive_key_for_epoch` (KDF de época): pasa a `chacha20_encrypt` como PRF (no es
  AEAD; sin Poly1305).

## Testing

**1. Known-Answer Tests RFC 8439 en `nert_crypto_self_test` (boot):** reemplazan el
self-test roto actual.
- ChaCha20 block — §2.3.2 (keystream de 64B).
- ChaCha20 encrypt — §2.4.2 (plaintext "sunscreen").
- Poly1305 — §2.5.2 (otk 32B + msg → tag 16B).
- AEAD seal — §2.8.2 (key, nonce, AAD, pt → ct + tag conocidos).
- AEAD open — descifrar §2.8.2 → recuperar pt; **+ tamper**: flipear 1 byte del ct
  → verify falla.
Si alguno falla, loguear/haltar como el self-test actual.

**2. Interop e2e en QEMU:** micrOs Queen + worker(s) nanOs reconstruidos;
`task prime N` cierra e2e (cifra en un lado, descifra+verifica en el otro con el
wire de tag 16B) y el descubrimiento sobre NERT sigue estable, sin crashes.

**3. Revisión adversarial (workflow) del diff antes de commitear:** cripto crítica
⇒ verificar sin reúso de OTK, verify constante-en-tiempo, rechazo de frames
forjados (MAC todo-ceros / byte flipeado → falsificación ~2⁻¹²⁸ con Poly1305 real),
y que ningún call-site quede en la ruta vieja.

## Alcance

**En alcance (se compila para x86 y/o micrOs):**
- `nanOs/include/nert.h`: `NERT_MAC_SIZE` 8→16; rounds 20; decls AEAD.
- `nanOs/kernel/protocol/nert.c`: primitivas + AEAD + refactor call-sites + KDF +
  self-tests.
- `nanOs/lib/nert/nert_security.c` + `nert_security.h`: **se compila** (rekey
  manual, inactivo en runtime) — rename a chacha20 + adaptar a tag 16B / firmas
  nuevas para que compile.
- `micrOs/distributed/nert/nert_hal_micros.c`: round-trip `chacha8_encrypt` →
  `chacha20_encrypt`.

**Fuera de alcance:**
- `nanOs/lib/nert/{nert_auth,nert_batch,nert_buffer,crypto/entropy}.c`: llaman las
  primitivas pero **NO están en los SRCS del build x86**. Quedan con refs viejas;
  marcados para actualizar si se revive algún target que los compile. (YAGNI para
  el objetivo QEMU x86.)
- `micrOs/kernel/crypto/chacha20.c`: cripto interna de micrOs, ajena al NERT
  compartido.
- Derivación de nonce, época/PSK (Phase 5), espacio de tipos, HALs ARM/ESP32.

## Limitaciones conocidas (documentadas)

- **Reúso de nonce (I1) — MITIGADO en Phase 6, con residual documentado:**
  con época fija (Phase 5) la session key es estable; antes el `nonce_counter`
  arrancaba de un valor casi determinístico por boot (RNG sembrado con
  `ticks~0 ^ DEADBEEF ^ &var` sin ASLR) → reboots reutilizaban pares `(key,
  nonce)`, catastrófico para una AEAD real (fuga de keystream + reúso de la OTK de
  Poly1305 → falsificación). **Phase 6** siembra el `nonce_counter` de forma
  diferida (al primer TX) mezclando la mejor entropía disponible: RDTSC (HALs
  x86), un acumulador de entropía de RX (bytes de frame + tick de llegada, que
  varían por boot en el swarm mcast), y el reloj de ticks. El counter se sigue
  transmitiendo → sin impacto de wire, el receptor reconstruye el nonce igual.
  **Residual:** es un fix REAL en hardware con TSC corriendo; bajo un replay 100%
  determinístico (mismo VM, misma secuencia) sigue siendo best-effort — la
  unicidad *garantizada* necesita persistencia del counter (no hay en un nodo
  desechable) o entropía real. También queda el wrap del counter de 32 bits tras
  2³² mensajes (inalcanzable en el demo).
- Los archivos `lib/nert/*` no compilados quedan inconsistentes hasta que se
  revivan sus targets.
- El self-test de cripto (KATs) loguea pero **no halta** el boot ante fallo (M1);
  considerar panic-on-fail para no correr con cripto rota.

## Riesgos y mitigación

- Poly1305 de 130 bits es la parte delicada: se valida contra el KAT §2.5.2 y el
  AEAD §2.8.2 antes de cualquier interop.
- La ruptura de wire es total: se reconstruyen y prueban ambos lados juntos.
- Cripto crítica: revisión adversarial con workflow antes de commit (como en Phase
  5, que cazó un auth-bypass real).
