# NERT formal model (Coq/Rocq 9.2)

Abstract model of the NERT protocol *design* (tier b — not the C in
`kernel/protocol/nert.c`). Proves 5 properties that map to real defects of this
project. Stdlib only; no external deps; no global axioms; no admits.

## Build
    make            # compiles + checks all proofs
    make audit      # (see below) prints assumptions of headline theorems

## Modules & theorems
| Module | Theorem | Formalizes | In nert.c / docs |
|--------|---------|-----------|------------------|
| Nonce.v | nonce_gen_injective | no (key,nonce) reuse within a boot | nonce_counter / ensure_nonce_seeded |
| Nonce.v | i1_reuse_reachable | blocker I1: reboot reset => reuse | nonce_counter reset; swarmos-nert-crypto-bugs |
| Nonce.v | entropy_seed_injective_unique | Phase-6 sufficient condition | nert_hal_random RDTSC mixing |
| Aead.v  | auth_soundness | verify => keyholder origin | poly1305_verify |
| Aead.v  | zero_key_forgeable / zero_key_unforgeable_fails | Phase-5 auth-bypass; key_is_zero guard necessary | key_is_zero() guard |
| Replay.v| replay_no_double_accept / _monotone / _old_rejected | sliding-window replay (T4) | replay_bitmap (64-bit, NERT_REPLAY_WINDOW_SIZE=64); THREAT_MODEL T4 |
| Demux.v | demux_total / demux_unambiguous | 0x4E vs 0x4F RX demux | kernel.c nanos_loop demux |
| Tlv.v   | reassemble_len / _bounded_max / _progress | fragment reassembly termination+bound | pack_messages_tlv (Phase-3 loop fix) |

## Assumptions / non-goals
- ASSUMED (not proven): Poly1305 unforgeability (Aead.v `mac_unforgeable`); `mac zero_key = zero_tag` (models real Poly1305-with-zero-key); nonce = node_id‖counter with reboot reset; 64-entry window.
- NON-GOALS: linking to the C implementation (tier c); bit-exact ChaCha20; timing/side-channels; concurrency/interrupts; the ARM path; probabilistic security of random nonce seeding (only a deterministic sufficient condition is proven).
