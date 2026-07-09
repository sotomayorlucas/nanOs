(* Property A: nonce uniqueness. A nonce is (node_id, counter). Under the fixed epoch
   the session key is constant, so reusing a nonce reuses (key,nonce) — catastrophic
   for the AEAD. nert.c derives the nonce from node_id and a per-boot counter that
   RESETS on reboot (blocker I1); Phase 6 mixes RDTSC entropy into the seed. *)
From Stdlib Require Import Arith PeanoNat Lia.

Record Nonce := mkNonce { n_node : nat; n_ctr : nat }.

(* Nonce emitted at step k of a boot whose counter starts at [seed], node fixed. *)
Definition nonce_at (node seed k : nat) : Nonce := mkNonce node (seed + k).

(* Across boots: boot b starts its counter at (seed_of b). *)
Definition nonce_multi (node : nat) (seed_of : nat -> nat) (b k : nat) : Nonce :=
  nonce_at node (seed_of b) k.

(* A1: within one boot, distinct steps -> distinct nonces. *)
Theorem nonce_gen_injective : forall node seed k1 k2,
  nonce_at node seed k1 = nonce_at node seed k2 -> k1 = k2.
Proof. intros node seed k1 k2 H. injection H as H. lia. Qed.

(* A2 (I1): constant seed => reuse is reachable across boots. *)
Theorem i1_reuse_reachable : forall node c,
  let seed_of := fun _ : nat => c in
  exists b1 k1 b2 k2,
    (b1, k1) <> (b2, k2) /\
    nonce_multi node seed_of b1 k1 = nonce_multi node seed_of b2 k2.
Proof.
  intros node c seed_of.
  exists 0, 0, 1, 0. split.
  - intro H. discriminate H.
  - unfold nonce_multi, nonce_at, seed_of. reflexivity.
Qed.

(* A3 (Phase-6 sufficient condition): if each boot uses < STEPS nonces and seeds are
   strictly increasing with gap >= STEPS, then (boot,step) -> nonce is injective.
   NOTE: real Phase-6 uses random entropy, which only makes collision improbable, not
   impossible; this theorem states a *deterministic sufficient* condition. *)
Definition well_separated (seed_of : nat -> nat) (STEPS : nat) : Prop :=
  forall b, seed_of b + STEPS <= seed_of (S b).

(* seeds are monotone-nondecreasing when well separated *)
Lemma ws_monotone : forall seed_of STEPS,
  well_separated seed_of STEPS ->
  forall a b, a <= b -> seed_of a <= seed_of b.
Proof.
  intros seed_of STEPS Hws a b Hab. induction Hab as [|b Hab IH].
  - lia.
  - specialize (Hws b). lia.
Qed.

Theorem entropy_seed_injective_unique :
  forall node seed_of STEPS,
    well_separated seed_of STEPS ->
    forall b1 k1 b2 k2,
      k1 < STEPS -> k2 < STEPS ->
      nonce_multi node seed_of b1 k1 = nonce_multi node seed_of b2 k2 ->
      b1 = b2 /\ k1 = k2.
Proof.
  intros node seed_of STEPS Hws b1 k1 b2 k2 Hk1 Hk2 Heq.
  unfold nonce_multi, nonce_at in Heq. injection Heq as Heq.
  (* Heq : seed_of b1 + k1 = seed_of b2 + k2 *)
  assert (b1 = b2).
  { destruct (Nat.lt_trichotomy b1 b2) as [Hlt|[Heqb|Hgt]].
    - (* b1 < b2 => seed_of b2 >= seed_of (S b1) >= seed_of b1 + STEPS; contradiction *)
      assert (S b1 <= b2) by lia.
      pose proof (ws_monotone seed_of STEPS Hws (S b1) b2 H) as Hm.
      specialize (Hws b1). lia.
    - assumption.
    - assert (S b2 <= b1) by lia.
      pose proof (ws_monotone seed_of STEPS Hws (S b2) b1 H) as Hm.
      specialize (Hws b2). lia. }
  subst b2. split; [reflexivity | lia].
Qed.
