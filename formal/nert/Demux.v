(* Property D: the single RX ring is demultiplexed by the first payload byte
   (nert.c / kernel.c: 0x4E = encrypted NERT, 0x4F = raw NANO). Totality + no ambiguity. *)
From Stdlib Require Import Arith PeanoNat.
From NERT Require Import Bytes.

Inductive FrameKind := Nert | Raw | Drop.

Definition classify (b : byte) : FrameKind :=
  if Nat.eqb b NERT_MAGIC then Nert
  else if Nat.eqb b RAW_MAGIC then Raw
  else Drop.

Theorem demux_total : forall b, exists k, classify b = k.
Proof. intro b. eexists. reflexivity. Qed.

Theorem classify_nert : classify NERT_MAGIC = Nert.
Proof. unfold classify. rewrite Nat.eqb_refl. reflexivity. Qed.

Theorem classify_raw : classify RAW_MAGIC = Raw.
Proof.
  unfold classify.
  replace (Nat.eqb RAW_MAGIC NERT_MAGIC) with false.
  - rewrite Nat.eqb_refl. reflexivity.
  - symmetry. apply Nat.eqb_neq. intro H. apply magics_distinct. symmetry; exact H.
Qed.

Theorem demux_unambiguous :
  Nert <> Raw /\ classify NERT_MAGIC <> classify RAW_MAGIC.
Proof.
  split.
  - discriminate.
  - rewrite classify_nert, classify_raw. discriminate.
Qed.
