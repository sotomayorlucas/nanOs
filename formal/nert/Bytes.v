(* NERT formal model — base types. Bytes/words are modeled as nat (real bytes < 256);
   we only need concrete magic values and a payload bound for the properties. *)
From Stdlib Require Import Arith PeanoNat Lia.

Definition byte : Type := nat.

Definition NERT_MAGIC : byte := 78.   (* 0x4E — encrypted NERT frame *)
Definition RAW_MAGIC  : byte := 79.   (* 0x4F — raw NANO pheromone *)

Definition MAX_PAYLOAD : nat := 200.  (* NERT_MAX_PAYLOAD *)

Lemma magics_distinct : NERT_MAGIC <> RAW_MAGIC.
Proof. unfold NERT_MAGIC, RAW_MAGIC. discriminate. Qed.
