(* Property E: fragment reassembly terminates and is length-bounded. Models the FIXED
   reassembler: structural recursion consuming each fragment (list strictly shrinks),
   unlike the Phase-3 bug where the primary tx_queue entry was re-found -> no progress
   -> infinite loop. Structural recursion => Coq-checked termination by construction. *)
From Stdlib Require Import List Arith PeanoNat Lia.
Import ListNotations.
From NERT Require Import Bytes.

Record Frag := mkFrag { f_off : nat; f_data : list byte }.

Fixpoint reassemble (fs : list Frag) : list byte :=
  match fs with
  | [] => []
  | f :: rest => f_data f ++ reassemble rest
  end.

Definition total_len (fs : list Frag) : nat :=
  fold_right (fun f acc => length (f_data f) + acc) 0 fs.

(* E1: output length = sum of fragment lengths. *)
Theorem reassemble_len : forall fs, length (reassemble fs) = total_len fs.
Proof.
  induction fs as [|f rest IH]; simpl.
  - reflexivity.
  - rewrite length_app. rewrite IH. reflexivity.
Qed.

(* E2: bounded by MAX_PAYLOAD when the total is. *)
Theorem reassemble_bounded_max : forall fs,
  total_len fs <= MAX_PAYLOAD -> length (reassemble fs) <= MAX_PAYLOAD.
Proof. intros fs H. rewrite reassemble_len. exact H. Qed.

(* E3: consuming a fragment strictly decreases the remaining list (progress => the
   structural measure that guarantees termination). *)
Theorem reassemble_progress : forall (f : Frag) (rest : list Frag), length rest < length (f :: rest).
Proof. intros f rest. simpl. lia. Qed.
