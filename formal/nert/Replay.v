(* Property C: replay protection via a sliding window (nert.c replay_bitmap_high/low,
   128-bit). THREAT_MODEL T4. Pure data-structure proofs, no crypto assumptions.

   Modeling note: acc keeps the full accept history rather than a bounded 128-bit
   bitmap; combined with the too_old gate this is a sound abstraction for the
   *safety* properties (no-double-accept, old-rejected, monotone) — it never
   accepts something the real bounded window would reject. The memory-boundedness
   of the real bitmap is not modeled. *)
From Stdlib Require Import List Arith PeanoNat Lia Bool.
Import ListNotations.

Definition WINDOW : nat := 128.

Record Win := mkWin { top : nat; acc : list nat }.
Definition w0 : Win := mkWin 0 [].

Definition too_old (w : Win) (s : nat) : bool := Nat.leb (s + WINDOW) (top w).
Definition seen   (w : Win) (s : nat) : bool := existsb (Nat.eqb s) (acc w).

Definition check_and_update (w : Win) (s : nat) : option Win :=
  if too_old w s then None
  else if seen w s then None
  else Some (mkWin (Nat.max (top w) s) (s :: acc w)).

(* Run the window over a list of incoming seqs; return final window + accepted list. *)
Fixpoint run (w : Win) (input : list nat) : Win * list nat :=
  match input with
  | [] => (w, [])
  | s :: rest =>
      match check_and_update w s with
      | Some w' => let '(wf, out) := run w' rest in (wf, s :: out)
      | None => run w rest
      end
  end.

(* C1: sequences below the window are rejected. *)
Theorem replay_old_rejected : forall w s,
  s + WINDOW <= top w -> check_and_update w s = None.
Proof.
  intros w s H. unfold check_and_update, too_old.
  replace (Nat.leb (s + WINDOW) (top w)) with true.
  - reflexivity.
  - symmetry. apply Nat.leb_le. exact H.
Qed.

(* helper: check_and_update never decreases top *)
Lemma cau_top_mono : forall w s w', check_and_update w s = Some w' -> top w <= top w'.
Proof.
  intros w s w' H. unfold check_and_update in H.
  destruct (too_old w s); [discriminate|].
  destruct (seen w s); [discriminate|].
  injection H as H. subst w'. simpl. lia.
Qed.

(* C2: top is monotone across a run. *)
Theorem replay_monotone : forall input w, top w <= top (fst (run w input)).
Proof.
  induction input as [|s rest IH]; intros w; simpl.
  - lia.
  - destruct (check_and_update w s) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl.
      pose proof (cau_top_mono w s w1 E) as Hm.
      specialize (IH w1). rewrite E2 in IH. simpl in IH.
      lia.
    + apply IH.
Qed.

(* helper: a successful check_and_update means s was not previously seen, and
   the new acc list is exactly s prepended to the old one. *)
Lemma cau_fresh : forall w s w',
  check_and_update w s = Some w' -> ~ In s (acc w) /\ acc w' = s :: acc w.
Proof.
  intros w s w' H. unfold check_and_update in H.
  destruct (too_old w s); [discriminate|].
  destruct (seen w s) eqn:Ese; [discriminate|].
  injection H as H. subst w'. split.
  - simpl. intro Hin.
    assert (Hs : seen w s = true).
    { unfold seen. apply existsb_exists. exists s.
      split; [exact Hin | apply Nat.eqb_eq; reflexivity]. }
    rewrite Hs in Ese. discriminate.
  - simpl. reflexivity.
Qed.

(* helper: a single check_and_update step only ever grows acc (as a set). *)
Lemma cau_acc_mono : forall w s w' x,
  check_and_update w s = Some w' -> In x (acc w) -> In x (acc w').
Proof.
  intros w s w' x H Hin.
  apply cau_fresh in H as [_ Hacc].
  rewrite Hacc. right. exact Hin.
Qed.

(* helper: acc only ever grows (as a set) across a whole run. *)
Lemma run_acc_mono : forall input w x,
  In x (acc w) -> In x (acc (fst (run w input))).
Proof.
  induction input as [|s rest IH]; intros w x Hin; simpl.
  - exact Hin.
  - destruct (check_and_update w s) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl.
      pose proof (cau_acc_mono w s w1 x E Hin) as Hin1.
      specialize (IH w1 x Hin1). rewrite E2 in IH. simpl in IH.
      exact IH.
    + apply IH; exact Hin.
Qed.

(* invariant: every accepted output is recorded in acc of the final window *)
Lemma run_out_in_acc : forall input w s,
  In s (snd (run w input)) -> In s (acc (fst (run w input))).
Proof.
  induction input as [|x rest IH]; intros w s Hin; simpl in *.
  - contradiction.
  - destruct (check_and_update w x) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl in *.
      destruct Hin as [Heq | Hin].
      * subst x.
        apply cau_fresh in E as [_ Hacc1].
        assert (Hin1 : In s (acc w1)) by (rewrite Hacc1; left; reflexivity).
        pose proof (run_acc_mono rest w1 s Hin1) as Hm.
        rewrite E2 in Hm. simpl in Hm. exact Hm.
      * specialize (IH w1 s). rewrite E2 in IH. simpl in IH. exact (IH Hin).
    + apply IH; auto.
Qed.

(* invariant: NoDup of the accumulator is preserved across a run. *)
Lemma run_acc_nodup : forall input w,
  NoDup (acc w) -> NoDup (acc (fst (run w input))).
Proof.
  induction input as [|x rest IH]; intros w Hnd; simpl.
  - exact Hnd.
  - destruct (check_and_update w x) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl.
      apply cau_fresh in E as [Hnotin Hacc1].
      assert (Hnd1 : NoDup (acc w1)) by (rewrite Hacc1; constructor; assumption).
      specialize (IH w1 Hnd1). rewrite E2 in IH. simpl in IH. exact IH.
    + apply IH; assumption.
Qed.

(* helper: once s is already accepted (recorded in acc), it can never be
   freshly accepted again later in the same run — check_and_update's
   freshness gate rejects it, and acc only grows (run_acc_mono), so s
   remains recorded at every later step. *)
Lemma run_acc_excludes_out : forall input w s,
  In s (acc w) -> ~ In s (snd (run w input)).
Proof.
  induction input as [|x rest IH]; intros w s Hin; simpl.
  - intro H; contradiction.
  - destruct (check_and_update w x) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl.
      intro Hcontra. destruct Hcontra as [Heq | Hcontra].
      * subst x.
        apply cau_fresh in E as [Hnotin _].
        contradiction.
      * apply cau_fresh in E as [_ Hacc1].
        assert (Hin1 : In s (acc w1)) by (rewrite Hacc1; right; exact Hin).
        specialize (IH w1 s Hin1). rewrite E2 in IH. simpl in IH.
        contradiction.
    + apply IH; exact Hin.
Qed.

(* strengthened invariant: NoDup of acc w propagates to NoDup of the freshly
   accepted output list, using run_acc_excludes_out for the "head not in
   tail" step and the induction hypothesis for the tail. *)
Lemma run_nodup_inv : forall input w,
  NoDup (acc w) -> NoDup (snd (run w input)).
Proof.
  induction input as [|x rest IH]; intros w Hnd; simpl.
  - constructor.
  - destruct (check_and_update w x) as [w1|] eqn:E.
    + destruct (run w1 rest) as [wf out] eqn:E2. simpl.
      apply cau_fresh in E as [Hnotin Hacc1].
      constructor.
      * assert (Hin1 : In x (acc w1)) by (rewrite Hacc1; left; reflexivity).
        pose proof (run_acc_excludes_out rest w1 x Hin1) as Hex.
        rewrite E2 in Hex. simpl in Hex. exact Hex.
      * assert (Hnd1 : NoDup (acc w1)) by (rewrite Hacc1; constructor; assumption).
        specialize (IH w1 Hnd1). rewrite E2 in IH. simpl in IH. exact IH.
    + apply IH; assumption.
Qed.

(* C3: over any input sequence, the accepted seqs contain no duplicates —
   each seq is accepted at most once. *)
Theorem replay_no_double_accept : forall input, NoDup (snd (run w0 input)).
Proof.
  intro input. apply run_nodup_inv. unfold w0. simpl. constructor.
Qed.
