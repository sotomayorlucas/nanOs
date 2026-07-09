(* Property B: authentication soundness, and why the key_is_zero guard is necessary.
   AEAD/MAC modeled abstractly inside a Section: primitives are Variables, security is a
   Hypothesis (no global Axiom). Ties to the Phase-5 auth-bypass: an all-zero Poly1305
   key produces an all-zero tag, so a forged all-zero-MAC frame verifies unless the
   receiver rejects zero keys (the key_is_zero() guard). *)
From Stdlib Require Import List.
Import ListNotations.

Section Aead.
  Variable Key Msg Tag : Type.
  Variable key_eqb : Key -> Key -> bool.
  Variable tag_eqb : Tag -> Tag -> bool.
  Variable zero_key : Key.
  Variable zero_tag : Tag.
  Variable mac : Key -> Msg -> Tag.

  Hypothesis tag_eqb_true : forall a b, tag_eqb a b = true <-> a = b.

  Definition verify (k : Key) (m : Msg) (t : Tag) : bool := tag_eqb (mac k m) t.
  Definition key_is_zero (k : Key) : bool := key_eqb k zero_key.

  (* The swarm PSK, and the trace of frames legitimately produced by keyholders. *)
  Variable psk : Key.
  Variable legit : list (Msg * Tag).
  Hypothesis legit_correct : forall m t, In (m, t) legit -> t = mac psk m.

  (* Symbolic (Dolev-Yao) unforgeability: a tag that verifies under the PSK must have
     been produced by a keyholder (i.e., appears in [legit]). This is THE crypto
     assumption; it is not proven. *)
  Hypothesis mac_unforgeable :
    forall m t, verify psk m t = true -> In (m, t) legit.

  (* B1: soundness — verifying under the (non-zero) PSK implies keyholder origin. *)
  Theorem auth_soundness : forall m t,
    verify psk m t = true -> In (m, t) legit /\ t = mac psk m.
  Proof.
    intros m t Hv. split.
    - apply mac_unforgeable; exact Hv.
    - apply legit_correct, mac_unforgeable; exact Hv.
  Qed.

  (* Model the real zero-key behavior: Poly1305 with r=s=0 yields the zero tag. *)
  Hypothesis mac_zero : forall m, mac zero_key m = zero_tag.

  (* B2: with the zero key, ANY message's zero tag verifies — forgeable, no keyholder. *)
  Theorem zero_key_forgeable : forall m, verify zero_key m zero_tag = true.
  Proof. intro m. unfold verify. rewrite mac_zero. apply tag_eqb_true. reflexivity. Qed.

  (* B3: hence unforgeability is FALSE for the zero key (empty legit) — the guard is
     necessary. A genuine refutation, not a comment. *)
  Theorem zero_key_unforgeable_fails : forall m,
    ~ (forall t, verify zero_key m t = true -> In (m, t) (@nil (Msg * Tag))).
  Proof.
    intros m H. specialize (H zero_tag (zero_key_forgeable m)). inversion H.
  Qed.
End Aead.
