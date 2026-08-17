# Witnessed Authority Checkpoints (v1)

## Problem

MNDe can already prove an authority bundle is internally valid and anchored to a
pinned, out-of-band trusted root. That proves a bundle is *well-formed and
root-signed* — it does **not** prove that a single authority operator has not
produced two *different* valid histories and shown each to a different party.

Example the base system cannot distinguish:

```
history A: authority mnde-prod, epoch 42, key K7 revoked
history B: authority mnde-prod, epoch 42, key K7 active
```

If both are legitimately authority-root-signed, ordinary signature verification
accepts each in isolation. Nothing forces the two to be *the same*.

This layer makes that divergence **externally detectable**.

## Threat model

- **Network attacker** — can observe, delay, replay, reorder, duplicate, drop,
  or modify artifacts, but holds no trusted private keys.
- **Compromised authority operator** — holds legitimate authority signing
  capability and may publish different bundles to different customers, rewrite
  revocation, present inconsistent epochs, backdate, omit, or fork history.
- **Compromised witness** — may refuse to sign, sign stale checkpoints, sign a
  conflicting checkpoint, lie about observation time, or disappear. Threshold
  witnessing reduces reliance on any single witness.
- **Malicious verifier input** — every malformed / unknown / expired /
  wrong-role / duplicate / forged / mismatched artifact must fail closed.

## Artifacts

### `mnde.authority.checkpoint.v1`

An immutable, authority-signed observation of one authority-state at one history
position. Signed body fields (exact; strict — no extra top-level fields):

```
schema, authority_id, authority_epoch, sequence,
previous_checkpoint_digest, authority_bundle_digest, issued_at, root_key_id
```

plus `signature: { algorithm: "ED25519", key_id, value }`.

- **Identity / digest:** `checkpoint_digest = "sha256:" + sha256(canonicalJSON(body))`
  — the repository's existing canonical-JSON + sha256 convention (`shared/hash.ts`).
  No second digest encoding.
- **Chain:** `previous_checkpoint_digest` equals the digest of the immediately
  preceding accepted checkpoint; genesis (`sequence: 0`) uses an explicit `null`.
- **History position:** `sequence` strictly increases by 1; `authority_epoch`
  never decreases. Conflict detection uses both.
- **State commitment:** `authority_bundle_digest` binds the checkpoint to the
  exact authority bundle (which itself contains the revocation state), so v1 does
  not duplicate revocation/policy state into the checkpoint.
- **Signer:** a dedicated `checkpoint`-role key in the authority bundle — never a
  receipt/ledger/etc. key. `root_key_id` binds the checkpoint to the bundle's root.

### `mnde.witness.attestation.v1`

An independent witness's statement "I observed this exact checkpoint digest".
Signed body:

```
schema, checkpoint_digest, authority_id, authority_epoch,
witness_id, observed_at, witness_key_id
```

plus `signature`. **The attestation carries no public key** — the witness public
key comes only from the trusted witness bundle, never from the attestation.

### `mnde.witness.bundle.v1`

The witness trust source, pinned out of band **independently** of the MNDe
authority root:

```
schema, authority_id, witnesses: [
  { witness_id, key_id, public_key, roles: ["checkpoint-witness"],
    valid_from, valid_until, revoked }
], revocation?
```

### `mnde.witness.policy.v1`

```
schema, required, eligible_witnesses: [witness_id, ...]
```

### `mnde.authority.equivocation-proof.v1`

```
schema, authority_id, checkpoint_a, checkpoint_b, reason, detected_at
```

Self-verifying from the two signed checkpoints; no trusted detector signature.

## Witness trust

Witness trust is **separate** from MNDe authority trust. A witness key is trusted
only because it appears in a witness bundle the verifier pinned out of band — a
key beside an attestation is never trusted on that basis. Witnesses use a
dedicated `checkpoint-witness` role: a receipt/ledger/checkpoint authority key
cannot witness, and a witness key cannot sign an authority checkpoint.

This independence is the whole point (§33/§34): if MNDe controlled both the
authority root and every witness key, witnessing would give little protection
against MNDe itself. The intended shape is MNDe-as-authority plus one or more
*independent* design-partner / auditor witnesses, later a 2-of-3 threshold.

## Threshold

`evaluateWitnessThreshold` counts **unique, valid, eligible** witness identities
over one exact checkpoint digest and compares to `required`. It never counts:
duplicate attestations, duplicate keys for the same witness, expired/revoked/
wrong-role/unknown/ineligible witnesses, invalid signatures, or attestations over
another checkpoint. Duplicates from one witness count once. `required: 0` passes
only when the policy explicitly says 0.

## Equivocation & forks

Given two checkpoints that both validly authenticate under the same pinned root:

- **AUTHORITY_EQUIVOCATION** — same `authority_id`, same history position (same
  `sequence`, or same `authority_epoch`), different digest.
- **CHAIN_FORK** — two different children referencing the same
  `previous_checkpoint_digest`.
- **WITNESS_EQUIVOCATION** — the *same* witness validly attests two *different*
  checkpoint digests at the same authority position. Kept distinct from authority
  misconduct; the same witness attesting the same digest twice is a duplicate.

Conflicts are **surfaced, never resolved**. When two conflicting checkpoints each
meet threshold, that is strong equivocation evidence involving both the authority
and the overlapping witnesses — the verifier reports it and refuses to silently
pick a winner. There is no "most witnesses wins".

## Offline verification

All core verification runs with only: the checkpoint, the authority bundle, the
trusted root fingerprint, witness attestations, the witness bundle, the witness
policy, and (optionally) the previous checkpoint. No network, DNS, GitHub, hosted
MNDe service, or timestamp-authority dependency.

Rough local timings (Node v24): checkpoint verify ~0.7 ms, one witness verify
~0.2 ms, 3-witness threshold ~0.5 ms, equivocation-proof verify ~1.3 ms.

## Root binding

The chain of trust is unchanged and additive:

```
out-of-band trusted root fingerprint
  → production authority bundle (root-signed)
    → checkpoint-signing key (checkpoint role in the bundle)
      → authority checkpoint
        → witness attestation (independent witness trust)
```

Witnesses add observation; they do not replace or redefine the MNDe authority root.

## Limitations / non-goals (v1)

- **Not consensus, not a blockchain, not a global transparency log.** No
  append-only service, no distributed agreement, no federation, no witness
  discovery over the internet.
- **No production wiring yet.** These are pure primitives + offline verifiers.
  Production startup does not yet *require* witnessed checkpoints; that enforcement
  (and its fail-closed witness policy) is deliberately a later step. Nothing here
  is half-enforced in production.
- **Witness bundle is pinned config in v1** (optionally revocation-aware); it is
  not itself root-signed. Independent witness-root signing is a future extension.
- **No delegated authority.** That is the next layer, built on witnessed history.
- **No trusted timestamping.** `observed_at` / `issued_at` are self-asserted and
  validated against key validity windows; they are not third-party notarized.
- **Detection, not prevention.** Witnessing does not stop an insider from
  producing conflicting histories.

## The accurate claim

Witnessing makes conflicting signed authority histories **externally detectable**
when independent witnesses retain and present their attestations. It does not
prevent all insider abuse; it converts silent divergence into verifiable evidence.
