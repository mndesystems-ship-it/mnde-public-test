# Policy Lifecycle

A policy moves through four states. Only an explicit activation operation grants
execution authority.

```text
DRAFT ──► READY ──► (explicit activation) ──► ACTIVE ──► RETIRED
```

- **DRAFT** — authored/edited locally. Has validation issues or is otherwise
  unreviewed. No execution authority.
- **READY** — compiles and passes review (`schema_version "1.0"`, a non-empty
  `rules[]`, unique rule IDs, valid effects). A signable artifact — still zero
  authority.
- **ACTIVE** — the exact compiled policy the execution path trusts right now.
  ACTIVE is bound to the compiled **`policy_hash`** recorded on a signed
  `mnde.policy.bundle.v1`, not to the `policy_id`.
- **RETIRED** — a previously active policy, superseded by a later serial.
  Preserved in activation history for evidence; grants nothing.

The controlling invariant: **editing a policy never changes active authority.**
Editing the active policy produces a new DRAFT revision; the prior ACTIVE policy
stays authoritative until an activation operation succeeds.

## Answering "which policy is active right now?"

`policy:status` is read-only. It reads the authoritative bundle-state file and
classifies a working policy against it.

```bash
npm run policy:status -- \
  --policy   ./policy.json \
  --bundle   ./acme.bundle.json \
  --state    ./bundle-state.json
```

Environment fallbacks: `MNDE_PE_POLICY_BUNDLE`, `MNDE_PE_POLICY_BUNDLE_STATE`.

It prints the active authority (policy id, serial, fingerprint), the working
policy's phase, and the activation history (each entry labelled ACTIVE or
RETIRED). It never signs or writes. When the working policy shares the active
policy line but differs by hash, it reports a new revision and states that the
active authority is unchanged.

## Activating a reviewed policy

`policy:activate` is the **only** operation that grants authority. It is a thin
wrapper over the existing signing (`signPolicyBundle`) and activation
(`activateSignedPolicyBundle`) modules — it adds no second crypto or trust path.

```bash
npm run policy:activate -- ./policy.json \
  --key         ./policy-key.pem \
  --key-id      policy-1 \
  --authority   ./authority-bundle.json \
  --trusted-root <root-fingerprint> \
  --state       ./bundle-state.json \
  --out         ./acme.bundle.json
```

Environment fallbacks: `MNDE_POLICY_SIGNING_KEY`, `MNDE_POLICY_KEY_ID`,
`MNDE_PE_AUTHORITY_BUNDLE`, `MNDE_PE_TRUSTED_ROOT_FINGERPRINT`,
`MNDE_PE_POLICY_BUNDLE_STATE`. `MNDE_PROFILE=production` requires the trusted
root.

What it does, in order:

1. Requires a **READY** policy (a raw draft is refused).
2. Requires the signing key, key id, authority bundle, trusted root, and state
   path; in production the trusted root must bind the authority bundle.
3. Determines the **next serial** from authoritative activation state.
4. Signs the **exact compiled policy hash**.
5. Verifies the freshly signed bundle binds to that compiled policy before
   activation.
6. Activates — `activateSignedPolicyBundle` re-verifies the signature against the
   trusted authority, enforces the serial floor, and writes state atomically.
7. Re-reads authoritative state and **proves the requested hash is ACTIVE** with
   the same lifecycle classifier `policy:status` uses.
8. Only then writes the signed bundle to `--out`, and prints the previous
   authority, new authority, policy hash, serial, signer fingerprint, and result.

Wire the resulting bundle via `MNDE_PE_POLICY_BUNDLE` and start the engine.

## No partial activation

Activation is all-or-nothing. State is mutated only inside the atomic activation
commit. If signing succeeds but validation, trust binding, state persistence,
signature verification, or the final ACTIVE confirmation fails, the command
exits non-zero, writes no signed bundle, and **the previous ACTIVE authority
remains authoritative**.

Refusals are surfaced with a reason, including: unreviewed policy, missing
signer, missing/mismatched trusted root, unreadable or encrypted key, malformed
state, wrong policy hash, a bundle modified after signing, invalid signature,
wrong authority role, unknown key, expired key, serial reuse, serial rollback,
state-write failure, verification failure after signing, and failure to confirm
the result is ACTIVE.

## Explicit operator action only

Activation happens only through `policy:activate` (and the `activatePolicy`
module it calls). The Policy Editor never activates: no autosave, import,
compile, review change, or READY transition invokes activation. The editor's
Lifecycle panel is read-only — it displays the working phase and, when you load
the active bundle/state, the active identity and history, and defers the exact
ACTIVE determination to `policy:status`.

```text
DRAFT → READY → explicit activation → ACTIVE → later RETIRED
```

Never `DRAFT → save → ACTIVE`.

## What proves this

- `npm run test:policy-lifecycle` — the DRAFT/READY/ACTIVE/RETIRED classifier and
  the hash-bound "editing an active policy is not ACTIVE" invariant.
- `npm run test:policy-activate` — hostile coverage of every refusal above, the
  no-partial-activation guarantee, that the editor contains no activation code
  path, and one end-to-end proof: an ACTIVE policy is edited (the revision is
  READY while the runtime still reports the original as ACTIVE), the revision is
  activated (it becomes ACTIVE, the original becomes RETIRED), and decision
  receipts bind to the new policy hash.

## Modules

- `src/policy-lifecycle/index.mjs` — read-only classifier
  (`evaluatePolicyPhase`, `activationHistory`, `currentActivation`, `reviewReady`).
- `src/policy-activate/index.mjs` — `activatePolicy` orchestration.
- `src/policy-bundles/index.mjs` — the reused signing/activation boundary
  (`signPolicyBundle`, `activateSignedPolicyBundle`, `policyHash`).
- `tools/policy-status.mjs`, `tools/activate-policy.mjs` — the CLIs.
