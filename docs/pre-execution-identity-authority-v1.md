# Pre-Execution Identity Authority v1 (ADR + Threat Model)

Status: **Proposed** · Supersedes the caller-set `principal.verified` trust input in
`mnde.execution_request.v1`. Lives next to [`execution-request-v1.md`](execution-request-v1.md)
and follows the trust-split model of [`activation-authority-v1.md`](activation-authority-v1.md).

## 1. Context

MNDe already has a complete, correctly-layered principal-identity stack:

- `src/identity/assertion.mjs` — `mnde.identity_assertion.v1`, a hash-bound claims object
  (`assertion_hash` excludes itself; tamper-evident).
- `src/identity/verify-assertion.mjs` — deterministic structural + hash verifier.
- `src/identity/adapters/github-actions.mjs` — offline OIDC verification (JWKS passed in,
  pinned by `trusted_jwks_hash`; **no network fetch**), producing an identity assertion.
- `src/identity/passport.mjs` — `passport_subject_id = sha256(canonicalize({schema,
  authority_scope, issuer, verified_identity}))`, explicitly refusing `executor.id`.

This stack is wired only to the **execution result / signed-receipt (post-execution)** path
(`src/execution-gate/verify-result.mjs`, `verify-signed-result.mjs`). The **pre-execution
gate** ignores it: `applyGates` in `src/execution-gate/index.mjs` fires
`PRINCIPAL_NOT_VERIFIED` off the caller-set boolean `principal.verified`
(`index.mjs:32`), which `schema.mjs` validates as a required boolean but never checks against
any proof (`schema.mjs:106`).

## 2. Decision

**`principal.verified` is removed as a trust input. The gate derives verification from an
attached, verified `mnde.identity_assertion.v1`, never from a caller-supplied flag.**

This restores authority-*before*-execution in the identity dimension: the ALLOW/REFUSE
decision consumes proof, not a claim about proof.

## 3. The two invariants this design must not break

Two properties of the current gate are load-bearing and MUST survive:

### 3.1 Deterministic, offline replay

`applyGates(request)` is a pure function of the request. `replayExecutionGate(receipt,
request)` (`index.mjs:116`) re-derives the decision offline from the request alone, with no
network, no clock, no bundle; `decided_at` is copied from `requested_at`, never wall-clock
(`receipt.mjs:26`). This reproducibility is the product.

> **Therefore the OIDC adapter MUST NOT run inside the gate.** OIDC verification is live
> (JWKS, token `exp`/`iat`/age vs. current time). Running it at decision time makes the
> decision depend on network + wall-clock, so a replayed request would REFUSE once its token
> expires. OIDC verification happens **upstream, once**, producing the hash-bound assertion.
> The gate consumes the finished assertion and performs only **deterministic** checks:
> structural + `assertion_hash` integrity (`verify-assertion.mjs`), `verifier_policy_hash` ∈
> the approved signed-policy set, and achieved level ≥ required level.

### 3.2 The trust ladder is two rungs, not three

The offline verifier emits only `ASSERTED_ONLY` and `ASSERTION_HASH_BOUND`
(`verify-result.mjs:146–154`). **`VERIFIED_BY_EXTERNAL_VERIFIER` does not exist in the code**
— it was deliberately removed, because an offline verifier cannot honestly *re-prove*
external verification. Passport derivation already keys on `ASSERTION_HASH_BOUND`
(`verify-signed-result.mjs:479`).

> **Therefore the policy floor is not a third label.** "External verification strength" is
> captured by *which* verifier produced the assertion — i.e. the gate additionally requires
> `identity_assertion.verifier_policy_hash` to be a member of the **approved, signed verifier
> policy set**, plus a trusted `verifier_name`/`verifier_version`. The distinction is:
>
> - **Decision time** (online): the caller ran the OIDC adapter upstream; external
>   verification is genuinely true at that instant. The gate requires the assertion to have
>   been produced under an approved verifier policy and records that evidence.
> - **Replay time** (offline): only `assertion_hash` integrity + the outer Ed25519 signature +
>   the recorded `verifier_policy_hash`/policy version are re-provable. Replay confirms the
>   *recorded evidence*, never a re-run.

## 4. Schema change (additive)

`mnde.execution_request.v1` gains one optional-then-required field, `identity_assertion`,
carrying a full `mnde.identity_assertion.v1` object. `principal.verified` MAY remain for
logging/UX but is never read by the gate. Staged behind `MNDE_REQUIRE_IDENTITY_ASSERTION=1`
until callers migrate — mirroring how activation was staged behind `MNDE_REQUIRE_ACTIVATION`
(`activation-authority-v1.md` §9.1).

## 5. Gate flow (all steps deterministic)

1. Validate the request; if an `identity_assertion` is present, validate it structurally via
   `validateIdentityAssertion` (`assertion.mjs`).
2. **Identity gate (new Gate 1):**
   - No assertion present → REFUSE `IDENTITY_PROOF_MISSING` (in `production`, or whenever
     `MNDE_REQUIRE_IDENTITY_ASSERTION=1`).
   - Assertion fails `verifyIdentityAssertion` (hash mismatch, malformed) → REFUSE
     `IDENTITY_PROOF_INVALID`.
   - `assertion.verifier_policy_hash` ∉ approved signed-policy set → REFUSE
     `VERIFIER_POLICY_UNTRUSTED`.
   - Achieved level < required level for `(environment.name, authority_scope)` → REFUSE
     `IDENTITY_LEVEL_INSUFFICIENT`.
   - The gate NEVER reads `principal.verified`.
3. Existing hard gates (`APPROVAL_REQUIRED`, `DESTRUCTIVE_REQUIRES_APPROVAL`) run unchanged.
4. Compute `passport_subject_id` via `derivePassportSubjectId(request.identity_assertion,
   authority_scope)` (`passport.mjs`) and bind it into the receipt **at build time, before
   execution** — replacing the echoed `principal.verified` field in `receipt.mjs:29–33` and
   `signed-receipt.mjs:68–72` with an `identity` block.
5. Record in the receipt the evidence needed for deterministic replay: `achieved_level`,
   `required_level`, `verifier_policy_hash`, `verifier_policy_version`, `passport_subject_id`.

Replay re-runs steps 2 and 4 using the request's attached assertion and the **receipt-recorded
policy snapshot** (not live config), reproducing the identical decision offline.

### 5.1 `authority_scope` provenance (resolved)

`authority_scope` = `authority_chain_id`. Today it is **caller-chosen and root-unanchored**:
it is a required parameter to `buildSignedExecutionResult` (`signed-result.mjs:69,78`), covered
by the result signature but not pinned by the bundle — so `mnde.authority.bundle.v1`
(`bundle.mjs:76–84`) carries `authority_id` but no `authority_chain_id`, and the verifier's
cross-check (`verify-signed-result.mjs:391`) never runs, always falling to
`AUTHORITY_CHAIN_ASSERTED_ONLY` (`:397`). A result-key holder can therefore mint any scope, and
the passport's scope component is forgeable while its identity components are not.

**Resolution: `authority_scope` is sourced from the gate's own root-anchored bundle, never from
the request.** "Under whose authority" is a property of the deployed gate, not of the caller.

1. Add `authority_chain_id` as a first-class field in the **root-signed** bundle body
   (`bundle.mjs:76–84`), anchoring it exactly like `authority_id`.
2. The existing check at `verify-signed-result.mjs:391–396` becomes mandatory — closing
   `AUTHORITY_CHAIN_ASSERTED_ONLY` for the result path as well.
3. **Both** the pre-execution gate and the result path derive `authority_scope` from the
   *verified* bundle's `authority_chain_id`, keeping the pre-exec receipt passport and the
   post-exec result passport identical so audit can join them.
4. The gate ignores any request-supplied scope; a request carrying a scope that mismatches the
   bundle's → REFUSE (§8 test 5).

Default model is one bundle ↔ one `authority_chain_id`; if an authority spans multiple chains,
the bundle carries an allowlist and the envelope must name a member. Staged like activation
(§9.1): production hard-fails on an unpinned chain id; local/legacy tolerates asserted-only.

## 6. Verifier policy as first-class signed material

Today the verifier policy is an **ad-hoc argument** to `verifyGitHubActionsOidc`
(`github-actions.mjs:111`): `{ issuer, audience, subject_allowlist | allow_all_subjects,
trusted_jwks_hash, max_token_age_seconds, clock_skew_seconds }`. It is validated loudly at call
time (audience required, `trusted_jwks_hash` required, subject scope explicit — "silence is
never allow-all", `github-actions.mjs:133–162`) but is **not signed, persisted, or versioned**.

This ADR promotes it to `mnde.verifier_policy.v1`: a custody-signed object (same root/custody
key and canonical-without-signature signing as `mnde.authority.bundle.v1`, `src/custody/
bundle.mjs`) carrying the policy entries, a `(environment, authority_scope) → min_level` table,
and a **monotonic `policy_version`**. Verified at load; rejected if the signature fails or if
`policy_version` ≤ the stored high-water mark (rollback protection).

Refinements (single trust anchor + clean operational/replay split):

- **The policy does not embed its own root key.** It references the authority via `authority_id`
  (+ optional `root_key_id`) and is verified using the root key carried by the already-verified
  `mnde.authority.bundle.v1`. There is exactly one copy of the trust anchor, not one per policy.
- **Operational vs. replay verification are separate.** *Operational* (`loadVerifierPolicy`):
  signature + root trust + version high-water mark + optional `not_after` (only when a `now` is
  supplied) + JWKS-pin freshness — run when accepting a newly published policy. *Replay*
  (`verifyPolicySignature` + the receipt-recorded decision object): signature only, no
  version/expiry/clock. **A receipt must never fail replay because its policy later expired or
  was superseded.**
- **Assurance levels are one ordered enum** (`IDENTITY_LEVELS`), rank = array index, so no two
  call sites can disagree on ordering. `verify-result.mjs` SHOULD import it (same anti-drift
  move as the adapter and `effectiveVerifierPolicyHash`).
- **`requiredDecisionPolicy(environment, authority_scope)`** returns a frozen, receipt-ready
  object `{ level, policy_version, policy_document_hash, authority_scope, accepts(achieved) }`.
  The gate records this verbatim; replay compares against it without reloading the policy. A
  missing rule yields `level: "DENY"` whose `accepts()` is always false (fail closed).

Policy hashing is canonical and defined once: `effectiveVerifierPolicyHash` hashes exactly
`canonicalizeJson({ issuer, audience, trusted_jwks_hash, max_token_age_seconds,
clock_skew_seconds, subject_allowlist | allow_all_subjects })`, matching what the adapter
records (`github-actions.mjs §15`).

### 6.1 Policy distribution & lifecycle (future work)

Once multiple versions exist, publication/activation/retention need answering — and MNDe
already has the pattern: `mnde.activation.v1` (`activation-authority-v1.md`). A verifier policy
should be **activated** the same way a release is: a signed, hash-linked transition naming the
policy that became authoritative, so a receipt can reference the active policy version and
historical policies stay verifiable for as long as their receipts do. This is a follow-up spec,
not part of this slice; the high-water mark handles rollback safety in the interim.

## 7. Threat model — poisoned verifier policy

Principal keys are **not** in the authority bundle (it holds only MNDe's own signing keys:
receipt/policy/approval/result/ledger/activation, `bundle.mjs:18`). Trust in the external
issuer is therefore entirely a function of the verifier policy. That policy — not the bundle —
is the attack surface.

| Threat | Effect | Control |
|---|---|---|
| Wrong/substituted `trusted_jwks_hash` | Forge arbitrary "verified" assertions | Policy (incl. JWKS hash) custody-signed, verified at load; two-source fetch-and-compare of the real JWKS before pinning |
| Over-broad `subject_allowlist` / `allow_all_subjects` | Any token from the right issuer inherits trust regardless of tenant | Exact-match default; wildcards need explicit sign-off + CI lint failing broad patterns outside a designated dev policy |
| Missing/wrong `audience` | Cross-service token replay | `audience` required, no skip-if-absent path (already enforced in adapter); fail closed |
| Stale/typo'd issuer entry | Decommissioned or look-alike issuer accepted | Issuers checked against a change-controlled master allowlist; decommissioned issuers removed, not left dangling |
| Unsigned policy at rest | Config-write access silently edits JWKS hash/allowlist/audience | `mnde.verifier_policy.v1` custody-signed, verified at load |
| Policy rollback | Replay an old, broader signed policy | Monotonic `policy_version` vs. high-water mark (same anti-replay concept the ledger applies per-request) |
| Min-level misconfiguration | Sensitive scope mapped to too low a floor by authoring error | Signed + reviewed like the rest of the policy; hard CI floor for known-sensitive scopes |

## 8. Hostile tests (must all pass)

1. Caller sets `principal.verified: true`, no assertion attached → REFUSE.
2. Assertion valid but achieved level < required for the scope → REFUSE `IDENTITY_LEVEL_INSUFFICIENT`.
3. Assertion's `verifier_policy_hash` ∉ approved signed-policy set → REFUSE `VERIFIER_POLICY_UNTRUSTED`.
4. Tampered assertion body (hash mismatch) → REFUSE `IDENTITY_PROOF_INVALID`.
5. Request carries an `authority_scope` that mismatches the gate's verified bundle `authority_chain_id` → REFUSE (scope is sourced from the bundle, never the request; see §5.1).
6. Previously-consumed assertion/token resubmitted → REFUSE (nonce/replay against `assertion_hash`/`identity_token_hash`, reusing the ledger primitive).
7. Older, validly-signed-but-superseded verifier policy loaded → REFUSE to apply (rollback protection).
8. No min-level entry for a `(environment, authority_scope)` → REFUSE (fail closed on policy gaps, never default-to-lowest).
9. **Determinism guard:** replay a previously-ALLOWED request after its OIDC token's `exp` has passed → decision UNCHANGED (proves live verification never leaked into the deterministic gate).

## 9. What is reused vs. new

- **Reused unchanged:** `assertion.mjs`, `verify-assertion.mjs`, the OIDC adapter, `passport.mjs`, the custody signing pattern, the ledger nonce/replay primitive.
- **New:** gate control flow (`applyGates`), the `identity_assertion` request field, the `identity` receipt block + recorded policy snapshot, and `mnde.verifier_policy.v1` (signed, versioned).

No new cryptography is introduced.
