# mnde.authority_grant.v1

Status: **Implemented** (P0). Replaces the bearer-style authority grant produced by
[`src/policy-engine/trust.mjs`](../src/policy-engine/trust.mjs)'s `signAuthorityGrant`/
`verifyAuthorityGrant` — a signed `{authority_id, valid_from, valid_until}` object matched
only by `authority_id` string equality against a policy rule's `authority_required` array.
Any validly-signed grant of the right id satisfied *any* principal, tool, or tenant, and
could be replayed indefinitely. This spec closes that gap: a grant now proves exactly who
received authority, what they may authorize, where that authority applies, and when it
expires, and authorizes exactly one execution. See [`trust-anchored-verification.md`](trust-anchored-verification.md)
for the signature-chain model this extends, and [`key-custody.md`](key-custody.md) for the
authority-manifest key-validity/revocation rules this reuses unchanged from
[f3b4b4a](../shared/authority-manifest.mjs).

## 1. Schema

Implementation: [`src/policy-engine/authority-grants.mjs`](../src/policy-engine/authority-grants.mjs).

```jsonc
{
  "schema_version": "mnde.authority_grant.v1", // versioned schema id; unknown values fail closed
  "grant_id": "3da79a7d-...",           // globally unique, stable for the grant's lifetime, single-use key
  "authority_id": "grant-deploy",       // matched against a policy rule's authority_required — same
                                        // role this field has always played, unchanged for compatibility
  "principal": "alice",                 // exact authenticated principal this grant is bound to
  "tool": "deploy",                     // exact tool/adapter this grant authorizes
  "tenant": "tenant-a",                 // exact tenant/isolation-domain this grant authorizes
  "scope": {
    "action": "deploy",                 // ALWAYS equal to `tool` in this architecture (see §3) — kept
                                        // as its own field so `scope` is self-contained
    "resource": "cluster-1",            // optional; omitted means "not resource-scoped"
    "constraints": {}                   // optional; each key must exactly match request.parameters[key]
  },
  "nonce": "P56AZ7J5Ni6XlAh-...",       // cryptographically strong, single-use, independent of grant_id
  "issued_at": "2026-07-17T12:00:00.000Z",   // authenticated issuance time (signed)
  "expires_at": "2026-07-17T12:05:00.000Z",  // authenticated expiry (signed), strictly later than issued_at
  "issuer": "mnde-public-test-local",   // authority_id resolved via shared/authority-manifest.mjs
  "authority_key_id": "receipt-key-local", // signing key id within that authority's manifest
  "signature": { "key_id": "receipt-key-local", "value": "<hex ed25519>" }
}
```

**Naming**: the task that produced this feature suggested the field name `grant_version` for
the versioned-schema identifier. The repository's existing convention — `policy.schema_version`,
`request.schema_version`, every receipt's `schema_version` — uses `schema_version` for exactly
this role, and every other signed artifact in this codebase follows it. This spec follows the
repository's convention rather than introducing a second name for the same concept.

**Canonicalization and signing**: identical to `trust.mjs`/`authenticated-approvals.mjs` —
Ed25519 over `canonicalizeJson(grant without .signature)` ([`shared/json.ts`](../shared/json.ts)).
No second canonicalization system was introduced.

## 2. Required-field and duplicate-field checks

All twelve top-level fields above are required; a grant missing any of them, or with a
non-string/non-object value where one is required, fails closed as `AUTHORITY_GRANT_MALFORMED`.

Two ambiguity checks run before signature verification (both `AUTHORITY_GRANT_MALFORMED` on
disagreement):

- `signature.key_id` must equal the signed `authority_key_id` — these name the same key
  through two different paths (one inside the signed payload, one in the unsigned signature
  wrapper) and must never disagree.
- `tool` must equal `scope.action` — see §3.

## 3. Scope model

```
{"action": "<= tool>", "resource": "<exact string, optional>", "constraints": {"<key>": "<exact value>", ...}}
```

`action` is always identical to the grant's own `tool` field. In this architecture,
`request.tool.tool_name` is already the action-granularity identifier (existing self-governance
policy rules match on strings like `"read_status"` or block `"git push"` directly — there is no
separate coarser "tool" plus finer "action" split anywhere in the current request schema). Given
that, `scope.action` exists only so `scope` is independently meaningful as its own sub-object,
and its value is enforced to equal `tool` (§2) rather than being allowed to name a different,
finer-grained action the current architecture has no way to express.

Matching is **exact-match only** — no substring, prefix, wildcard, or path normalization of any
kind, deliberately, per this slice's P0 scope:

- `scope.action` must equal `request.tool.tool_name` exactly.
- If `scope.resource` is present, it must equal `request.parameters.resource` exactly. If
  absent, resource is not checked (not a wildcard — the field is genuinely absent from the
  signed grant, not present with a wildcard value).
- For every key in `scope.constraints` (if any), `request.parameters[key]` must equal the
  grant's value exactly.

There is no wildcard syntax (e.g. `"*"`) supported anywhere in this scope model. Where a call
site cannot supply a narrow `resource`/`constraints` value, the grant simply omits that
sub-check rather than the verifier inventing a default. **Known limitation**: a genuine
narrower-request-satisfies-broader-grant subset relationship (e.g. `filesystem.read` on `/tmp/`
authorizing a read of `/tmp/a.txt`) is not modeled in this slice — only exact equality.

## 4. Principal, tool, tenant binding

- **Principal**: bound against `options.caller.id` — the sidecar's authenticated bearer-token
  identity (see [`src/sidecar-auth/index.mjs`](../src/sidecar-auth/index.mjs)) — **never**
  `request.principal.id`. `sidecar-adapter.mjs`'s `decidePolicyEngine` already overwrites
  `request.principal.id` with the authenticated caller before evaluation, then separately
  forwards the same `caller` object to grant verification, so both paths agree without either
  trusting the request body directly. **Known limitation**: `src/sidecar-auth` is a flat,
  config-mapped bearer-token map with no cryptographic identity proof, expiry, or scope of its
  own. A stronger principal source already exists in this codebase — the identity-assertion /
  passport stack (`src/identity/`, see
  [`pre-execution-identity-authority-v1.md`](pre-execution-identity-authority-v1.md)) — but it
  is wired only to the post-execution signed-result path today, not to policy-engine requests.
  Wiring it into grant principal binding is a natural follow-up, not part of this slice.
- **Tool**: bound against `request.tool.tool_name`, exact string match.
- **Tenant**: bound against `request.principal.tenant_id`. **Known limitation**: no tenant /
  workspace / organization concept existed anywhere in this codebase before this slice (confirmed
  by exhaustive search — the only prior hits were an unrelated dashboard-actor RBAC field and an
  illustrative fixture value). This adds the minimal field needed to satisfy the security
  requirement; it is caller-declared, not independently authenticated by any separate identity
  system, exactly like `request.principal.id` is before caller-auth override. A request with no
  `tenant_id` at all fails closed (`AUTHORITY_GRANT_TENANT_MISMATCH`) rather than being treated
  as a wildcard/default tenant.

## 5. Lifetime, clock skew, and expiry boundary

- `issueAuthorityGrant` requires a positive, bounded `lifetimeMs` (default 5 minutes); there is
  no unbounded/"no expiry" option.
- `expires_at` must be strictly later than `issued_at`; equal or earlier fails closed
  (`AUTHORITY_GRANT_MALFORMED`).
- **Clock skew**: `issued_at` may be up to `DEFAULT_CLOCK_SKEW_MS` (60s, overridable via
  `options.clockSkewMs`) ahead of the verifier's authenticated `now`, tolerating minor clock
  drift between issuer and verifier. Beyond that, `AUTHORITY_GRANT_NOT_YET_VALID`.
- **Expiry boundary: exclusive.** A grant is valid for `issued_at <= now < expires_at`; it is
  expired at exactly `now === expires_at` (`AUTHORITY_GRANT_EXPIRED`). This matches the existing
  house convention already used for authority-key windows (`trust.mjs`'s
  `t >= Date.parse(key.valid_until)`) and approvals (`authenticated-approvals.mjs`'s
  `t >= Date.parse(approval.expires_at)`) — a grant does not get a extra instant of validity at
  its own boundary. Tested explicitly at the exact boundary and one millisecond before it.

## 6. Authority key validity and revocation

`issuer` + `authority_key_id` resolve through
[`shared/authority-manifest.mjs`](../shared/authority-manifest.mjs) — the same authority
manifest used for receipt-signing keys, **not** the separate `trustAnchors.authority_keys` array
`trust.mjs` uses for legacy grants. Key material is obtained via the new `findAnyAuthorityKey`
(existence only, used to get a public key for signature verification), and validity/revocation
is checked via the **unmodified** `findAuthorityReceiptKey` from
[f3b4b4a](../shared/authority-manifest.mjs), first at signed `grant.issued_at` and then at the
authenticated evaluation time with `activeOnly: true`. In live evaluation that second time is
verifier-local server time; in offline receipt replay it is the receipt's signed
`decision_output.evaluated_at`. This prevents an expired-but-leaked key from minting a
long-lived grant backdated into its former validity window. A retired or revoked key can never
authorize a grant consumed now. The revocation boundary is inherited unchanged from f3b4b4a:
**inclusive** (`revoked_at` itself is already revoked).

**Known limitation**: `shared/authority-manifest.mjs` has no writer for `revoked_at` on this
simple manifest shape (unlike the richer, already-wired `evaluateRevocation()` in
`src/custody/bundle.mjs`) — see the P1 roadmap item, "Add a safe key-revocation lifecycle
command."

## 7. Replay protection

Implementation: [`src/policy-engine/grant-nonce-store.mjs`](../src/policy-engine/grant-nonce-store.mjs).
Durable, atomic, file-based — mirrors `sidecar/auth_authority.mjs`'s proven nonce-reservation
mechanism (one file per key, `O_EXCL` creation, which is a single atomic kernel syscall on both
POSIX and Windows). No SQLite exists anywhere in this codebase; the file-based pattern is the
established prior art and is reused rather than introducing a new dependency.

**Two independent keys** are reserved per grant — `grant_id` and `nonce` — because either alone
being reusable would create a gap:

- reusing a `nonce` under a *different* `grant_id` fails (the nonce file already exists).
- reusing a `grant_id` with a *different* `nonce` fails (the grant_id file already exists).

Both reservations must succeed for the grant to authorize. If the `grant_id` reservation
succeeds but the `nonce` reservation then fails, **the `grant_id` reservation is not rolled
back** — a grant that has been partially matched must never become retryable, even under a
condition (nonce collision) that is itself anomalous and worth treating conservatively.

**State machine**: `RESERVED` (file created) → `CONSUMED` (terminal). There is no separate
"confirm downstream execution" callback anywhere in the policy engine — `evaluatePolicyRequest`
is a single synchronous call that returns ALLOW/REFUSE — so a successful reservation is
consumed in the same call, per the safest-default rule: **a grant is spent once authorization
has been granted, even if whatever runs next fails.** A file left at `RESERVED` (without
reaching `CONSUMED`) can only be observed if a process crashed between the two writes; on retry
this correctly refuses (`AUTHORITY_GRANT_ALREADY_RESERVED`) rather than silently treating the
crash as "never happened."

Verified by real cross-process races (two separate OS processes, not just threads, spawned the
same way `tests/test_nonce_replay.mjs` proves `reserveNonce`'s atomicity) in
`tests/test_authority_grants.mjs`, plus explicit tests for: replay after success, replay after a
simulated downstream failure, replay after a simulated process restart (in-process cache reset,
durable file store intact), same-grant/different-request-id, same-nonce/different-grant-id, and
same-grant-id/different-nonce.

**Offline replay/audit** (`verifyPolicyReceipt`) never touches this store — it re-verifies every
other check (signature, trust, key validity, all four bindings) but passes
`consumeAuthorityGrants: false`, so an audit run is idempotent and never itself decides whether a
grant was "used."

## 8. Validation order

1. Parse the grant.
2. Reject malformed/unknown `schema_version`.
3. Confirm all required fields exist and are well-formed.
4. Reject duplicate/ambiguous representations (§2).
5. Canonicalize the signed payload.
6. Resolve the issuer and authority key (existence only).
7. Verify the signature.
8. Validate the key at signed `issued_at` and authenticated evaluation time (§6).
9. Validate `issued_at`/`expires_at` and clock skew (§5).
10. Match tenant.
11. Match principal.
12. Match tool.
13. Match scope.
14. Grant-level revocation — no such mechanism exists today (only authority-*key*
    revocation, step 8); a no-op step reserved for a future grant-revocation list.
15. Reserve and consume the nonce and grant_id atomically (§7) — skipped only for offline replay.
16. Authorize execution.

## 9. Error codes

`AUTHORITY_GRANT_MALFORMED`, `AUTHORITY_GRANT_VERSION_UNSUPPORTED`,
`AUTHORITY_GRANT_SIGNATURE_INVALID`, `AUTHORITY_GRANT_ISSUER_UNTRUSTED`,
`AUTHORITY_GRANT_KEY_INVALID`, `AUTHORITY_GRANT_KEY_REVOKED`, `AUTHORITY_GRANT_NOT_YET_VALID`,
`AUTHORITY_GRANT_EXPIRED`, `AUTHORITY_GRANT_PRINCIPAL_MISMATCH`, `AUTHORITY_GRANT_TOOL_MISMATCH`,
`AUTHORITY_GRANT_TENANT_MISMATCH`, `AUTHORITY_GRANT_SCOPE_MISMATCH`, `AUTHORITY_GRANT_REPLAY`,
`AUTHORITY_GRANT_ALREADY_RESERVED`, `AUTHORITY_GRANT_ALREADY_CONSUMED`. Never exposed with
grant contents attached — the reason code alone is returned; no scope, principal, or tenant
value from the grant appears in the refusal.

## 10. Receipt / audit fields

Every decision built with at least one `mnde.authority_grant.v1` grant carries
`decision_output.authority_grants.verifications`, an array with one entry per grant attempted:

```jsonc
{
  "grant_id": "...", "authority_id": "...", "grant_version": "mnde.authority_grant.v1",
  "issuer": "...", "authority_key_id": "...",
  "scope_digest": "sha256:...", "nonce_digest": "sha256:...",
  "issued_at": "...", "expires_at": "...",
  "result": "OK" // or the specific AUTHORITY_GRANT_* reason it failed with
}
```

Deliberately **excludes** raw `principal`/`tool`/`tenant`/`scope` plaintext — those already live
in the receipt's own `canonical_request`, and duplicating them here would be redundant exposure
with no audit value the request doesn't already provide. `scope_digest`/`nonce_digest` are
sha256 over canonical JSON — safe, non-reversible references, never inputs to any security
decision. This is metadata, like the existing `approval` summary — not part of `decision_hash`
(the raw `authorities` array is already covered, tamper-evidently, by the pre-existing
`authority_chain_hash`) — so `verifyPolicyReceipt` checks it with an explicit canonical-JSON
deep-equality comparison on replay, separate from the `decision_hash`/field-equality checks.

## 11. Compatibility

| Path | Classification | Production behavior |
|---|---|---|
| `src/policy-engine/trust.mjs` `signAuthorityGrant`/`verifyAuthorityGrant` (unscoped bearer grant) | **Legacy** | Refused outright — see below. Never issued new. |
| `src/policy-engine/authority-grants.mjs` (this spec) | **Production** | The only grant format production accepts. |

Production (`rejectLegacyAuthorities`, set from `config.production` in
`sidecar-adapter.mjs`) refuses every non-`mnde.authority_grant.v1` grant, unconditionally,
**regardless of whether `trustAnchors` is configured** — this is new: previously, a
correctly-signed legacy grant with configured `trustAnchors.authority_keys` was accepted in
production. See `tests/test_signed_policy_bundle.mjs`'s
"production REFUSES a legacy bearer-style authority grant even with trust anchors configured"
(fixed to reflect this intentional change) and its companion test proving the v1 migration path
reaches ALLOW in the identical scenario. No new grants are issued in the legacy format by
anything in this codebase; `trust.mjs`'s signing helper remains only for already-existing test
coverage of the legacy verification path itself.

## 12. Migration impact

- `src/policy-engine/index.mjs`: `evaluatePolicyRequest`'s authority-checking loop now branches
  per-grant on `schema_version`; legacy-grant handling (verification against `trustAnchors`, or
  passthrough when `trustAnchors` is absent) is otherwise byte-for-byte unchanged.
  `authorityStatus()` skips its own `valid_from`/`valid_until` check for `mnde.authority_grant.v1`
  entries (already fully — and more correctly, with clock-skew tolerance — checked upstream).
- `src/policy-engine/receipt.mjs`: `buildPolicyReceipt` forwards `caller`/`repoRoot`/
  `consumeAuthorityGrants` to the engine; `verifyPolicyReceipt` always replays with
  `consumeAuthorityGrants: false` and derives the replay caller from the embedded request's
  `principal.id` (already set to the authenticated caller by `sidecar-adapter.mjs`'s existing
  convention).
- `src/policy-engine/sidecar-adapter.mjs`: `decidePolicyEngine` now forwards `caller` to
  `buildPolicyReceipt` (previously used only to overwrite `request.principal.id`, never passed
  further).
- `shared/authority-manifest.mjs`: one small additive export, `findAnyAuthorityKey` (existence-only
  lookup); `findAuthorityReceiptKey` itself (the f3b4b4a fix) is untouched.
- No public API was removed or renamed. No dependency was added — all cryptography is `node:crypto`,
  matching `trust.mjs`/`authenticated-approvals.mjs`'s existing (already-allowlisted) pattern in
  `tests/test_ci_contract.mjs`.

## 13. Known limitations

- Principal identity is a config-mapped bearer-token label (§4), not independently
  cryptographically proven; the stronger identity-assertion/passport stack exists but isn't
  wired to this path yet.
- Tenant is caller-declared (§4), not backed by any authenticated tenant-context system — none
  exists in this codebase yet.
- Scope matching is exact-only (§3) — no subset/prefix semantics, by deliberate P0 choice.
- No grant-level revocation list (§7 step 14) — only authority-key revocation.
- No writer for authority-key `revoked_at` on the simple manifest shape (§6) — tracked as the P1
  roadmap item.
- Tenant binding only flows through the native policy-engine request shape
  (`sidecar-adapter.mjs`'s `toPolicyEngineRequest`); the legacy execution-request envelope
  adapter path does not currently populate `principal.tenant_id`.
