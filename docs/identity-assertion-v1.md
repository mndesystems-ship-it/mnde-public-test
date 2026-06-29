# mnde.identity_assertion.v1

An identity assertion is a structured record produced by an **external identity verifier** (an adapter) after completing offline OIDC verification. MNDe does not produce identity assertions. MNDe validates their structure, verifies their hash integrity, and binds them into the signed execution result.

**Core rule:** MNDe does not verify who you are by calling the internet. MNDe verifies that a trusted identity verifier produced a structurally intact proof record, then binds that record — by hash — to the execution result.

**What the label means:** When an `identity_assertion` is present and hash-intact, `identity_evidence` is `"ASSERTION_HASH_BOUND"`. This means MNDe has verified the assertion record has not been tampered with. It does **not** mean MNDe independently confirmed the identity with the issuer. The external adapter did that.

---

## Boundary

```
┌──────────────────────────────────────────────────────────┐
│  Adapter (outside MNDe core)                             │
│  - Accepts: raw_jwt, verifier_policy, jwks               │
│  - Validates policy: audience required (non-empty string)│
│    subject_allowlist required (non-empty) OR             │
│    allow_all_subjects: true                              │
│  - Verifies JWKS hash against trusted_jwks_hash          │
│  - Verifies JWT signature, issuer, audience, subject,    │
│    exp (finite number), iat (finite number), not-before, │
│    and token age — all offline                           │
│  - Hashes effective policy (with defaults applied)       │
│  - Outputs: mnde.identity_assertion.v1                   │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│  MNDe core (verify-assertion.mjs)                        │
│  - No network. No live issuer calls.                     │
│  - Validates structural fields                           │
│  - Recomputes assertion_hash to detect tampering         │
│  - Reports identity_evidence: ASSERTION_HASH_BOUND       │
└──────────────────────────────────────────────────────────┘
```

---

## Envelope shape

```jsonc
{
  "schema": "mnde.identity_assertion.v1",

  // Who the caller says is executing (e.g. executor display name or service ID).
  "asserted_identity": "string",

  // Subject from the verified token — immutable proof of who was verified.
  "verified_identity": "string",

  // How identity was verified (e.g. "github_actions_oidc").
  "identity_verification_method": "string",

  // Token issuer URL.
  "identity_issuer": "string",

  // Token subject claim.
  "identity_subject": "string",

  // Token audience claim (first element if array).
  "identity_audience": "string",

  // sha256:<hex> of the raw JWT bytes. Commits to the exact token verified.
  "identity_token_hash": "sha256:<64-hex>",

  // Verifier name and version for auditability.
  "verifier_name": "string",
  "verifier_version": "string",

  // sha256:<hex> of canonical(effective_verifier_policy).
  // The effective policy has all defaults materialized before hashing, so a
  // policy with max_token_age_seconds omitted hashes identically to one with
  // it set to 600 (the default). Changing any policy value changes the hash.
  "verifier_policy_hash": "sha256:<64-hex>",

  // ISO-8601 UTC timestamp at which the adapter completed verification.
  "verified_at": "2026-06-26T12:00:00.000Z",

  // sha256:<hex> of canonical(assertion body excluding assertion_hash).
  // Tamper-evidence: any field change invalidates this hash.
  "assertion_hash": "sha256:<64-hex>"
}
```

---

## assertion_hash computation

```
assertion_hash = "sha256:" + sha256(canonicalize(body_excluding_assertion_hash))
```

- `canonicalize` is deterministic key-sorted JSON (no whitespace).
- The field `assertion_hash` is **excluded** from its own hash input.
- Recomputed by `verifyIdentityAssertion` to detect tampering.

---

## verifier_policy_hash computation

The hash covers the **effective policy** — with all defaults applied — not the raw policy object. This means:

```js
const effectivePolicy = {
  issuer,                   // from policy or default (GitHub OIDC issuer)
  audience,                 // required; no default
  trusted_jwks_hash,        // required; no default
  max_token_age_seconds,    // default: 600
  clock_skew_seconds,       // default: 30
  // Either:
  allow_all_subjects: true
  // Or:
  subject_allowlist: [...]
};
verifier_policy_hash = sha256TaggedObj(effectivePolicy)
```

A policy that omits `max_token_age_seconds` and one that sets it to `600` explicitly produce the **same** `verifier_policy_hash`. Changing any value changes the hash.

---

## JWKS hash pinning (adapter requirement)

The adapter MUST verify the caller-supplied JWKS before trusting any key in it:

```
sha256(canonicalize(jwks)) === verifier_policy.trusted_jwks_hash
```

If the hashes do not match, the adapter MUST throw `OIDC_JWKS_HASH_MISMATCH` and produce no assertion. This prevents an attacker from substituting a JWKS containing their own public key.

---

## Binding into execution result

When `executor.identity_assertion` is present in an `mnde.execution_result.v2`:

1. `validateExecutionResult` calls `validateIdentityAssertion` structurally.
2. `verifyExecutionResult` calls `verifyIdentityAssertion` (structure + hash integrity).
3. If valid, `verifyExecutionResult` returns `identity_level: "ASSERTION_HASH_BOUND"`.
4. `verifySignedExecutionResult` propagates this as `identity_evidence: "ASSERTION_HASH_BOUND"` in the signed-result verdict.

When `executor.identity_assertion` is absent, `identity_evidence` is `"ASSERTED_ONLY"`.

**What `ASSERTION_HASH_BOUND` means:** MNDe verified the assertion record is structurally intact and its `assertion_hash` matches its contents. MNDe did **not** call the issuer. The adapter performed the live OIDC verification offline before producing the assertion.

---

## Adapter: GitHub Actions OIDC

**Input:**

| Field | Type | Description |
|-------|------|-------------|
| `raw_jwt` | string | Raw GitHub Actions OIDC token |
| `verifier_policy` | object | See policy fields below |
| `jwks` | object | Pre-fetched JWKS `{ keys: [...] }` |
| `options.nowMs` | number? | Clock reference in milliseconds |
| `options.assertedIdentity` | string? | Overrides `asserted_identity` in output |

**Policy fields:**

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `issuer` | string | GitHub OIDC issuer | no | Required `iss` claim |
| `audience` | string | — | **yes** | Required `aud` claim. Omitting silently skips audience validation — reject. |
| `subject_allowlist` | string[] | — | **yes\*** | Allowed subjects (exact or `*`-prefix wildcard). |
| `allow_all_subjects` | boolean | false | no | Set `true` to skip subject check. Replaces `subject_allowlist`. |
| `trusted_jwks_hash` | string | — | **yes** | `sha256:<hex>` of canonical JWKS |
| `max_token_age_seconds` | number | 600 | no | Token age limit from `iat` |
| `clock_skew_seconds` | number | 30 | no | Allowed clock difference |

\* Either `subject_allowlist` (non-empty) **or** `allow_all_subjects: true` is required. An absent or empty `subject_allowlist` without `allow_all_subjects: true` is rejected — silence is never allow-all.

**Claim requirements:**

- `exp` must be a **finite number**. Missing, `null`, string, `NaN`, or `Infinity` → `OIDC_TOKEN_EXPIRED` (fail-closed).
- `iat` must be a **finite number**. Missing, `null`, string, `NaN`, or `Infinity` → `OIDC_TOKEN_TOO_OLD` (fail-closed).

**Verification sequence (15 steps):**

1. Policy validation: `trusted_jwks_hash` present; `audience` is non-empty string; `subject_allowlist` non-empty OR `allow_all_subjects: true`
2. JWKS canonical hash === `trusted_jwks_hash`
3. Parse JWT (header + payload + signature)
4. `alg` must be `RS256`
5. Find JWK by `kid` in JWKS
6. Verify RS256 signature
7. `exp` must be a finite number (fail → `OIDC_TOKEN_EXPIRED`)
8. `iat` must be a finite number (fail → `OIDC_TOKEN_TOO_OLD`)
9. `iss` === `issuer`
10. `aud` contains `audience` (unconditional — policy guarantees non-empty string)
11. `sub` matches `subject_allowlist` (skipped only if `allow_all_subjects: true`)
12. `exp + clock_skew_seconds >= now`
13. `nbf - clock_skew_seconds <= now` (when `nbf` is present)
14. `now - iat <= max_token_age_seconds + clock_skew_seconds`
15. Build effective policy, hash it, return `mnde.identity_assertion.v1`

---

## Error codes (adapter)

| Code | Condition |
|------|-----------|
| `OIDC_JWKS_HASH_MISMATCH` | Canonical JWKS hash does not match `trusted_jwks_hash` |
| `OIDC_JWT_MALFORMED` | JWT is not a string, not three base64url parts, not valid JSON, or policy is misconfigured (`audience` missing/empty, `subject_allowlist` missing/empty without `allow_all_subjects`, `trusted_jwks_hash` missing) |
| `OIDC_ALGORITHM_UNSUPPORTED` | `alg` is not `RS256` |
| `OIDC_KEY_NOT_FOUND` | No JWK matching `kid` in JWKS, or `kid` absent from header |
| `OIDC_SIGNATURE_INVALID` | RS256 signature verification failed |
| `OIDC_ISSUER_MISMATCH` | `iss` does not match policy issuer |
| `OIDC_AUDIENCE_MISMATCH` | `aud` does not include policy audience |
| `OIDC_SUBJECT_NOT_ALLOWED` | `sub` is not in `subject_allowlist` (and `allow_all_subjects` is not true) |
| `OIDC_TOKEN_EXPIRED` | `exp` is not a finite number, or `now > exp + clock_skew_seconds` |
| `OIDC_TOKEN_NOT_YET_VALID` | `now < nbf - clock_skew_seconds` |
| `OIDC_TOKEN_TOO_OLD` | `iat` is not a finite number, or `now - iat > max_token_age_seconds + clock_skew_seconds` |

---

## Error codes (verifier)

Errors from `validateIdentityAssertion` / `verifyIdentityAssertion` are structured objects `{ field, code, message }`. Route on `.code` — never on `.message` text, which is allowed to change.

| Code | Field | Condition |
|------|-------|-----------|
| `IDENTITY_ASSERTION_SCHEMA_INVALID` | `schema` | `schema` field is wrong or input is not an object |
| `IDENTITY_ASSERTION_FIELD_REQUIRED` | varies | A required string field is missing or empty |
| `IDENTITY_ASSERTION_TOKEN_HASH_INVALID` | `identity_token_hash` | Not `sha256:<64-hex>` |
| `IDENTITY_ASSERTION_POLICY_HASH_INVALID` | `verifier_policy_hash` | Not `sha256:<64-hex>` |
| `IDENTITY_ASSERTION_VERIFIED_AT_INVALID` | `verified_at` | Not a valid ISO-8601 UTC datetime |
| `IDENTITY_ASSERTION_HASH_INVALID` | `assertion_hash` | Wrong format, or recomputed hash does not match |
