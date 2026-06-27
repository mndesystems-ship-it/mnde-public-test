# mnde.signed_execution_result.v1

## Purpose

`mnde.signed_execution_result.v1` is the third and final link in the MNDe audit chain. It wraps an `mnde.execution_result.v2` object in an authority-signed envelope that:

- Proves the result was recorded under a specific MNDe authority
- Binds the result to a verified signed execution receipt via a three-way request hash check
- Is verifiable entirely offline using a pre-distributed authority bundle and trusted root fingerprint

The audit chain is:

```
mnde.execution_request.v1          →  what was asked?
mnde.execution_gate.receipt.v1     →  was it authorized?       (Ed25519 signed by receipt key)
mnde.execution_result.v2           →  what happened?           (hash-bound, optional executor sig)
mnde.signed_execution_result.v1    →  authority record of outcome  (Ed25519 signed by result key)
```

The signed result does **not** authorize execution. It records what happened after the gate decision was made.

---

## Object Shape

```json
{
  "schema": "mnde.signed_execution_result.v1",
  "signed_at": "<ISO-8601>",
  "trust_model": "offline-root-pinned",
  "authority_chain_id": "<stable authority lineage ID>",

  "execution_result": { /* mnde.execution_result.v2 */ },

  "receipt_binding": {
    "execution_receipt_hash": "<sha256-hex of canonical signed receipt>",
    "execution_request_hash": "<sha256-hex of canonical execution request>",
    "execution_id":           "<execution_id>",
    "receipt_schema":         "mnde.execution_gate.receipt.v1"
  },

  "authority": {
    "authority_id":                 "<authority_id from bundle>",
    "authority_bundle_fingerprint": "<64-hex sha256 of root public key DER>",
    "signing_key_fingerprint":      "<64-hex sha256 of signing key DER>",
    "key_id":                       "<signing key_id in bundle>",
    "key_role":                     "result",
    "algorithm":                    "ED25519"
  },

  "signature_payload_hash": "<64-hex sha256>",

  "verifiable_signature": {
    "algorithm": "ED25519",
    "key_id":    "<signing key_id in bundle>",
    "value":     "<hex Ed25519 signature>"
  }
}
```

---

## Canonical Construction

Two distinct canonical payloads are computed to avoid circular hash inclusion.

### Payload hash body

Computed from the envelope with **both** `signature_payload_hash` and `verifiable_signature` removed:

```
payload_hash_body = canonicalizeJson(envelope \ {signature_payload_hash, verifiable_signature})
signature_payload_hash = sha256(payload_hash_body)
```

### Signature body

Computed from the envelope with **only** `verifiable_signature` removed (i.e., includes `signature_payload_hash`):

```
signature_body = canonicalizeJson(envelope \ {verifiable_signature})
verifiable_signature.value = ed25519_sign(signature_body, private_key)
```

This is non-circular: `signature_payload_hash` covers a body that does not yet contain it. The signature then covers a body that does contain the hash, so the hash cannot be swapped without breaking the signature. The Ed25519 operation signs the canonical UTF-8 bytes directly — not the hash of the hash.

`canonicalizeJson` from `shared/json.ts` is deterministic: it sorts all object keys recursively, rejects floats, and encodes to UTF-8.

---

## Trust Model

The only accepted `trust_model` value in v1 is `"offline-root-pinned"`. Any other value causes verification to fail with `SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED`.

Offline verification requires:
- The authority bundle (public material, can be distributed with the envelope)
- The trusted root fingerprint (out-of-band, pinned in the verifier's configuration — never embedded in the envelope)

The verifier derives both `authority_bundle_fingerprint` and `signing_key_fingerprint` independently from the bundle. Self-reported values in the envelope are checked as consistency assertions only.

---

## authority_chain_id

`authority_chain_id` is a stable authority lineage identifier. It identifies the governance lineage, not a specific key or bundle version. It survives key rotation within the same authority.

`authority_chain_id` must not be a 64-char lowercase hex string (to prevent confusion with fingerprints).

If the authority bundle carries `authority_chain_id`, the verifier checks it matches the envelope value. If the bundle does not carry it (older bundle format), verification still succeeds but the check is recorded as `AUTHORITY_CHAIN_ASSERTED_ONLY` in the output.

---

## Role Separation

Only keys with role `"result"` in the authority bundle may sign a signed result envelope. Receipt keys (role `"receipt"`), policy keys (role `"policy"`), and approval keys (role `"approval"`) are all rejected with `SIGNED_RESULT_KEY_NOT_FOUND` (key does not exist in the result role).

`findBundleKey(bundle, "result", keyId, signedAt)` enforces validity window and revocation at lookup time.

### Cross-role key uniqueness

The authority bundle verifier rejects any bundle where the same `key_id` or public key fingerprint appears in more than one role across receipt, policy, approval, and result roles. This is enforced both at build time (`buildAuthorityBundle`) and at verification time (`verifyAuthorityBundle`). Violation returns `SIGNED_RESULT_AUTHORITY_INVALID` from the signed result verifier.

---

## Request Hash Three-Way Binding

The verifier enforces that all three sources of `execution_request_hash` agree:

1. `receipt_binding.execution_request_hash`
2. `execution_result.execution_request_hash`
3. `signedReceipt.request_hash` (the verified, independent receipt)

Any mismatch returns `SIGNED_RESULT_RECEIPT_BINDING_INVALID`. This prevents an attacker from constructing a result that claims a different request than the one that was actually authorized, even if `receipt_binding` and `execution_result` internally agree on the wrong hash.

---

## Verification Sequence

The verifier (`verifySignedExecutionResult`) applies all checks in order. The first failure aborts and returns the relevant error code. All checks are fail-closed.

1. **Schema + trust_model** — `schema === "mnde.signed_execution_result.v1"` and `trust_model === "offline-root-pinned"` → `SIGNED_RESULT_SCHEMA_INVALID`, `SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED`
2. **signed_at format + clock skew** — valid ISO-8601; must not be more than `maxClockSkewMs` (default 300,000 ms) in the future → `SIGNED_RESULT_SCHEMA_INVALID`, `SIGNED_RESULT_SIGNED_AT_FUTURE`
3. **authority_chain_id format** — 1-128 safe chars, must not be a 64-char hex fingerprint → `SIGNED_RESULT_AUTHORITY_CHAIN_INVALID`
4. **authority object fields** — required fields present and well-formed; `key_role === "result"`; fingerprints are 64-char hex → `SIGNED_RESULT_AUTHORITY_INVALID`, `SIGNED_RESULT_KEY_ROLE_INVALID`, `SIGNED_RESULT_ALGORITHM_UNSUPPORTED`, `SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID`, `SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID`, `SIGNED_RESULT_KEY_NOT_FOUND`
5. **verifiable_signature fields** — required; `algorithm === "ED25519"`; `key_id` matches `authority.key_id` → `SIGNED_RESULT_SIGNATURE_MISSING`, `SIGNED_RESULT_ALGORITHM_UNSUPPORTED`, `SIGNED_RESULT_SIGNATURE_INVALID`
6. **signature_payload_hash format** — 64-char lowercase hex → `SIGNED_RESULT_HASH_FORMAT_INVALID`
7. **receipt_binding shape** — required fields present and well-formed → `SIGNED_RESULT_RECEIPT_BINDING_INVALID`
8. **Unsigned execution_result** — calls `verifyExecutionResult` on embedded result → `SIGNED_RESULT_RESULT_INVALID`
9. **Signed execution receipt** — `options.signedReceipt` required; calls `verifySignedExecutionReceipt` → `SIGNED_RESULT_RECEIPT_INVALID`
10. **Receipt binding — three-way request hash check** — `receipt_binding.execution_receipt_hash`, `execution_result.execution_receipt_hash`, `receipt_binding.execution_request_hash`, `execution_result.execution_request_hash` must all match the verified receipt; `execution_id` and `decision` must match → `SIGNED_RESULT_RECEIPT_BINDING_INVALID`
11. **Decision-status compatibility** — `REFUSE` receipt requires `NOT_EXECUTED` status → `SIGNED_RESULT_DECISION_STATUS_INVALID`
12. **STARTED freshness** — if `status === "STARTED"` and `ended_at` is absent and `maxOpenStatusAgeMs` is set: rejects when `now - signed_at > maxOpenStatusAgeMs` → `SIGNED_RESULT_STARTED_TOO_OLD`
13. **Authority bundle valid** — calls `verifyAuthorityBundle` (includes cross-role key uniqueness check); `authority_id` matches bundle → `SIGNED_RESULT_AUTHORITY_INVALID`, `SIGNED_RESULT_AUTHORITY_MISMATCH`
14. **Authority chain lineage** — if bundle carries `authority_chain_id`, must match envelope → `SIGNED_RESULT_AUTHORITY_CHAIN_INVALID`
15. **Result signing key** — `findBundleKey(bundle, "result", ...)` — role, validity window, revocation → `SIGNED_RESULT_KEY_NOT_FOUND`, `SIGNED_RESULT_KEY_REVOKED`, `SIGNED_RESULT_KEY_EXPIRED`
16. **Fingerprint consistency** — derived fingerprints match envelope assertions; malformed PEM is caught → `SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID`, `SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID`, `SIGNED_RESULT_KEY_MALFORMED`
17. **Signature payload hash** — recomputes `signature_payload_hash` → `SIGNED_RESULT_PAYLOAD_HASH_INVALID`, `SIGNED_RESULT_CANONICALIZATION_INVALID`
18. **Ed25519 signature** — verifies signature over canonical signature body → `SIGNED_RESULT_SIGNATURE_INVALID`, `SIGNED_RESULT_CANONICALIZATION_INVALID`
19. **Evidence safety** — recursive, case-insensitive scan of all evidence items for forbidden field names → `SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD`

---

## Decision-Status Compatibility

The verifier enforces the same decision-status rules as `mnde.execution_result.v2`:

| Decision | Permitted statuses |
|----------|--------------------|
| `ALLOW`  | `STARTED`, `SUCCEEDED`, `FAILED`, `PARTIALLY_SUCCEEDED`, `CANCELLED`, `ROLLED_BACK`, `ROLLBACK_FAILED`, `UNKNOWN` |
| `REFUSE` | `NOT_EXECUTED` only |

A `REFUSE` decision with any status other than `NOT_EXECUTED` is rejected at both builder and verifier.

Additional lifecycle constraints enforced by `validateExecutionResult`:

- `NOT_EXECUTED` status requires `effects` to be empty.
- `non_execution_reason` is only permitted on `NOT_EXECUTED` (required) and `CANCELLED` (optional). All other statuses must not include it.

---

## STARTED Freshness

When `status === "STARTED"` and `ended_at` is absent, the envelope represents an in-progress action. The verifier supports two optional freshness controls:

| Option | Default | Effect |
|--------|---------|--------|
| `maxClockSkewMs` | 300,000 ms | Rejects `signed_at` more than this far in the future relative to `now` |
| `maxOpenStatusAgeMs` | (unset) | If set, rejects STARTED results where `now - signed_at > maxOpenStatusAgeMs` |

Both are passed as verifier options. When `maxOpenStatusAgeMs` is not set, stale STARTED results are not rejected (the caller is responsible for policy enforcement).

---

## Identity Limitation

MNDe does not verify executor identity by itself. The executor identity in `execution_result.executor.identity_evidence` is asserted by the executor and recorded as-is. The signed result verifier always reports `identity_evidence: "ASSERTED_ONLY"`.

Production use requires a real identity binding layer such as OIDC, SAML, mTLS, or CI-native signed claims, applied before or alongside MNDe. See `executor.identity_evidence_asserted_only: true` in the embedded result.

---

## Timestamp Limitation

All timestamps in `execution_result` are executor-reported wall-clock values. MNDe does not verify that `started_at`, `ended_at`, or `recorded_at` are accurate. The `signed_at` field in the envelope is authority-asserted and is signed, but MNDe does not synchronize clocks with executors.

---

## Evidence Safety Rules

The verifier rejects any evidence item in the embedded execution result that contains one of the following forbidden field names anywhere in the evidence object tree (recursive walk, case-insensitive comparison):

```
uri, url, href, token, secret, password, authorization, bearer,
private_key, access_key, refresh_token, session_cookie,
raw_log, env, environment, stdout, stderr
```

The scan walks nested objects and arrays recursively. Key names are compared case-insensitively (`Authorization` matches `authorization`). Violation → `SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD`.

This check is enforced at the signed result verifier layer only, not in the `mnde.execution_result.v2` validator, as a defense-in-depth measure.

---

## Offline Verification Inputs

To verify a `mnde.signed_execution_result.v1` envelope offline, the verifier requires:

| Input | Source |
|-------|--------|
| `authorityBundle` | Distributed alongside the envelope, or from authority bundle export |
| `trustedRootFingerprint` | Out-of-band, pinned in verifier config — **never** from the envelope |
| `signedReceipt` | The original `mnde.execution_gate.receipt.v1` object |
| `now` | Caller-supplied ISO-8601 (for validity window checks) |
| `nowMs` | Optional number (ms); overrides `now` for freshness checks |
| `executorPublicKey` | Optional — enables executor signature verification in embedded result |
| `maxClockSkewMs` | Optional — max ms `signed_at` may be in the future (default 300,000) |
| `maxOpenStatusAgeMs` | Optional — max age in ms for STARTED results without `ended_at` |

No network access is required or performed during verification.

---

## Stable Error Codes

| Code | Meaning |
|------|---------|
| `SIGNED_RESULT_SCHEMA_INVALID` | `schema` missing/wrong, or `signed_at` is malformed |
| `SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED` | `trust_model` is not `"offline-root-pinned"` |
| `SIGNED_RESULT_SIGNED_AT_FUTURE` | `signed_at` exceeds `now + maxClockSkewMs` |
| `SIGNED_RESULT_AUTHORITY_CHAIN_INVALID` | `authority_chain_id` malformed, is a fingerprint, or mismatches bundle |
| `SIGNED_RESULT_AUTHORITY_INVALID` | Authority bundle fails `verifyAuthorityBundle` (includes cross-role key conflict) |
| `SIGNED_RESULT_AUTHORITY_MISMATCH` | `authority_id` in envelope does not match verified bundle |
| `SIGNED_RESULT_ALGORITHM_UNSUPPORTED` | Algorithm is not `"ED25519"` |
| `SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID` | `authority_bundle_fingerprint` malformed or mismatches derived fingerprint |
| `SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID` | `signing_key_fingerprint` malformed or mismatches derived fingerprint |
| `SIGNED_RESULT_KEY_NOT_FOUND` | Key not found in bundle result role (or `authority.key_id` missing) |
| `SIGNED_RESULT_KEY_REVOKED` | Signing key is in the bundle revocation list |
| `SIGNED_RESULT_KEY_EXPIRED` | Signing key is outside its validity window |
| `SIGNED_RESULT_KEY_MALFORMED` | Result signing key PEM in bundle is malformed |
| `SIGNED_RESULT_SIGNATURE_MISSING` | `verifiable_signature` is missing or lacks required fields |
| `SIGNED_RESULT_SIGNATURE_INVALID` | Ed25519 signature verification failed, or `key_id` mismatch |
| `SIGNED_RESULT_HASH_FORMAT_INVALID` | `signature_payload_hash` is not 64-char lowercase hex |
| `SIGNED_RESULT_PAYLOAD_HASH_INVALID` | Recomputed `signature_payload_hash` does not match envelope |
| `SIGNED_RESULT_CANONICALIZATION_INVALID` | Envelope could not be canonicalized |
| `SIGNED_RESULT_RECEIPT_BINDING_INVALID` | Receipt binding shape malformed, or three-way request hash mismatch |
| `SIGNED_RESULT_RECEIPT_INVALID` | `signedReceipt` not provided, or fails `verifySignedExecutionReceipt` |
| `SIGNED_RESULT_RESULT_INVALID` | Embedded execution result fails `verifyExecutionResult` |
| `SIGNED_RESULT_KEY_ROLE_INVALID` | `authority.key_role` is not `"result"` |
| `SIGNED_RESULT_DECISION_STATUS_INVALID` | `REFUSE` receipt with non-`NOT_EXECUTED` status |
| `SIGNED_RESULT_STARTED_TOO_OLD` | STARTED result without `ended_at` exceeds `maxOpenStatusAgeMs` |
| `SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD` | Evidence item (recursively) contains a forbidden field name |

Error codes are exported as `SIGNED_RESULT_ERROR_CODES` from `src/execution-gate/verify-signed-result.mjs` and checked against this table by `tests/test_signed_result_codes.mjs`.

---

## Known Limitations

- **Revocation freshness** — revocation is checked against the distributed authority bundle, not a live endpoint. The bundle may be stale. The verifier reports `revocation_freshness: "CURRENT_TO_BUNDLE"` to make this explicit.
- **Executor identity** — see Identity Limitation above.
- **Timestamps** — see Timestamp Limitation above.
- **authority_chain_id** — if the bundle predates this field, the chain ID in the envelope is recorded as `AUTHORITY_CHAIN_ASSERTED_ONLY` and is not verified against bundle state.
- **No cross-result ordering** — signed results do not commit to a sequence number or ordering relationship with other results for the same execution.
- **Evidence forbidden-field scan is name-based** — the scan walks key names recursively but does not inspect values. A field named `data` containing a token value would not be caught.
