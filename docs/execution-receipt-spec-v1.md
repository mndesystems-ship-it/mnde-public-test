# Execution Receipt Specification (ERS) v1

## 1. Abstract

An execution receipt is a cryptographically verifiable record of a pre-execution authorization decision. It binds an execution request, a policy reference, a deterministic decision output, pipeline trace data, and a signature produced by an authority-approved receipt signing key.

An execution receipt MAY represent either an `ALLOW` decision or a `REFUSE` decision. A conforming verifier MUST be able to distinguish receipt integrity failures from authority trust failures.

## 2. Goals

ERS v1 defines a receipt format and verification procedure that provides:

- decision integrity
- tamper detection
- independent verification
- replay verification
- authority validation
- offline verification

ERS v1 does not guarantee:

- that an allowed action actually executed
- that an external system correctly enforced the decision
- that the policy was appropriate for a deployment
- that a compromised root authority key remains trustworthy
- that runtime telemetry outside the receipt is complete
- that storage systems preserve receipts indefinitely

## 3. Terminology

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as normative requirement terms.

`Execution Request`: The structured input submitted for pre-execution authorization.

`Decision`: The pre-execution authorization result.

`ALLOW`: A decision that permits the proposed execution to continue.

`REFUSE`: A decision that denies the proposed execution before execution.

`Receipt`: A signed object conforming to ERS v1 that records an execution decision.

`Authority Bundle`: A verifier-provided bundle containing the trusted root authority public key and a signed authority manifest.

`Replay Verification`: Recomputing the deterministic decision from receipt contents and comparing the recomputed result with the stored decision.

`Trust Anchor`: The independently obtained root authority public key used to validate the authority manifest.

`Policy Hash`: A cryptographic hash identifying the policy document used during decision evaluation.

`Signature`: A cryptographic signature over the canonical receipt payload.

`Verifier`: Software that validates ERS receipts without trusting the producer, dashboard, server, operator, or receipt-provided key material.

## 4. Threat Model

ERS v1 is designed to detect:

- receipt modification
- forged decisions
- altered timestamps
- altered policy references
- altered request hashes
- altered decision hashes
- signature replacement
- authority substitution
- receipt signing with an unknown key
- receipt signing with an unknown authority
- manifest tampering

Out of scope:

- compromise of the trusted root authority private key
- malicious or defective policy authoring
- denial-of-service against the verifier
- loss or deletion of receipt storage
- user-interface deception outside the receipt
- execution bypasses outside the enforcement integration

## 5. Receipt Format

An ERS v1 receipt is a JSON object. The current MNDe schema identifier is `ecs.receipt.v2`. Implementations claiming ERS v1 compatibility MUST support this schema.

### 5.1 Top-Level Fields

| Field | Type | Required | Description |
|---|---:|---:|---|
| `schema_version` | string | yes | Receipt schema identifier. MUST be `ecs.receipt.v2` for this version. |
| `canonical_request` | string | yes | Canonical JSON string containing the request and policy inputs used for decision evaluation. |
| `request_hash` | string | yes | SHA-256 hash of `canonical_request`, lowercase hexadecimal. |
| `decision_output` | object | yes | Deterministic decision result. |
| `pipeline_trace` | object | yes | Layer-specific deterministic trace data. |
| `signature` | object | optional | Legacy HMAC signature metadata. MUST NOT be used as the origin trust anchor. |
| `verifiable_signature` | object | yes | Trust-anchored public signature metadata and value. |
| `receipt_id` | string | optional | Stable receipt identifier, if assigned by a producer. |
| `timestamp` | string | optional | Producer timestamp, if supplied. The verifier MUST NOT trust it unless signed. |
| `verifier_version` | string | optional | Verifier version that produced a verification report, not part of receipt origin. |

### 5.2 `decision_output`

| Field | Type | Required | Description |
|---|---:|---:|---|
| `decision` | string | yes | MUST be `ALLOW` or `REFUSE`. |
| `decision_hash` | string | yes | SHA-256 hash of the canonical decision hash payload. |
| `request_hash` | string | yes | MUST equal the top-level `request_hash`. |
| `reason_code` | string | yes | Machine-readable reason, such as `OK_ALLOW` or `ERR_FORBIDDEN_ACTION_IN_PARAMETERS`. |
| `policy_version` | string | yes | Policy version used for decision evaluation. |
| `policy_hash` | string | yes | SHA-256 policy hash. |
| `execution_id` | string | yes | Deterministic execution identifier. |
| `key_set_version` | string | yes | Receipt key-set version identifier. |
| `total_cost_usd` | string | yes | Decimal cost string for the evaluated request. |
| `allowed_cost_usd` | string | yes | Decimal cost string allowed by the decision. |
| `prevented_cost_usd` | string | yes | Decimal cost string prevented by the decision. |

### 5.3 `pipeline_trace`

`pipeline_trace` MUST contain `preflight`, `orbit`, `arm`, and `ramona` objects.

`preflight` MUST contain:

- `layer`
- `request_hash`
- `policy_hash`
- `policy_version`

`orbit` MUST contain:

- `layer`
- `decision`
- `reason_code`
- `validation_hash`

`arm` MUST contain:

- `layer`
- `decision`
- `reason_code`
- `projected_total_cost_cents`
- `allowed_cost_cents`
- `prevented_cost_cents`
- `execution_id`

`ramona` MUST contain:

- `layer`
- `decision`
- `reason_code`
- `runtime_hash`

### 5.4 `verifiable_signature`

| Field | Type | Required | Description |
|---|---:|---:|---|
| `algorithm` | string | yes | MUST be `ED25519` for ERS v1. |
| `authority_id` | string | yes | Authority identifier. MUST match the signed authority manifest. |
| `key_id` | string | yes | Receipt signing key identifier. MUST be listed in the signed authority manifest. |
| `public_key_fingerprint` | string | yes | SHA-256 fingerprint of the authority-approved receipt public key. |
| `signed_at` | string | yes | RFC 3339 timestamp indicating when the receipt signature was produced. |
| `value` | string | yes | Signature over the canonical receipt payload, lowercase hexadecimal. |

The receipt MUST NOT be accepted merely because it contains a public key matching its signature. Public key authority MUST come from the Authority Bundle.

## 6. Canonicalization Rules

ERS v1 canonicalization uses deterministic JSON serialization:

- Objects are serialized with keys sorted lexicographically.
- Arrays preserve element order.
- Strings use JSON string escaping.
- Numbers MUST be safe integers.
- Booleans and `null` use standard JSON literals.
- UTF-8 encoding MUST be used for hash and signature input.
- No insignificant whitespace is included.
- Duplicate JSON keys MUST be rejected before canonicalization.

`request_hash` is:

```text
SHA-256(UTF8(canonical_request))
```

`decision_hash` for normal pipeline decisions is:

```json
{
  "request_hash": "...",
  "policy_hash": "...",
  "decision": "ALLOW|REFUSE",
  "reason_code": "...",
  "policy_version": "...",
  "execution_id": "...",
  "projected_total_cost_cents": 0,
  "allowed_cost_cents": 0,
  "prevented_cost_cents": 0
}
```

The object above MUST be canonicalized before hashing. Incompatible canonicalization invalidates verification.

Sidecar-level refusal receipts that do not contain a full execution request MAY use a canonical refusal envelope. For such receipts, the decision hash payload is:

```json
{
  "request_hash": "...",
  "decision": "REFUSE",
  "reason_code": "..."
}
```

## 7. Signature Requirements

ERS v1 requires an Ed25519 signature in `verifiable_signature`.

The signature payload is the canonical receipt object excluding:

- `signature`
- `verifiable_signature`

The verifier MUST:

1. Load the Authority Bundle.
2. Verify the authority manifest signature using the trust anchor.
3. Locate `authority_id`.
4. Locate `key_id`.
5. Confirm the receipt `signed_at` timestamp falls within the key validity window.
6. Confirm the receipt key fingerprint matches the authority manifest.
7. Verify the receipt signature with the authority-approved receipt public key.

Any signature verification failure MUST fail closed.

## 8. Authority Bundle Requirements

An Authority Bundle contains:

- trusted root authority public key
- signed authority manifest

The authority manifest MUST contain:

- `authority_id`
- `authority_name`
- `root_key_fingerprint`
- `active_keys`
- `retired_keys`
- `manifest_signature`

Each receipt key entry MUST contain:

- `key_id`
- `public_key`
- `public_key_fingerprint`
- `valid_from`
- `valid_to`

The authority manifest MUST be signed by the root authority private key. Verifiers MUST verify the manifest before trusting any receipt key.

Receipts generated on one system can be independently verified on another system only when the verifier has the corresponding trusted Authority Bundle. Unknown authority IDs and unknown key IDs MUST fail closed.

Implementations SHOULD support multiple active keys and retired keys. Retired keys MAY verify old receipts if the receipt `signed_at` timestamp falls within the retired key validity interval. Active-only verification policies MAY reject retired keys.

## 9. Verification Procedure

A conforming verifier MUST perform the following steps:

1. Parse the receipt as JSON.
2. Validate receipt schema and required fields.
3. Parse and canonicalize `canonical_request`.
4. Recompute `request_hash`.
5. Validate `decision_output.request_hash`.
6. Recompute `decision_hash`.
7. Recompute or validate `policy_hash`.
8. Load the Authority Bundle.
9. Verify the authority manifest signature using the root public key.
10. Locate `authority_id`.
11. Locate `key_id`.
12. Validate key validity for `signed_at`.
13. Verify the Ed25519 receipt signature.
14. Perform replay verification.
15. Produce a verdict.

Required verdicts:

- `VERIFIED`: Schema, hashes, authority, signature, and replay all pass.
- `INVALID`: Receipt structure, hashes, signature, or replay fail.
- `UNTRUSTED`: Authority bundle, authority ID, key ID, or key validity fail.

Implementations MAY expose more detailed sub-results, but MUST NOT collapse `UNTRUSTED` into `VERIFIED`.

## 10. Replay Verification

Replay verification recomputes the deterministic decision from receipt contents.

Replay inputs:

- `canonical_request`
- policy document embedded in `canonical_request`, if present
- deterministic pipeline logic
- sidecar refusal envelope, if applicable

Replay outputs:

- recomputed `decision`
- recomputed `reason_code`
- recomputed `decision_hash`
- recomputed cost fields
- recomputed policy identifiers

Matching criteria:

- `request_hash` MUST match.
- `decision` MUST match.
- `reason_code` MUST match.
- `decision_hash` MUST match.
- `policy_hash` MUST match when policy data is present.
- cost fields MUST match for normal pipeline receipts.

A replay mismatch MUST fail verification.

## 11. Failure Conditions

A verifier MUST fail verification for:

- malformed JSON
- unsupported receipt version
- missing required fields
- invalid field types
- duplicate JSON keys in canonical inputs
- invalid canonicalization
- request hash mismatch
- decision hash mismatch
- policy hash mismatch
- invalid signature
- missing Authority Bundle
- invalid authority manifest signature
- authority mismatch
- unknown authority ID
- unknown key ID
- expired or not-yet-valid key
- receipt signed by a key not authorized by the manifest
- replay mismatch

## 12. Security Considerations

The Authority Bundle is security-critical. A verifier MUST obtain the trust anchor through an independent trusted channel. A receipt-provided public key MUST NOT establish authority.

Authority operators SHOULD maintain key rotation procedures. Old receipts SHOULD remain verifiable through retired key entries whose validity windows include the receipt signing time.

Receipt storage SHOULD preserve the original receipt bytes or canonical JSON object. Storage systems SHOULD prevent unauthorized modification and deletion.

Offline verification requires that the verifier possess:

- receipt file
- verifier implementation
- trusted root public key
- signed authority manifest

Long-term audit retention SHOULD include preservation of historical authority manifests or retired key metadata sufficient to validate old receipts.

## 13. Example ALLOW Receipt

The following example is illustrative. Hex strings are shortened.

```json
{
  "schema_version": "ecs.receipt.v2",
  "canonical_request": "{\"execution_request\":{\"actor\":{\"user_id\":\"TESTER-001\"},\"request_id\":\"reviewer-kit-allow-read-status\",\"tool_calls\":[{\"priority\":1,\"tool\":\"read_status\"}]},\"policy_document\":{\"policy_version\":\"policy.v1\",\"schema_version\":\"ecs.policy.v1\"},\"pricing_data\":{\"gpu_hour_cents\":500}}",
  "request_hash": "1f7e522f22acff953adb6d24ddfbae2b0161756deba52025c166bfd2fdb70604",
  "decision_output": {
    "decision": "ALLOW",
    "decision_hash": "cb88a841ba51bd07902d5c357109f64e8f06cfd451fd9ab9fffd3c74a6c34593",
    "request_hash": "1f7e522f22acff953adb6d24ddfbae2b0161756deba52025c166bfd2fdb70604",
    "reason_code": "OK_ALLOW",
    "total_cost_usd": "5.00",
    "allowed_cost_usd": "5.00",
    "prevented_cost_usd": "0.00",
    "policy_version": "policy.v1",
    "policy_hash": "acbd4b9d8339f32aa4273caa73ed49995c9c4ca7e9df9b62ceb14286c1b8ca87",
    "execution_id": "reviewer-kit-allow-read-status",
    "key_set_version": "receipt-key-set-v1"
  },
  "pipeline_trace": {
    "preflight": {
      "layer": "preflight",
      "request_hash": "1f7e522f22acff953adb6d24ddfbae2b0161756deba52025c166bfd2fdb70604",
      "policy_hash": "acbd4b9d8339f32aa4273caa73ed49995c9c4ca7e9df9b62ceb14286c1b8ca87",
      "policy_version": "policy.v1"
    },
    "orbit": {
      "layer": "orbit",
      "decision": "ALLOW",
      "reason_code": "OK_ORBIT",
      "validation_hash": "d709d898175990b456aff970f588dacbeec3cad94d41caf8b998a56a920f404c"
    },
    "arm": {
      "layer": "arm",
      "decision": "ALLOW",
      "reason_code": "OK_ARM",
      "projected_total_cost_cents": 500,
      "allowed_cost_cents": 500,
      "prevented_cost_cents": 0,
      "execution_id": "reviewer-kit-allow-read-status"
    },
    "ramona": {
      "layer": "ramona",
      "decision": "ALLOW",
      "reason_code": "OK_RAM0NA",
      "runtime_hash": "4a36d19a9b1609ddd67cbfb5c9f6ab2a4e5e3f590a3c588f20219dd442db5e99"
    }
  },
  "signature": {
    "algorithm": "HMAC-SHA256",
    "key_id": "reviewer-kit-hmac-key",
    "value": "0464695bfbbd45500e3577f37f1bc2ee9e511360032315c9632ba4354acb9d63"
  },
  "verifiable_signature": {
    "algorithm": "ED25519",
    "authority_id": "mnde-public-test-local",
    "key_id": "receipt-key-local",
    "public_key_fingerprint": "f3dd3a09596ff42603c09bc2b2d569f68af7428f718a69c25b0d6f272ff14dcb",
    "signed_at": "2026-06-10T00:58:12.194Z",
    "value": "327afb85290d515ef1c6fdf5e391fb6009a548ac3d867574b5e577271e690a2ff57bca7864a7ec1462d6c16c74c94cabedf3091c0985d143aa84c8f63c739f0e"
  }
}
```

## 14. Example REFUSE Receipt

The following example is illustrative. Hex strings are shortened.

```json
{
  "schema_version": "ecs.receipt.v2",
  "canonical_request": "{\"execution_request\":{\"actor\":{\"user_id\":\"TESTER-001\"},\"request_id\":\"reviewer-kit-refuse-recursive-delete\",\"tool_calls\":[{\"parameters\":{\"script\":\"rm -rf /tmp/workspace\"},\"priority\":1,\"tool\":\"recursive_delete\"}]},\"policy_document\":{\"policy_version\":\"policy.v1\",\"schema_version\":\"ecs.policy.v1\"},\"pricing_data\":{\"gpu_hour_cents\":500}}",
  "request_hash": "7698b5ddde96a4a35be89180c100d98b401b2b5762e2d2fd7541b2f8bab4e73e",
  "decision_output": {
    "decision": "REFUSE",
    "decision_hash": "101166da268ca2d1033dd59ba33c7da96f9e812d47ab226a2a6c8f052974ab41",
    "request_hash": "7698b5ddde96a4a35be89180c100d98b401b2b5762e2d2fd7541b2f8bab4e73e",
    "reason_code": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
    "total_cost_usd": "5.00",
    "allowed_cost_usd": "5.00",
    "prevented_cost_usd": "0.00",
    "policy_version": "policy.v1",
    "policy_hash": "acbd4b9d8339f32aa4273caa73ed49995c9c4ca7e9df9b62ceb14286c1b8ca87",
    "execution_id": "reviewer-kit-refuse-recursive-delete",
    "key_set_version": "receipt-key-set-v1"
  },
  "pipeline_trace": {
    "preflight": {
      "layer": "preflight",
      "request_hash": "7698b5ddde96a4a35be89180c100d98b401b2b5762e2d2fd7541b2f8bab4e73e",
      "policy_hash": "acbd4b9d8339f32aa4273caa73ed49995c9c4ca7e9df9b62ceb14286c1b8ca87",
      "policy_version": "policy.v1"
    },
    "orbit": {
      "layer": "orbit",
      "decision": "REFUSE",
      "reason_code": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
      "validation_hash": "e88e9ee2b77f60c92950d43b9820017874972d3d162fd07e2e9a15b87259a0dd"
    },
    "arm": {
      "layer": "arm",
      "decision": "REFUSE",
      "reason_code": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
      "projected_total_cost_cents": 500,
      "allowed_cost_cents": 500,
      "prevented_cost_cents": 0,
      "execution_id": "reviewer-kit-refuse-recursive-delete"
    },
    "ramona": {
      "layer": "ramona",
      "decision": "REFUSE",
      "reason_code": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
      "runtime_hash": "4a36d19a9b1609ddd67cbfb5c9f6ab2a4e5e3f590a3c588f20219dd442db5e99"
    }
  },
  "signature": {
    "algorithm": "HMAC-SHA256",
    "key_id": "reviewer-kit-hmac-key",
    "value": "425a7b7f17b35841e33bb500a65aa9ddf6e2e76f16535b773eb6bd0ecd8943b0"
  },
  "verifiable_signature": {
    "algorithm": "ED25519",
    "authority_id": "mnde-public-test-local",
    "key_id": "receipt-key-local",
    "public_key_fingerprint": "f3dd3a09596ff42603c09bc2b2d569f68af7428f718a69c25b0d6f272ff14dcb",
    "signed_at": "2026-06-10T03:00:53.586Z",
    "value": "4bea977f8f076a4591994628381c6486613b3a303a5c84fdc592fbc8b5847f5488b921de999affd8e4a9b635ef3b42014e047a29cc94ebe623bd1377cc3a040a"
  }
}
```

## 15. Verifier Conformance Requirements

An implementation claiming `Execution Receipt Specification v1 Compatible`:

- MUST parse and validate ERS v1 receipt schema.
- MUST reject malformed receipts.
- MUST implement the canonicalization rules in this specification.
- MUST recompute request, policy, and decision hashes.
- MUST verify the authority manifest signature using an independent trust anchor.
- MUST reject unknown authorities.
- MUST reject unknown receipt signing keys.
- MUST reject keys outside their validity window.
- MUST verify the Ed25519 receipt signature using the authority-approved key.
- MUST perform replay verification.
- MUST fail closed on verification errors.
- SHOULD distinguish `INVALID` from `UNTRUSTED`.
- SHOULD support retired keys for historical receipts.
- MAY expose implementation-specific diagnostic detail.

## 16. Versioning

ERS versions use the format:

```text
ERS v<major>
```

Receipt schema versions are independent strings. ERS v1 currently specifies `ecs.receipt.v2`.

Compatible extensions MAY add optional fields. Compatible extensions MUST NOT change canonicalization, hash semantics, authority validation, or signature input for existing fields.

Breaking changes MUST use a new ERS major version.

## 17. References

- Ed25519 digital signatures
- SHA-256 cryptographic hashing
- JSON canonicalization
- Public key trust anchors
- Key rotation and retired-key verification
- Deterministic replay verification
