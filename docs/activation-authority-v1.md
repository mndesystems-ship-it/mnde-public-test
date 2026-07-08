# Activation Authority Specification v1 (`mnde.activation.v1`)

## 1. Abstract

An activation record is a cryptographically verifiable record of a software authority transition. It binds a specific verified release artifact to a customer-held trust root at the moment that release is granted execution authority.

Activation extends the pre-execution authorization model to the software lifecycle itself. Install, upgrade, and rollback are not filesystem operations; they are authority transitions, and each transition leaves signed evidence.

## 2. Core Invariant

> **No execution may proceed until the active authority transition has been verified.**

This invariant governs execution decisions (ERS receipts), software activation (this specification), upgrade, and rollback identically. A conforming runtime MUST NOT produce execution receipts unless a verified activation record designates the running release as the active execution authority, subject to the profile rules in section 9.

## 3. Trust Split

Three parties sign three different things. No party signs on behalf of another.

| Statement | Signer | Artifact |
|---|---|---|
| "This is what was shipped." | Vendor (MNDe) release key | Release manifest |
| "This is what I allowed to run." | Customer trust root (activation role key) | Activation record |
| "This is what executed." | Runtime receipt key | Execution receipts |

The vendor proves what it shipped. The customer proves what they allowed. Receipts prove what executed.

A verifier MUST NOT accept a vendor signature as evidence of activation, and MUST NOT accept an activation record as evidence of release authenticity. Each link is verified independently.

## 4. Terminology

`Release`: A versioned software artifact identified by the SHA-256 hash of its canonical distribution artifact.

`Release Manifest`: A vendor-signed document attesting a release (section 6).

`Activation`: The authority transition that designates one verified release as the active execution authority for an installation.

`Activation Record`: A signed object conforming to `mnde.activation.v1` recording one activation.

`Activation Chain`: The hash-linked sequence of activation records for one installation, beginning at genesis.

`Genesis Activation`: The first activation record of an installation; the first signed act of a newly created customer trust root.

`Active Execution Authority`: The release designated by the most recent verified activation record in the chain.

## 5. Threat Model

This specification is designed to detect:

- execution by a release that was never verified or activated
- substitution of the running release without a recorded transition
- forged or tampered activation records
- activation records signed by unknown or revoked keys
- reordering, truncation, or forking of the activation chain
- a second genesis record grafted onto an existing installation
- receipts attributed to the wrong activation (including across rollback to an identical binary)

Out of scope:

- compromise of the customer trust root private key
- compromise of the vendor release signing key
- a runtime that is already malicious lying about its own artifact hash (see section 12, Self-Measurement)
- kernel- or OS-level substitution of code outside the activation model

## 6. Release Manifest (`mnde.release.manifest.v1`)

Activation consumes a release manifest; this section defines the minimum an activation implementation requires. Full release-management semantics (build provenance, channel packaging, reproducibility) are specified separately.

| Field | Type | Required | Description |
|---|---:|---:|---|
| `schema_version` | string | yes | MUST be `mnde.release.manifest.v1`. |
| `release_version` | string | yes | Human-readable version, e.g. `1.2.4`. |
| `artifact_hash` | string | yes | SHA-256 of the canonical release artifact, lowercase hexadecimal. |
| `source_commit` | string | yes | VCS commit identifier the artifact was built from. |
| `built_at` | string | yes | RFC 3339 build timestamp. |
| `provenance` | object | optional | Build provenance attestation reference. |
| `vendor_authority_id` | string | yes | Vendor authority identifier. |
| `signature` | object | yes | Ed25519 signature by a vendor release key over the canonical manifest excluding `signature`. |

The canonical release artifact is one artifact. Distribution channels (npm, archive, container image, standalone binary) MUST package the identical canonical artifact. Channel packaging bytes MAY differ; the `artifact_hash` refers to the canonical artifact, not the channel wrapper.

## 7. Activation Record Format

An activation record is a JSON object. Canonicalization follows ERS v1 rules (sorted keys, UTF-8, no insignificant whitespace, duplicate keys rejected).

### 7.1 Fields

| Field | Type | Required | Description |
|---|---:|---:|---|
| `schema_version` | string | yes | MUST be `mnde.activation.v1`. |
| `activation_id` | string | yes | SHA-256 of the canonical record excluding `activation_id` and `signature`, lowercase hexadecimal. Deterministic and self-verifying. |
| `authority_id` | string | yes | Customer authority identifier (from the customer's `mnde.authority.bundle.v1`). |
| `kind` | string | yes | MUST be `genesis`, `upgrade`, `rollback`, or `reinstall`. |
| `previous_activation_id` | string or null | yes | `activation_id` of the previous record in the chain. MUST be `null` for `genesis` and MUST NOT be `null` otherwise. |
| `release_version` | string | yes | From the verified release manifest. |
| `artifact_hash` | string | yes | From the verified release manifest. |
| `release_manifest_hash` | string | yes | SHA-256 of the canonical release manifest, lowercase hexadecimal. |
| `vendor_authority_id` | string | yes | Vendor authority that signed the release manifest. |
| `verification` | object | yes | Verification evidence recorded at activation time (7.2). |
| `channel` | string | optional | Distribution channel the artifact was obtained through (`npm`, `github-release`, `oci`, `binary`). Informational. |
| `activated_at` | string | yes | RFC 3339 timestamp of the activation decision. |
| `signature` | object | yes | Ed25519 signature (7.3). |

### 7.2 `verification`

The activation record captures what was verified *before* activation, so the evidence survives even if inputs later change state (e.g. later revocation).

| Field | Type | Required | Description |
|---|---:|---:|---|
| `manifest_signature` | string | yes | MUST be `VERIFIED`. A record with any other value MUST NOT exist; activation MUST be refused instead. |
| `artifact_hash_match` | string | yes | MUST be `VERIFIED`. Same rule. |
| `vendor_root_fingerprint` | string | yes | SHA-256 fingerprint of the vendor root key the manifest chain was verified against. |
| `revocation_status_at_activation` | string | yes | `NOT_REVOKED` or `REVOKED`. Activation MUST be refused when `REVOKED`; the field exists so the recorded value is explicit, not implied. |
| `verifier_version` | string | yes | Version of the verifier that performed the checks. |

### 7.3 `signature`

| Field | Type | Required | Description |
|---|---:|---:|---|
| `algorithm` | string | yes | MUST be `ED25519`. |
| `key_id` | string | yes | MUST be listed in the `activation` role of the customer's authority bundle. |
| `public_key_fingerprint` | string | yes | SHA-256 fingerprint of the signing public key. |
| `signed_at` | string | yes | RFC 3339 signature timestamp. |
| `value` | string | yes | Signature over the canonical record excluding `activation_id` and `signature`, lowercase hexadecimal. |

The signature payload excludes `activation_id` because `activation_id` is derived from the identical payload; including it would be circular. A verifier MUST recompute `activation_id` and reject a record whose stored identifier does not match.

## 8. Authority Bundle Extension

`mnde.authority.bundle.v1` key roles are extended with an `activation` role, alongside `receipt`, `policy`, and `approval`:

```jsonc
"keys": {
  "receipt":    [ ... ],
  "policy":     [ ... ],
  "approval":   [ ... ],
  "activation": [ { "key_id": "...", "public_key": "...", "fingerprint": "...", "valid_from": "...", "valid_until": "..." } ]
}
```

This is a compatible extension: existing verifiers ignore unknown roles; activation verification requires the role to be present. Activation keys follow the same validity-window, rotation, and revocation rules as receipt keys. An activation record MUST fail verification if its `key_id` is absent from the `activation` role, revoked, or outside its validity window at `signed_at`.

The customer trust root signs the bundle; the bundle authorizes the activation key; the activation key signs transitions. Root private-key use remains rare (bundle issuance), consistent with existing custody practice.

## 9. Runtime Requirements

### 9.1 Preflight

Before accepting traffic, a conforming runtime MUST determine the active execution authority:

1. Load the configured activation record.
2. Verify it against the customer authority bundle (signature, key role, validity, revocation, recomputed `activation_id`).
3. Confirm chain integrity to the extent records are available (section 10).
4. Expose the verified `activation_id` to the receipt signing path.

Profile rules:

- `MNDE_PROFILE=production`: a verified activation record is REQUIRED. Absence or verification failure MUST refuse startup, fail-closed, with a distinct reason code (`ERR_ACTIVATION_MISSING`, `ERR_ACTIVATION_INVALID`, `ERR_ACTIVATION_UNTRUSTED`, `ERR_ACTIVATION_CHAIN`). There is no downgrade path.
- `MNDE_PROFILE` unset or `local`: an activation record MAY be absent. When absent, receipts carry no activation binding. When present, it MUST verify structurally — a present-but-invalid record fails startup in every profile. A record that verifies but was signed by a demo/local authority MUST be refused in production by the existing dev-key rules.

> **Deployment staging (current MNDe implementation).** A configured `MNDE_ACTIVATION_RECORD` is always fully verified, fail-closed, in every profile. The production *requirement* (refuse startup when no record is configured) is staged behind `MNDE_REQUIRE_ACTIVATION=1` until supported release/activation tooling ships — a requirement no deployment can satisfy through a supported path would only train operators to bypass it. Once the activation CLI exists, the requirement becomes the unconditional production default and this note is removed. This staging mirrors how custody signing and bearer caller-auth were introduced.

### 9.2 Receipt Binding

MNDe binds receipts to activations in the **custody attestation** of the signed-receipt envelope (`mnde.signed-receipt.v1`), not inside the inner receipt:

```json
"custody_attestation": {
  "schema_version": "mnde.custody.attestation.v1",
  "…": "…",
  "activation_id": "…64 hex…",
  "signed_at": "…"
}
```

Placement rules:

- `activation_id` is part of the signed attestation payload. Tampering with it invalidates the attestation signature.
- The inner receipt remains byte-for-byte untouched; decision replay semantics, canonicalization, and all existing hashes are unchanged. This keeps the binding a compatible ERS v1 extension.
- When the producing runtime is activation-bound (preflight verified a record), every attestation it produces MUST carry the verified `activation_id`. When it is not (local profile without a record), the field is omitted.
- Verifiers expose the attested `activation_id` in the verification result so audit tooling can join receipts to the activation chain.

Rollback consequence: when an installation activates 1.2.4 (activation A), then rolls back to 1.2.3 (activation B), receipts produced under each carry different `activation_id`s even where artifacts are identical. Evidence attributes decisions to transitions, not merely to binaries.

## 10. Activation Chain Rules

- Each record's `previous_activation_id` MUST equal the `activation_id` of the chain's prior record.
- Exactly one `genesis` record exists per `authority_id`. A verifier encountering two genesis records for one authority MUST report the chain as forked (`ERR_ACTIVATION_CHAIN_FORK`) and fail closed.
- `rollback` and `upgrade` records differ only in `kind` and subject; both are ordinary transitions appended to the chain. Rollback never rewrites or removes records.
- The chain is append-only. Implementations SHOULD store records in an append-only log alongside the receipt log and SHOULD include activation records in audit exports.

### 10.1 Genesis Rules

Genesis is the bootstrap case: before the first activation, no customer authority exists to sign one.

Required ordering:

1. `init` creates the customer trust root, role keys (including the `activation` role), and the signed authority bundle.
2. The genesis activation record is created and signed as the **first authorized act** of that new authority.
3. Only then may the runtime start.

Constraints a verifier MUST enforce on a genesis record:

- `kind` is `genesis` and `previous_activation_id` is `null`.
- `signed_at` is not earlier than the authority bundle's `issued_at`.
- The signing key's `valid_from` is not later than `signed_at`.

A genesis record self-asserts the birth of an installation; it cannot prove the machine was clean at birth. What genesis anchors is everything *after* it: any later transition that fails to chain back to this genesis is detectable.

## 11. Revocation Verdicts

Revocation status changes over time; a single boolean conflates two different questions. A conforming verifier MUST produce two distinct verdicts when evaluating a release or key against revocation data:

| Verdict | Question answered | Consequence |
|---|---|---|
| `REVOKED_AS_OF_EVENT` | Was the subject revoked at the time of the evaluated event (`signed_at` / `activated_at`)? | The event itself is untrustworthy. An activation performed after revocation MUST be reported invalid; receipts under it inherit `UNTRUSTED`. |
| `REVOKED_NOW` | Is the subject revoked at verification time? | Advisory for the operator: stop running / do not activate. Historical evidence produced before revocation remains verifiable and truthful. |

A receipt produced before its release or key was revoked is still a truthful receipt. A verifier MUST NOT collapse the two verdicts into one result field.

To support time-based verdicts, `revocation` entries in `mnde.authority.bundle.v1` and release revocation lists MAY be objects:

```jsonc
"revocation": [
  "legacy-key-id",                                                   // string form: treated as revoked since always
  { "key_id": "receipt-key-2", "revoked_at": "2026-08-01T00:00:00Z", "reason_code": "KEY_COMPROMISE" },
  { "artifact_hash": "…", "revoked_at": "2026-09-01T00:00:00Z", "reason_code": "RELEASE_DEFECT" }
]
```

The bare-string form remains valid and is interpreted conservatively (revoked for all time — both verdicts fire). Revocation data is distributed through the same signed, offline-verifiable channel as the artifacts it governs; this specification does not require any online endpoint.

## 12. What This Specification Does Not Prove

- **Self-measurement is not proof.** A runtime reporting its own artifact hash proves nothing if the runtime is already compromised. The activation record proves what the customer *verified and authorized*; binding the currently-executing bytes to that record is channel-dependent (a standalone binary is externally hashable; an npm install tree is checkable against the manifest by an external verifier) and always an external check, never a self-report.
- Activation does not prove the release is free of defects — only that it is the release the vendor shipped and the customer verified.
- Activation does not prove subsequent execution decisions were correct — receipts and replay verification do that.
- Compromise of the customer trust root allows forged activations, exactly as compromise of a receipt key allows forged receipts. Custody rules for activation keys follow existing key-custody practice.

## 13. Verification Procedure (Activation Record)

1. Parse the record as JSON; validate schema and required fields.
2. Canonicalize; reject duplicate keys.
3. Recompute `activation_id`; reject on mismatch.
4. Load the customer Authority Bundle; verify root fingerprint and bundle signature (existing bundle rules).
5. Locate `signature.key_id` in the `activation` role; enforce validity window and revocation at `signed_at` (both verdicts, section 11).
6. Verify the Ed25519 signature over the canonical payload.
7. Enforce kind/chain constraints (section 10) against available chain records.
8. Where the release manifest is available: recompute `release_manifest_hash`, verify the vendor signature chain, and evaluate release revocation with both verdicts.
9. Produce a verdict: `VERIFIED`, `INVALID` (structure, hashes, signature, chain), or `UNTRUSTED` (bundle, key, authority, revocation-as-of-event).

Any failure fails closed. `UNTRUSTED` MUST NOT be collapsed into `VERIFIED`.

## 14. Audit Answers

A verifier holding the activation chain, authority bundles, release manifests, and receipts can answer, offline:

- **Which release produced this decision?** Receipt `activation.activation_id` → activation record → `release_version` / `artifact_hash`.
- **Which trust root approved it?** Activation record `signature.key_id` → customer bundle → root fingerprint.
- **Was the release verified before activation?** Activation record `verification` block, signed at `activated_at`.
- **Was the release later revoked?** Release revocation data → `REVOKED_AS_OF_EVENT` vs `REVOKED_NOW` for the decision timestamp.

## 15. Versioning

`mnde.activation.v1` follows ERS versioning practice: compatible extensions MAY add optional fields; changes to canonicalization, hash semantics, signature payload, or chain rules require a new major version.
