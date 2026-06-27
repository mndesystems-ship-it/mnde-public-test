# mnde.execution_ledger_entry.v1

## Purpose

`mnde.execution_ledger_entry.v1` records a signed execution result in an ordered ledger. It does not authorize execution and it does not prove that an entry is the latest entry in a ledger. It proves that one entry was signed by a dedicated MNDe ledger key and, when a previous entry is supplied, that the entry links to it by hash and sequence number.

## Envelope Shape

```json
{
  "schema": "mnde.execution_ledger_entry.v1",
  "ledger_entry": {
    "ledger_id": "ledger-prod-deployments",
    "sequence_number": 1,
    "previous_entry_hash": null,
    "entry_type": "EXECUTION_RESULT",
    "execution_request_hash": "<64-hex request hash>",
    "receipt_hash": "sha256:<64-hex canonical signed receipt hash>",
    "result_hash": "sha256:<64-hex canonical signed result hash>",
    "policy_hash": "sha256:<64-hex policy hash or null>",
    "executor_id": "<executor asserted id>",
    "environment": "prod",
    "created_at": "<ISO-8601 UTC>",
    "metadata": {}
  },
  "entry_hash": "sha256:<64-hex canonical ledger_entry hash>",
  "authority": {
    "authority_id": "<authority_id from bundle>",
    "authority_bundle_fingerprint": "<64-hex root fingerprint>",
    "signing_key_fingerprint": "<64-hex ledger key fingerprint>",
    "key_id": "<ledger key id>",
    "key_role": "ledger",
    "algorithm": "ED25519"
  },
  "signature_payload_hash": "<64-hex>",
  "verifiable_signature": {
    "algorithm": "ED25519",
    "key_id": "<ledger key id>",
    "value": "<hex Ed25519 signature>"
  }
}
```

## Hashing Rules

`entry_hash` is:

```text
"sha256:" + sha256(canonicalizeJson(ledger_entry))
```

`signature_payload_hash` is:

```text
sha256(canonicalizeJson({ schema, ledger_entry, authority }))
```

The Ed25519 signature covers:

```text
canonicalizeJson({ schema, ledger_entry, authority, signature_payload_hash })
```

This keeps the payload hash non-circular while preventing a verifier from accepting a swapped hash.

## Authority Role

Authority bundles have five first-class signing roles:

```text
receipt, policy, approval, result, ledger
```

Only a key in `keys.ledger` may sign ledger entries. Bundle verification rejects duplicate key ids and duplicate public key fingerprints across roles, including `ledger`. Malformed public keys return structured invalid verdicts rather than throwing.

## Ledger Entry Rules

- `sequence_number` must be a positive integer.
- Sequence `1` requires `previous_entry_hash: null`.
- Sequence greater than `1` requires `previous_entry_hash` in `sha256:<64-hex>` form.
- `created_at` must be an ISO-8601 UTC timestamp.
- `entry_type` is `EXECUTION_RESULT` in v1.
- `metadata` recursively rejects forbidden evidence field names case-insensitively.

## Verification Order

The verifier fails closed and returns `{ valid: false, code, message, checks }`.

1. Envelope schema.
2. `ledger_entry` and `authority` presence.
3. Ledger entry structure, sequence, timestamp, and metadata field validation.
4. Optional `expectedLedgerId` and `expectedEnvironment`.
5. Future `created_at` check using `nowMs` and `maxClockSkewMs`.
6. Authority object shape, algorithm, and `key_role`.
7. Authority bundle verification against the caller-supplied `trustedRootFingerprint`.
8. Ledger key lookup in the `ledger` role, including validity window and revocation list from the supplied bundle.
9. Derived key and bundle fingerprint checks.
10. Signed receipt verification.
11. Signed execution result verification, with a request-hash preflight to classify receipt/result disagreement as `LEDGER_REQUEST_HASH_MISMATCH`.
12. Receipt, result, request, and policy hash binding.
13. `signature_payload_hash` recomputation.
14. Ed25519 signature verification.
15. Previous-entry verification and chain checks when `sequence_number > 1`.

For sequence greater than `1`, `previousLedgerEntry` is required by default. Set `requirePreviousEntry: false` only for isolated entry inspection where chain continuity is intentionally not proven.

## Error Codes

```text
LEDGER_SCHEMA_INVALID
LEDGER_ENTRY_REQUIRED
LEDGER_AUTHORITY_REQUIRED
LEDGER_FIELD_REQUIRED
LEDGER_SEQUENCE_INVALID
LEDGER_CREATED_AT_INVALID
LEDGER_CREATED_AT_FUTURE
LEDGER_AUTHORITY_INVALID
LEDGER_KEY_ROLE_INVALID
LEDGER_KEY_NOT_FOUND
LEDGER_KEY_EXPIRED
LEDGER_KEY_REVOKED
LEDGER_KEY_MALFORMED
LEDGER_METADATA_FORBIDDEN_FIELD
LEDGER_RECEIPT_INVALID
LEDGER_RESULT_INVALID
LEDGER_RECEIPT_HASH_MISMATCH
LEDGER_RESULT_HASH_MISMATCH
LEDGER_REQUEST_HASH_MISMATCH
LEDGER_POLICY_HASH_MISMATCH
LEDGER_GENESIS_PREVIOUS_HASH_INVALID
LEDGER_PREVIOUS_REQUIRED
LEDGER_PREVIOUS_INVALID
LEDGER_ID_MISMATCH
LEDGER_ENVIRONMENT_MISMATCH
LEDGER_SEQUENCE_GAP
LEDGER_PREVIOUS_HASH_MISMATCH
LEDGER_SIGNATURE_PAYLOAD_HASH_INVALID
LEDGER_SIGNATURE_INVALID
```

## Known Limitations

- Revocation freshness is only current to the supplied authority bundle. No live revocation lookup is performed.
- `created_at` is a signed wall-clock assertion, not an external timestamping authority.
- Executor identity remains asserted by the execution result layer.
- A single entry does not prove global latest state. Consumers need ledger storage or checkpoint policy to prevent replay of older valid entries.
- The verifier checks direct predecessor continuity only for the previous entry it is given.
