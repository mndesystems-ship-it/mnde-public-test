# Authority Bundle

An authority bundle is the public trust document used to verify custody-signed MNDe receipts offline.

It contains public keys, validity windows, revocation state, and a root signature. It must not contain private keys, bearer tokens, credentials, or signing material.

## Format

```json
{
  "schema_version": "mnde.authority.bundle.v1",
  "authority_id": "mnde-prod",
  "issued_at": "2026-06-14T00:00:00.000Z",
  "not_after": "2027-06-14T00:00:00.000Z",
  "root_key": {
    "key_id": "prod-root",
    "public_key": "-----BEGIN PUBLIC KEY-----...",
    "fingerprint": "sha256..."
  },
  "keys": {
    "receipt": [
      {
        "key_id": "receipt-key-1",
        "public_key": "-----BEGIN PUBLIC KEY-----...",
        "fingerprint": "sha256...",
        "valid_from": "2026-06-14T00:00:00.000Z",
        "valid_until": "2027-06-14T00:00:00.000Z"
      }
    ],
    "policy": [],
    "approval": []
  },
  "revocation": [],
  "signature": {
    "algorithm": "ED25519",
    "value": "base64url..."
  }
}
```

## Verification Rules

A verifier must:

- verify the root fingerprint against the trusted fingerprint it already holds
- verify the bundle signature
- reject stale bundles after `not_after`
- reject revoked keys
- reject expired keys
- reject unknown keys
- reject receipts whose attestation fingerprint does not match the bundle

## Portability

A custody-signed receipt is independently verifiable only when the verifier has the trusted authority bundle for that receipt. Unknown bundles and unknown keys fail closed.

## Rotation

Multiple receipt keys may be present in the bundle at the same time. Old receipts remain verifiable when their signing key is still present and was valid at the receipt signing time. Revoked keys fail even inside their validity window.
