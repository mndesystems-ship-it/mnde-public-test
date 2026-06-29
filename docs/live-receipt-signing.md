# Live Receipt Signing

MNDe live traffic has two receipt signing modes.

## Legacy Mode

Legacy mode is the default.

```text
MNDE_RECEIPT_SIGNING_MODE=legacy
```

If the variable is unset, MNDe behaves as legacy mode. Existing legacy receipts and existing verifier behavior are unchanged.

## Custody Mode

Custody mode is opt-in.

```text
MNDE_RECEIPT_SIGNING_MODE=custody
MNDE_KEY_CUSTODY=file-backed-production
MNDE_AUTHORITY_BUNDLE=/path/to/mnde.authority.bundle.json
MNDE_RECEIPT_SIGNING_KEY=/path/to/receipt.private.pem
MNDE_RECEIPT_KEY_ID=receipt-key-id
```

In custody mode, the sidecar signs the finished receipt payload after the decision engine has produced it. The decision engine does not import custody code and does not sign receipts.

The delivered receipt is wrapped in a custody envelope:

```json
{
  "schema_version": "mnde.signed-receipt.v1",
  "receipt": {
    "schema_version": "mnde.pe.receipt.v1"
  },
  "custody_attestation": {
    "schema_version": "mnde.custody.attestation.v1",
    "receipt_type": "mnde.pe.receipt.v1",
    "receipt_hash": "sha256...",
    "authority_bundle_fingerprint": "sha256...",
    "signed_at": "2026-06-14T00:00:00.000Z",
    "signing_key_id": "receipt-key-id",
    "signature": {
      "algorithm": "ED25519",
      "value": "base64url..."
    }
  }
}
```

The inner receipt is not mutated. Custody signing is additive.

## Fail-Closed Rules

When custody mode is selected, MNDe does not silently fall back to legacy signing.

The request is refused with `receipt: null` when any custody requirement fails:

- missing bundle
- invalid bundle
- stale bundle
- missing signing key
- expired signing key
- revoked signing key
- signing failure
- invalid custody provider configuration

MNDe-controlled custody-signing paths are designed and tested not to write configured private keys, bearer tokens, or signing material into receipts or error bodies. Operators should still treat stdout, stderr, and host logs as sensitive and keep secrets out of request content and external tooling.

## Offline Verification

Custody-signed receipts are verified with the unified verifier:

```bash
node tools/verify.mjs receipt.json --authority-bundle mnde.authority.bundle.json
```

Verification checks both layers:

1. The inner MNDe receipt.
2. The custody attestation against the published authority bundle.

If the authority bundle is missing, invalid, stale, revoked, or does not match the receipt, verification fails.

Legacy receipts do not require an authority bundle and continue through the legacy verification path.

## Production Caveat

`file-backed-production` is deployable, but it is not as strong as a managed KMS or HSM. It keeps key custody outside the codebase and supports published bundles, expiry, and revocation, but the private key still exists as a local file. Higher-assurance deployments should replace the file-backed provider with a KMS/HSM provider that implements the same custody interface.
