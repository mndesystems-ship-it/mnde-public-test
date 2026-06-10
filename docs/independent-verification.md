# Independent Receipt Verification

Run:

```powershell
npm run verify-receipt receipt.json
```

Expected:

```text
FINAL VERDICT: VERIFIED
```

This process requires:

- no running sidecar
- no running desktop
- no network access
- no live MNDe process

Verification is performed from the receipt contents and the public verification logic in this repository.

Receipt origin is verified through the signed authority manifest. The receipt identifies `authority_id` and `key_id`; the verifier only accepts the signature if that key is approved by the trusted MNDe authority manifest.
