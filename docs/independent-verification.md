# Independent Receipt Verification

Run:

```bash
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

Verification is performed from the receipt contents, public verification logic in this repository, and the trusted authority bundle available to the verifier.

Receipt origin is verified through a signed authority manifest. The receipt identifies `authority_id` and `key_id`; the verifier only accepts the signature if that key is approved by a trusted authority manifest.

Committed example receipts use the demo authority in `authority/`. Reviewer-kit receipts use the local tester authority generated under `.mnde-test/authority/`.
