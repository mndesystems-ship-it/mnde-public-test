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

