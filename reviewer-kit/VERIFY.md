MNDe Reviewer Verification

Run:

```powershell
npm run reviewer-kit
```

Pass criteria:

- Environment verification returns `VERDICT: PASS`
- ALLOW example stores `receipts/allow-receipt.json`
- REFUSE example stores `receipts/refuse-receipt.json`
- Both receipts return `VERDICT: PASS`
- Final verdict is `PASS`
