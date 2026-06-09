# Security Review Checklist

Scan before publication:

- Secrets
- Tokens
- Certificates
- Private keys
- Credential files
- Internal URLs
- Developer emails
- Local filesystem paths
- Internal workflow notes
- Roadmap material
- Experimental code not required for testing

Required verification:

```powershell
npm run reviewer-kit
npm run test:receipt-verifier
```

Expected:

```text
FINAL VERDICT: PASS
PASS receipt verifier tests
```

