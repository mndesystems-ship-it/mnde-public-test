# Signed Policy Bundle Evidence

This export contains the public evidence needed to verify a policy-engine receipt against the original signed policy bundle. It does not include private keys, credentials, or signing material.

## Export

```text
npm run policy-bundle:evidence:export -- --receipt receipt.json --policy-bundle policy-bundle.json --policy-authority-bundle policy-authority-bundle.json --state policy-bundle-state.json --out review-evidence
```

The export folder contains:

- `receipt.json`
- `policy-bundle.json`
- `policy-authority-bundle.json`
- `trusted-root-fingerprint.txt`
- `serial-floor-snapshot.json` when a valid enforce-mode state file was supplied

The serial-floor snapshot contains only the enforce-mode serial high-water marks. It excludes activation events and bundle digests.

## Offline Verification

```text
node tools/verify.mjs review-evidence/receipt.json --policy-bundle review-evidence/policy-bundle.json --policy-authority-bundle review-evidence/policy-authority-bundle.json --policy-root-fingerprint <contents of review-evidence/trusted-root-fingerprint.txt>
```

Expected result:

```text
FINAL VERDICT: VERIFIED
```

When the optional historical bundle is supplied, verification checks the signed policy bundle, bundle identity, serial, policy hash, policy signing key, and rollback authorization reference. Without the optional bundle arguments, policy receipt verification keeps its existing replay and receipt-signature behavior.
