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

## Export-safe policy fields

The export refuses any top-level `policy_document` field that is not a known structural field (`policy_id`, `schema_version`, `version`, `state`, `rules`) unless the policy author lists it in `policy_document.export_safe_fields`. This is the authoritative control over what policy content is published; the credential/secret scan is defense-in-depth, not the primary gate. Nested values are still deep-scanned for secret-like material.

## Reviewer notes (intentional trust-model trade-offs)

- **Provenance trust without the historical check is issuer-asserted.** A receipt's `policy_bundle_provenance` is included in the receipt's signed payload and is rejected unless its `policy_hash` matches the replayed policy, but it is only tied to an independently signed policy bundle when you run the optional historical verification (`--policy-bundle --policy-authority-bundle --policy-root-fingerprint`, which requires a pinned root fingerprint). Without it, the provenance is as trustworthy as the receipt signer. This is by design — run the historical check for independent assurance.
- **A rollback authorization binds to `(policy_id, from_serial, to_serial)`, not to a specific bundle digest.** One approval-signed grant authorizes activating any validly policy-key-signed bundle at that serial. This is the intended two-key model: the policy key authenticates the bundle's content, and a separate approval key authenticates the serial rollback. Grants are single-use (a consumed `authorization_id` is recorded in state) and time-bounded.
