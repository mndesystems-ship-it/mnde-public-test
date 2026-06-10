# Trust-Anchored Receipt Verification

Earlier public-test receipts embedded the public key needed to verify the receipt signature. That proved internal consistency, but it did not prove origin. A hostile reviewer could create a new keypair, sign a forged receipt, embed the matching public key, and pass a self-keyed verification model.

MNDe now verifies a trust chain:

```text
Root Authority Key
  -> signed authority manifest
  -> approved receipt signing key
  -> receipt signature
```

The verifier does not trust the receipt as the source of key authority.

## Authority Manifest

`authority/authority-manifest.json` contains the authority ID, root key fingerprint, active receipt keys, retired receipt keys, validity windows, and a root-authority signature over the manifest.

The trusted root public key is stored at:

```text
authority/root_authority_public.pem
```

The root private key is local-only and gitignored.

## Verification Flow

`node tools/verify-receipt.mjs receipt.json` performs:

1. Receipt schema validation.
2. Authority manifest loading.
3. Manifest signature verification using the trusted root public key.
4. `authority_id` lookup.
5. `key_id` lookup.
6. Receipt key validity-window check.
7. Receipt signature verification using the authority-approved public key.
8. Request hash, decision hash, policy hash, and replay determinism checks.

Unknown authority, unknown key, expired key, invalid manifest, or self-signed receipts fail closed.

## Key Rotation

The manifest supports multiple active keys, retired keys, and validity windows. Retired keys remain verifiable when the receipt `signed_at` time falls inside the key validity window. An active-only policy can reject retired keys.

## Buyer Proof

Run:

```powershell
npm run test:trust-anchor
```

The test proves:

- attacker self-signed receipt: FAIL
- authority-approved receipt: PASS
- modified `authority_id`: FAIL
- modified `key_id`: FAIL
- retired key valid at signing time: PASS
- retired key under active-only policy: FAIL
