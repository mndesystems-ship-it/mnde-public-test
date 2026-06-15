# Key Custody

MNDe signs decisions, policies, and approvals. Those signatures are only worth what the signing keys are worth. This page describes how MNDe holds signing material, how a verifier trusts it, and what is in and out of scope today.

The guiding split: **custody** (where private keys live and how signing happens) is separate from **verification** (how a third party checks evidence offline). Verification depends only on a published public bundle, never on the signer's environment. That is what lets a receipt be verified on a machine that has never seen MNDe's keys.

## The authority bundle: `mnde.authority.bundle.v1`

A custody provider publishes a single, signed, public artifact. It contains **only public material**.

```jsonc
{
  "schema_version": "mnde.authority.bundle.v1",
  "authority_id": "mnde-prod",
  "issued_at": "2026-06-14T00:00:00.000Z",
  "not_after":  "2027-06-14T00:00:00.000Z",   // bundle staleness window
  "root_key": {
    "key_id": "prod-root",
    "public_key": "-----BEGIN PUBLIC KEY----- ...",
    "fingerprint": "<sha256 of the SPKI DER>"   // the out-of-band trust anchor
  },
  "keys": {
    "receipt":  [ { "key_id": "...", "public_key": "...", "fingerprint": "...", "valid_from": "...", "valid_until": "..." } ],
    "policy":   [ ... ],
    "approval": [ ... ]
  },
  "revocation": [ "key_id-that-is-no-longer-trusted" ],
  "signature": { "algorithm": "ED25519", "value": "<root signature over the canonical bundle>" }
}
```

- The **root key** signs the rest of the bundle. A verifier trusts the root by its **fingerprint**, supplied out of band — never from the bundle, a request, or a receipt.
- **Signing keys** are grouped by role (`receipt`, `policy`, `approval`), each with a key id and a validity window.
- **Revocation** lists key ids that must be rejected even inside their validity window.
- Private keys are **never** present.

## Offline verification

Given a bundle and a trusted root fingerprint, verification is fully offline and deterministic:

1. Schema is `mnde.authority.bundle.v1`.
2. `root_key.fingerprint` equals the published public key's actual fingerprint (no swap).
3. `root_key.fingerprint` equals the verifier's trusted anchor (`UNTRUSTED_ROOT` otherwise).
4. The bundle signature verifies under the root public key over the canonical bundle (`BUNDLE_SIGNATURE_INVALID` on any tamper).
5. The bundle is not stale: `now <= not_after`, and optionally within a caller `maxAgeMs` (`BUNDLE_STALE` otherwise).

To verify a receipt/policy/approval signature, the key is looked up by role + key id at the signing time:

- key id present in that role (`UNKNOWN_KEY` otherwise),
- key id not revoked (`KEY_REVOKED` otherwise),
- signing time within the key's window (`KEY_EXPIRED` otherwise),
- signature verifies under that public key (`SIGNATURE_INVALID` otherwise).

All reason codes are distinct so a verifier can tell *why* something failed.

## Custody providers

Selected with `MNDE_KEY_CUSTODY`. Default is `local-demo`.

### `local-demo` (default)

Ephemeral in-process Ed25519 keys with a self-asserted root. Use it to develop and demo the complete sign/verify loop offline.

> **Local-demo is not production custody.** The keys are in memory, the root is not externally anchored, and nothing survives a restart. Do not anchor production trust on it.

### `file-backed-production` (opt-in)

Loads a published bundle plus role private keys from the filesystem — keys live outside the codebase, are durable, and can be rotated and revoked. This is a real deployable mode and the reference for how a managed-KMS/HSM provider plugs in.

| Variable | Purpose |
| --- | --- |
| `MNDE_KEY_CUSTODY=file-backed-production` | Selects the provider |
| `MNDE_AUTHORITY_BUNDLE` | Path to the published `mnde.authority.bundle.v1` |
| `MNDE_RECEIPT_SIGNING_KEY` | Path to the receipt private key (PEM) |
| `MNDE_RECEIPT_KEY_ID` | Receipt key id in the bundle (defaults to first) |
| `MNDE_POLICY_SIGNING_KEY` / `MNDE_POLICY_KEY_ID` | Optional policy signing key |
| `MNDE_APPROVAL_SIGNING_KEY` / `MNDE_APPROVAL_KEY_ID` | Optional approval signing key |

Missing, malformed, or non-matching configuration **fails closed** — `createCustody()` returns `{ ok: false, reason }` and never silently falls back to demo keys.

### Future provider slots (not implemented)

`aws-kms`, `azure-key-vault`, `gcp-kms`, `hsm-pkcs11`. Each implements the same four-method interface — `signReceipt`, `signPolicy`, `signApproval`, `getPublicBundle` — so the private key never leaves the managed boundary. Verification does not change: it still runs offline against the public bundle.

## Publishing the public bundle

```bash
npm run authority-bundle:export -- --out ./mnde.authority.bundle.json
```

Writes only public material and prints the **root fingerprint** to distribute as the trust anchor. The command refuses to export a bundle it cannot itself verify.

## Threat model and guarantees

- **No secrets in evidence or logs.** Private keys, tokens, and signing material never appear in bundles, receipts, logs, or error messages. Fail-closed errors reference paths and reasons only.
- **Trust is out of band.** A verifier trusts the root by a fingerprint it already holds. A bundle cannot vouch for itself, and a request/receipt cannot inject a trust anchor.
- **Tamper-evident.** Any change to a bundle or a signed payload breaks verification with a specific reason code.
- **Rotation and revocation.** Multiple keys per role with validity windows support rotation; the revocation list disables a key immediately, even within its window.
- **Stale-bundle rejection.** `not_after` (and an optional `maxAgeMs`) bound how long a published bundle is honored.

### Out of scope (today)

- Live sidecar receipts can be custody-signed when `MNDE_RECEIPT_SIGNING_MODE=custody` and `MNDE_KEY_CUSTODY=file-backed-production` are set. Legacy mode remains the default.
- No automated rotation scheduler, transparency log, or distributed revocation propagation.
- Managed-KMS/HSM providers are interface slots, not implementations.

See [Live Receipt Signing](live-receipt-signing.md) for the sidecar integration path.
