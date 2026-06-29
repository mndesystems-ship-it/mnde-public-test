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

Loads a published bundle plus role private keys from the filesystem — keys live outside the codebase, are durable, and can be rotated and revoked. This is the file-backed custody mode and the reference for how a managed-KMS/HSM provider plugs in.

| Variable | Purpose |
| --- | --- |
| `MNDE_KEY_CUSTODY=file-backed-production` | Selects the provider |
| `MNDE_AUTHORITY_BUNDLE` | Path to the published `mnde.authority.bundle.v1` |
| `MNDE_RECEIPT_SIGNING_KEY` | Path to the receipt private key (PEM) |
| `MNDE_RECEIPT_KEY_ID` | Receipt key id in the bundle (defaults to first) |
| `MNDE_POLICY_SIGNING_KEY` / `MNDE_POLICY_KEY_ID` | Optional policy signing key |
| `MNDE_APPROVAL_SIGNING_KEY` / `MNDE_APPROVAL_KEY_ID` | Optional approval signing key |

Missing, malformed, or non-matching configuration **fails closed** — `createCustody()` returns `{ ok: false, reason }` and never silently falls back to demo keys.

## Tier 2: external-signer custody

`file-backed-production` keeps the receipt signing key on disk. Higher-assurance deployments usually want the private key in hardware — an HSM — where it cannot be copied. External-signer custody supports that pattern **without a vendor SDK and without leaving Ed25519**: MNDe delegates signing to a command you supply.

Enable it with:

```bash
MNDE_RECEIPT_SIGNING_MODE=external-signer
MNDE_AUTHORITY_BUNDLE=/etc/mnde/authority.bundle.json
MNDE_EXTERNAL_SIGNER_CMD='["/usr/bin/your-signer","--slot","0"]'   # JSON array = no shell, no injection
MNDE_EXTERNAL_SIGNER_KEY_ID=receipt-1                              # must exist in the bundle
MNDE_EXTERNAL_SIGNER_PUBLIC_KEY=/etc/mnde/receipt.pub.pem          # must match the bundle key
# optional:
MNDE_EXTERNAL_SIGNER_TIMEOUT_MS=5000                              # default 5000
```

**Signer contract** — your command:

- reads the **exact canonical bytes to sign on stdin**,
- writes a **64-byte Ed25519 signature, hex-encoded, on stdout**,
- exits `0` on success; any nonzero exit means failure.

MNDe runs the command with argv parsing (never a shell), and **verifies every returned signature against the configured public key before accepting it**. It fails closed on timeout, nonzero exit, stderr-only failure, invalid hex, wrong length, or a signature that does not verify. The private key never enters the MNDe process.

The command is the integration point for any HSM — examples, none hardcoded:

- **PKCS#11 HSM** (YubiHSM2, Thales Luna): a small wrapper around `pkcs11-tool` / your HSM CLI that signs with the on-device Ed25519 key.
- **SoftHSM**: the same wrapper against a software token, for testing the path without hardware.
- **Any custom signer** that meets the contract above.

In `MNDE_PROFILE=production`, external-signer is accepted only after the pre-flight confirms the signer command runs, the key id is present, active, and not revoked in the bundle, the configured public key matches the bundle key, and a **live self-test signature verifies**.

## Production trust-root pre-flight (`MNDE_PROFILE`)

MNDe must never enter live enforcement while signing with development keys. A deterministic pre-flight runs once before the decision server accepts traffic (`src/authority-signing/preflight.mjs`, `assertTrustRoot`).

| `MNDE_PROFILE` | Behavior |
| --- | --- |
| unset / `local` (default) | Local/demo mode. Legacy signing or `local-demo` custody allowed. Existing behavior unchanged; custody is not loaded. |
| `production` | Live enforcement. MNDe **refuses to start** unless a valid production custody provider is configured and no demo/dev key material is in use. |

In `production` the pre-flight fails closed — with a human-readable, actionable message — when:

| Reason code | Condition |
| --- | --- |
| `ERR_TRUST_ROOT_REQUIRES_CUSTODY` | `MNDE_RECEIPT_SIGNING_MODE` is not `custody` or `external-signer` (legacy signing uses dev keys) |
| `ERR_TRUST_ROOT_DEMO_CUSTODY` | with `MNDE_RECEIPT_SIGNING_MODE=custody`, `MNDE_KEY_CUSTODY` is not `file-backed-production` (e.g. `local-demo`) |
| `ERR_TRUST_ROOT_DEV_KEY` | a configured key/bundle path points at repo dev material (`shared/receipt_keys/`, `.mnde-test/`, `authority/`, `*receipt_signing_private.pem`, `demo`/`local-demo` paths), or the bundle is a demo bundle (`mnde-local-*` authority) |
| `ERR_TRUST_ROOT_SIGNER_SELFTEST` | with `MNDE_RECEIPT_SIGNING_MODE=external-signer`, the live self-test signature did not verify |
| `ERR_CUSTODY_*` | the configured custody provider does not load/verify (missing/malformed/stale bundle, missing/expired/revoked key, key/public-key mismatch, signer unavailable) — see table above |

There is **no automatic downgrade**: if production is selected and custody is unusable, MNDe exits non-zero rather than signing with fallback keys.

### Required environment for production

```bash
MNDE_PROFILE=production
MNDE_RECEIPT_SIGNING_MODE=custody
MNDE_KEY_CUSTODY=file-backed-production
MNDE_AUTHORITY_BUNDLE=/etc/mnde/authority.bundle.json   # published, signed, NOT in the repo
MNDE_RECEIPT_SIGNING_KEY=/etc/mnde/receipt-signing.key.pem
MNDE_RECEIPT_KEY_ID=<receipt key id present in the bundle>   # optional; defaults to first
```

Verified by `npm run test:trust-root` (production-without-custody refuses; production-with-demo refuses; dev-key path refuses; demo bundle refuses; valid custody starts and serves; local mode unchanged).

### Hardware / KMS signing

Use **external-signer custody** (above) to keep the private key in an HSM or PKCS#11 device — that is the supported, vendor-neutral path today, and it does not require a vendor SDK in MNDe. Dedicated in-process providers (`aws-kms`, `azure-key-vault`, `gcp-kms`) remain possible behind the same four-method interface (`signReceipt`, `signPolicy`, `signApproval`, `getPublicBundle`), but note most cloud KMS do not sign Ed25519; the external-signer command is how you bridge to whatever holds your key.

## Bootstrapping the trust root

To create a production trust root:

```bash
npm run authority:init -- --out /secure/path/outside/the/repo --authority-id your-org-prod
```

This generates the long-lived **root** key and the first **receipt signing** key, builds a root-signed `mnde.authority.bundle.v1`, verifies it, and writes four files (private keys `0600`). It refuses to write inside the repository, refuses to overwrite, and refuses a `demo`/`local` authority id.

- `root.key.pem` — the root private key. It signs the bundle and key rotations only; it is **not** needed on the serving host. Move it offline / into an HSM or escrow.
- `receipt-signing.key.pem` — the only secret the sidecar needs.
- `authority.bundle.json` — publish this; have verifiers pin its **root fingerprint** out of band.

The command prints the root fingerprint and the exact `MNDE_PROFILE=production` environment to run the sidecar. Rotate and revoke afterward with `npm run authority -- rotate|revoke`.

## Publishing the public bundle

```bash
npm run authority-bundle:export -- --out ./mnde.authority.bundle.json
```

Writes only public material and prints the **root fingerprint** to distribute as the trust anchor. The command refuses to export a bundle it cannot itself verify.

## Key rotation, retirement & revocation

Production trust roots must be operable. The `mnde-authority` CLI (`npm run authority -- <rotate|revoke> ...`, library `src/custody/lifecycle.mjs`) re-issues an authority bundle using only the **root private key** — signing keys' private material is never needed. The output is verified before it is written; on any error nothing is written and the exit code is non-zero (fail-closed). The input bundle is never overwritten unless `--force`, so the prior bundle is retained for rollback.

**Rotate** (scheduled rotation, or replacing a soon-to-expire key):

```bash
npm run authority -- rotate \
  --bundle authority.bundle.json --root-key root.key.pem \
  --key-id receipt-2 --generate --new-private-out receipt-2.key.pem \
  --out authority.bundle.v2.json
# or supply an externally-held public key (HSM/KMS): --new-public receipt-2.pub.pem
```

Rotation adds the new key (active from `now`) and **retires** the prior key by closing its validity window at `now`. The result:

- Receipts signed by the old key **before** rotation **stay verifiable** (their `signed_at` is still inside the old key's window) — offline verification of historical evidence is preserved.
- The old key **cannot sign** anything dated at/after rotation (`KEY_EXPIRED`).
- The new key signs and verifies after rotation.
- Use `--role policy|approval` to rotate other roles; `--no`-retire is available via the library (`retire:false`) for an overlap window.

**Revoke** (compromise — immediate, irreversible distrust):

```bash
npm run authority -- revoke \
  --bundle authority.bundle.json --root-key root.key.pem \
  --key-id receipt-1 --out authority.bundle.v2.json
```

A revoked key id is rejected **immediately, even inside its validity window** (`KEY_REVOKED`), including for receipts it already signed — a compromised key's receipts are no longer trustworthy.

Every re-issue advances `issued_at` (monotonic ordering) and stays **root-signed and offline-verifiable**. Distribute the new bundle the same way as the initial one; verifiers need no change.

### Operational model

- **Rotation cadence:** rotate signing keys on a fixed schedule and immediately on suspicion. Keep each prior bundle file (versioned by `issued_at`).
- **Revocation:** revoke + redistribute the new bundle; verifiers pick up the revocation as soon as they have the newer bundle (governed by `not_after`/`maxAgeMs`).
- **Rollback:** redeploy the previous bundle file (rotation/revoke never overwrite it without `--force`).
- **Disaster recovery:** the **root private key** is the recovery anchor — store it offline (HSM/escrow), separate from signing keys. Retain the published bundle history. Losing the root means a trust-anchor rollover (new root + out-of-band redistribution of the new fingerprint), which is why the root must be protected above all else.
- **Key storage:** generated private keys are written `0600` (POSIX; Windows uses ACLs). For production, hold signing keys in `file-backed-production` outside the repo, or in a future HSM/KMS provider where the private key never leaves the boundary — the lifecycle commands are provider-agnostic and only need the root to re-sign.

## Threat model and guarantees

- **Secret exposure controls.** MNDe-controlled custody, receipt, and error paths are designed and tested not to emit configured private keys, tokens, or signing material. Operators must still keep secrets out of request content, external tooling, screenshots, and general host logs.
- **Trust is out of band.** A verifier trusts the root by a fingerprint it already holds. A bundle cannot vouch for itself, and a request/receipt cannot inject a trust anchor.
- **Tamper-evident.** Any change to a bundle or a signed payload breaks verification with a specific reason code.
- **Rotation and revocation.** Operable via the `mnde-authority` CLI (above): multiple keys per role with validity windows support rotation; the revocation list disables a key immediately, even within its window. Re-issued bundles stay root-signed and offline-verifiable.
- **Stale-bundle rejection.** `not_after` (and an optional `maxAgeMs`) bound how long a published bundle is honored.

### Out of scope (today)

- Live sidecar receipts can be custody-signed when `MNDE_RECEIPT_SIGNING_MODE=custody` and `MNDE_KEY_CUSTODY=file-backed-production` are set. Legacy mode remains the default.
- Rotation/revocation are operator-driven (CLI). No automated rotation scheduler, transparency log, or distributed revocation propagation.
- Managed-KMS/HSM providers are interface slots, not implementations; the lifecycle layer is already provider-agnostic and ready for them.

See [Live Receipt Signing](live-receipt-signing.md) for the sidecar integration path.
