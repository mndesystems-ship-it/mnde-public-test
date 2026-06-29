# Cryptography and Key Management

This document summarizes cryptographic functionality present in the repository. It does not claim FIPS validation, regulatory compliance, or external cryptographic audit.

## Algorithms

| Use | Algorithm |
| --- | --- |
| Authority bundle signatures | Ed25519 |
| Receipt signatures and custody attestations | Ed25519 |
| Policy and approval signatures | Ed25519 |
| Signed execution result signatures | Ed25519 |
| Ledger entry signatures | Ed25519 |
| Canonical hashes, fingerprints, receipt hashes, policy hashes, result hashes, ledger hashes | SHA-256 |
| Constant-time byte comparison | Provider-exposed constant-time equality where used |

## Provider Boundary

Cryptographic primitives are centralized under:

- `src/crypto/provider.mjs`
- `src/crypto/node-provider.mjs`

The provider exposes the narrow primitive shape used by the current repository. WebCrypto support is not implemented.

## Key Roles

Authority bundles separate keys by role:

- Root key: signs authority bundles and key lifecycle updates.
- Receipt key: signs receipts and custody attestations.
- Policy key: signs policy bundles.
- Approval key: signs approval grants.
- Result key: signs execution results.
- Ledger key: signs execution ledger entries.

Tests reject cross-role misuse for signed results and ledger entries where implemented.

## Custody Modes

| Mode | Status | Notes |
| --- | --- | --- |
| `local-demo` | Default evaluation/demo mode | Ephemeral in-process keys; not production custody. |
| `file-backed-production` | Opt-in file-backed custody | Durable local key files outside the repo; not equivalent to KMS/HSM custody. |
| `external-signer` | Opt-in command signer | Allows signing outside the MNDe process through a strict stdin/stdout contract. |

See [docs/key-custody.md](docs/key-custody.md) and [docs/live-receipt-signing.md](docs/live-receipt-signing.md).

## Trust Anchors

Verifiers must obtain trusted root fingerprints out of band. A receipt, request, policy, or bundle cannot establish its own trust anchor.

## Rotation and Revocation

Implemented key lifecycle support includes:

- Rotation through `npm run authority -- rotate`.
- Revocation through `npm run authority -- revoke`.
- Validity windows.
- Root-signed bundle re-issue.
- Historical receipt verification when old keys remain valid for the signing time.

Revoked keys are rejected immediately, including within their former validity window.

## Assumptions

MNDe assumes:

- Private keys are protected by the operator's host and deployment process.
- The root private key receives stronger protection than active signing keys.
- Verifiers use a trusted root fingerprint from an independent channel.
- Operators keep private keys out of request content, logs, screenshots, support artifacts, and general backups.

## Missing Evidence

Before high-assurance production use, add:

- External cryptographic review.
- FIPS or regulated-environment analysis if required.
- KMS/HSM implementation or deployment runbook.
- Trust-anchor distribution procedure.
- Algorithm lifecycle and deprecation policy.
- Signed release provenance for verifier binaries and scripts.
