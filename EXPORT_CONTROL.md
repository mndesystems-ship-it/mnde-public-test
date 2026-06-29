# Export Control and Sanctions

MNDe includes cryptographic signing and verification functionality. This document records the current private beta posture. It does not determine export classification and is not legal advice.

## Current Status

- No export-control classification is documented in this repository.
- No sanctions screening process is implemented in this repository.
- No country-specific distribution controls are implemented in code.
- No hosted service account system exists in this repository.
- The software is evaluation-only under [LICENSE](LICENSE).

## Cryptography Touchpoints

MNDe uses cryptography for:

- Ed25519 signatures on authority bundles, receipts, approvals, policies, signed execution results, and ledger entries.
- SHA-256 hashes and fingerprints for canonical artifacts, bundles, receipts, policy evidence, and subject derivation.

See [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md), [docs/key-custody.md](docs/key-custody.md), and [SECURITY.md](SECURITY.md).

## Distribution Rule for Private Beta

Before distributing MNDe outside an approved private beta audience:

1. Identify distribution countries and recipients.
2. Review export-control classification requirements for the software and cryptographic functionality.
3. Check applicable sanctions and restricted-party requirements.
4. Confirm whether source distribution, binary distribution, or hosted access changes the analysis.
5. Document approval for the distribution channel.

## Prohibited Uses

Evaluators may not use MNDe to:

- Violate sanctions or export-control restrictions.
- Support unauthorized access to third-party systems.
- Evade technical or legal controls.
- Provide production services without a separate written agreement.

## Missing Evidence

Before enterprise, government, or broad public distribution, add:

- Export classification memo or decision record.
- Sanctions screening process for distribution.
- Release distribution approval checklist.
- Maintainer owner for export/sanctions review.
- Contract language for restricted use where appropriate.
