# Security Model

MNDe is a pre-execution authority layer. Integrated tools ask MNDe before execution. MNDe returns a decision and produces verifiable evidence.

This document describes the security boundary for onboarding and auto-wiring.

## Protected Invariants

Onboarding must never weaken:

- deterministic decisions
- signed receipts
- receipt schema validation
- policy hashing
- replay verification
- trust-anchored authority verification
- fail-closed behavior
- refusal reasons
- offline verification

Onboarding code is not allowed to special-case reviewer flows or bypass authority checks.

## Authority Separation

The authority system owns decisions, receipts, signatures, replay, trust anchors, and policy hashes.

Onboarding owns local discovery, wiring plans, backups, restore, and policy drafts.

These are separate concerns. A successful onboarding run does not mean a policy is trusted or active. It means supported clients have been configured to route tool calls through MNDe.

## Auto-Wiring Threat Model

Auto-wiring introduces these risks:

- modifying the wrong config file
- corrupting a config file
- double-wrapping an already protected server
- losing the original upstream command
- leaving a user without an obvious restore path
- giving a false impression that all execution paths are protected

The implementation reduces those risks by using deterministic discovery, explicit `--apply`, backups, backup metadata, manifests, post-write verification, and `mnde uninstall`.

## Fail-Closed Expectations

Malformed configs are not wired.

Missing configs are not created.

Already-wrapped servers are skipped.

If post-write verification fails, the original config is restored.

If the sidecar is unavailable at execution time, the proxy must not forward the tool call as if it were allowed.

## Offline Behavior

Discovery, planning, policy drafting, backup, restore, and onboarding tests run without network access and without live MNDe services.

Receipt verification remains independently offline when the verifier has the trusted authority bundle for the receipt being checked.

## Remaining Limits

MNDe only protects integrated paths. It does not provide kernel enforcement or operating-system-wide process control.

Auto-wiring currently supports known MCP config formats. Unknown tools and unsupported clients require manual integration.

The generated policy draft is not production policy. It requires human review before use.

Production deployments still need authority operations such as key custody, rotation, revocation, identity binding, approval signing, and audit retention.

## Key Custody and Production Trust Roots

Signing material has to live somewhere. MNDe separates *where keys live* (custody) from *how evidence is verified* (the authority bundle), so verification never depends on the signer's environment.

- **Custody is pluggable and opt-in.** `MNDE_KEY_CUSTODY` selects the provider. Unset or `local-demo` (the default) uses ephemeral in-process keys for development and demos. `file-backed-production` is an opt-in mode that loads a published bundle plus role private keys from outside the codebase. Documented future slots — AWS KMS, Azure Key Vault, GCP KMS, HSM/PKCS#11 — implement the same interface so the private key never leaves the custody boundary.
- **Local-demo is not production custody.** Demo keys are ephemeral, self-asserted, and non-durable. They exist to exercise the sign/verify loop, not to anchor production trust.
- **Verification depends on the public authority bundle, not on custody.** A verifier holds the trusted root fingerprint out of band, confirms the `mnde.authority.bundle.v1` root matches it, checks the root-signed bundle signature, rejects a stale bundle, and looks up signing keys honoring validity windows and revocation. This is fully offline and identical regardless of which custody provider produced the signatures.
- **Private keys never need to leave the custody provider.** Bundles and receipts carry only public material. Private keys, tokens, and signing material are never written to receipts and never appear in logs or error messages — fail-closed errors reference paths and reasons only.
- **Fail closed.** Missing, malformed, unsigned, stale, or unverifiable custody configuration refuses rather than degrading to demo keys.

See [Key Custody](key-custody.md) for formats, configuration, and the threat model.
