# Production Readiness Notes

This document separates public tester evidence from production deployment requirements.

## What the Public Tester Proves

The public tester demonstrates:

- fresh-clone setup
- local tester identity initialization
- pre-execution `ALLOW` and `REFUSE` decisions through the reviewer kit
- signed receipt generation
- offline receipt verification
- replay determinism
- trust-anchored receipt origin validation
- tamper detection
- hostile input refusal behavior
- executor-level blocking before a destructive demo action runs

## What the Public Tester Does Not Prove

The public tester does not prove:

- kernel-level enforcement
- operating-system-wide process control
- prevention of arbitrary processes that bypass integration
- production authentication configuration
- production key custody
- production availability guarantees
- suitability of the demo denylist policy for a real deployment

MNDe is demonstrated here as a pre-execution authority layer. Integrated systems enforce MNDe decisions by asking before execution and running only after `ALLOW`.

## Local Test Authority vs Production Authority

The repository contains two authority paths:

- `authority/`: committed demo authority for example receipts and documentation fixtures
- `.mnde-test/authority/`: generated local tester authority for reviewer-kit receipts

`npm run tester:init -- TESTER-001` creates or reuses the local tester authority. It must not modify the committed demo authority or invalidate committed example receipts.

Production deployments require a stable published authority bundle distributed through a trusted channel. Independent verification depends on the verifier having that trusted root public key and signed authority manifest.

### Runtime profile and trust-root pre-flight (`MNDE_PROFILE`)

MNDe will not enter live enforcement while signing with development keys. A deterministic pre-flight (`src/authority-signing/preflight.mjs`) runs once before the decision server accepts traffic:

- `MNDE_PROFILE` unset or `local` (default): demo/local mode — legacy signing or `local-demo` custody allowed; behavior unchanged; custody is not loaded.
- `MNDE_PROFILE=production`: MNDe **refuses to start** unless `MNDE_RECEIPT_SIGNING_MODE=custody`, `MNDE_KEY_CUSTODY=file-backed-production`, a valid published authority bundle + signing key are configured, and no demo/dev key material is detected. Failures are fail-closed with distinct `ERR_TRUST_ROOT_*` reason codes and an actionable message; there is no automatic downgrade to legacy/dev-key signing.

Required production environment and reason codes are documented in [Key Custody](key-custody.md). Verified by `npm run test:trust-root`.

## Executor Integration Model

MNDe does not execute arbitrary tools by itself. An integrated executor or tool wrapper must:

1. Receive the proposed action.
2. Submit it to `POST /v1/decisions`.
3. Persist the returned receipt.
4. Execute only when the decision is `ALLOW`.
5. Return a denied result when the decision is `REFUSE`.

If a tool bypasses this integration path, MNDe has not evaluated that action.

## Demo Policy Behavior

The public tester uses demo policy logic to make the pre-execution decision flow visible. The demo policy is intentionally small and deterministic. It is not presented as a complete production policy engine.

Receipt generation, authority validation, offline verification, replay verification, and tamper detection are separate proof areas from the demo policy behavior.

## Policy Engine Implementation Slice

The repository now includes an initial MNDe Policy Engine implementation slice under:

```text
src/policy-engine/
```

It is covered by:

```text
npm run test:policy-engine
```

This slice currently supports request validation, policy validation, deterministic rule evaluation, `ALLOW` / `REFUSE` decisions, reason codes, conflict resolution where `REFUSE` wins, no-match refusal, invalid-input refusal, basic policy hashing, basic authority chain hashing, basic decision hashing, and first-pass authority checks for missing or expired authority.

It is not yet the full production PE described in `docs/mnde-policy-engine-production-spec-v1.md`. Signed policy verification, authority signature verification, revocation checking, threshold signer enforcement, simulation mode, lockdown mode, and full production conformance vectors remain production work.

## Fail-Closed Expectations

Production integrations should fail closed when:

- MNDe is unreachable
- a decision response is malformed
- the receipt is missing
- receipt persistence fails when durability is required
- signature or authority validation fails
- replay verification fails
- authentication or authorization is missing

Fail-closed behavior should be tested at the executor boundary.

## Authentication Considerations

Production use should define:

- which actors may submit decisions
- which actors may activate policy
- which actors may export receipts or audit bundles
- token lifetime and refresh behavior
- expected unauthenticated behavior
- audit logging for administrative actions

The public tester may use local test identity and local authority material. That is not a production authentication model.

## Key Rotation Approach

Production authority manifests should support:

- multiple active receipt signing keys
- retired keys for historical receipts
- validity windows
- manifest signatures from the root authority
- documented rotation procedures

Old receipts should remain verifiable when the receipt signing time falls inside the retired key validity window.

## Deployment Considerations

Before production use, evaluate:

- sidecar lifecycle management
- service supervision and restart policy
- log retention
- receipt durability mode
- backup and recovery for receipt stores
- policy release process
- integration tests for every protected executor
- network exposure and local binding rules

## Audit Retention Considerations

Long-term audit packages should preserve:

- receipts
- trusted authority manifests
- root authority public keys
- policy documents or policy hashes
- verifier version
- replay verification reports
- environment and tester/operator identifiers where appropriate

Receipts copied to another machine remain verifiable only when the verifier has the matching trusted authority bundle.
