# Security Policy

MNDe Public Test is an evaluation-only pre-execution authority layer. This file documents the security posture that is supported by the repository today. It does not claim compliance, certification, or production hardening.

## Supported Versions

| Version | Support status |
| --- | --- |
| `0.1.x` / current `main` | Supported for private beta evaluation and security reports. |
| Older commits, forks, and modified builds | Not supported unless the private beta coordinator agrees in writing. |

## Security Model Overview

MNDe receives a proposed action before the caller executes it, evaluates the request against configured policy, returns `ALLOW` or `REFUSE`, and emits verifiable evidence for routed decisions. Integrated callers are responsible for asking MNDe before execution and running only after `ALLOW`.

Supporting documentation:

- [docs/security-model.md](docs/security-model.md)
- [docs/production-readiness.md](docs/production-readiness.md)
- [docs/execution-firewall-overview.md](docs/execution-firewall-overview.md)
- [docs/integration-guide.md](docs/integration-guide.md)
- [docs/key-custody.md](docs/key-custody.md)
- [docs/live-receipt-signing.md](docs/live-receipt-signing.md)

## Security Boundaries

MNDe's enforcement boundary is cooperative. It applies only to calls routed through an MNDe integration such as the executor, MCP server, MCP proxy, or another wrapper that calls the decision API before execution.

MNDe does not provide kernel enforcement, operating-system-wide process control, endpoint management, malware prevention, or protection for code paths that bypass MNDe.

## Supported Threat Model

The current repository is designed and tested for these cases:

- A routed tool call receives `REFUSE` and the integrated executor or proxy does not run or forward the tool call.
- A decision receipt, signed receipt, signed result, or ledger entry is tampered with and verification fails.
- Authority bundles, signing keys, and trust roots are missing, expired, revoked, stale, malformed, or substituted, and verification or production pre-flight fails closed.
- Policy-engine requests are malformed, unsupported, unmatched, or conflict with a `REFUSE` rule, and the decision fails closed.
- Sidecar caller authentication is enabled and an unauthenticated or wrong-token caller is rejected before evaluation.
- Custody signing is configured but cannot complete, and the sidecar refuses rather than silently downgrading to demo signing.

Representative tests:

- `npm run test:executor`
- `npm run test:mcp`
- `npm run test:mcp-proxy`
- `npm run test:policy-engine`
- `npm run test:policy-receipt`
- `npm run test:production-signing`
- `npm run test:signed-execution-result`
- `npm run test:execution-ledger`
- `npm run test:trust-root`
- `npm run test:sidecar-pe`

## Out-of-Scope Threats

The current public test does not claim to address:

- Actions never submitted to MNDe.
- Compromised host operating systems or malicious local administrators.
- Kernel, EDR, sandbox, or hypervisor enforcement.
- Network perimeter security.
- Production IAM, SSO, mTLS, or full enterprise identity binding.
- Full policy coverage for a specific organization.
- Managed KMS/HSM providers, except through the external-signer command interface.
- Automated key rotation scheduling or distributed revocation propagation.
- Regulatory compliance such as SOC 2, ISO 27001, HIPAA, FedRAMP, ADA, or WCAG conformance.

## Vulnerability Reporting Process

Report suspected vulnerabilities through the private beta coordinator or the security contact assigned with your evaluation access. If no security contact has been assigned, do not send exploit details in a public issue, chat, or forum. Request a private reporting channel first.

Include:

- A short summary of the issue.
- Affected commit, version, platform, and configuration.
- Reproduction steps.
- Expected and actual behavior.
- Logs, receipts, or proof artifacts with secrets removed.
- Whether the issue affects confidentiality, integrity, availability, authorization, receipt verification, key custody, or bypass of routed enforcement.

Do not include private keys, bearer tokens, credentials, unrelated local files, browser history, or customer data.

## Security Contact

Primary contact: the private beta coordinator or maintainer channel that provided access to this repository.

If the project later publishes a dedicated security email or advisory intake, this file should be updated before public distribution.

## Expected Response Timeline

These are private beta targets, not service-level commitments:

| Severity | Initial acknowledgement target | Triage target |
| --- | --- | --- |
| Critical | 1 business day | 3 business days |
| High | 2 business days | 5 business days |
| Medium | 5 business days | 10 business days |
| Low | 10 business days | Next planned review cycle |

## Responsible Disclosure Policy

Please give maintainers a reasonable opportunity to investigate and remediate before public disclosure. Do not exploit a vulnerability beyond what is necessary to demonstrate it. Do not access, modify, delete, or exfiltrate data that is not yours. Do not disrupt other testers or systems.

MNDe is evaluation-only. Participation in the private beta does not grant permission to attack third-party systems.

## Security Update Policy

Security fixes should:

- Document the affected behavior and supported threat model.
- Add or update regression tests where the issue is testable.
- Preserve fail-closed behavior.
- Avoid weakening verification, signature, custody, policy, or receipt semantics.
- Update security documentation when the boundary or assumptions change.

Critical and high-severity fixes should be released with a clear note describing impact, affected versions, mitigation, and verification steps.

## Key Management Overview

MNDe separates custody from verification:

- Custody controls where private signing material lives and how signatures are produced.
- Verification uses public authority bundles and trust anchors supplied out of band.

Current custody modes:

- `local-demo`: default development/demo mode with ephemeral in-process keys. Not production custody.
- `file-backed-production`: opt-in file-backed custody with bundle and private key paths outside the codebase. Stronger than demo custody, but not equivalent to KMS/HSM custody.
- `external-signer`: opt-in command interface for signers that hold private keys outside the MNDe process.

See [docs/key-custody.md](docs/key-custody.md) for configuration, rotation, revocation, and caveats.

## Cryptographic Algorithms Used

The repository currently uses:

- Ed25519 signatures for authority bundles, receipts, policy trust, approvals, signed results, and ledger entries.
- SHA-256 for canonical hashes, fingerprints, receipt hashes, policy hashes, result hashes, ledger hashes, and subject derivation.
- Constant-time equality for provider-exposed byte comparison where applicable.

The provider primitive shape is intentionally narrow. WebCrypto support is not implemented in this public test.

## Security Assumptions

MNDe assumes:

- The caller integrates MNDe before execution and honors `REFUSE`.
- The sidecar URL, token configuration, authority bundle, and trust root are controlled by the operator.
- The verifier obtains the trusted root fingerprint through an independent channel.
- Private keys, tokens, and sensitive configuration are protected by the host and deployment environment.
- Local logs, receipts, and generated authority material are protected according to the operator's filesystem permissions and retention policy.

## What MNDe Guarantees

For routed and correctly integrated calls, MNDe is designed and tested to:

- Return a deterministic `ALLOW` or `REFUSE` decision for supported request shapes.
- Preserve `REFUSE` at the executor/proxy boundary so the routed action is not run or forwarded.
- Emit receipts for successful decision paths where receipt creation is configured and succeeds.
- Verify receipts offline when the verifier has the required authority evidence.
- Fail closed for malformed requests, invalid policy, invalid signatures, missing trust roots, and custody failures covered by tests.

## What MNDe Does Not Guarantee

MNDe does not guarantee:

- Protection for actions that bypass MNDe.
- Completeness of the bundled demo policy for real deployments.
- Regulatory compliance or certification.
- Production availability, backup, recovery, or incident response without operator process.
- Enterprise identity, SSO, or government procurement readiness.
- That all possible logs or host tooling outside MNDe are free of sensitive data.
- That a compromised host cannot alter local files inside its trust boundary.

## Supporting Documentation

- [PRIVACY.md](PRIVACY.md)
- [TERMS.md](TERMS.md)
- [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)
- [DATA_RETENTION.md](DATA_RETENTION.md)
- [SUPPORT.md](SUPPORT.md)
- [SECURITY_CLAIMS.md](SECURITY_CLAIMS.md)
- [LICENSES.md](LICENSES.md)
- [SBOM.md](SBOM.md)
- [COMPLIANCE_SUMMARY.md](COMPLIANCE_SUMMARY.md)
