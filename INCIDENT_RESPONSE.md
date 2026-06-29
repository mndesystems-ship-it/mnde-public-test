# Incident Response Plan

This plan is for evaluation-only private beta operation. It documents a repeatable process; it is not a guarantee of regulatory compliance or a substitute for legal advice.

## Severity Levels

| Severity | Description | Examples |
| --- | --- | --- |
| Critical | Active compromise or likely compromise of signing keys, authority bundles, release artifacts, or routed enforcement. | Private key exposure, forged receipts accepted, production pre-flight bypass, malicious release artifact. |
| High | Security control failure with meaningful integrity, confidentiality, or availability impact. | `REFUSE` routed action runs, invalid signature accepted, auth bypass when auth is enabled. |
| Medium | Security weakness with limited exploitability or limited impact. | Missing audit event, confusing error that could lead to unsafe operations, documentation that overstates a boundary. |
| Low | Hardening issue or low-risk documentation/process defect. | Missing contact detail, unclear retention note, non-sensitive diagnostic leak. |

## Detection

Possible detection sources:

- Tester reports through the private beta coordinator.
- Test failures in `npm test` or targeted scripts.
- Sidecar logs and receipt logs configured by the operator.
- Verification failures from `tools/verify.mjs` or `tools/verify-receipt.mjs`.
- Mismatched authority bundle fingerprints or stale/revoked key errors.
- Unexpected sidecar readiness or health behavior.

## Initial Response

1. Acknowledge receipt using the targets in [SECURITY.md](SECURITY.md).
2. Assign an owner and severity.
3. Preserve the first report exactly as received.
4. Open a private incident record.
5. Identify affected versions, commits, configurations, custody mode, and operating systems.
6. Decide whether the incident requires immediate containment before root-cause analysis.

## Containment

Containment options depend on the issue:

- Stop the sidecar or affected integration.
- Disable a vulnerable integration path.
- Rotate or revoke affected signing keys.
- Distribute a new authority bundle.
- Revert a vulnerable release artifact.
- Disable public distribution of affected packages.
- Add temporary documentation warnings for private beta testers.

Containment must not silently downgrade production custody to demo custody.

## Evidence Preservation

Preserve:

- Original report and timestamps.
- Git commit hash and diff.
- Relevant receipts and signed envelopes.
- Authority bundle and trusted root fingerprint used by the reporter.
- Policy files and policy hashes.
- Sidecar stdout/stderr logs where available.
- Auth audit logs where available.
- Reproduction commands and output.
- Environment variables with secrets redacted.

Do not collect private keys, bearer tokens, credentials, browser history, or unrelated local files.

## Recovery

Recovery should include:

- Fix or mitigation.
- Regression test when the issue is testable.
- Documentation update when the boundary or user action changes.
- Fresh verification using the relevant targeted test and `npm test`.
- Release note or private beta advisory describing impact and mitigation.

## Key Rotation

Rotate or revoke keys when:

- A private key is exposed or suspected exposed.
- A signing command, signer host, or file-backed key path is compromised.
- An authority bundle is published with incorrect key metadata.
- A maintainer cannot rule out signing material exposure.

Use the procedures in [docs/key-custody.md](docs/key-custody.md). Revocation invalidates affected key ids immediately, including historical receipts signed by the revoked key.

## Communication Process

Private beta communications should include:

- What happened.
- What versions or configurations are affected.
- Whether receipts, authority bundles, keys, logs, or local artifacts are affected.
- What action testers should take.
- Whether key rotation or bundle redistribution is required.
- Which verification command confirms the fix.

Avoid speculative claims. If impact is unknown, say so and update when evidence changes.

## Customer Notification Process

The public test does not include a customer-notification system. For private beta, notify affected testers through the same private channel used to distribute evaluation access.

Before paid, enterprise, or public launch, define:

- Legal/regulatory notification owner.
- Customer contact source of truth.
- Notification approval process.
- Jurisdiction-specific breach notification review.
- External counsel escalation criteria.

## Postmortem Requirements

For Critical and High incidents, write a postmortem containing:

- Timeline.
- Impact.
- Root cause.
- Detection source.
- What worked.
- What failed.
- Corrective actions.
- Tests added.
- Documentation changed.
- Follow-up owner and due date.

## Timeline Expectations

Private beta targets:

- Critical: contain or publish mitigation guidance within 3 business days when feasible.
- High: contain or publish mitigation guidance within 5 business days when feasible.
- Medium: schedule remediation in the next planned hardening cycle.
- Low: track with documentation or hardening backlog.

These are not service-level commitments.
