# Privacy Notice

MNDe Public Test is designed for evaluation-only local use. This notice describes the repository's current data behavior. It does not claim privacy-law compliance.

## Data Collected

MNDe does not operate a hosted service in this repository. By default, data is generated and stored locally by the tester or operator.

Local evaluation artifacts can include:

- Tester ID entered by the tester or assigned by the test coordinator.
- Installation ID generated locally.
- Decision requests submitted to MNDe.
- Decision receipts and signed receipt envelopes.
- Policy hashes, policy identifiers, authority identifiers, and verification results.
- Sidecar stdout/stderr logs when the reviewer kit or sidecar harness is used.
- Auth audit log entries when authority-gated endpoints or sidecar auth are enabled.
- Local configuration backup metadata created by onboarding.
- Operating system, Node.js version, command run, receipt path, log path, screenshot, or copied error text if the tester chooses to send feedback.

## Data Never Collected by Default

The current repository does not intentionally collect by default:

- Names, email addresses, phone numbers, mailing addresses, or payment details.
- Browser history.
- Passwords.
- Private keys.
- Bearer tokens.
- Card data.
- Health, biometric, financial, child, or precise-location data.
- Customer content for model training.

If a tester places sensitive content inside a request, receipt, log, screenshot, or feedback message, MNDe may preserve that content as part of the local artifact. Testers should avoid submitting sensitive data during evaluation.

## Where Data Is Stored

Generated data stays on the tester's machine unless the tester shares it.

Common local paths:

| Data | Path |
| --- | --- |
| Tester identity | `.mnde-test/identity.json` |
| Local tester authority | `.mnde-test/authority/` |
| Development receipt keys | `shared/receipt_keys/` |
| Reviewer kit logs | `reviewer-kit/artifacts/logs/` |
| Reviewer kit receipts | `reviewer-kit/artifacts/receipts/` |
| Executor receipts | `mnde-receipts/` or configured `receiptsDir` |
| Onboarding backups | Operator-specific backup path documented in `docs/onboarding.md` |

## Telemetry

No automatic telemetry is implemented in this repository.

## Analytics

No analytics service is implemented in this repository.

## Cookies

The local operational dashboard does not set cookies.

## Third-Party Services

MNDe Public Test does not call third-party services by default. It uses local sidecar endpoints and local files. A tester or operator may configure external tools, upstream MCP servers, or signer commands; those integrations are outside this privacy notice and should be reviewed separately.

## Log Storage

Logs are local files when enabled by scripts, the reviewer kit, sidecar harness, or operator configuration. Logs can include request metadata, reason codes, health information, and error text. They should not include private keys or bearer tokens from MNDe-controlled paths, but operators should still treat logs as potentially sensitive because requests may contain user-supplied data.

## Receipt Storage

Receipts are local audit artifacts. They can include canonical request fields, actor metadata, tester identifiers, tool names, parameters, policy hashes, decision hashes, signatures, and authority metadata. Receipts are designed for auditability, not secrecy. Do not place secrets in execution requests.

## Retention Periods

The repository does not enforce automatic deletion or retention periods. Private beta testers should retain artifacts only as long as needed for evaluation, debugging, or agreed review.

Suggested private beta defaults:

- Reviewer kit artifacts: delete after feedback is accepted or no longer needed.
- Local tester identity: delete at the end of the evaluation if no longer participating.
- Receipts and logs: retain only for the agreed evaluation window.
- Authority bundles and keys: preserve only if needed to verify retained receipts; protect private keys until securely deleted.

See [DATA_RETENTION.md](DATA_RETENTION.md).

## Deletion Process

To remove local evaluation artifacts, stop MNDe and delete the relevant generated directories, such as:

```text
.mnde-test/
reviewer-kit/artifacts/
mnde-receipts/
shared/receipt_keys/
```

Before deleting keys or authority bundles, confirm that no retained receipts still need to be verified.

## Export Process

Export is manual. A tester may share selected logs, receipts, screenshots, or copied error text with the private beta coordinator. Review artifacts before sharing and remove secrets, credentials, unrelated local files, and sensitive request content.

## User Rights

Because the current repository is local evaluation software and not a hosted service, testers control their local artifacts. Testers can inspect, export, and delete generated local files. If artifacts have been shared with the private beta coordinator, use that same channel to request deletion or correction of shared copies.

## Contact Information

Use the private beta coordinator or maintainer channel that provided access. If no privacy contact has been assigned, request one before sharing artifacts that may contain sensitive data.
