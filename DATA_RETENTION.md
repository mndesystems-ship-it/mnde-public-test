# Data Retention

MNDe Public Test stores evaluation artifacts locally. It does not enforce automatic retention or deletion. Operators and testers are responsible for choosing retention periods appropriate for their evaluation.

## Logs

Common logs:

- Reviewer kit sidecar logs under `reviewer-kit/artifacts/logs/`.
- Sidecar harness logs under `mnde-receipts/_sidecar-logs/`.
- Auth audit logs when configured by `MNDE_AUTH_AUDIT_LOG`.
- Receipt persistence logs when configured by `MNDE_RECEIPT_LOG`.

Suggested private beta retention: keep logs only until the issue, test, or review is complete.

Deletion: stop MNDe, confirm logs are no longer needed, then delete the generated log files or parent artifact directory.

## Receipts

Receipts can exist under:

- `reviewer-kit/artifacts/receipts/`
- `mnde-receipts/`
- A configured executor `receiptsDir`
- A configured sidecar receipt log path

Receipts are audit evidence. They can include request metadata and tester identifiers. Treat them as sensitive operational records.

Suggested private beta retention: keep receipts only for the agreed evaluation window, unless they are needed to verify a reported issue.

Deletion: delete receipt files after confirming no retained report or audit package depends on them.

## Policies

Committed sample policies and docs remain in the repository. Operator-created policies may live in local config or deployment-specific paths.

Suggested private beta retention: preserve the policy document or policy hash for any receipt retained for audit or debugging.

Deletion: delete local policy drafts and generated policy files when they are no longer needed.

## Authority Bundles

Authority bundles contain public keys and metadata. They are needed to verify signed receipts and custody attestations.

Suggested private beta retention: retain the matching public authority bundle for as long as any receipt signed under it must remain verifiable.

Deletion: delete old public bundles only after confirming no retained receipt depends on them.

## Private Keys

Generated private keys may appear under local-only paths such as `.mnde-test/authority/` or `shared/receipt_keys/` during evaluation. Production-like key material should live outside the repository.

Suggested private beta retention: keep private keys only while needed to generate evaluation receipts. Delete them at the end of evaluation if no further signing is needed.

Deletion: stop MNDe, confirm the key is no longer needed, remove the file, and remove any backups that contain the key.

## Configuration

Onboarding can create backups and manifests for supported MCP client configs.

Suggested private beta retention: keep backups until the tester confirms the original configuration can be restored or is no longer needed.

Deletion: run the documented uninstall/restore process when applicable, then delete stale backup metadata if it is no longer needed.

## Backup

The repository does not provide a managed backup service. If receipts, authority bundles, policies, or logs are needed for audit, operators should back them up according to their own process.

Recommended backup contents for an audit package:

- Receipts.
- Matching public authority bundles.
- Trusted root fingerprints.
- Policy documents or policy hashes.
- Verifier version or commit hash.
- Replay verification reports.

Do not back up private keys with general logs or receipts.

## Recovery

Recovery depends on what was lost:

- Lost logs: rerun the test if the scenario is reproducible.
- Lost receipts: regenerate only if the original decision can be safely rerun; otherwise record that the evidence is unavailable.
- Lost public bundle: re-export or recover it from the operator if the root and bundle history still exist.
- Lost private signing key: rotate to a new key. If compromise is possible, revoke the old key.
- Lost root key: perform a trust-anchor rollover and distribute the new root fingerprint out of band.

## Export

Before exporting artifacts:

- Remove private keys, tokens, passwords, unrelated local files, browser history, and sensitive request content.
- Include only the receipts, logs, policy documents, authority bundles, and commands needed for the report.
- Prefer public authority bundles over private key material.
- Include the repository commit hash and test command output when relevant.
