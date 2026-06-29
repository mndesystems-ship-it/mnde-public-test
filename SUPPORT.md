# Support

MNDe Public Test is evaluation-only software. Support is limited to private beta coordination, bug reports, security reports, and documentation clarification.

## Support Process

Use the private beta coordinator or maintainer channel that provided access to the repository. Include:

- Operating system.
- Node.js version.
- Git commit hash.
- Command run.
- Expected behavior.
- Actual behavior.
- Relevant receipt path, log path, or screenshot with secrets removed.

Do not send private keys, bearer tokens, credentials, browser history, or unrelated local files.

## Security Contact

Report security issues through the private beta coordinator or assigned security contact. If no private security contact exists, request one before sharing exploit details.

Every private beta distribution must include a named security, privacy, and support contact supplied with the invite or written beta agreement.

If no contact is supplied, testers should report issues through the distribution channel that provided the beta materials.

See [SECURITY.md](SECURITY.md) for the full vulnerability reporting process.

## Bug Reporting

Useful bug reports include:

- Reproduction steps from a clean clone where possible.
- The output of the failing command.
- Whether `npm test` or a targeted `npm run test:*` command fails.
- Any generated receipt or authority bundle needed to reproduce the issue, with secrets removed.

## Responsible Disclosure

Do not disclose vulnerabilities publicly until maintainers have had a reasonable opportunity to investigate and remediate. Do not test against third-party systems or other testers without explicit authorization.

## Issue Templates

No issue-template automation is included in this repository yet. Until templates exist, use these headings:

```text
Summary:
Impact:
Environment:
Commit:
Steps to reproduce:
Expected result:
Actual result:
Artifacts:
Secrets removed: yes/no
```

For security reports, add:

```text
Affected security boundary:
Exploitability:
Suggested severity:
Disclosure timeline:
```

## Expected Response Times

Private beta targets:

| Request type | Acknowledgement target |
| --- | --- |
| Critical security issue | 1 business day |
| High security issue | 2 business days |
| Bug blocking evaluation | 3 business days |
| Documentation question | 5 business days |
| General feedback | Best effort |

These are targets, not contractual commitments.
