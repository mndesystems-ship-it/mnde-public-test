# Security Policy

MNDe is a local pre-execution authority layer: callers submit a proposed action,
MNDe evaluates it against a policy, returns `ALLOW` or `REFUSE`, and writes a
signed, offline-verifiable receipt. Security reports about any of those
guarantees are taken seriously and are the fastest way to make this project
better.

## Supported Versions

MNDe is pre-1.0 public-test software. Only the latest state of the default
branch and the most recent tagged release are supported. Older commits and
releases are not patched; fixes land forward.

| Version | Supported |
| --- | --- |
| Latest default branch / latest release | Yes |
| Anything older | No |

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting on this repository (Security tab, "Report a vulnerability"). If that
is unavailable, open a GitHub issue that contains no exploit details and asks
for a secure contact channel; one will be provided.

Please do not disclose vulnerability details in public issues, discussions,
pull requests, or receipts attached to feedback.

## What to Include

- The commit hash or release you tested.
- Operating system and Node.js version.
- The exact configuration (relevant `MNDE_*` environment variables, profile,
  decision engine, signing mode).
- Steps to reproduce, ideally as a minimal script or request sequence.
- The observed behavior and the security property you believe is violated
  (for example: a `REFUSE`d action executed, a tampered receipt verified, a
  replayed nonce was accepted, a signature check was bypassed).
- Receipts, ledger entries, or logs that demonstrate the issue, with any
  private key material removed.

## Scope

In scope, in rough order of severity:

- Policy engine evaluation: any input that produces `ALLOW` where the policy
  requires `REFUSE`, or that bypasses fail-closed behavior.
- Receipt signing and verification: forging, tampering with, or replaying a
  receipt that still verifies; verifier confusion between receipt schemas.
- Authority model: using a signed grant outside its bound subject, tenant,
  tool, resource, or request; reusing a single-use grant or approval nonce.
- Execution ledger: undetected deletion, reordering, or modification of
  chained entries.
- Canonicalization: two different payloads producing the same canonical bytes
  or hash, or non-deterministic canonical output.
- Sidecar authentication and authorization: bypassing bearer caller
  authentication, authority assertions, capability checks, or nonce
  single-use on gated endpoints.
- Production posture and trust-root pre-flights: any configuration that
  reaches live enforcement while violating the documented production
  requirements.
- MCP server and proxy: a `tools/call` that executes or is forwarded upstream
  without an `ALLOW`.
- Onboarding CLI: wiring changes that corrupt configs, lose backups, or
  silently weaken protection.
- Key handling: private key material appearing in receipts, logs, error
  messages, or API responses.

## Out of Scope

- Bypassing enforcement by not routing an action through MNDe. Enforcement is
  cooperative by design and this limitation is documented; MNDe does not claim
  OS-level or kernel-level process control.
- The unauthenticated decision API in the local development profile. This is
  the documented default, is restricted to the loopback interface, and prints
  a startup warning; production requires authenticated access and refuses to
  start without it.
- The committed demo authority under `authority/` and generated local test
  keys. These exist for documentation fixtures and local testing and anchor no
  production trust.
- Denial of service against a local development sidecar by a process on the
  same machine.
- Vulnerabilities exclusively in Node.js, the operating system, or other
  third-party software.
- Reports from automated scanners without a demonstrated, MNDe-specific
  impact.
- Social engineering, phishing, and physical attacks.

If you are unsure whether something is in scope, report it privately anyway.

## Disclosure Expectations

- Coordinated disclosure is expected: please allow a fix to land before
  publishing details.
- Reports are acknowledged as quickly as possible, normally within seven
  days.
- MNDe is currently maintained by a single developer. There is no formal SLA,
  no 24/7 response, and no certification program (no SOC 2, no ISO 27001).
  Response and fix times reflect that honestly; severe findings in the
  receipt, signing, or policy-evaluation paths are prioritized above all
  other work.
- Reporters are credited in release notes if they wish.

## No Bug Bounty

There is no bug bounty program at this time. If one is introduced, it will be
announced explicitly; no monetary reward should be assumed for any report.

## Security Notes: Local Sidecar

- The sidecar binds to `127.0.0.1` only and must not be exposed to other
  machines or the Internet, directly or through port forwarding or reverse
  proxies.
- Caller authentication is off by default in the local profile, and a warning
  is printed at startup. Enable it with `MNDE_SIDECAR_AUTH=bearer` where
  multiple local processes share the machine.
- Local receipts chain to a locally generated test authority. They demonstrate
  the verification flow; they are not production evidence.

## Security Notes: Production

- `MNDE_PROFILE=production` refuses to start without caller authentication, a
  production custody provider, a published authority bundle, and a signed
  policy bundle. There is no automatic downgrade to development keys or
  unauthenticated operation.
- Sensitive endpoints require signed authority assertions with scoped
  capabilities; assertion nonces are single-use.
- See [docs/security-model.md](docs/security-model.md),
  [docs/production-readiness.md](docs/production-readiness.md), and
  [docs/key-custody.md](docs/key-custody.md) for the security model, the
  production requirements, and key custody, rotation, and revocation.
