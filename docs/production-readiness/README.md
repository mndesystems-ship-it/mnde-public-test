# MNDe Production Readiness Initiative

This folder is the evidence package for evaluating MNDe as a production-grade execution firewall — not a demo. Every finding cites real code (`file:line`) or a runnable command, so a skeptical engineering leader can verify each claim independently.

## Scope

Goal: transform MNDe from an advanced prototype into a system that *survives scrutiny* on stability, reliability, operational readiness, auditability, security, and adoption. No new product categories, AI features, or dashboards were added; the one UI change (Authority Console navigation) is a simplification, not a feature.

## Deliverables

| # | Report | What it answers |
| --- | --- | --- |
| 1 | [Production Readiness Report](01-production-readiness-report.md) | Is the code stable? Placeholders, mocks, silent failures, edge cases, upgrade risk. |
| 2 | [Security Readiness Report](02-security-readiness-report.md) | Threat model, trust boundaries, key management, fail-closed, replay, signatures, audit integrity — with authority-verification proof. |
| 3 | [Operational Readiness Report](03-operational-readiness-report.md) | Health checks, recovery, backups, shutdown, diagnostics, log rotation, version tracking. |
| 4 | [UX Simplification Report](04-ux-simplification-report.md) | Authority Console, persona evaluation (security/platform/founder/auditor). |
| 5 | [Documentation Audit Report](05-documentation-audit-report.md) | Accuracy, currency, prototype-language removal. |
| 6 | [Prioritized Production Roadmap](06-production-roadmap.md) | Critical → High → Medium → Future, with risk, impact, effort, order. |

## Method

- Static audit of 14,284 lines (`*.mjs` + `*.ts`, excluding `node_modules`) across 81 `.mjs` and 21 `.ts` files.
- Pattern sweeps for prototype smells: `TODO/FIXME/HACK/XXX/TEMP`, `placeholder/stub/not implemented`, `mock/fake/dummy`, empty `catch` blocks, stray debug logging.
- Targeted reads of the authority path (engines, sidecar, executor, verifier, custody, authority manifest).
- Behavioral confirmation via the test suite: **20 suites** under `tests/test_*.mjs`.

## Headline assessment

MNDe's **core is production-shaped today**: fail-closed enforcement, signed offline-verifiable receipts, deterministic replay, a runtime watchdog, worker auto-restart, graceful shutdown, a durable receipt queue, and Prometheus metrics — with no TODO/FIXME, no mocks, and no swallowed errors found in the audit.

The gaps that block a clean pilot are **operational and trust-root provisioning**, not core correctness:

1. **Live signing defaults to development keys** (custody is opt-in). — *Critical*
2. **No production installer / upgrade / rollback for the runtime.** — *High*
3. **Receipt log is unbounded and defaults to a demo-named path.** — *High*

Full prioritization in the [roadmap](06-production-roadmap.md).
