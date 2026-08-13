# desktop/ — MNDe operational dashboard

The local, no-login operational view for MNDe. It answers exactly one question:

> **Is routed execution protected right now?**

MNDe is local execution infrastructure, not a SaaS product. The dashboard is built to feel like a firewall / runtime / OS component: you launch it and immediately see whether MNDe-routed execution is protected — **no login, no signup, no account, no email, no forced cloud**.

## How it runs

`dashboard.html` is a single static file with no build step and no dependencies. The local sidecar serves it at the root:

```bash
npm run sidecar        # or: npm run dashboard
# then open http://127.0.0.1:8787/
```

It reads only the sidecar's **unauthenticated local status endpoints** (`/readyz`, `/healthz`, `/receipts/recent`, `/policy/current`, `/capabilities`, `/identity`) over same-origin requests. It makes no external/cloud calls and collects nothing.

## Startup flow

1. Launch the application (start the local sidecar).
2. The sidecar starts / is connected to locally.
3. Runtime status is verified via local endpoints.
4. Routed protection status is displayed — within seconds, with no account.

## What it shows

The layout is an operator console — a persistent left rail, a top summary row, a live execution stream with a receipt inspector, and a governance rail — but every value is read from the live sidecar. Nothing is asserted the page cannot back with an endpoint.

| Element | Source | Meaning |
| --- | --- | --- |
| Decision Gate | `/readyz` + `/receipts/recent` | last real verdict — ALLOW–EXECUTED / REFUSE–BLOCKED / FAIL-CLOSED / DEGRADED |
| Last Decision | `/receipts/recent` | most recent ALLOW/REFUSE, action, reason, policy, receipt id |
| Decision Counts | `/receipts/recent` | ALLOW / REFUSE / verifier-proved VALID / shown, over the loaded window |
| Execution Stream | `/receipts/recent` | recent decisions; click a row to inspect its receipt |
| Receipt inspector | `/receipts/recent` + `/verify` | full receipt fields, signature block, and **Verify Now** (offline replay + Ed25519 check) |
| System Status rail | `/readyz` `/healthz` `/policy/current` `/capabilities` `/identity` | sidecar, receipt log, replay, authority bundle, policy, durability |
| Governance rail | `/identity` + `/policy/current` + `/capabilities` | release identity, active policy + hash, exposed capabilities, trust model |

### Honesty constraints

The runtime's receipt API exposes verdicts of **ALLOW/REFUSE only** (no "held/awaiting-approval" state) and **no caller/executor fields**, so the dashboard renders none of those. Signature state is shown exactly as recorded: only a verifier-proved `VALID` reads as trust — `UNKNOWN`/`NOT_REPORTED`/`INVALID` render as *unverified*, never as a green check. `Verify Now` POSTs the receipt to `/verify`; that route is authority-gated, so when it refuses the panel says so and points to the offline verifier (`node tools/verify.mjs <receipt.json>`) rather than faking a result.

## Navigation / copy

Infrastructure vocabulary only — no marketing or auth funnels. The rail's views are:

`Decisions` · `Receipts` · `Governance` · `Reconstruct` · `System`

Removed entirely: Login, Sign In, Create Account, Welcome, Get Started.

## Enterprise identity is optional and OFF by default

Identity / team features — **Microsoft Entra ID, Okta, SSO, team management, centralized audit, policy distribution** — are reserved for future enterprise use and are **disabled by default**. MNDe enforces decisions and signs receipts with none of them. MNDe does not currently provide a public login or account system. Private beta uses local sidecar access or bearer-protected machine access; production sidecar mode requires `MNDE_SIDECAR_AUTH=bearer`. Enabling bearer auth never adds a login screen to this dashboard.

## Guarantees preserved

This is a read-only view. It does **not** change the decision engine, the receipt system, replay verification, the authority model, or policy enforcement. It only removes authentication as a startup requirement for *seeing* protection status.

See [docs/operational-dashboard.md](../docs/operational-dashboard.md) for the full repositioning notes.
