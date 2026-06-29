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

| Panel | Source | Meaning |
| --- | --- | --- |
| Protection Status | `/readyz` + `/healthz` | PROTECTED / DEGRADED / FAIL-CLOSED / OFFLINE |
| Sidecar Status | `/healthz` | runtime health, worker, event-loop lag |
| Last Decision | `/receipts/recent` | most recent ALLOW/REFUSE, tool, reason |
| Receipt Count | `/receipts/recent` | signed receipts observed |
| Active Policy | `/policy/current` | active policy version + hash |
| Connected Tool Sources | `/receipts/recent` | distinct tools that have routed through MNDe |
| Trust Status | receipts + `/identity` | receipts signed & offline-verifiable |

## Navigation / copy

Infrastructure vocabulary only — no marketing or auth funnels:

`Authority` · `Protection Status` · `Infrastructure` · `Audit Record` · `Policy` · `Demonstration`

Removed entirely: Login, Sign In, Create Account, Welcome, Get Started.

## Enterprise identity is optional and OFF by default

Identity / team features — **Microsoft Entra ID, Okta, SSO, team management, centralized audit, policy distribution** — are reserved for future enterprise use and are **disabled by default**. MNDe enforces decisions and signs receipts with none of them. Sidecar caller authentication (`MNDE_SIDECAR_AUTH`) is likewise off by default; enabling it never adds a login screen to this dashboard.

## Guarantees preserved

This is a read-only view. It does **not** change the decision engine, the receipt system, replay verification, the authority model, or policy enforcement. It only removes authentication as a startup requirement for *seeing* protection status.

See [docs/operational-dashboard.md](../docs/operational-dashboard.md) for the full repositioning notes.
