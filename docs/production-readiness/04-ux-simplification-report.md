# 4. UX Simplification Report

Repositions the desktop experience as an **Authority Console** and validates it against four evaluator personas.

## What changed

The console answers one question on launch — **"Is MNDe protecting execution right now?"** — with a live verdict (PROTECTED / DEGRADED / FAIL-CLOSED / OFFLINE). It is served by the sidecar at `/` (`desktop/dashboard.html`, wired in `mnde-local-sidecar.mjs` `serveDashboard`), reads only local unauthenticated status endpoints, and makes no external calls.

**SaaS patterns removed:** login walls, account-first flow, welcome/marketing screens, empty widgets, redundant navigation. Verified by `tests/test_dashboard.mjs` (no Login/Sign In/Create Account/Welcome/Get Started, no password/email field, no `<form>`, no external origins).

**Navigation reduced to five:** `Status · Decisions · Policy · Audit · Settings`.

**Status screen shows exactly the required signals:** Protection Status, Sidecar Status, Active Policy, Trust Status, Last Decision, Receipt Count, Protected Sources — each backed by a real endpoint (no placeholder widgets):

| Panel | Source |
| --- | --- |
| Protection Status | `/readyz` + `/healthz` |
| Sidecar Status | `/healthz` |
| Active Policy | `/policy/current` |
| Trust Status | receipts + `/identity` |
| Last Decision | `/receipts/recent` |
| Receipt Count | `/receipts/recent` |
| Protected Sources | distinct tools observed in `/receipts/recent` |

Enterprise identity (Entra ID, Okta, SSO, centralized policy, fleet, shared audit) appears under **Settings** as *optional · disabled* — never required for local protection.

## Persona evaluation

### Security Engineer — "Does it enforce? Can I verify it? Can it be bypassed?"
- **Enforce:** Status shows live PROTECTED/FAIL-CLOSED; Decisions shows ALLOW/REFUSE in real time.
- **Verify:** Audit tab gives the exact offline command (`node tools/verify.mjs <receipt.json>`) and replay/bundle endpoints.
- **Bypass:** answered by the executor invariant (`executor/index.mjs:6-15`) — surfaced in docs; **gap:** the console doesn't yet link to the bypass/threat note. *(minor — UX-1)*

### Platform Engineer — "How do I deploy / operate / recover it?"
- **Operate:** Settings exposes runtime (ready/degraded/inflight/pid) + capabilities; metrics at `/metrics`.
- **Deploy/recover:** **gap** — no in-console install/upgrade/recover guidance; covered by Operational report O-01. *(UX-2)*

### Founder — "Why do I need it? How long to deploy? What proof exists?"
- **Why/proof:** the one-question framing + signed receipts + reviewer kit answer "what proof exists."
- **Time to deploy:** **gap** — no stated time-to-protection; recommend a "Protected in N seconds" first-run affordance and a one-command quickstart. *(UX-3)*

### Auditor — "Can decisions be verified? Can records be trusted? Is evidence preserved?"
- **Verified/trusted/preserved:** Audit tab covers offline verification, trust anchor (policy hash + authority root), and evidence export. Strong fit.

## Findings

| ID | Severity | Finding | Recommendation |
| --- | --- | --- | --- |
| UX-1 | Low | Console doesn't link to the bypass/threat model | Add a Settings → "Security model" link to `docs/production-readiness/02-...` |
| UX-2 | Medium | No deploy/recover guidance in-console | Link Settings → install/upgrade guide (after O-01) |
| UX-3 | Low | No stated time-to-protection | First-run "Protected in N s" + quickstart command |

## Verdict

The desktop experience is now **infrastructure-shaped, not SaaS-shaped**: no identity gate, one clear question, five tabs, real data. It satisfies the security and auditor personas well; the platform and founder personas need the deploy guidance and quickstart that the roadmap already schedules.
