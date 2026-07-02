# Operational Dashboard — Infrastructure, Not SaaS

MNDe is local execution infrastructure. Infrastructure works **before identity exists** — a firewall protects packets before anyone logs in; a runtime executes code before an account is created. The MNDe desktop experience follows the same principle.

## The repositioning

A fresh user installs MNDe, launches it, and within seconds sees whether execution is protected — **without creating an account or connecting to any cloud service**.

Removed as startup requirements:

- No login screen
- No signup flow
- No account creation prompts
- No email collection
- No forced cloud dependency
- No blocking authentication checks during startup
- No "Get Started" marketing flow

The first screen answers one question: **"Is routed execution protected right now?"**

## Startup flow

```
Launch application
  → start or connect to the local sidecar
  → verify runtime status (local endpoints)
  → display protection status
```

No step blocks on authentication or network identity.

## Primary UI

Seven operational panels, each backed by a real local endpoint (no fabricated data):

- **Protection Status** — is execution being gated right now
- **Sidecar Status** — runtime health
- **Last Decision** — most recent ALLOW/REFUSE
- **Receipt Count** — signed receipts emitted
- **Active Policy** — version + hash in force
- **Connected Tool Sources** — tools observed routing through MNDe
- **Trust Status** — receipts signed and offline-verifiable

It is served by the sidecar at `http://127.0.0.1:8787/` (`npm run sidecar`), reads only same-origin local status endpoints, and makes no external calls.

## Navigation and copy

| Removed | Replaced with |
| --- | --- |
| Login | Authority |
| Sign In | Protection Status |
| Create Account | Infrastructure |
| Welcome | Audit Record |
| Get Started | Policy |
| (marketing) | Demonstration |

## Enterprise identity: optional, disabled by default

Identity code remains available for **future enterprise features** but is **off by default** and never gates startup:

- Microsoft Entra ID
- Okta
- SSO
- Team management
- Centralized audit
- Policy distribution

MNDe does not currently provide a public login or account system. Private beta access is local sidecar access or bearer-protected machine access. Enabling sidecar caller authentication (`MNDE_SIDECAR_AUTH=bearer`) gates the decision API for machine callers — it does **not** add a login screen to the dashboard. Public web login requires a separate IdP/OIDC-backed authentication layer in front of MNDe. Production sidecar mode requires bearer auth. See [Sidecar Caller Authentication](mnde-policy-engine-production-spec-v1.md).

## Browser origins (CORS): deny by default

The sidecar rejects any request carrying an `Origin` header that is not explicitly allowlisted (`ERR_UNAUTHORIZED_ORIGIN`), and returns CORS headers only for allowlisted origins. The allowlist is empty by default — no browser origin is trusted implicitly. To let a browser page served from another local origin call the sidecar, set:

```
MNDE_ALLOWED_ORIGINS=http://127.0.0.1:8080,http://localhost:8080
```

Non-browser callers (no `Origin` header) are unaffected. The dashboard served by the sidecar itself uses same-origin GET requests and needs no CORS configuration. Earlier builds implicitly trusted `http://127.0.0.1:8080` and `http://localhost:8080`; that implicit trust is removed — any page on those origins could previously issue cross-origin requests to the sidecar. Verified by `npm run test:dashboard`.

## What did NOT change

Removing authentication as a *startup requirement* changed none of the security core:

- Decision engine — unchanged
- Receipt system — unchanged
- Replay verification — unchanged
- Authority model — unchanged
- Policy enforcement — unchanged

The dashboard is a read-only local view over endpoints that were already unauthenticated. Verified by `npm run test:dashboard` (serves at `/`, shows all seven panels, uses the infrastructure vocabulary, contains no login/signup/account CTAs, no password/email fields, no external origins, and the decision path still decides and signs).

## Design principle

> MNDe is infrastructure. Infrastructure works before identity exists.
