# MNDe Decision API — Canonical Contract

This is the single source of truth for the request MNDe's sidecar accepts at
`POST /v1/decisions` on the **default** configuration (legacy decision engine).
The canonical examples are committed and exercised by a live test
(`npm run test:api-contract`), so this document cannot drift from reality.

## Endpoint

```
POST /v1/decisions      Content-Type: application/json
```

Returns `{ "decision": "ALLOW" | "REFUSE", "reason_code": "...", "receipt": {...}|null, "request_hash": "...", "decision_hash": "...", ... }`.

- `ALLOW` returns an inline signed receipt.
- `REFUSE` persists a receipt (visible at `GET /receipts/recent`); set `MNDE_INLINE_REFUSAL_RECEIPTS=1` to inline it too.

## Canonical request

The accepted request is an **execution-request envelope**. Canonical, runnable
copies live in [`examples/decisions/`](../examples/decisions/):

- [`allow-read-status.json`](../examples/decisions/allow-read-status.json) → `ALLOW`
- [`refuse-recursive-delete.json`](../examples/decisions/refuse-recursive-delete.json) → `REFUSE`

Shape:

```jsonc
{
  "execution_request": {
    "request_id": "allow-read-status",
    "submitted_region": "us-west-2",
    "actor": { "user_id": "evaluator" },
    "parameters": { "tester_id": "evaluator", "installation_id": "console" },
    "resources": { "gpu_type": "a10g", "gpu_count": 1, "hours": 1 },
    "execution": { "auto_scale": false, "max_scale_multiplier": 1, "retry_on_fail": false, "max_retries": 0 },
    "tool_calls": [ { "tool": "read_status", "priority": 1 } ],   // the action being authorized
    "orbit_intent": { "orbit_version": "2.0", "action": "execute", "boundary": "...", "payload": { "tool_calls": [...] }, "lifecycle_state": "ARMED", "signatures": [ { "alg": "hmac-sha256", "sig": "..." } ] },
    "release_request": { "execution_id": "allow-read-status", "hold_state": "APPROVED", "already_consumed": false },
    "runtime_observation": { "kill_switch_active": false, "actual_gpu_count": 1, "actual_hours": 1, "actual_total_cost_cents": 500 }
  },
  "pricing_data": { "gpu_hour_cents": 500 }
}
```

The decision is driven by the **active policy** evaluated over the whole request — not by a tool-name denylist. The default active policy (`mnde-release-package/sidecar-local/policy.v1.signed.json`) is **limits-based** (cost, GPU count, hours, manual-approval threshold, retry count) and additionally refuses requests whose **parameters contain a destructive command**.

- A benign action (e.g. `read_status`) → **ALLOW**.
- A destructive action — e.g. a tool whose `parameters` include a command like `rm -rf` — → **REFUSE** with reason `ERR_FORBIDDEN_ACTION_IN_PARAMETERS`, before anything runs.
- The same tool **without** destructive parameters may **ALLOW**: under the default policy, `recursive_delete` with no dangerous parameters returns `ALLOW`, while `recursive_delete` with `parameters.script = "rm -rf ..."` returns `REFUSE`. The refusal is about *what the action does*, not its name.

> The files in [`sample-policies/`](../sample-policies/) (which list tool names under `refuses`) are **examples only**. They are **not** the active default policy and do not affect default behavior.

Build a request programmatically with `reviewerRequest({ requestId, tool, parameters })` from [`scripts/reviewer-request.mjs`](../scripts/reviewer-request.mjs) — the same builder the Authority Console and tests use.

## Console (local, read-only) endpoints

Served same-origin by the sidecar for the Authority Console. They expose only
verdicts over receipts that `GET /receipts/recent` already returns, and mutate
nothing — so they are ungated, unlike the authority-gated `/verify` and
`/replay/recent` (which are unchanged for remote/authority callers).

| Method · Path | Purpose | Body |
| --- | --- | --- |
| `GET /authority` | Public trust/authority state (signing mode, trust chain, root fingerprint, policy hash) | — |
| `POST /console/verify` | Verify a receipt (signature + decision integrity) | the receipt JSON |
| `POST /console/replay` | Replay recent persisted receipts deterministically | `{ "limit": 100 }` |

## CORS

The sidecar binds `127.0.0.1` only. Same-origin requests from the console it
serves are accepted; other origins must be on the allowlist or are rejected
with `ERR_UNAUTHORIZED_ORIGIN`.

## Drift prevention

`npm run test:api-contract` starts a real sidecar and POSTs the two committed
example requests, asserting `ALLOW`/`REFUSE`. If the accepted contract ever
changes, this test fails — keeping this document honest.
