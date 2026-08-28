# Normalized Execution Envelope — `mnde.execution.request.v1`

Status: **Implemented (M1).** The first milestone of the agentic-execution
expansion ([agentic-execution-expansion.md](agentic-execution-expansion.md),
Section F). This is pure superstructure over the existing policy engine: adapters
translate any protocol's request into one envelope, and a normalizer maps that
envelope into the **existing** policy-engine request (`schema_version "1.0"`). The
decision core, its frozen decision-hash material, and all cryptographic behavior
are unchanged.

Implementation: [`src/execution-envelope/index.mjs`](../src/execution-envelope/index.mjs).
Example adapters: [`adapters/mcp-tool-call.mjs`](../src/execution-envelope/adapters/mcp-tool-call.mjs),
[`adapters/http-json.mjs`](../src/execution-envelope/adapters/http-json.mjs).
Tests: `npm run test:execution-envelope`.

> This schema id (`mnde.execution.request.v1`, dotted) is **distinct** from the
> deploy-pipeline `mnde.execution_request.v1` (underscore) in
> [execution-request-v1.md](execution-request-v1.md). That schema is unchanged and
> unaffected.

## Why

The spec's central abstraction is *one core, many protocols* (spec §6, §31): MCP,
AP2, REST, cloud APIs, and future protocols become adapters around a single MNDe
authority/decision core. M1 establishes that boundary as a stable, testable public
shape without touching the core, so later milestones (delegation, AP2, payments)
become "emit the envelope" rather than "modify the engine."

## The envelope

```jsonc
{
  "schema": "mnde.execution.request.v1", // exact; any other value fails closed
  "request_id": "req_...",               // required, non-empty string
  "timestamp": "2026-08-26T12:00:00.000Z", // required, UTC ISO-8601 (optional millis)
  "principal": { "type": "agent", "id": "agent://acme/purchasing" }, // id required; type optional
  "action": { "namespace": "payments", "operation": "purchase" },    // both required
  "resource": { "type": "merchant_checkout", "id": "checkout_1" },   // optional; type+id required if present
  "parameters": { "amount": 320, "currency": "USD" }, // required object (may be empty), free-form
  "authority": [],                        // optional array of signed grants (passed through unchanged)
  "environment": {},                      // optional object
  "context": {},                          // required object (may be empty), free-form
  "nonce": "…",                           // optional; carried as metadata, NOT enforced in M1
  "expires_at": "…"                       // optional; carried as metadata, NOT enforced in M1
}
```

**Strict frame, free-form payload.** The top-level key set is fixed: an unknown
top-level key fails closed, so no field can be silently dropped in normalization.
`parameters` and `context` are free-form and carried through losslessly.

**Injective action join.** `action.namespace` and `action.operation` must each match
`^[A-Za-z0-9_-]+$` (no dots/separators). They are joined into the engine's
`tool.tool_name` as `namespace + "." + operation`, and the character restriction
guarantees two different `(namespace, operation)` pairs can never collide onto one
`tool_name` — so they can never receive the same policy treatment by accident.

## Field mapping (envelope → policy-engine request `1.0`)

| Envelope | Policy-engine request | Notes |
|---|---|---|
| `request_id` | `request_id` | verbatim |
| `timestamp` | `timestamp` | verbatim; still the sole deterministic time source |
| `principal` | `principal` | preserved (id, type, and any extra fields policies match) |
| `principal.id` (+`type`) | `agent` | `{ id }` or `{ id, type }` — the envelope models one principal |
| `action.{namespace,operation}` | `tool.tool_name` = `"ns.op"`, plus `tool.namespace`, `tool.operation` | policies may match either the joined name or the parts |
| `resource` | `context.resource` = `{ type, id }` | top-level `resource` overrides any caller `context.resource` |
| `parameters` | `parameters` | verbatim, free-form |
| `environment` | `environment` | verbatim; `{}` when absent |
| `context` | `context` | verbatim, free-form (plus injected `resource`) |
| `authority` | engine `options.authorities` | passed through to existing authority verification; `[]` when absent |
| `nonce`, `expires_at` | `meta` (not in the request) | metadata only in M1 |

## Fail-closed contract

`normalizeExecutionEnvelope(envelope)` returns either `{ ok: true, request,
authorities, meta }` or `{ ok: false, reason }`, and **never a partial request**. A
caller MUST treat `ok: false` as REFUSE. Reason codes:

- `ERR_ENVELOPE_SCHEMA_UNSUPPORTED` — missing/wrong `schema`.
- `ERR_ENVELOPE_MALFORMED` — any structural defect (missing/mistyped required
  field, unknown top-level key, malformed optional field, dotted action token).

`decideFromEnvelope(envelope, policy, options)` is a convenience that always returns
a genuine, replayable policy-engine decision object plus `envelope_ok` /
`envelope_reason` metadata. An invalid envelope is routed through the engine as an
`INVALID_REQUEST` REFUSE — no execution, no partial request. Numbers still obey the
integer-only model: a non-integer in `parameters` normalizes structurally but the
engine refuses it with `NON_INTEGER_NUMBER`.

## Adapter equivalence (the M1 acceptance property)

The same semantic execution expressed in two different source shapes must receive
the same policy treatment (spec §47). The MCP and HTTP example adapters demonstrate
this: given equal semantic values, both normalize to a **byte-identical** canonical
request and therefore an identical `decision_hash`; with differing `request_id`s
they still yield the same `decision`/`reason_code` (identity is bound into the hash,
so `decision_hash` differs — by design). Adapters are pure translations; all
validation lives in the envelope module, which is what makes equivalence testable.

## M1 non-goals (deliberately deferred)

- **`nonce` / `expires_at` enforcement** — validated-if-present, carried as metadata;
  replay/expiry enforcement is M4.
- **Delegation** — `authority[]` flows to the existing single-hop verification
  unchanged; multi-hop chains are M2.
- **Sidecar/HTTP wiring** — this milestone ships the library, adapters, and
  equivalence tests only. Wiring the envelope into the sidecar decision endpoint is
  a small, separate follow-up (see the expansion doc); the existing request paths
  (`toPolicyEngineRequest`) are untouched.
