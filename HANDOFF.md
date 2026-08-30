# HANDOFF — Agentic Execution Expansion (M1 complete, awaiting review)

This document lets a new session continue the work without chat history. It is
grounded in the actual working tree as of the verification point below. Every
result here was re-run, not copied.

- **Repository:** `mnde-public-test`
- **Branch:** `feat/generic-event-import-foundation`
- **HEAD (base commit):** `ce2363b9b0e2fcdd3f9701ec11ffbcd45f09be12` — `ce2363b Merge pull request #8 … hotfix/ledger-route-authorization`
- **All expansion work is UNCOMMITTED** working-tree changes on top of that commit. Nothing has been committed, staged, or pushed.
- **Verification date:** 2026-08-27 (UTC, system clock at verification). Note the project memory's "today" was 2026-08-26; the machine clock read 2026-08-27T02:27Z when tests were run.
- **Node:** v24.14.1 (required for native `.ts` import / type-stripping, which the tests rely on).
- **Current stopping point:** M1 is implemented and green. **It has NOT been reviewed or approved.** Do not start M2.

---

## 1. Project objective

### What MNDe is
MNDe is a **local pre-execution authorization layer**. Callers (tools, agents,
automation) ask MNDe *before* they execute. MNDe evaluates the proposed action
against a signed, active policy and returns a decision, and writes a signed,
independently verifiable receipt. Enforcement is **cooperative** (it governs only
actions routed through it; it is not OS-level). The canonical decision set today is
strictly **`ALLOW` / `REFUSE`**. See [README.md](README.md) and
[docs/execution-firewall-overview.md](docs/execution-firewall-overview.md).

### Goal of the agentic-execution expansion
Generalize MNDe from an AI/deploy-shaped gate into a **protocol-independent
authority, policy, execution-decision, and evidence layer** for autonomous agents,
MCP tools, machine commerce, and delegated agent networks — *one core, many
protocol adapters*. The core invariant: **no consequential protected execution
occurs without an explicit MNDe decision**, and every decision produces
independently verifiable evidence. Full analysis in
[docs/agentic-execution-expansion.md](docs/agentic-execution-expansion.md).

### Required pipeline (target)
```
REQUEST → IDENTITY → AUTHORITY → DELEGATION → POLICY → DECISION
        → GRANT → EXECUTION → SIGNED RECEIPT
```

### Important security invariants (must never regress)
- Unknown / missing / expired / revoked / unverifiable authority **never** becomes `ALLOW`.
- A valid authority credential does **not** guarantee `ALLOW` (authority ≠ policy).
- An `ALLOW` applies only to the execution it is bound to; replays fail.
- Delegated authority never silently expands (monotonic narrowing) — *not yet applicable; delegation is unimplemented*.
- Receipts prove a decision without trusting the requesting agent.
- Parser / resolver failure fails closed (never executes).
- Malformed / incomplete input fails closed.

---

## 2. Authoritative documents

| Document | Status | What it is |
|---|---|---|
| [docs/agentic-execution-expansion.md](docs/agentic-execution-expansion.md) | **Proposal / architecture target** | Current-state map, gap analysis (EXISTS/PARTIAL/MISSING/CONFLICT/DEFER), threat model, milestone plan. Nothing in it beyond "EXISTS" items is shipped. |
| [docs/execution-envelope-v1.md](docs/execution-envelope-v1.md) | **Implemented (M1)** | Spec for the `mnde.execution.request.v1` envelope + field-mapping table + explicit M1 non-goals. Matches the code. |
| [docs/execution-request-v1.md](docs/execution-request-v1.md) | Implemented | The **distinct** deploy-pipeline `mnde.execution_request.v1` (underscore). Unchanged by M1. |
| [docs/authority-grant-v1.md](docs/authority-grant-v1.md) | Implemented (P0) | Scope-bound single-use `mnde.authority_grant.v1`. |
| [docs/pre-execution-identity-authority-v1.md](docs/pre-execution-identity-authority-v1.md) | **Proposed (ADR)** | Plan to consume identity proof at the pre-exec gate. Not wired to the gate yet. |
| [docs/policy-lifecycle.md](docs/policy-lifecycle.md) | Implemented (in-flight branch) | DRAFT/READY/ACTIVE/RETIRED + activation. Part of pre-existing branch work, not M1. |
| [docs/execution-receipt-spec-v1.md](docs/execution-receipt-spec-v1.md), [docs/execution-ledger.md](docs/execution-ledger.md), [docs/budget-token-hold-lifecycle.md](docs/budget-token-hold-lifecycle.md) | Implemented | Receipts (ERS v1), hash-chained ledger, budget hold/commit/release. |

**Rule of thumb:** anything labeled "Proposed"/"Proposal"/"ADR"/"future work" is
*design only*. Treat only "Implemented" + a passing test as shipped.

---

## 3. Current architecture

Classifications are relative to the expansion spec's target shape.

| Capability | Class | Module(s) | Notes |
|---|---|---|---|
| Decision engine (rules, attrs, ALLOW/REFUSE) | **EXISTS** | [src/policy-engine/index.mjs](src/policy-engine/index.mjs) | Strict `ALLOW`/`REFUSE` (`VALID_EFFECTS`); REFUSE wins; no match → `NO_MATCHING_RULE`; deterministic (`evaluated_at` from `request.timestamp`); integer-only numbers (`NON_INTEGER_NUMBER`). |
| Enforcement-engine selector | **EXISTS** | [shared/decision-engine.mjs](shared/decision-engine.mjs) | `policy-engine` enforced; unknown value → `null` → caller fails closed. |
| Deploy-pipeline gate | **EXISTS** | [src/execution-gate/](src/execution-gate/) | `mnde.execution_request.v1`; hard fail-closed gates; deterministic replay. |
| Authority grant (single-use, scope-bound) | **EXISTS (single-hop)** | [src/policy-engine/authority-grants.mjs](src/policy-engine/authority-grants.mjs) | Binds principal/tool/tenant/scope/nonce/expiry; atomic reserve+consume. `scope.action == tool`; exact-match scope. |
| Replay protection | **EXISTS** | [src/policy-engine/grant-nonce-store.mjs](src/policy-engine/grant-nonce-store.mjs), [sidecar/auth_authority.mjs](sidecar/auth_authority.mjs) | Durable `O_EXCL` single-use reservation; cross-process race-tested. |
| Identity (assertion / OIDC / passport) | **PARTIAL** | [src/identity/](src/identity/) | Wired to the **post-execution** result path; pre-exec gate still reads caller-set `principal.verified`. ADR proposes closing this. |
| Receipts + offline verification | **EXISTS** | [docs/execution-receipt-spec-v1.md](docs/execution-receipt-spec-v1.md), [src/execution-gate/verify-*.mjs](src/execution-gate/), [tools/verify-receipt.mjs](tools/verify-receipt.mjs) | Ed25519, authority-bundle trust anchor, `VERIFIED`/`INVALID`/`UNTRUSTED`, replay. |
| Execution ledger | **EXISTS** | [src/execution-ledger/](src/execution-ledger/) | Append-only hash chain over receipts; Merkle proofs; anchor; production fail-closed. |
| Policy lifecycle / activation | **EXISTS (in-flight branch)** | [src/policy-lifecycle/](src/policy-lifecycle/), [src/policy-activate/](src/policy-activate/) | DRAFT/READY/ACTIVE/RETIRED; explicit activation only. Pre-existing branch work. |
| Stateful budgets | **PARTIAL** | [shared/state.ts](shared/state.ts), [arm/engine.ts](arm/engine.ts) | In-process hold/commit/release; **not durable, not cross-worker** (deferred). |
| MCP enforcement | **EXISTS** | [mcp/mnde-mcp-proxy.mjs](mcp/mnde-mcp-proxy.mjs), [mcp/mnde-mcp-server.mjs](mcp/mnde-mcp-server.mjs), [executor/](executor/) | Every `tools/call` gated; REFUSE never forwards. |
| Sidecar decision path | **EXISTS** | [src/policy-engine/sidecar-adapter.mjs](src/policy-engine/sidecar-adapter.mjs), [sidecar/](sidecar/) | `toPolicyEngineRequest` accepts native `1.0` and legacy envelope. **Not** aware of the new M1 envelope. |
| Event import (evidence) | **EXISTS (in-flight branch)** | [src/event-import/](src/event-import/) | Raw evidence → canonical events; replay/simulation. Pre-existing branch work. |
| **Normalized execution envelope** | **EXISTS (M1, this work)** | [src/execution-envelope/](src/execution-envelope/) | See §4. |
| Multi-hop delegation + effective-authority resolver | **MISSING** | — | M2. Not started. |
| REVIEW / INDETERMINATE as first-class decisions | **PARTIAL / CONFLICT** | shell path only ([shell/policy.mjs](shell/policy.mjs) `APPROVAL_REQUIRED`, caller-gated) | Core engine is ALLOW/REFUSE only. |
| Grant-level revocation list | **MISSING** | — | Only authority-*key* revocation exists. |
| AP2 / payments / cloud verticals | **MISSING** | — | Policy packs + adapters; future. |
| Physical / machine-to-machine | **DEFERRED** | — | Spec defers explicitly. |

---

## 4. Completed M1 work

### `mnde.execution.request.v1` (the normalized envelope)
A single, protocol-independent request envelope that **adapters emit** and a
**normalizer maps into the existing policy-engine request** (`schema_version
"1.0"`). Pure superstructure: the module never hashes, signs, or verifies — it only
reshapes a request. Distinct id from the deploy `mnde.execution_request.v1`
(underscore); the deploy schema is untouched.

### Files new/modified in M1
| File | Change | Purpose |
|---|---|---|
| [src/execution-envelope/index.mjs](src/execution-envelope/index.mjs) | **new** | `EXECUTION_ENVELOPE_SCHEMA`, `ENVELOPE_REASONS`, `validateExecutionEnvelope`, `normalizeExecutionEnvelope`, `decideFromEnvelope`. |
| [src/execution-envelope/adapters/mcp-tool-call.mjs](src/execution-envelope/adapters/mcp-tool-call.mjs) | **new** | Example adapter: MCP `tools/call` shape → envelope. |
| [src/execution-envelope/adapters/http-json.mjs](src/execution-envelope/adapters/http-json.mjs) | **new** | Example adapter: REST/AP2-ish shape → envelope. |
| [tests/test_execution_envelope.mjs](tests/test_execution_envelope.mjs) | **new** | 37 tests (see §6). |
| [docs/execution-envelope-v1.md](docs/execution-envelope-v1.md) | **new** | Envelope spec + mapping table + non-goals. |
| [package.json](package.json) | **modified (1 line added by M1)** | Added `"test:execution-envelope": "node ./tests/test_execution_envelope.mjs"`. All other diff lines are pre-existing branch work (see §9). |
| [tests/expected-test-scripts.json](tests/expected-test-scripts.json) | **modified (1 line added by M1)** | Added `"test:execution-envelope"` (sorted). Other added lines are pre-existing branch work. |

> [docs/agentic-execution-expansion.md](docs/agentic-execution-expansion.md) was authored/updated in this session's architecture pass (M0), not part of M1 implementation code.

### Validation (`validateExecutionEnvelope`)
Returns `null` (valid) or a stable reason: `ERR_ENVELOPE_SCHEMA_UNSUPPORTED`
(missing/wrong `schema`) or `ERR_ENVELOPE_MALFORMED` (any structural defect).
Enforced:
- `schema` must equal `mnde.execution.request.v1` exactly.
- **Strict frame:** unknown top-level keys are rejected (no silent drop).
- Required: `request_id` (non-empty string), `timestamp` (UTC ISO-8601), `principal` (object w/ non-empty `id`; optional non-empty `type`), `action` (object w/ `namespace` + `operation`), `parameters` (object), `context` (object).
- Optional-if-present must be well-formed: `resource` (`type`+`id`), `authority` (array), `environment` (object), `nonce` (non-empty string), `expires_at` (valid timestamp).
- `action.namespace`/`action.operation` must each match `^[A-Za-z0-9_-]+$` (see §5).
- **Dangerous-key defense (prototype-pollution guard):** `__proto__`, `constructor`, or `prototype` as an own key at any depth within `principal`/`action`/`resource`/`parameters`/`environment`/`context` is rejected fail-closed (`ERR_ENVELOPE_MALFORMED`). Signed `authority[]` grants are exempt — they are passed through untouched. Added during M1 security hardening (see §5, §7).

### Normalization (`normalizeExecutionEnvelope`) — field mapping
Returns `{ ok: true, request, authorities, meta }` or `{ ok: false, reason }` — **never a partial request**.

Caller-controlled objects (`principal`, `parameters`, `environment`, `context`) are deep-copied into **null-prototype** objects (via `sanitizeUntrusted`), and the derived `agent`/`tool`/`resource` are built null-prototype too. Consequences: a literal `__proto__` can never invoke a prototype setter, and no inherited property (`hasOwnProperty`, `toString`, or anything on a polluted prototype) can be observed by the engine's `in`-based attribute lookups. Canonicalization reads only own keys, so this is byte-identical to the pre-hardening output for ordinary payloads. Signed `authority[]` grants are passed through untouched (never copied/reserialized, so signatures are preserved).

| Envelope | Policy-engine request `1.0` |
|---|---|
| `request_id`, `timestamp` | verbatim |
| `principal` | `principal` (preserved; `undefined`-valued keys stripped) |
| `principal.id` (+ `type`) | `agent` = `{ id }` or `{ id, type }` |
| `action.{namespace,operation}` | `tool.tool_name = "namespace.operation"`, plus `tool.namespace`, `tool.operation` |
| `resource` | `context.resource = { type, id }` (top-level resource overrides any caller `context.resource`) |
| `parameters` | `parameters` (verbatim, free-form) |
| `environment` | `environment` (`{}` when absent) |
| `context` | `context` (verbatim + injected `resource`) |
| `authority` | returned as `authorities` array (→ engine `options.authorities`); `[]` when absent |
| `nonce`, `expires_at` | returned in `meta` only (not in the request) |

### Adapters
Pure translations only (no validation/coercion). The MCP adapter splits a dotted
tool name on the **last** dot into namespace/operation; a name with no dot yields an
empty namespace → rejected by validation (fail closed). The HTTP adapter builds
`principal` without an `undefined` `type` key.

### Fail-closed behavior
- Invalid envelope → normalizer returns `ok:false`; **no request produced**.
- `decideFromEnvelope` on an invalid envelope produces a genuine engine `INVALID_REQUEST` `REFUSE` by evaluating a guaranteed-invalid sentinel (`REJECTED_ENVELOPE_SENTINEL`) — it **never** hands the rejected envelope to the engine, because a malformed envelope can also be a well-formed native request and would otherwise reach `ALLOW` (fail-open, found and fixed during M1 review — see §7).
- A structurally valid envelope with a non-integer number still `REFUSE`s at the engine (`NON_INTEGER_NUMBER`).

### Backward compatibility
The policy engine and `toPolicyEngineRequest` are **unchanged**. Native `1.0`
requests and the legacy decision envelope work exactly as before. A regression test
asserts a native request still returns `ALLOW`/`OK_ALLOW`.

### What M1 explicitly does NOT do
- Does **not** enforce `nonce` or `expires_at` (metadata only; replay/expiry = M4).
- Does **not** wire the envelope into the sidecar/HTTP endpoint (deferred).
- Does **not** interpret `authority[]` beyond passing it to existing single-hop verification (delegation = M2).
- Does **not** bind envelope `resource` to authority-grant `scope.resource` (deferred).
- Does **not** touch decision-hash material, signing, receipts, verifier, or any crypto.

---

## 5. Security and design caveats

1. **`expires_at` / `nonce` are metadata, NOT enforced.** Documented in the module
   header, [docs/execution-envelope-v1.md](docs/execution-envelope-v1.md), and a
   test ("nonce/expires_at are carried as metadata but NOT enforced in M1") that
   shows an already-expired envelope still `ALLOW`s. Enforcement is M4.
2. **Sidecar/HTTP wiring is deferred.** The envelope is usable only via the library
   API today. Do not wire it into the sidecar without explicit authorization.
3. **Resource → authority-grant binding is deferred.** Grants bind
   `scope.resource` to `request.parameters.resource`; the envelope maps resource to
   `context.resource`. Reconciling these is M2/M4 work, not done.
4. **Multi-hop delegation is not implemented.** `authority[]` flows to existing
   single-hop verification unchanged. Monotonic-narrowing enforcement does not exist.
5. **Core engine remains `ALLOW`/`REFUSE`.** No REVIEW/INDETERMINATE decision was
   added. (A caller-gated `APPROVAL_REQUIRED` exists only in the illustrative shell
   path.)
6. **Action-token restriction + compatibility risk.** `namespace`/`operation` must
   each match `^[A-Za-z0-9_-]+$` so the `"namespace.operation"` join is injective
   (two different action pairs can never collide onto one `tool_name`).
   - *Verified compatible:* every tool name currently in the repo — `read_status`,
     `restart_service`, `delete_backups`, `run_command`, `deploy`, `delete`,
     `delete_file`, `recursive_delete`, `read`, `delete_everything`, `Deploy` — is a
     valid single token.
   - *Risk / behavior change:* an envelope-sourced request for `read_status`
     becomes `tool_name = "<namespace>.read_status"`, which does **not** equal the
     flat `"read_status"` that existing policies/grants match. Envelope flows need
     policies authored for the dotted name — this is exactly why M1 is **not** wired
     into the sidecar. Any real source whose action identifier contains `.`, `/`, or
     whitespace must be split by its adapter (the MCP adapter demonstrates this).
7. **No cryptographic/decision-integrity change.** By construction, the M1 module
   imports only `evaluatePolicyRequest` (no `node:crypto`); the CI-contract crypto
   lint passes. Decision-hash material, signing, receipts, and verifier code were
   not modified.

---

## 6. Verification (re-run at handoff)

Commands and **fresh** results (Node v24.14.1, 2026-08-27 UTC):

| Command | Result |
|---|---|
| `npm run test:execution-envelope` | `PASS execution-envelope (37/37)` |
| `npm run test:ci-contract` | `PASS CI contract` |
| `npm run check:whitespace` | `PASS whitespace check (339 tracked files)` |
| `npm test` (full suite) | **`PASS all test scripts (75/75)`** |

(Re-verified 2026-08-27 after the M1 review fix and the prototype-pollution hardening below; the envelope suite grew 26 → 29 → 37 tests. The new M1 files remain untracked, so the tracked-only `check:whitespace` does not yet cover them.)

Notes:
- `check:whitespace` covers **tracked** files only; the new M1 files are untracked,
  so they are not yet whitespace-checked by that command (they will be once added).
  They were authored clean.
- Re-run these before trusting any claim here.

---

## 7. Current review checkpoint (do this before approving M1)

**Review outcome (2026-08-27):** The focused review was performed against the code,
across two passes.

- **Pass 1 — one clear defect found and fixed:** a fail-open in `decideFromEnvelope` —
  an invalid envelope that also satisfied the native policy-engine request schema
  reached `ALLOW`, because the invalid branch fed the raw envelope to the engine.
  Fixed by evaluating a guaranteed-invalid sentinel instead (see §4). +3 tests.
- **Pass 2 — security hardening (requested):** the `__proto__` observation was
  addressed. `parameters`/`context` (and `principal`/`environment`) are now treated
  as untrusted: dangerous own keys (`__proto__`/`constructor`/`prototype`) are
  rejected fail-closed at any depth, and all normalized objects are rebuilt with null
  prototypes so no prototype can be polluted and no inherited property can influence
  policy evaluation. +8 tests (JSON-parsed `__proto__` in parameters/context/
  principal, `constructor`/`prototype`, no-pollution, null-prototype representation,
  and an inherited-property-cannot-match-`exists` test).

The envelope suite is now **37/37** and the full suite **75/75**. All checklist items
below pass. **M1 still requires explicit user approval before proceeding.**

Verify each item against the code:

- [x] **Caller-controlled `context` cannot overwrite derived identity/tenant/action/resource.** In `normalizeExecutionEnvelope`, the request is built with separate top-level keys; `envelope.context` only becomes `request.context`. Derived `principal`/`agent`/`tool`/`parameters`/`environment` are set from their own envelope fields, and top-level `resource` overrides `context.resource` (not vice-versa). *Tenant is not modeled by the envelope at all* — confirm that is acceptable and that nothing derives a tenant that context could shadow. **Covered by the test "caller-supplied context cannot shadow derived identity/action/resource."**
- [x] **Untrusted `parameters`/`context` cannot pollute a prototype or inject inherited properties.** Dangerous own keys are rejected fail-closed; normalized objects are null-prototype. **Covered by the 5 dangerous-key tests + "never pollute Object.prototype" + "prototype-safe (null prototype)" + "no inherited property can satisfy a policy `exists` match."**
- [x] **Normalization is deterministic and does not mutate inputs.** `sanitizeUntrusted`/`nullProtoObject` return new objects; the function never assigns to `envelope.*`. Deterministic canonical output is covered by the "byte-identical request" test; input-immutability by "normalization does not mutate the input envelope."
- [x] **Malformed / missing / ambiguous / adapter-error cases fail closed.** Covered by the 16-case malformed matrix + `decideFromEnvelope` malformed test + the fail-open regression test + the dangerous-key tests. (The fail-open defect in this category was found and fixed — see the review outcome above.)
- [x] **Action-token restrictions work with existing tool names.** See §5 — all current repo tool names are valid tokens; the dotted-name behavior change is documented.
- [x] **Non-enforcement of `expires_at`/`nonce` is unmistakably documented.** Module header + envelope doc + a dedicated test.
- [x] **The diff contains no unrelated changes.** M1 touched only the 5 new files + 1 line each in `package.json` and `tests/expected-test-scripts.json`. Everything else in the working tree is pre-existing branch work (§9).

---

## 8. Next steps (ordered)

1. **Perform the focused M1 review** in §7 against the code. Add the two suggested tests (context-cannot-shadow-derived-fields; normalize-does-not-mutate-inputs) if the reviewer wants them.
2. **Get explicit user approval of M1.** Do not proceed past this without it.
3. Only if the user explicitly authorizes it, and as a **separate** change: wire the envelope into the sidecar decision path (additive branch in `toPolicyEngineRequest` / `decidePolicyEngine`, routing `body.schema === "mnde.execution.request.v1"` and `body.authority`). Keep it independent of M2.
4. **Future work — do NOT start without approval:**
   - **M2** — multi-hop delegation + effective-authority resolver (`effectiveAuthority(child) ⊆ effectiveAuthority(parent)`), chain hashing into the receipt.
   - **M3** — REVIEW/INDETERMINATE decision surface (new decision-output schema version; touches conformance vectors + every verifier verdict).
   - **M4** — grant-level revocation + `request_hash`/nonce/expiry binding.
   - **M5** — durable cross-worker atomic budget reservation.
   - **M6** — AP2 adapter + payment policy pack (simulation only).

---

## 9. Working-tree state

`git status --short` (HEAD `ce2363b`, nothing committed/staged):

```
 M README.md
 M docs/policy-drafting.md
 M package.json
 M src/policy-bundles/index.mjs
 M src/policy-drafting/index.mjs
 M tests/expected-test-scripts.json
?? docs/agentic-execution-expansion.md
?? docs/execution-envelope-v1.md
?? docs/generic-event-import-foundation.md
?? docs/policy-lifecycle.md
?? policy-editor/
?? src/event-import/
?? src/execution-envelope/
?? src/policy-activate/
?? src/policy-lifecycle/
?? tests/helpers/
?? tests/test_event_import_foundation.mjs
?? tests/test_execution_envelope.mjs
?? tests/test_policy_activate.mjs
?? tests/test_policy_editor_draft_import.mjs
?? tests/test_policy_editor_review.mjs
?? tests/test_policy_lifecycle.mjs
?? tools/activate-policy.mjs
?? tools/policy-status.mjs
?? tools/sign-policy-bundle.mjs
?? verifier/
```

### Attribution (what came from where)

| Change | Origin |
|---|---|
| `src/execution-envelope/`, `tests/test_execution_envelope.mjs`, `docs/execution-envelope-v1.md` | **M1 (this work)** |
| 1 added line in `package.json` (`test:execution-envelope`) + 1 in `tests/expected-test-scripts.json` (`"test:execution-envelope"`) | **M1 (this work)** |
| `docs/agentic-execution-expansion.md` | This session's **M0 architecture pass** |
| `HANDOFF.md` | This task |
| `README.md`, `docs/policy-drafting.md`, `src/policy-bundles/index.mjs`, `src/policy-drafting/index.mjs`; all **other** added lines in `package.json` / `tests/expected-test-scripts.json`; untracked `policy-editor/`, `src/event-import/`, `src/policy-activate/`, `src/policy-lifecycle/`, `tests/helpers/`, `verifier/`, `docs/generic-event-import-foundation.md`, `docs/policy-lifecycle.md`, `tools/{activate-policy,policy-status,sign-policy-bundle}.mjs`, `tests/test_{event_import_foundation,policy_activate,policy_editor_draft_import,policy_editor_review,policy_lifecycle}.mjs` | **Pre-existing branch work** (present at session start; not this task). Do not attribute to M1. |

Concise diffstat of tracked files (mix of M1 + pre-existing):
```
 README.md                        |  7 +++++++   (pre-existing)
 docs/policy-drafting.md          | 32 ++++++++   (pre-existing)
 package.json                     | 10 ++++++++   (1 line M1, rest pre-existing)
 src/policy-bundles/index.mjs     |  2 +-        (pre-existing)
 src/policy-drafting/index.mjs    | 37 +++++++    (pre-existing)
 tests/expected-test-scripts.json |  6 ++++++    (1 line M1, rest pre-existing)
```

**Do not commit, discard, stage, clean, or overwrite any of these changes.** The
tree intentionally holds both the in-flight branch work and the new expansion work.

---

## 10. Continuation instructions (read this first, next session)

**Read these files, in order:**
1. This `HANDOFF.md`.
2. [docs/agentic-execution-expansion.md](docs/agentic-execution-expansion.md) — the plan and gap analysis.
3. [docs/execution-envelope-v1.md](docs/execution-envelope-v1.md) — the M1 spec.
4. [src/execution-envelope/index.mjs](src/execution-envelope/index.mjs) — the implementation (~305 lines).
5. [src/execution-envelope/adapters/mcp-tool-call.mjs](src/execution-envelope/adapters/mcp-tool-call.mjs) and [http-json.mjs](src/execution-envelope/adapters/http-json.mjs).
6. [tests/test_execution_envelope.mjs](tests/test_execution_envelope.mjs).
7. For context on what the envelope maps into: [src/policy-engine/index.mjs](src/policy-engine/index.mjs) and [src/policy-engine/sidecar-adapter.mjs](src/policy-engine/sidecar-adapter.mjs).

**Safest verification commands (read-only, no writes):**
```bash
npm run test:execution-envelope
npm run test:ci-contract
npm run check:whitespace
npm test
```
Optional working-tree inspection (read-only):
```bash
git status --short
git diff -- package.json tests/expected-test-scripts.json
```

**Stopping point / what needs user approval:** M1 is complete and green but
**unreviewed**. The next action is the focused review in §7, then obtain **explicit
user approval**. Sidecar wiring and M2+ require separate explicit authorization.

**Warnings for the next session:**
- Do **not** expand scope. Do only what is asked.
- Do **not** change frozen decision-hash material, signing, receipts, verifier, or any cryptographic behavior.
- Do **not** start M2 (or any later milestone) automatically.
- Do **not** wire the envelope into the sidecar unless explicitly authorized, and if so keep it a separate change.
- Do **not** commit, discard, or clean the working tree.
- Keep all new inputs fail-closed; never let unknown/malformed data reach `ALLOW`.
