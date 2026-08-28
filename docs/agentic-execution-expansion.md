# Agentic Execution & Machine-Commerce Expansion — Architecture Mapping and Gap Analysis

Status: **Proposal / architecture target.** Nothing in this document is shipped
capability. It maps the "MNDe Agentic Execution and Machine Commerce Expansion
Specification" (v0.1 concept) against the current repository, classifies every
proposed capability, and recommends the smallest foundational change. Per the
source spec §55, this document is the deliverable to review **before** any
implementation begins.

Claims discipline (spec §54.H) is applied throughout. Every capability is tagged:

- **EXISTS** — implemented and tested in this repository today.
- **PARTIAL** — a real implementation exists but does not meet the spec's shape.
- **MISSING** — not present.
- **CONFLICT** — the spec's shape contradicts a load-bearing current invariant.
- **DEFER** — out of scope for the near term by deliberate choice.

Everything under "Architecture Proposal" and later is **planned**, not built.

---

## A. Current-State Map

MNDe is already a pre-execution authorization layer that returns `ALLOW`/`REFUSE`
and emits an offline-verifiable signed receipt. The spec's generalized model
(`REQUEST → IDENTITY → AUTHORITY → DELEGATION → POLICY → DECISION → GRANT →
EXECUTION → RECEIPT`) maps onto existing modules with surprisingly little
missing — the main absences are **multi-hop delegation**, a **single normalized
protocol envelope**, and **REVIEW/INDETERMINATE as first-class decisions**.

### A.1 Decision core

- [`src/policy-engine/index.mjs`](../src/policy-engine/index.mjs) — the canonical
  evaluator. Validates a request against a signed, `ACTIVE` policy of
  `schema_version "1.0"`; boolean rule expressions (`all`/`any`/`not`, operators
  `eq`/`neq`/`contains`/`prefix`/`path_prefix`/`exists`/`missing`) over attribute
  roots `principal`/`agent`/`tool`/`parameters`/`environment`/`context`. Effects
  are **strictly `ALLOW`/`REFUSE`** (`VALID_EFFECTS`). REFUSE wins over ALLOW; an
  ALLOW rule with unmet `authority_required` falls through to the next; no match
  is `NO_MATCHING_RULE` (fail closed). Deterministic: `evaluated_at` derives from
  `request.timestamp`, never wall-clock; integer-only number model.
- [`shared/decision-engine.mjs`](../shared/decision-engine.mjs) — the single
  source of truth for "is enforcement enabled." `policy-engine` is the enforced
  path; `legacy` is the non-enforced compute pipeline. Unknown engine value →
  `null` → caller fails closed.
- [`src/execution-gate/`](../src/execution-gate/) — the `mnde.execution_request.v1`
  deploy-pipeline gate: hard-coded fail-closed gates
  (`PRINCIPAL_NOT_VERIFIED` first, `APPROVAL_REQUIRED`,
  `DESTRUCTIVE_REQUIRES_APPROVAL`) plus deterministic receipt + offline replay
  (`replayExecutionGate`). See [execution-request-v1.md](execution-request-v1.md).

### A.2 Authority / grant

- [`src/policy-engine/authority-grants.mjs`](../src/policy-engine/authority-grants.mjs)
  — **`mnde.authority_grant.v1`** (spec [authority-grant-v1.md](authority-grant-v1.md)).
  This is already very close to the spec's "execution grant" (§7) **and**
  single-issuer "authority" (§8): a signed grant bound to exact
  `principal`/`tool`/`tenant`/`scope`, `nonce` + `grant_id` (two independent
  single-use reservations), bounded lifetime with clock-skew tolerance,
  issuer/key resolved through the authority manifest, and atomic
  reserve-and-consume. Exact-match scope only.
- [`src/policy-engine/grant-nonce-store.mjs`](../src/policy-engine/grant-nonce-store.mjs)
  — durable, atomic, file-based single-use reservation (`O_EXCL`), cross-process
  race-tested. This is the spec's replay-resistance primitive (§28).
- [`src/policy-engine/trust.mjs`](../src/policy-engine/trust.mjs) — legacy
  unscoped bearer grant. Refused outright in production; retained only for its own
  test coverage.

### A.3 Identity

- [`src/identity/`](../src/identity/) — `mnde.identity_assertion.v1` (hash-bound
  claims), deterministic verifier, offline GitHub-Actions OIDC adapter (JWKS
  pinned by hash, **no network fetch at gate time**), and `passport.mjs`
  (`passport_subject_id`). Wired today to the **post-execution** signed-result
  path; the pre-execution gate still reads a caller-set `principal.verified`
  boolean. [pre-execution-identity-authority-v1.md](pre-execution-identity-authority-v1.md)
  is the *proposed* ADR to close that (consume proof, not a claim). This is the
  spec's "consume external identity, don't reinvent it" position (§22) already
  argued in-repo.

### A.4 Evidence / receipts / ledger

- [`docs/execution-receipt-spec-v1.md`](execution-receipt-spec-v1.md) — ERS v1:
  Ed25519 receipts, authority-bundle trust anchor (receipt never trusts its own
  embedded key), offline verification, deterministic replay, `VERIFIED`/`INVALID`/
  `UNTRUSTED` verdicts. This is the spec's receipt/verification requirement (§23,
  §38) — already implemented and conformance-vectored
  ([`conformance/`](../conformance/)).
- [`src/execution-ledger/`](../src/execution-ledger/) — append-only hash-chained
  ledger over finalized receipts, Merkle proofs, anchor/witness support,
  authority-gated export, production fail-closed. Spec's evidence-integrity and
  "witness the head" story (§38, §27 revocation-state anchoring) — largely EXISTS.
- [`src/policy-lifecycle/`](../src/policy-lifecycle/) +
  [`src/policy-activate/`](../src/policy-activate/) — DRAFT/READY/ACTIVE/RETIRED,
  hash-bound ACTIVE, explicit-activation-only, no partial activation
  ([policy-lifecycle.md](policy-lifecycle.md)). This is the "policy is
  change-controlled, versioned, signed" property the spec assumes.

### A.5 Stateful budgets

- [`docs/budget-token-hold-lifecycle.md`](budget-token-hold-lifecycle.md),
  `shared/state.ts`, `arm/engine.ts` — hold/commit/release budget accounting with
  concurrent-hold accounting against the sum of outstanding holds (closes the
  two-concurrent-requests-both-fit window **in-process**). Explicitly **in-memory,
  per-worker, non-durable**; the durable cross-worker atomic ledger is a named
  future stage. Directly relevant to spec §29–30.

### A.6 Adapters

- [`mcp/mnde-mcp-proxy.mjs`](../mcp/mnde-mcp-proxy.mjs) — transparent MCP proxy;
  every `tools/call` is gated through MNDe before forwarding, REFUSE never
  forwards. Plus `mcp/mnde-mcp-server.mjs`, `mcp/shell-mcp-server.mjs`,
  `executor/` wrapper. This is the spec's MCP vertical (§16) — EXISTS in
  demonstrable form.
- [`src/event-import/`](../src/event-import/) — Generic Event Import Foundation
  (in-flight on this branch): raw-evidence staging, adapter normalization to
  `mnde.canonical_execution_event.v1`, tenant-scoped search, and **replay/policy
  simulation over historical events**. This is the spec's "consume authority/
  evidence from many sources through adapters into one canonical model" pattern
  (§6, §31) applied to *evidence* rather than *live requests* — the same adapter
  discipline the live path will need.

---

## B. Gap Analysis

| # | Spec capability | Class | Where it stands |
|---|---|---|---|
| §6 | Normalized protocol-independent execution envelope (`mnde.execution.request.v1`) | **PARTIAL** | Two request schemas exist (policy-engine `1.0` AI-shaped; `mnde.execution_request.v1` deploy-shaped). Neither is the spec's single `principal/action/resource/authority[]/context` envelope. Adapters translate ad hoc. |
| §7 | Narrow, signed, single-use execution grant bound to request/principal/action/resource/policy/nonce | **EXISTS (≈)** | `mnde.authority_grant.v1` covers principal/tool(action)/tenant/scope/nonce/expiry/policy-key binding + single-use. Not yet bound to a `request_hash`, and `action==tool` (no finer action granularity). |
| §8 | Generalized authority object (issuer/subject/actions/resources/constraints/delegation/expiry/revocation) | **PARTIAL** | Grant has issuer/subject(principal)/action/resource/constraints/expiry. **No `delegation` block, no `revocation_reference`.** |
| §9–10 | Delegated authority; full delegation-chain verification; monotonic narrowing | **MISSING** | Grants are single-hop (one issuer → one principal). No chain, no depth, no `effectiveAuthority(child) ⊆ effectiveAuthority(parent)` enforcement. This is the single largest gap. |
| §11 | Deterministic effective-authority resolver with explicit states (VALID/EXPIRED/REVOKED/UNVERIFIABLE/AMBIGUOUS/…) | **PARTIAL** | `verifyAndConsumeAuthorityGrant` returns rich `AUTHORITY_GRANT_*` reason codes, but there is no single resolver returning `{status, effective_actions, effective_resources, effective_constraints, authority_chain_hash}`. |
| §12 | Authority separate from policy (a valid credential does not guarantee ALLOW) | **EXISTS** | `authority_required` (authority) and `rules[]` (policy) are independent; ALLOW needs both a matching ALLOW rule and satisfied authority. Invariant 4 already holds. |
| §13–15 | Agentic payments vertical; AP2 adapter; payment policy pack (limits, merchant allowlists, categories) | **MISSING** | No payment concepts, no AP2 adapter. AP2 is treated (correctly, per spec §3) as an upstream authority source to consume, not replace. |
| §16–17 | MCP enforcement adapter for dangerous tool ops | **EXISTS** | MCP proxy + server gate `tools/call` before execution; REFUSE never forwards; receipt proves it. Namespace/resource mapping is by tool name only (coarse). |
| §18 | Cloud-infrastructure vertical | **MISSING** | No cloud-operation policy pack. Architecturally an adapter + policy pack; not built. |
| §19–20 | Machine-to-machine commerce; autonomous supply chain | **DEFER** | Depends on delegation + stateful budgets + payments; explicitly later in the spec's own sequence (§44). |
| §21 | Physical systems | **DEFER** | Spec itself says do not prioritize before software integrations. |
| §22 | Consume external identity (OAuth/OIDC/SPIFFE/PKI/AP2) rather than reinvent | **PARTIAL** | OIDC assertion/passport stack EXISTS but is wired only post-execution; pre-execution binding is the proposed ADR ([pre-execution-identity-authority-v1.md](pre-execution-identity-authority-v1.md)). No SPIFFE/OAuth adapters yet. |
| §23–24 | Independently verifiable receipts; stable machine-readable reason codes | **EXISTS / PARTIAL** | ERS v1 receipts + verifier EXIST. Reason codes are rich but named per-subsystem; the spec's flat `AUTHORITY_*`/`POLICY_*`/`DELEGATION_*`/`EXECUTION_GRANT_*` taxonomy (§24) is not the current naming. Mapping needed, not a rewrite. |
| §25 | Fail-closed invariants (unknown/missing/expired/revoked/unverifiable never ALLOW; replay fails; parser failure never executes) | **EXISTS** | This is the codebase's core discipline and is heavily tested (`test_authority_grants`, `test_nonce_replay`, `test_production_posture`, `test_startup_checks`, hostile suites). |
| §26 | REVIEW as a first-class execution decision state | **PARTIAL / CONFLICT** | Canonical policy engine is strictly `ALLOW`/`REFUSE`. A third `APPROVAL_REQUIRED` decision exists only in the illustrative shell path and is gated on a caller-supplied `hold_state`; `authenticated-approvals.mjs` verifies signed approvals but still resolves to ALLOW/REFUSE. Making REVIEW a returned decision touches the frozen decision-hash material and every verifier — deliberate, staged change required. |
| §27 | Revocation (grant-level, not just key-level) | **PARTIAL** | Authority-**key** revocation exists (`findAuthorityReceiptKey` honours `revoked_at`; custody `evaluateRevocation`). **No grant-level revocation list** (`authority-grant-v1.md` §8 step 14 is a reserved no-op). No writer for `revoked_at` on the simple manifest (P1 roadmap). |
| §28 | Replay protection (nonce, request/resource binding, single-use) | **EXISTS** | `grant-nonce-store.mjs` + `sidecar/auth_authority.mjs` nonce reservation; grant binds `nonce` + `grant_id`. Not yet bound to a per-request `request_hash` on the grant. |
| §29–30 | Stateful budgets; atomic reservation under concurrency (durable, cross-worker) | **PARTIAL** | In-process hold/commit/release with concurrent-hold accounting EXISTS; **durable, cross-worker, restart-surviving** reservation is explicitly deferred (budget doc §6). |
| §31–32 | Adapter architecture; core free of protocol-specific assumptions | **PARTIAL** | MCP + executor + event-import adapters exist and the policy core is protocol-agnostic, but there is no formal `/adapters` boundary contract or `authority/execution/policy/evidence/state` module layout. |
| §38 | External verification without trusting the originating agent | **EXISTS** | ERS v1 + authority bundle + ledger give exactly this for the decision/receipt; delegation-chain evidence for a verifier is the missing piece (blocked on §9–10). |
| §48 | The ten critical invariants | **MOSTLY EXISTS** | Invariants 1,3,4,5,6,7,8,9 hold today for the single-hop path. Invariant 2 (delegation never expands) is **untestable until delegation exists**. Invariant 10 (stateful limits under concurrency) holds in-process, not yet durably. |

**Bottom line:** MNDe already implements the hard cryptographic and fail-closed
core the spec calls for. The genuine *new* surface is: (1) a single normalized
execution envelope, (2) multi-hop delegation with monotonic narrowing + a chain
resolver, and (3) an honest REVIEW/INDETERMINATE decision surface. Payments,
cloud, and machine commerce are **policy packs + adapters** on top of that core,
not new cryptography.

---

## C. Architecture Proposal (smallest changes that preserve current invariants)

The guiding constraint (spec §33, §54): **do not rewrite MNDe.** Every proposal
below is additive and staged behind a flag, mirroring how `MNDE_REQUIRE_ACTIVATION`
and `MNDE_REQUIRE_IDENTITY_ASSERTION` were staged.

### C.1 Normalized envelope as an adapter output, not a core rewrite

Introduce `mnde.execution.request.v1` (spec §6) as a **new envelope that adapters
emit and a thin normalizer maps into the existing policy-engine request** — the
`1.0` schema and its frozen decision-hash material stay untouched. The core keeps
evaluating today's shape; the envelope is a stable public boundary. Adapter
equivalence (spec §47: "same semantic execution through two adapters →
equivalent policy treatment") becomes a testable property at the normalizer.

### C.2 Delegation as a verifiable chain over existing grants

Extend `mnde.authority_grant.v1` (or add `mnde.authority.v1` alongside it) with an
optional `delegation { allowed, max_depth }` block and a `parent_grant_ref`.
Add a resolver `resolveEffectiveAuthority(chain, request, now)` that:

- verifies each edge with the **existing** `verifyAndConsumeAuthorityGrant`
  machinery (signature, key validity, expiry, binding) — no new crypto;
- enforces `effectiveAuthority(child) ⊆ effectiveAuthority(parent)` (actions,
  resources, constraints monotonically narrow; depth non-increasing);
- returns a spec-§11 result object with an `authority_chain_hash` that binds into
  the receipt (the receipt already carries `authority_chain_hash`).

Fail-closed on any unverifiable/ambiguous edge. This is the highest-value new
capability and the only one that unlocks §9–11, §37, §52.

### C.3 REVIEW / INDETERMINATE as a staged decision surface

Add `REVIEW` and `INDETERMINATE` to the decision enum **behind a decision-output
schema bump (v2 → v3)**, never mutating the frozen v1/v2 decision material. A
REVIEW produces no execution grant; reviewer approval mints a **narrowly scoped,
single-use** grant bound to the original `request_hash` (reusing
`authenticated-approvals.mjs` + `authority-grants.mjs`), so approval cannot widen
authority (spec §26 invariant). Conformance vectors and every verifier verdict
path must be updated in the same change.

### C.4 Grant-level revocation + request binding

Add an optional `revocation_reference` to the grant and a checked
grant-revocation list (the reserved no-op step in `authority-grant-v1.md` §8).
Add optional `request_hash` binding to the grant so an ALLOW binds to exactly one
request (spec §7, §28), closing the last replay gap.

### C.5 Adapters and payment/cloud policy packs

Formalize an `/adapters` contract (parse → normalize to envelope → evaluate →
translate decision) and ship the AP2 adapter (§15) and a payment policy pack
(§14) as the first vertical, then a cloud policy pack (§18). No core changes.

### C.6 Durable budget reservation

Land the named durable stage of the budget ledger (budget doc §6): a parent-owned
`budget_reservations` ledger keyed by `(budget_token, execution_id)`, finalized in
the same transaction as the `execution_id` terminal write. Fail-closed default is
RELEASE (never silently overcharge). Required before any real-money vertical.

---

## D. Threat Model (spec §46, §54.D)

| Threat | Current control | Gap to close |
|---|---|---|
| Compromised / prompt-injected agent submits unauthorized execution | Policy + authority evaluated before execution; REFUSE never forwards (MCP proxy) | None for single-hop; the flagship demo (§40) is buildable today on MCP |
| Malicious delegate escalates authority | — | **MISSING** until §C.2 delegation resolver enforces monotonic narrowing |
| Stolen authority credential replayed | Single-use `nonce`+`grant_id`, atomic reservation | Bind grant to `request_hash` (§C.4) to also stop same-grant/different-request |
| Replayed execution grant | Durable nonce store, cross-process race-tested | Covered |
| Revoked authority still used | Key-level revocation honoured at issue + eval time | **Grant-level** revocation list (§C.4) |
| Adapter confusion (same action, different treatment via two adapters) | — | Normalizer equivalence tests (§C.1, spec §47) |
| Executor impersonation / TOCTOU between decision and execution | Grant is single-use and consumed at decision; executor is the run() closure on ALLOW | Executor-binding + `request_hash` binding (§C.4) hardens this |
| Receipt forgery | ERS v1: authority-bundle trust anchor, receipt never trusts own key, Ed25519, replay | Covered |
| Compromised reviewer | Authenticated approvals are signed; approval mints only a narrow single-use grant | Depends on §C.3 landing with approval→scoped-grant binding |
| Budget race (two valid requests overspend) | In-process hold-sum accounting | **Durable cross-worker** reservation (§C.6) |
| Poisoned verifier policy (forged "verified" identity) | Proposed `mnde.verifier_policy.v1` custody-signed, version high-water mark | Land the pre-exec identity ADR |
| Revocation state unavailable at decision time | Fail-closed philosophy established | Define explicit REFUSE-vs-INDETERMINATE split (spec §46 Q8/Q19/Q20) |

---

## E. Migration & Milestone Sequence (spec §34–37, §54.E)

Each milestone: additive, flag-staged, existing tests stay green, new tests
required, independent rollback.

1. **M1 — Normalized envelope + adapter equivalence.** `mnde.execution.request.v1`
   + normalizer into the existing engine. Tests: two adapters → equivalent
   decision. Rollback: drop the envelope; core unchanged.
2. **M2 — Delegation chain + effective-authority resolver.** The core new
   capability. Tests: valid multi-hop, expansion attempt REFUSE, depth exceeded,
   constraint/resource/action expansion REFUSE, chain mutation REFUSE. Rollback:
   feature flag off → single-hop behavior identical to today.
3. **M3 — REVIEW/INDETERMINATE decision surface (schema v3).** Reviewer approval →
   scoped single-use grant bound to `request_hash`. Tests: review approval
   binding, review request mutation, approval cannot widen authority. Highest
   compatibility care (touches verifier verdicts + conformance vectors).
4. **M4 — Grant-level revocation + `request_hash` binding.** Tests: revoked grant
   REFUSE; grant valid for request A rejected for request B.
5. **M5 — Durable budget reservation.** Tests: concurrent cross-worker budget race
   cannot overspend; restart survives; fail-closed = RELEASE.
6. **M6 — First vertical: AP2 adapter + payment policy pack.** Consume AP2 mandate
   as upstream authority; do not mutate AP2 semantics. Simulation only, no real
   money. Then the three flagship demos (spec §39–40).

---

## F. Recommended First PR (spec §35, §55.F)

**M1 only: the normalized execution envelope + normalizer + adapter-equivalence
tests.** Rationale:

- It is the smallest change that establishes the spec's central abstraction (one
  core, many adapters) **without** touching the frozen decision-hash material,
  the receipt format, or any existing test.
- It is a pure superstructure over the existing engine, so it cannot regress the
  security core.
- It makes M2 (delegation) and M6 (AP2) tractable, because both become "emit the
  envelope" rather than "modify the core."

Do **not** bundle MCP hardening, AP2, payments, delegation, durable budgets, and a
new decision surface into one PR (explicit spec §54.F warning).

---

## G. Compatibility (spec §54.G)

- The frozen v1 decision material and the `ecs.receipt.v2` / conformance vectors
  MUST stay byte-identical; every change here is additive and version-gated.
- Existing tests remain green; new behavior ships behind flags
  (`MNDE_REQUIRE_*`-style), defaulting off until callers migrate.
- No new runtime dependency: all cryptography stays on `node:crypto`, matching
  `test_ci_contract.mjs`'s allowlist.
- The legacy bearer grant stays refused in production; nothing here reintroduces
  it.

---

## H. Open Questions to Resolve Before M2/M3 (spec §46)

1. Delegation representation: extend `mnde.authority_grant.v1` in place, or a
   sibling `mnde.authority.v1` with a `delegation` block? (Affects receipt
   `authority_chain_hash` shape.)
2. When revocation state is unavailable at decision time — REFUSE or the new
   INDETERMINATE? (Spec §46 Q8/Q20 demand an explicit, tested answer.)
3. Executor→grant binding: does the executor present proof of identity the grant
   is checked against, or is single-use consumption at decision sufficient for
   the near term? (Spec §46 Q10/Q11.)
4. Reviewer approval scope: confirm approval mints a grant that can only *narrow*,
   never widen, the original request's authority (spec §26).

---

## References

- Source spec: "MNDe Agentic Execution and Machine Commerce Expansion
  Specification" v0.1 (concept).
- [authority-grant-v1.md](authority-grant-v1.md) — the grant this expansion builds on.
- [execution-request-v1.md](execution-request-v1.md), [execution-receipt-spec-v1.md](execution-receipt-spec-v1.md).
- [pre-execution-identity-authority-v1.md](pre-execution-identity-authority-v1.md) — identity binding ADR.
- [policy-lifecycle.md](policy-lifecycle.md), [budget-token-hold-lifecycle.md](budget-token-hold-lifecycle.md), [execution-ledger.md](execution-ledger.md).
- External (spec §56): Mastercard Agent Pay for Machines; AP2 protocol + agent-authorization + v0.2 spec; NIST AI-agent identity/authorization concept paper.

---

**Next step:** review this mapping. Per spec §55, implementation should not begin
until the architecture is agreed. When it does, start with **M1 (Section F)**.
