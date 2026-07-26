# Durable, Actor-Bound Budget Authority — Design Spec

**Status:** DRAFT · design-only · **no runtime code changes in this branch**
**Branch:** `design/durable-actor-bound-budget` (documentation only)
**Continues:** the hold/commit/release correctness fix (PR #4, `fix/budget-token-hold-finalization`)
**Frames:** the MNDe *authority-flow calculus*

> **Trust a fixed cryptographic root and an append-only history — verify everything else.**

This document specifies the design for making budget-token authority **durable**
(survives restart), **shared-atomic** (correct across all executors), and
**actor-bound** (a token spends only for the actor it was issued to). It does
**not** change runtime behavior. It resolves four decisions first, because those
decisions determine the state machine, the receipt schema, and the recovery
semantics — everything downstream depends on them.

Nothing here modifies PR #4. The correctness fix (defer the charge to a
post-Ramona commit; release on any terminal refuse) is the *foundation* this
builds on, not something to revisit.

---

## 0. Why budget is special (one paragraph of calculus)

An authority grant is `A = (Q, C, Θ, D)`: qualitative permissions `Q`, conserved
capacities `C`, temporal/state conditions `Θ`, delegation provenance `D`.
Qualitative authority is a **set** governed by containment (`Q_{i+1} ⪯ Q_i`) and
verifies **statelessly**. Budget is **conserved** authority `C ∈ ℝ^k_{≥0}` — it
depletes, so its validity is **ledger-relative**: "is this within budget?" is
only answerable against authenticated history `H`. The governing invariant, at
every instant, for every token:

```
C_issued = C_available + C_held + C_committed
```

and the conservation law that the no-refund defect violated:

```
ΔC_committed = 0  unless an execution validly commits.
```

A failure must never reduce total authority. This spec is the durable, shared,
actor-scoped realization of that invariant.

---

## 1. DECISION 1 — Prepaid vs. Metered commit  *(decide first)*

**Why first:** this choice defines what `commit` *means*, therefore the state
machine's terminal transitions, the receipt's cost fields, and what recovery
must reconcile after a crash. Nothing else can be finalized until this is set.

**The fork.** At `hold` time we only know the **projected** cost. By commit time,
Ramona has already observed the **actual** cost (`runtime_observation.actual_gpu_count`,
`actual_hours`, `actual_total_cost_cents`) — today it uses these only as a drift
*gate*, then discards them.

| | **Prepaid (book the estimate)** | **Metered (reconcile to actual)** |
|---|---|---|
| Committed amount | `projected` (the full hold) | `actual` (from runtime observation) |
| On `actual < projected` | over-charges vs. usage | refunds the delta (`release(projected − actual)`) |
| State machine | `held → committed \| released` (binary) | adds `held → partially_committed` (commit `actual`, release remainder) |
| Receipt fields | `held_cents`, `committed_cents = held` | `held_cents`, `actual_cents`, `committed_cents = actual`, `released_delta_cents` |
| Recovery after crash | resolve hold to committed-or-released | resolve hold to committed-**at-actual**-or-released; needs the observed actual persisted |
| Trust surface | simplest; no dependence on runtime meter | commit trusts Ramona's observed actuals → those actuals must be authenticated (signed into `h_after`) |

**Consequence chain (why this is decision #1):**
- *State machine* — metered introduces a third terminal state (partial commit).
- *Receipt* — metered requires `actual_cents` and `released_delta_cents` as
  **signed** fields, because the committed amount is now a claim about observed
  reality, not just the request.
- *Recovery* — metered means a crash between observation and commit must recover
  the **actual**, so the observed actual must be durably written *before* commit.

**Recommendation (for ratification, not yet built):** the **safe target** is a
*reserve-cap → commit-actual → release-remainder* model — but it must **not** be
ratified merely because Ramona surfaces `actual`. Metered commit *trusts* that
number, so a precondition gates the whole decision:

> **D1a (gating sub-question):** Is `actual_cents` **authoritative,
> tamper-resistant, and available before the irreversible execution point**? If
> it is operator-asserted, or observable only *after* irreversible spend, it is
> not yet a safe basis for commit.

Target model, **only once D1a is satisfied**:

1. **Reserve a worst-case cap** atomically at hold — the hold is a *ceiling*, not
   an estimate.
2. **Commit the verified actual** cost.
3. **Release the unused remainder** (`hold − actual`).
4. **Never permit actual to exceed the hold** without an **atomic top-up hold
   taken before execution proceeds**. Reconciliation only ever adjusts
   *downward*; any upward move is a new atomic reservation, never a post-hoc
   overshoot. (A consuming action must never be allowed to run past its reserved
   ceiling.)
5. **Retain prepaid** (commit the full cap) wherever trustworthy actual
   measurement is unavailable — prepaid is the correct model, not a fallback to
   apologize for, when the meter cannot be trusted.

Reserve the `actual_cents` / `released_delta_cents` receipt fields now so that a
later prepaid → metered transition is non-breaking.

**Status: OPEN** — and **D1a** must be answered before D1 can be ruled.

---

## 2. DECISION 2 — Strict reservation vs. Overbooking

Delegation makes budget a **flow** on the authority graph. The conservation
constraint across a node `u` and its children:

```
Σ_{v ∈ children(u)}  C_{u→v}  +  C_u^consumed  +  C_u^held   ≤   C_u^issued
```

The ambiguity is *what `C_{u→v}` counts*:

| | **Strict reservation** | **Overbooking** |
|---|---|---|
| Constraint on | sum of child **grant limits** | sum of child **actual consumption** |
| Guarantee | every issued grant is fully honorable; no run on the budget | higher capital efficiency; limits may sum > parent |
| Failure mode | under-utilization (reserved-but-unspent capacity is idle) | a "bank run": simultaneously-valid grants that cannot all be honored |
| Analogy | escrow | airline overbooking / cloud quota |
| Verification | `Σ child-limits ≤ issued` — checkable at issuance, statelessly | requires live `Σ child-committed ≤ issued` — ledger-relative, at spend time |

**Recommendation:** **Strict reservation at the leaf / spend boundary** (a token
that authorizes real spend must be fully backed), with overbooking permitted, if
ever, only at *internal allocation* tiers under an explicit, separately-audited
policy. For a security-authority system the default must be that a valid grant is
always honorable — no bank runs on authority. This is the invariant the flow
formula should state as an **axiom**, not leave implicit.

**Status: OPEN — must be stated as an explicit axiom of the delegation model.**

---

## 3. DECISION 3 — Revocation behavior for available / held / committed

Revocation (`Θ`, timeline regime) interacts with conservation (`C`). Clawing
back **committed** capacity would be a refund-in-reverse — itself a conservation
violation and, worse, a rewrite of settled history. The rule:

| Bucket at revocation time `t_r` | Behavior | Rationale |
|---|---|---|
| `C_available` | → **0** | no new holds may be taken after revocation |
| `C_held` (in-flight) | → **released**, executions denied | in-flight work is not yet settled; deny fail-closed |
| `C_committed` | **unchanged** | already settled; the past is immutable |

**Revocation caps the future; it cannot rewrite the past.** Formally the ordering
predicate is `grant_issued ≺ execution_committed ≺ grant_revoked`; a commit whose
authenticated order precedes `t_r` stands, one after `t_r` does not. This is
**event-order**, not wall-clock — see §5.

*Consistency with §6:* `held → released` applies only when non-consumption is
**provable**. If a revoked grant has an **in-flight** hold whose execution may
already have performed a consuming action, that reservation goes to
`RECOVERY_REQUIRED` (freeze + reconcile), never blind release.

**Status: OPEN — but the recommended rule above is the conservation-preserving
one; ratify it.**

---

## 4. DECISION 4 — Atomic shared `hold()` across all executors

The conservation invariant is only real if capacity can be reserved
**atomically over state shared by every executor**. Per-worker in-memory holds
(today's model, and PR #4's model) satisfy the algebra *locally* while violating
it *globally*: with `N` worker threads each holding a private store, `Σ` holds
across workers can exceed `C_issued`. That is the cross-worker overspend.

**Key placement insight:** the authoritative, must-be-atomic moment is **`hold`,
not `commit`**. If `hold` atomically decrements shared available capacity, then
`commit`/`release` merely move a value between buckets and cannot be starved.
Feasibility checked at *request* time is advisory; feasibility is only
*authoritative* at the atomic hold.

Options for the shared, durable substrate:

| Option | Atomicity mechanism | Durability | Notes |
|---|---|---|---|
| **Parent-owned store** (single owning process holds the ledger; workers RPC to it) | serialized in the owner | owner persists | matches the "parent-owned claim" pattern already used for `execution_id`; no new storage engine |
| **SQLite + WAL**, one row per token, `UPDATE … WHERE available ≥ cost` | DB transaction / conditional update | WAL on disk | conditional-update is the atomic hold; survives restart natively |
| **Append-only ledger with a compare-and-append** | CAS on ledger head | the ledger *is* the store | unifies with §5 conserved receipts; heaviest |

**Recommendation:** reuse the **execution-ledger / parent-owned** machinery that
already backs `execution_id` durability, so budget holds and execution-id claims
finalize in the **same transaction** (see §6) rather than introducing a second,
independent persistence engine. The atomic conditional hold
(`available ≥ cost` → decrement) is the primitive to implement.

**Status: OPEN — pick the substrate; the atomic-`hold` requirement is fixed
regardless of substrate.**

---

## 5. Conserved receipts as chained state-transition proofs

Qualitative receipts describe an *event* and verify statelessly. **Conserved
receipts must prove a valid state transition** and are therefore **chained**.

For a budget token, receipt `n` commits to the token's pre- and post-state:

```
R_n = Sign_k( Canon[ e, g, p, h_before, h_after, o, π ] )
    where  h_after = δ(h_before, e)         (the applied hold/commit/release)
           h_before(R_{n+1}) == h_after(R_n)  for the same token
```

- `e` — canonical execution (request + execution_id)
- `g` — grant id + content hash (the token's issued limit, owner, dimensions)
- `p` — authority-path commitment (root ⇝ execution), for §0's `Chain(D,H)`
- `h_before` / `h_after` — authenticated commitments to the token's conserved
  state *before* and *after* this transition (available / held / committed vector)
- `o` — outcome (ALLOW/REFUSE and, if **metered**, the reconciled `actual`)
- `π` — inclusion proof tying `h_before`/`h_after` into the **append-only ledger**
  (Merkle root / accumulator), so a third party can verify the transition without
  the operator's word

**Consequence:** conserved-authority receipts for one token form a **hash chain**
(each `h_after` is the next `h_before`), anchored in the ledger's Merkle root.
This is *why* the verification regimes split:

| Regime | Verifies | Needs |
|---|---|---|
| **Stateless** `V_s(R, A)` | signatures, canonical action, target containment, delegation narrowing, policy-hash equality | root keys only — offline, eternal |
| **Ledger-relative** `V_ℓ(R, A, H)` | remaining budget, sibling allocation, hold/commit state, nonce/replay | a compact authenticated commitment to `H` (Merkle root + inclusion proof) |
| **Timeline** `V_t(R, A, T)` | revocation, expiry, ordering | an authenticated **ordering** source `T` (signed monotonic ledger / transparency log / checkpoint) — *event-order*, not necessarily wall-clock |

A verifier's guarantee therefore **degrades gracefully**: qualitative legitimacy
is verifiable offline forever; conserved and temporal legitimacy are verifiable
against the ledger commitment. That is the honest, still-strong claim behind the
framing line at the top.

---

## 6. Storage & transaction model (informed by §1, §4)

A `budget_reservations` record keyed by `(budget_token, execution_id)`:

```
state ∈ { PENDING_HOLD, COMMITTED, RELEASED, RECOVERY_REQUIRED }   // + PARTIALLY_COMMITTED if §1 = metered
held_cents          // reserved at hold
actual_cents        // observed at Ramona (metered only)
committed_cents     // = held (prepaid) | actual (metered)
owner_actor_id      // §7
h_before, h_after   // §5 ledger commitments
```

**Transaction boundary.** The final decision must atomically write, in **one
transaction**: (a) the `execution_id` terminal state, (b) the budget
commit-or-release, and (c) the authoritative receipt bytes. This prevents the
split-state the no-refund defect could otherwise reintroduce durably (one
authority persisted without the other).

**Ambiguity must FREEZE, not release.** RELEASE is safe **only** when the system
can *prove* no budget-consuming action occurred (e.g. the crash is provably
before any irreversible execution *and* before the commit transaction). If it is
*unknown* whether a consuming action fired, recovery must transition the
reservation to **`RECOVERY_REQUIRED`** (a.k.a. `FROZEN`): the hold is
**preserved**, further spending against the token is **blocked**, and the
reservation is resolved to COMMITTED-or-RELEASED **only** by explicit
reconciliation against authenticated history. Blindly releasing under uncertainty
would return capacity that may already have been spent — a latent *overspend*,
the same class of error as the no-refund defect but in the opposite direction.
Contrast `execution_id`, where fail-closed means blocking reuse; here fail-closed
means **freeze and reconcile**, never auto-refund.

**Recovery table (sketch):**

| Crash point | `execution_id` | budget | Receipt | Recovery |
|---|---|---|---|---|
| before dispatch — no irreversible action possible, before commit tx | inflight | PENDING_HOLD | none | **provably** no consumption → RELEASE hold |
| dispatched; unknown whether the consuming action fired; commit tx not durably recorded | inflight/unknown | PENDING_HOLD → **RECOVERY_REQUIRED** | none | **FREEZE**: preserve hold, block token, reconcile against history |
| commit tx durably applied | allowed | COMMITTED/PARTIAL | persisted | replay-safe; nothing to do |
| after tx, before response | allowed | COMMITTED | persisted | idempotent re-send of receipt |

---

## 7. Actor binding & provisioning (ratified: actor-bound)

Tokens are **actor-bound**. The non-negotiable sequencing invariant:

> **Owned-token provisioning and owner-enforcement must ship in the same change.**
> A stored `owner_actor_id` that nothing checks is *false security*.

Design:
- **Provisioning** — a real issuance entry point that mints a token with
  `(max_budget_cents, owner_actor_id, dimensions, expiry)` recorded durably. This
  is the piece that does **not exist today** (`defineBudgetToken` has no
  production caller).
- **Enforcement** — `hold(token, execution_id, cost, actor_id)` checks
  `actor_id == owner_actor_id`; mismatch → fail-closed refuse. The actor is
  already available on the canonical input (`execution_request.actor.user_id`).
- **Bearer fallback** — a token minted with no owner is bearer; this must be an
  explicit, logged provisioning choice, never a silent default.

**Status: OPEN — provisioning mechanism to design; enforcement point is known.**

---

## 8. Replay-hash prerequisite (carried, not resolved here)

Under today's hard-fail retry semantics, `begin()` not comparing `request_hash`
is **not** an enforcement bypass. But the approved future *same-hash
cached-response* design requires distinguishing "same execution_id + same
request_hash → return cached receipt" from "same execution_id + different
request_hash → reject as collision." That needs `request_hash` stored and
compared, plus a reason code to separate collision from replay. **This must land
*with* the retry-semantics change, not before or after.**

---

## 9. Open decisions summary

| # | Decision | Recommendation (to ratify) | Blocks |
|---|---|---|---|
| D1 | Prepaid vs metered commit | Reserve-cap → commit-actual → release-remainder **iff** actual is authoritative (**D1a**); else prepaid. Reserve `actual_cents` field now. | state machine, receipt schema, recovery |
| D2 | Strict reservation vs overbooking | Strict at spend boundary; state as axiom | delegation/flow model |
| D3 | Revocation for available/held/committed | 0 / released / unchanged | timeline regime, recovery |
| D4 | Atomic shared `hold()` substrate | Reuse parent-owned/execution-ledger; atomic conditional hold | durability engine, transaction boundary |
| P | Owned-token provisioning | Ship provisioning + enforcement together | actor binding |
| R | Replay-hash comparison | Land with retry-semantics change | future cached-response |

---

## 10. Non-goals

- **No runtime code changes on this branch.** This is a spec.
- Does not re-open PR #4's correctness fix; it is the foundation.
- Does not select a concrete DB schema/DDL — that follows D4 ratification.
- Does not design cross-*organization* delegation or risk-budget semantics beyond
  naming `risk` as a conserved dimension.
