# Durable, Actor-Bound Budget Authority — Design Spec

**Status:** DRAFT · design-only · **no runtime code changes in this branch**
**Branch:** `design/durable-actor-bound-budget` (documentation only)
**Continues:** the hold/commit/release correctness fix (PR #4, `fix/budget-token-hold-finalization`)
**Frames:** the MNDe *authority-flow calculus*

> **Trust a fixed cryptographic root and an append-only history — verify everything else.**

This document specifies the design for making budget-token authority **durable**
(survives restart), **shared-atomic** (correct across all executors), and
**actor-bound** (a token spends only for the actor it was issued to). It does
**not** change runtime behavior. Owner rulings D0 through D4 were ratified on
2026-07-26. They establish the authenticated cost basis, prepaid settlement,
strict reservation, freeze-on-uncertainty revocation, and the parent-owned
atomic ledger that determine the downstream implementation.

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
C_issued = C_available + C_held + C_committed + C_frozen + C_revoked
```

and the conservation law that the no-refund defect violated:

```
ΔC_committed = 0  unless an execution validly commits.
```

`C_revoked` is issued but permanently unavailable capacity; it is not erased.
A failure must never reduce or duplicate total authority. This spec is the
durable, shared, actor-scoped realization of that invariant.

---


## 1. DECISION 0 — Authenticated cost basis

**Decision: RATIFIED (2026-07-26).**

Treat every sidecar request as untrusted unless each security-relevant claim is
cryptographically authenticated. A deployment assumption that "the control
plane is trusted" is not an authority proof.

Requirements:

1. **Actor identity** comes from authenticated execution context. A caller field
   such as `execution_request.actor.user_id` is an asserted identifier, not proof
   of identity by itself.
2. **Price** comes from a signed policy schedule or a separately trusted pricing
   authority. Caller-provided `pricing_data` cannot establish or reduce a hold
   or charge.
3. **Usage** cannot reduce settlement unless it is authenticated by an approved
   executor or metering authority and bound to the execution, policy, actor,
   price schedule, and ledger event.
4. Caller-provided `runtime_observation` remains admissible as diagnostic input,
   but it is not authoritative cost evidence.
5. Failure to validate required cost-basis evidence fails closed before an
   authoritative hold.

Current code type-checks caller-provided pricing and actuals but does not
cryptographically authenticate them. Therefore neither prepaid nor metered
budget enforcement is sound against an untrusted submitter until D0 is
implemented. D0 is a release prerequisite for durable budget enforcement.

**Rationale:** an unauthenticated price or usage claim lets the spender choose
its own charge, defeating conservation regardless of ledger correctness.

---

## 2. DECISION 1 — Prepaid now; Metered later

**Decision: RATIFIED (2026-07-26).**

This choice defines what `commit` means, the state machine's terminal
transitions, the receipt cost fields, and what recovery must reconcile.

| | **Prepaid — ratified now** | **Metered — deferred** |
|---|---|---|
| Committed amount | authenticated worst-case cost: the full hold | authenticated actual usage |
| Unused amount | no settlement reduction | authenticated remainder is released |
| Required trust | authenticated actor and price | authenticated actor, price, and usage meter |
| Receipt fields | `held_cents`, `committed_cents = held` | also `actual_cents`, `released_delta_cents`, meter evidence |
| Recovery | committed-or-released/frozen | also recovers authenticated usage evidence |

Current enforcement uses **prepaid settlement**:

1. Resolve an authenticated worst-case authorized cost under D0.
2. Atomically hold that full amount.
3. On terminal ALLOW, commit the full hold.
4. On terminal REFUSE, release only when non-consumption is proven.
5. Never use caller-supplied `actual_cents` to reduce settlement.

The receipt schema may reserve nullable `actual_cents` and
`released_delta_cents` fields for compatibility, but those fields are
explicitly non-authoritative and unenforced in prepaid mode.

A future metered mode requires a separately reviewed trust path:

1. Reserve an authenticated worst-case cap before execution.
2. Commit authenticated actual usage.
3. Release the authenticated unused remainder.
4. Never permit actual usage to exceed the hold without an atomic top-up before
   execution proceeds.
5. Bind meter evidence to the actor, execution ID, policy, price schedule,
   ledger order, and receipt.

Ramona merely exposing `actual` does not satisfy this requirement. Metered mode
remains disabled until trusted usage evidence exists.

**Rationale:** conservative prepaid charging can be enforced with authenticated
pricing; metered settlement cannot be trusted without authenticated usage.

---

## 3. DECISION 2 — Strict reservation vs. Overbooking

**Decision: RATIFIED (2026-07-26).**

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

**Decision:** **Strict reservation at the leaf / spend boundary** (a token
that authorizes real spend must be fully backed), with overbooking permitted, if
ever, only at *internal allocation* tiers under an explicit, separately-audited
policy. For a security-authority system the default must be that a valid grant is
always honorable — no bank runs on authority. This is the invariant the flow
formula states as an **axiom**, not an implementation preference.

**Rationale:** overbooking converts a hard security limit into probabilistic
accounting.

---

## 4. DECISION 3 — Revocation behavior for available / held / committed

**Decision: RATIFIED (2026-07-26).**

Revocation (`Θ`, timeline regime) interacts with conservation (`C`). Clawing
back **committed** capacity would be a refund-in-reverse — itself a conservation
violation and, worse, a rewrite of settled history. The rule:

| Bucket at revocation time `t_r` | Behavior | Rationale |
|---|---|---|
| `C_available` | → **0** | no new holds may be taken after revocation |
| `C_held` (in-flight) | → **released only if non-consumption is proven; otherwise RECOVERY_REQUIRED / FROZEN** | uncertainty cannot return capacity to circulation |
| `C_committed` | **unchanged** | already settled; the past is immutable |

**Revocation caps the future; it cannot rewrite the past.** Formally the ordering
predicate is `grant_issued ≺ execution_committed ≺ grant_revoked`; a commit whose
authenticated order precedes `t_r` stands, one after `t_r` does not. This is
**event-order**, not wall-clock — see §6.

*Consistency with §7:* `held → released` applies only when non-consumption is
**provable**. If a revoked grant has an **in-flight** hold whose execution may
already have performed a consuming action, that reservation goes to
`RECOVERY_REQUIRED` (freeze + reconcile), never blind release.

A hold associated with a released ALLOW remains frozen until authoritative
settlement. Revocation never rewrites historical receipts.

**Rationale:** revocation stops future authority but cannot erase past or
potentially in-progress consumption.

---

## 5. DECISION 4 — Parent-owned atomic shared `hold()`

**Decision: RATIFIED (2026-07-26).**

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
| **Append-only ledger with a compare-and-append** | CAS on ledger head | the ledger *is* the store | unifies with §6 conserved receipts; heaviest |

Use the **parent-owned shared SQLite authority**. Execution-ID claims, budget
holds, authoritative receipt bytes, and terminal execution and budget
transitions use the same database and coordinated transactions. The atomic
conditional hold (`available ≥ authenticated_cost` → move available to held) is
the overspend-prevention primitive.

Workers remain stateless evaluators. They do not own, reset, reconstruct, or
mutate durable authority state. A separate worker-local fallback is prohibited.

**Rationale:** the hold is the overspend-prevention boundary; execution state
and budget state must not diverge after crashes.

---

## 6. Conserved receipts as chained state-transition proofs

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
- `o` — outcome (ALLOW/REFUSE and, in future **metered** mode, authenticated `actual`)
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

## 7. Storage & transaction model (informed by D0, D1, and D4)

A `budget_reservations` record keyed by `(budget_token, execution_id)`:

```
state ∈ { PENDING_HOLD, COMMITTED, RELEASED, RECOVERY_REQUIRED }
held_cents           // reserved at hold
actual_cents         // nullable schema reservation; non-authoritative in prepaid mode
released_delta_cents // nullable schema reservation; non-authoritative in prepaid mode
committed_cents      // = held in ratified prepaid mode
owner_actor_id       // authenticated context under D0
cost_basis_ref       // signed policy schedule or trusted pricing authority
h_before, h_after    // ledger commitments
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

## 8. Actor binding & provisioning (ratified: actor-bound)

Tokens are **actor-bound**. The non-negotiable sequencing invariant:

> **Owned-token provisioning and owner-enforcement must ship in the same change.**
> A stored `owner_actor_id` that nothing checks is *false security*.

Design:
- **Provisioning** — a real issuance entry point that mints a token with
  `(max_budget_cents, owner_actor_id, dimensions, expiry)` recorded durably. This
  is the piece that does **not exist today** (`defineBudgetToken` has no
  production caller).
- **Enforcement** — `hold(token, execution_id, cost, actor_id)` checks
  `actor_id == owner_actor_id`; mismatch → fail-closed refuse. The supplied
  `execution_request.actor.user_id` is not sufficient by itself: `actor_id`
  must come from authenticated execution context under D0 and be bound to the
  canonical request.
- **No bearer fallback** — the durable authority rejects a token without an
  authenticated owner. Any legacy bearer token remains outside this authority
  model and cannot exercise durable budget enforcement.

The actor-bound product decision is ratified. The concrete provisioning
mechanism remains an implementation-design item and must ship atomically with
owner enforcement.

---

## 9. Replay-hash prerequisite (carried, not resolved here)

Under today's hard-fail retry semantics, `begin()` not comparing `request_hash`
is **not** an enforcement bypass. But the approved future *same-hash
cached-response* design requires distinguishing "same execution_id + same
request_hash → return cached receipt" from "same execution_id + different
request_hash → reject as collision." That needs `request_hash` stored and
compared, plus a reason code to separate collision from replay. **This must land
*with* the retry-semantics change, not before or after.**

---


## 10. Decision status

| # | Decision | Status | Ruling |
|---|---|---|---|
| D0 | Authenticated cost basis | **RATIFIED** | authenticate actor and price; require authenticated usage before metered settlement |
| D1 | Prepaid vs metered commit | **RATIFIED** | prepaid now; metered disabled until trusted usage evidence exists |
| D2 | Strict reservation vs overbooking | **RATIFIED** | strict reservation at the spend boundary |
| D3 | Revocation for available/held/committed | **RATIFIED** | stop future holds; preserve committed history; freeze uncertain holds |
| D4 | Atomic shared `hold()` substrate | **RATIFIED** | parent-owned shared SQLite authority and coordinated transactions |
| P | Owned-token provisioning mechanism | Implementation design | provisioning and enforcement must ship together |
| R | Replay-hash comparison | Deferred prerequisite | land atomically with cached-response retry semantics |

### Decision log

| Date | Decision | Ruling | Rationale |
|---|---|---|---|
| 2026-07-26 | D0 — Authenticated cost basis | Ratified | An unauthenticated price or usage claim lets the spender choose its own charge. |
| 2026-07-26 | D1 — Settlement model | Ratified: prepaid now; metered later | Prepaid can be enforced with authenticated pricing; metered settlement also requires authenticated usage. |
| 2026-07-26 | D2 — Reservation model | Ratified: strict | A conserved security limit cannot rely on probabilistic overbooking. |
| 2026-07-26 | D3 — Revocation and uncertainty | Ratified: freeze uncertain holds | Capacity that may have been consumed cannot safely return to circulation. |
| 2026-07-26 | D4 — Durable ownership | Ratified: parent-owned shared SQLite | Atomic holds and coordinated terminal transitions prevent cross-worker overspend and split state. |

---

## 11. Non-goals

- **No runtime code changes on this branch.** This is a spec.
- Does not re-open PR #4's correctness fix; it is the foundation.
- Does not define final SQLite DDL, migration code, or operational tuning;
  those follow architectural review of the ratified D4 substrate.
- Does not design cross-*organization* delegation or risk-budget semantics beyond
  naming `risk` as a conserved dimension.
