# Budget-token hold / commit / release lifecycle

**Status:** implemented (correctness stage) · **Date:** 2026-07-25
**Touches:** `shared/state.ts`, `arm/engine.ts`, `audit/node_runtime.ts`
**Test:** `tests/test_budget_hold_lifecycle.mjs` (`npm run test:budget-token-lifecycle`)

This document explains *why* the budget-token accounting was changed, not just
what changed. It is deliberately verbose: the change corrects a
security-relevant money-handling defect, and future readers must understand the
reasoning before touching this code again.

---

## 1. What a budget token is (and how it differs from an execution_id)

Two different authority primitives flow through ARM. They look similar and are
reset by adjacent code, which is exactly why they were conflated:

| | `execution_id` | `budget_token` |
|---|---|---|
| Authorizes | **exactly one** execution | **many** executions up to a cap |
| Reuse below the limit | forbidden (replay) | **intended** — that's the point |
| State that must persist | "has this id been consumed?" | running `consumed_cents` vs `max_budget_cents` |
| Finalized when | after the true post-Ramona decision | *(was)* eagerly, inside ARM ← the bug |

Because a budget token is *meant* to be presented repeatedly, its correctness
depends entirely on an accurate running total. Anything that corrupts that
total — losing it, or charging it for work that never ran — breaks the cap.

---

## 2. The defect: "no-refund"

### The trace (pre-change)

1. `runStrictArm` computed the projected cost and, as its **final** gate,
   called `budgetTokenStore.reserve(token, projected)`.
2. `reserve()` **mutated `consumed_cents += projected` immediately** and
   returned. That is a *charge*, right there, inside ARM.
3. But ARM's `ALLOW` is only **provisional**. The pipeline then runs
   `runStrictRamona`, whose refusals (kill switch, GPU/hours/cost runtime
   drift — `ram0na/engine.ts`) can flip the final decision to `REFUSE`
   (`buildReceipt`: `decision = orbit && arm && ramona all ALLOW`).
4. On a Ramona refusal, `commitArmAllow` is correctly **not** called, so the
   `execution_id` is never consumed. But the budget was **already** charged in
   step 2, and **no code path could give it back.**

### Why it mattered

For a spending cap, the security-relevant failure mode is **overcharging** —
budget consumed for an execution that received a final `REFUSE`. Every
Ramona-refused request with a `budget_token` permanently ate budget it never
used. Enough of them and a legitimate caller is locked out of a cap they never
actually spent. This existed identically in `INsol` and was independent of the
separate "per-task reset wipes the store" problem — a perfectly consistent,
never-reset store still overcharged, because the bug was in the *ordering*, not
the persistence.

### Why it was easy to miss

`reserve()` did the check (`would this exceed the cap?`) **and** the mutation
in one call. The check was correct; the mutation was in the wrong place. Read
quickly, it looks like "ARM decides whether the budget allows this" — which is
true — and the permanent side effect hides behind that correct-looking check.

---

## 3. The fix: separate the check-and-hold from the charge

Budget accounting is now split into two independently tracked quantities and a
three-phase lifecycle that mirrors how `execution_id` is already finalized.

### Data model (`shared/state.ts`)

```
consumed_cents  — money COMMITTED to executions that reached a final ALLOW.
                  Only ever grows. This is the number that survives requests.
pending_holds[] — capacity RESERVED for an in-flight decision that passed ARM
                  but has no final verdict yet. Not a charge.
```

Available capacity at any instant is:

```
max_budget_cents - consumed_cents - sum(pending_holds)
```

**Why hold against the sum, not just `consumed_cents`:** two concurrent
in-flight requests could each individually "fit" under the cap while together
overspending it. Counting outstanding holds against availability is what closes
that window. (In-process today; the durable version is the next stage — see §6.)

### Lifecycle

- **`hold(token, execution_id, cost)`** — ARM's final gate. Reserves capacity,
  keyed by `execution_id`. Returns `held` / `exhausted` / `unknown_token`.
  Records nothing on a non-`held` result, so there is never a stray hold to
  clean up after a refusal.
- **`commit(token, execution_id)`** — the pipeline calls this on the **true,
  post-Ramona `ALLOW`**. Moves the hold into `consumed_cents`.
- **`release(token, execution_id)`** — the pipeline calls this on **any final
  `REFUSE`**, including a Ramona refusal that overturned ARM. Discards the hold
  with no change to `consumed_cents`. **This release is the actual fix.**

### Where finalize lives, and why *not* in ARM

The commit/release calls live in `executeDeterministicPipeline`
(`audit/node_runtime.ts`), immediately beside the existing `commitArmAllow`,
because that is the **only** place the true decision exists. ARM cannot finalize
its own budget hold for the same reason it cannot consume its own
`execution_id`: Ramona hasn't run yet. Putting finalize anywhere upstream of
Ramona would reintroduce the exact bug in a new location.

A hold needs finalizing **iff `arm.decision === "ALLOW" && arm.budget_token`** —
that is precisely the condition under which `hold()` recorded capacity. An
ARM-layer refusal (cost, GPU, execution-id, …) returns before `hold()` runs, so
there is nothing to release on those paths.

### Why gated on `enforceExecutionId`

Finalize (for both `execution_id` and budget) only runs in **live** mode
(`enforceExecutionId !== false`). In **replay** mode a stored receipt is
re-executed to check determinism; it must consume **nothing**. Gating budget
finalize the same way as `execution_id` keeps replay from mutating live
authority state — the two ledgers now share one clean live/replay boundary.

### Idempotency

`hold()` replaces any existing hold for the same `execution_id` rather than
stacking a second one, so a retried evaluation of the identical request can
never double-count against the cap. `commit()`/`release()` are no-ops when no
hold exists, so a finalize that somehow runs twice cannot double-charge or
underflow.

---

## 4. What deliberately did **not** change

### The replay-hash observation — DEFERRED (not resolved, not irrelevant)

`ExecutionAuthorityStore.begin()` does not compare `request_hash` when it sees a
known `execution_id`. Two things are both true and must not be conflated:

- **Under today's hard-fail retry semantics it is NOT an enforcement bypass.**
  A repeated `execution_id` is refused *regardless* of hash (`inflight_exists`
  → `ERR_EXECUTION_ID_ALREADY_CONSUMED`, `allowed_exists` →
  `ERR_EXECUTION_ID_REPLAYED`). Nothing gets through, so this change does not
  need to touch it, and adding a new reason code now would only drift the
  cross-repo `REASON_CODES` contract that has no parity gate yet (§5).

- **It is INCOMPATIBLE with the approved future design.** That design replaces
  hard-fail-on-repeat with *same-hash cached-response idempotency*: a re-submit
  of the identical request (same `execution_id` **and** same `request_hash`)
  should return the original cached receipt, while a re-submit of the same
  `execution_id` with a **different** `request_hash` must be rejected as a
  collision/forgery. Without storing and comparing `request_hash`, `begin()`
  cannot tell those two cases apart — so the future behavior cannot be built
  safely on top of the current store.

**Status: deferred, and explicitly carried as a prerequisite of the
cached-response work** — not resolved, not a non-issue. When the retry
semantics change, `request_hash` comparison (and the reason code to distinguish
collision from replay) must land as part of that change, not after it.

### Known limitations of this in-memory stage (by design, tracked for §6)

These are *not* defects introduced by this change; they are the boundary of what
an in-memory, ordering-only fix can guarantee. The durable stage (§6) closes
each one.

- **Cross-worker isolation.** `budgetTokenStore` is a per-module singleton, so
  under `worker_threads` each worker holds an independent balance. Concurrent
  holds cannot overspend a token *within one store instance* (see below), but
  two different workers can each independently approve up to the cap. Real
  cross-worker enforcement requires the shared durable ledger.
- **Atomicity scope.** `hold()` is fully synchronous (no `await` between reading
  the balance and recording the hold), so it is atomic *with respect to the
  event loop* — `available = limit - consumed - Σ(other pending holds)` is read
  and written without interleaving. That guarantee is per store instance, not
  cross-process.
- **Exception after `hold()`.** If an exception is thrown between a successful
  `hold()` and finalize (e.g. inside Ramona or receipt build), the pipeline
  throws and **no ALLOW is returned** (the criterion "release OR prevent ALLOW"
  is met by preventing ALLOW). The hold itself is *not* explicitly released; it
  is bounded by the worker's pre-task `resetRuntimeState()`, which clears the
  store before the next task. The durable stage must replace this reset-bounded
  cleanup with an explicit transactional release/`finally`.
- **`commit()` / execution-id atomicity.** The pipeline commits the
  `execution_id` and then the budget hold as two separate in-memory writes
  (neither can fail in memory). In the durable stage these must move into the
  **same** transaction so an ALLOW can never persist one authority without the
  other; a failed budget `commit()` must block the ALLOW response (it already
  runs before the response is returned — `audit/node_runtime.ts`).

### Actor-binding: ratified, but deferred to the persistence stage

The product decision is settled: **budget tokens are actor-bound** (a token
works only for the actor it was issued to — not bearer/cash). It is **not
implemented in this pass, on purpose.**

Enforcement is meaningless without a way to *provision* an owned token, and no
such provisioning exists in the live service today (`defineBudgetToken` has no
production caller). Storing an `owner_actor_id` that nothing checks would be
**false security** — worse than storing nothing, because an operator might
provision an "owned" token believing it is enforced when it is not.

**Invariant for the next stage:** owned-token *provisioning* and owner
*enforcement* must ship in the **same** change, so there is never a window where
an owned token exists but its owner is unchecked. The actor identity is already
available on the canonical input (`execution_request.actor.user_id`), so the
enforcement point is known; only the durable provisioning path is missing.

### Still in-memory

This stage fixes *ordering*, not *durability*. The store is still a
module-level in-memory `Map`. It does not survive a sidecar restart, and under
`worker_threads` each worker holds its own instance. Making budget state durable
and shared is the persistence stage (§6), tracked separately.

---

## 5. Cross-repository note (`INsol`)

`shared/state.ts` and `arm/engine.ts` are the byte-identical shared-contract
surface between `mnde-public-test` and `INsol`. This change landed in
`mnde-public-test` first (canonical), so:

1. **Port** the `hold/commit/release` interface + the ARM/pipeline finalize to
   `INsol`'s `audit/node_runtime.ts` path.
2. **Update** `INsol`'s `run_post_remediation_verification.ts` → `runBudgetStress`,
   whose assertions are written against the old eager-`reserve()` semantics and
   will (correctly) start failing once the shared files are ported.
3. **Add** the CI behavioral-parity check that hashes the shared-contract files
   across both checkouts. The `REASON_CODES` drift already present between the
   repos is exactly the kind of divergence this gate would have caught — nothing
   catches it today.

---

## 6. Next stage (not in this change)

Durable, restart-surviving, cross-worker budget accounting: a parent-owned
`budget_reservations` ledger keyed by `(budget_token, execution_id)` with states
`PENDING_HOLD → COMMITTED | RELEASED`, finalized in the **same** transaction as
the `execution_id` terminal write and the authoritative receipt bytes.
Fail-closed default under ambiguity is **RELEASE** (do not silently overcharge),
which is the security-correct direction for a spending cap — the mirror image of
`execution_id`, where fail-closed means blocking reuse. Owner-enforcement (§4)
ships with the provisioning path introduced here.

---

## 7. Test coverage

`tests/test_budget_hold_lifecycle.mjs`, one clean budget epoch, no reset between
requests (proving cross-request accounting):

| Case | Scenario | Asserts |
|---|---|---|
| T-B08 | ARM ALLOW → Ramona kill-switch REFUSE | `consumed_cents === 0`, no pending hold — **the no-refund regression guard** |
| T-B01a | clean final ALLOW | hold committed (`consumed_cents === 500`) |
| T-B01b | second ALLOW, same token | accumulates to 1000 (cross-request) |
| T-B02 | request exceeds remaining cap | `ERR_BUDGET_TOKEN_EXHAUSTED`, balance unchanged |

Under the pre-change eager-`reserve()` code, T-B08 fails (`consumed_cents` would
be 500), which is what makes it a genuine guard rather than a tautology.
