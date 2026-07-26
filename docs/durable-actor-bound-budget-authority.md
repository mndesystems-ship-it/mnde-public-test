# Durable, Actor-Bound Budget Authority — Normative Design Specification

**Status:** DESIGN — normative · **documentation only; no runtime code in this branch**
**Branch:** `design/durable-actor-bound-budget`
**Depends on:** PR #4 (`fix/budget-token-hold-finalization`) — see §25. PR #5 stays dormant until PR #4 is resolved.
**Documentation gate:** **FAIL — remediation in progress** (see §27).

> **Trust a fixed cryptographic root and, at startup, the latest authenticated external checkpoint. Verify everything else relative to that trust context.** (v1 history is operator-signed, not independently witnessed — §21.)

### Normative language

**MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **MAY**, **OPTIONAL** are used per RFC 2119/8174. Statements
without a normative keyword are descriptive.

### What this document is

A source-of-truth design for budget-token authority that is **durable** (survives
restart), **atomic across threads/processes sharing one authoritative SQLite
database on one host** (§1), and **actor-bound** (spends only for the
authenticated principal it was issued to). It does not change runtime behavior
and does not authorize implementation (§26). Ratified rulings are **D0–D38**
(§28). This revision remediates the post-remediation hostile-review findings
F1–F18: quantity-ceiling refusal, no linked replacement token, expiry
linearization, status-scoped recovery destinations, durable release-consumption
before execution, the composite terminal-ALLOW transition, deferral of
delegation, an administrative-correction state machine, principal-level SoD,
scoped rollback and checkpoint claims, outbox identity/ordering, receipt/proof
separation, credential liveness, migration genesis, weakened replica-detection
claims, a canonical event envelope, and metadata/reference correctness.

Nothing here modifies PR #4.

---

## PART I — FOUNDATIONS

## 0. Calculus & conservation

An authority grant is `A = (Q, C, Θ, D)`: qualitative permissions `Q`, conserved
capacities `C`, temporal/state conditions `Θ`, delegation provenance `D`.
Qualitative authority is a set governed by containment and verifies statelessly.
Budget is **conserved** authority; its validity is ledger-relative.

**v1 scopes `C` to a single monetary dimension in checked integer minor units**
(§8); `k = 1`. **Budget delegation / child tokens are deferred (§22);** the v1
conservation model is single-tier. Per token, at every instant:

```
C_issued = C_available + C_held + C_committed + C_revoked + C_expired
```

- `C_available` — spendable now (token ACTIVE only).
- `C_held` — reserved by a live `PENDING_HOLD` reservation.
- `C_committed` — settled spend; monotonically non-decreasing; immutable history.
- `C_revoked` — capacity removed from circulation by revocation; not spendable, not erased.
- `C_expired` — capacity removed from circulation by expiry; not spendable, not erased.

There is **no `C_frozen` bucket and no budget `RECOVERY_REQUIRED` state in prepaid
v1** (§12.4 explains why: the charge commits atomically before execution, so a
budget hold is never outstanding across an execution).

Conservation laws (normative):

- `C_issued` is fixed at issuance; the five-bucket sum **MUST** equal `C_issued`
  after every committed authority-changing transaction (per-transition proof in §12.5).
- `C_committed` **MUST** be monotonically non-decreasing; `ΔC_committed < 0` is
  **prohibited** for every transition, including administrative correction (§16).
- A failure **MUST NOT** reduce or duplicate `C_issued`.
- Capacity **MUST NOT** move into `C_available` except from `C_held` **while the
  token is ACTIVE**, or by an authenticated funding/issuance event (§16).

---

## PART II — DEPLOYMENT & TRUST SCOPE

## 1. Deployment scope (v1) — D14, D37

**Decision: RATIFIED (2026-07-26).**

- The system **MUST** run against exactly **one authoritative SQLite database** on
  **one host**, on a **supported local filesystem** (ext4, xfs, APFS, NTFS).
- Multiple **threads or OS processes on that host MAY** be concurrent clients of
  that exact database.
- The system **MUST NOT** operate active-active multi-host in v1; the DB **MUST
  NOT** be placed on **NFS**, **SMB/CIFS**, any network filesystem, or a
  replicated writable copy.
- **Replica/copy detection is a deployment control, not a runtime guarantee (F17):**
  a local SQLite process **cannot** generally detect a *disconnected* writable
  copy of its database. Therefore:
  - Disconnected/alternate writable copies are **prohibited deployment behavior**;
    operators **MUST** enforce single-writer topology through deployment controls.
  - Startup **MUST** fail closed on **locally observable** violations only
    (network/unsupported filesystem; a detectable second attached writer via OS
    file locking; missing single-writer lock).
  - Stronger guarantees (external lease/registry/fencing) are **deferred (§22).**

All correctness claims are scoped to "supported threads and processes sharing the
one authoritative local database," never "all executors" or across hosts.

## 2. Authenticated cost basis — D0

**Decision: RATIFIED (2026-07-26).**

Every request is untrusted unless each security-relevant claim is authenticated.

- **Actor identity MUST** come from an authenticated principal (§3); a caller
  `actor.user_id` string **MUST NOT** by itself establish identity/ownership.
- **Price MUST** come from a signed pricing envelope (§5); caller `pricing_data`
  **MUST NOT** establish, raise, or reduce a hold or charge.
- **Usage MUST NOT** reduce settlement in v1; prepaid settlement does not use it
  (§12). Caller `runtime_observation` is diagnostic only.
- Missing/invalid required evidence **MUST** fail closed before an authoritative hold.

## 3. Authenticated principal model — D7

**Decision: RATIFIED (2026-07-26).**

```
Principal = (issuer, tenant, subject, audience, assurance_level, delegation_chain)
```

- **Credential type** — the authority **MUST** accept only configured credential
  types (signed identity assertion / OIDC-style token / request-bound mTLS cert).
  A raw string user_id is **NOT** a credential.
- **Canonical derivation** — normalize `(issuer, tenant, subject)` per §3.1, bind
  `audience`, `assurance_level`. A copied `user_id` **MUST NOT** count as auth.
- **`owner_actor_id`** = `H_owner(issuer ‖ tenant ‖ subject)` using the
  domain-separated hash defined in §17.2. **MUST** be stable across credential
  rotation; **MUST** differ across tenants for identical subjects.
- **Tenant isolation** — every token/reservation/execution record **MUST** carry
  `tenant`; cross-tenant hold/commit/revoke/read **MUST** be rejected.
- **Audience validation** — credential `audience` **MUST** match this authority.
- **Impersonation** — act-as **MUST** be an explicit, authenticated, audited
  capability; **MUST NOT** be inferrable from a caller field.
- **Assurance level** — the authority **MAY** require a per-scope minimum; below
  minimum **MUST** be refused.
- **Cross-tenant collision** — identical `subject` in different tenants **MUST**
  derive distinct `owner_actor_id`.
- Delegation of **qualitative** authority narrows monotonically; **budget child
  tokens are deferred (§22).**

### 3.1 Normalization

Deterministic: NFC Unicode; case-folding only where the issuer declares
case-insensitivity; trim insignificant whitespace; reject embedded null/control
characters. Ambiguous/non-normalizable identifiers **MUST** be rejected.

**Bearer fallback is prohibited.** A token without an authenticated owner **MUST
NOT** exercise durable budget authority.

## 4. Credential liveness — D35

**Decision: RATIFIED (2026-07-26).**

Authentication requires that the credential is *live for new authority*, not merely
well-formed.

- Each credential has an **issuer**, **expiry**, and a **revocation/deprovisioning
  status** from a named **deprovisioning authority**.
- New authority (issue/hold/terminal-ALLOW/release/consume/admin) **MUST** verify
  credential status within a configured **maximum status freshness** window,
  evaluated against the **authenticated time source (§9.2)**.
- If status **cannot** be checked within freshness, the authority **MUST** fail
  closed for new authority (it **MUST NOT** assume live).
- **Key rotation** **MUST NOT** change `owner_actor_id`; validation accepts keys
  valid at the credential's authenticated time under the issuer's published set.
- **Grace periods**, if any, **MUST** be explicit, bounded, and audited; none by default.
- **Historical verification vs current authorization** — a credential valid at
  historical time remains valid for **verifying past receipts** even after it is
  expired/revoked, but **MUST NOT** authorize **new** authority once
  expired/revoked/deprovisioned.

## 5. Pricing authority envelope — D6, D22

**Decision: RATIFIED (2026-07-26).**

Canonical schema in §17.3. Fields: `issuer, key_role, tenant_scope,
environment_scope, policy_scope, resource_class, region, currency, canonical_unit,
quantity_ceiling, effective_time, expiry, schedule_version (monotonic),
unit_price_minor_units, signature`.

- **Signature/scope/window** — signed by a `key_role` authorized for the scope;
  validated **before** the hold; `resource_class/region/currency/policy_scope/
  tenant/environment` **MUST** match the request's authenticated context;
  `effective_time ≤ t < expiry`. Any failure ⇒ refuse.
- **Anti-rollback** — persist the highest accepted `schedule_version` per
  `(tenant, environment, policy_scope, resource_class, region)`; reject lower
  (rollback). Equal version, different content ⇒ **fork**, fail closed + alert;
  **MUST NOT** silently pick one.
- **Key rotation/revocation** — a revoked pricing key's envelopes **MUST NOT**
  authorize new holds.

### 5.1 Oversized requests are REFUSED, never clamped (F1)

- **The request hash MUST bind the exact `requested_quantity` the executor may
  consume.** The authority **MUST NOT** silently clamp an executable request.
- **Rule:** if `requested_quantity` exceeds **any** authenticated applicable
  ceiling (`quantity_ceiling` or policy cap for the scope), the authority **MUST
  REFUSE** (reason `ERR_QUANTITY_CEILING`). It **MUST NOT** substitute a smaller
  quantity for the same canonical request.
- **Worst-case charge** = `unit_price_minor_units × requested_quantity` using
  checked integer arithmetic (§8); overflow ⇒ refuse (`ERR_CHARGE_OVERFLOW`).
  Because oversized requests are refused, the charged quantity always equals the
  exact bounded executable quantity.
- The **release artifact (§13) MUST bind**: `authorized_quantity` (= the exact
  `requested_quantity`), `quantity_unit`, `resource_class`, `region`,
  `target_constraints`, and `monetary_maximum` (= worst-case charge).
- **Deferred:** authority-side request *rewriting* to a smaller quantity is
  **out of scope (§22)**; if ever added it **MUST** produce a **new canonical
  request and new `request_hash`**, never mutate an existing one.

## 6. Administrative authority & separation of duties — D8, D10

**Decision: RATIFIED (2026-07-26).**

Roles (least privilege): `issuer-admin`, `pricing-admin`, `revocation-admin`,
`recovery-admin`, `migration-admin`, `root-admin`. A budget/spend principal
confers **no** administrative capability.

### 6.1 Principal-level separation of duties (F10)

- **The same authenticated principal MUST NOT satisfy two required approval slots**
  of one operation, even if it holds multiple roles. A single principal counts as
  **one** approver regardless of role membership.
- **Destructive recovery, administrative correction (§16), migration (§23), and
  trust-root replacement MUST require two distinct, independently authenticated
  principals** (two-person). This is **MUST**, not SHOULD.
- Both **role membership and principal identity MUST** be checked; approvals
  **MUST** bind distinct credentials verified live (§4).
- Duplicate/withdrawn/expired approvals **MUST NOT** count; a replayed approval
  **MUST** be rejected.
- **Emergency override**, if retained, is **deferred (§22)**: it **MUST** be
  separately specified, time-limited, fully audited, and **unable to rewrite
  history**. Absent that spec, no override exists.
- Every administrative command **MUST** be authenticated and emit an immutable
  audit event (§18).

## 7. Parent/worker authority boundary — D9

**Decision: RATIFIED (2026-07-26).**

The **authority owner** (the process owning the authoritative SQLite DB) is the
only component that mutates authority. Workers/evaluators/executors are not.

Canonical authority tuple validated before any authority transaction:

```
AuthTuple = (execution_id, request_hash, actor, budget_token,
             cost_basis_ref, policy_hash, target, authorized_quantity,
             expiry, token_generation)
```

- A worker result **MUST** be bound to this exact tuple; the authority owner
  **MUST NOT** trust free-form identity/pricing/cost/request/target values
  returned by a worker and **MUST** re-derive/re-verify each field.
- **No TOCTOU:** the tuple validated at evaluation and used in the authority
  transaction **MUST** be identical and executed under the token-row conditional
  predicate (§10), so any concurrent generation/balance/pricing-key change
  invalidates the transaction.

---

## PART III — DATA MODEL & CONCURRENCY

## 8. Numeric model — D17

**Decision: RATIFIED (2026-07-26).**

- Single monetary dimension, **checked integer minor units**; floating-point
  accounting **prohibited**.
- Every value carries an explicit `currency`; different currencies **MUST NOT** be
  added/compared/netted. Cross-currency conversion is out of scope (§22).
- Width: signed 64-bit; enforced domain `0 ≤ value ≤ 2^63 − 1`; balances **MUST
  NOT** be negative.
- Add/subtract/multiply **MUST** be checked; overflow/underflow/domain violation
  **MUST** refuse (fail closed), never wrap/saturate.
- No rounding on integer minor units. Incompatible-unit/unknown-currency ⇒ reject.
- `token_generation` and `event_sequence` are unbounded monotone counters on
  signed-64; approaching the domain maximum **MUST** fail closed (no wraparound).

## 9. Token generation, expiry & anti-rollback — D10, D24

**Decision: RATIFIED (2026-07-26).**

- Every token row carries a **monotonically increasing `token_generation`**.
- Revocation and any authority-root/ownership change **MUST** increment it.
- Every hold, terminal-ALLOW commit, release, consume, recovery, and admin
  transaction **MUST** atomically validate the **expected `token_generation`**
  (§10); mismatch ⇒ abort (generation-stale, fail closed).

### 9.1 Expiry linearization (F3)

- **Expiry linearizes at its own authority transaction commit** (`expiry_applied`,
  SM-TOKEN), which increments `token_generation`.
- **After expiry linearizes, the token accepts: no new hold, no new terminal ALLOW,
  no new release artifact, no new execution start.**
- A reservation that **already reached terminal ALLOW** (composite commit, §12.2)
  and issued release authority **before** expiry **remains COMMITTED** under
  prepaid semantics. **Expiry MUST NOT retroactively invalidate committed prepaid
  charges.**
- A reservation still **PENDING_HOLD** when expiry linearizes is resolved by
  §12.3 hold-resolution: because no release artifact was issued/consumed for it
  (terminal ALLOW never occurred), **execution provably could not start**, so the
  held amount resolves to the **`expired` bucket** (not `available`).
- **Grandfathering predicate:** a terminal-ALLOW commit is admissible iff its
  `expected_token_generation` equals the token's current generation **and** the
  token status is ACTIVE at commit; the composite transaction (§12.2) enforces
  both atomically. There is no other grandfathering.

### 9.2 Authenticated time source

Expiry is a wall-clock condition evaluated against an **authenticated time source**
(a signed time attestation or the monotonic checkpoint timeline, §21). Where a
fresh authenticated time reading is unavailable, the authority **MUST** fail
closed for expiry-sensitive new authority (no new holds/ALLOW on a token whose
expiry cannot be evaluated). Ordering between authority transactions on one token
is total via `event_sequence` (§10); expiry vs. hold/commit races resolve by
which transaction commits first (§9.3).

### 9.3 Race resolution (normative)

The loser observes a changed `token_generation`/`event_sequence` and **MUST** abort.

| Race | Resolution |
|---|---|
| hold vs revoke | hold-first → hold stands, revoke blocks further holds; revoke-first → hold aborts (stale) → refuse |
| hold vs expiry | expiry-first → hold aborts → refuse; hold-first → hold stands (resolved later per status) |
| terminal-ALLOW commit vs revoke | commit-first → COMMITTED stands (immutable); revoke-first → composite commit aborts (stale) → reservation stays PENDING_HOLD → resolves to `revoked` bucket (§12.3) |
| terminal-ALLOW commit vs expiry | commit-first → COMMITTED stands; expiry-first → composite aborts → PENDING_HOLD → resolves to `expired` bucket |
| release/resolution vs revoke | apply in commit order; a PENDING_HOLD resolved after revoke goes to `revoked`, never `available` |
| release/resolution vs expiry | resolved after expiry goes to `expired`, never `available` |
| child-grant vs anything | N/A in v1 (delegation deferred, §22) |

## 10. Per-token serialization & the authoritative row — D11

**Decision: RATIFIED (2026-07-26).**

```
token_id, tenant, owner_actor_id, currency,
available_minor, held_minor, committed_minor, revoked_minor, expired_minor,
token_generation, event_sequence, current_state_hash, latest_event_id,
status (ACTIVE|REVOKED|EXPIRED), expiry, schema_version
```

- Every authority-changing transaction **MUST** conditionally update the row on
  **both** expected `token_generation` **and** `event_sequence`:
  `UPDATE … WHERE token_id=? AND token_generation=? AND event_sequence=?`.
  Zero rows ⇒ abort (fail closed).
- On success: increment `event_sequence`, update buckets, recompute
  `current_state_hash` (§17.2 chain), set `latest_event_id`.
- **Anti-fork:** the predicate guarantees exactly one linear successor per state;
  two concurrent transitions **MUST NOT** extend the same `current_state_hash`.
- The five-bucket sum (§0) **MUST** hold after every committed transaction.

## 11. SQLite security profile & rollback — D19, D11-rollback

**Decision: RATIFIED (2026-07-26).** (Indexes/perf deferred, §22.)

- **Local FS only** (§1); verify at startup; fail closed otherwise.
- **Path validation**: absolute, normalized, no traversal; **reject symlinks** on
  the path or on DB/WAL/SHM files.
- **Permissions**: DB/WAL/SHM created `0600` (Windows ACL equivalent); broader
  access ⇒ fail-closed startup.
- **Transaction mode**: `BEGIN IMMEDIATE`/`EXCLUSIVE`; `journal_mode=WAL`,
  `synchronous=FULL` (or EXTRA).
- **busy_timeout** configured; on lock timeout **refuse** (fail closed).
- **Disk full / write failure** ⇒ refuse; **MUST NOT** partially apply.
- **Corruption**: startup `PRAGMA integrity_check`; fail closed on corruption or
  missing/corrupt WAL/SHM.
- **No silent recreation**: a missing/empty authoritative DB **MUST NOT** be
  created in a serving role; requires explicit authenticated provisioning/migration.
- **Schema versioning & migration lock** (§23).

### 11.1 Rollback detection — scoped (F11)

v1 does **not** claim complete rollback detection from asynchronous operator
checkpoints. Normative:

- The authority **MUST** obtain, authenticate, and durably store the **latest
  trusted external checkpoint** (§21) available **at startup**, and compare the DB
  state against it.
- **v1 detects rollback only relative to that latest trusted external checkpoint.**
  Authority transactions committed **after** the last such checkpoint but before its
  publication **MAY** be lost by a DB rollback **without cryptographic detection**.
- If continuity from the latest trusted checkpoint **cannot be proven**, startup
  **MUST fail closed**.
- **Operator-controlled local state alone does not prove non-rollback.**
- If per-transaction rollback detection is required, it **MUST** use a durable
  **external monotonic high-water mark** updated before authority becomes
  executable; that stronger guarantee is otherwise **deferred (§22)**.

## 12. Storage, transaction model & prepaid settlement — D1, D5, D7-composite

**Decision: RATIFIED (2026-07-26).**

Reservation record keyed by `(budget_token, execution_id)`:

```
reservation_state ∈ { PENDING_HOLD, COMMITTED, RELEASED }
held_minor            // reserved at hold = worst-case charge
committed_minor       // = held_minor on terminal ALLOW (prepaid, full)
release_bucket        // for RELEASED: which bucket the hold returned to (available|revoked|expired)
owner_actor_id, cost_basis_ref, authorized_quantity, token_generation
h_before, h_after     // state-hash commitments (§17.2)
```

### 12.1 Hold

`hold` (SM-RES) requires token ACTIVE, not expired, `owner_actor_id` matches,
credential live (§4), pricing valid (§5), `available ≥ worst_case_charge`.
Effect: `available -= c; held += c`.

### 12.2 Composite `TERMINAL_ALLOW_COMMIT` (F7)

Terminal ALLOW is **one atomic composite transition** referenced by both SM-RES and
SM-EXEC. There are **no normative intermediate sub-states**.

```
TERMINAL_ALLOW_COMMIT
Preconditions (all in one tx):
  token.status = ACTIVE ; token.token_generation = expected_generation
  reservation.state = PENDING_HOLD ; execution.state = INFLIGHT
  AuthTuple matches ; pricing + actor + credential evidence valid ; not expired/revoked
Atomic effects:
  reservation.state := COMMITTED
  execution.state   := ALLOWED
  token.held_minor  -= amount ; token.committed_minor += amount
  release_artifact.state := ISSUED           (bound per §13)
  immutable receipt bytes stored (§19)
  token.event_sequence += 1 ; current_state_hash advanced (§17.2)
  outbox rows inserted (§20) for hold_committed, execution_allowed, release_issued
```

A failed budget commit **MUST** block the terminal-ALLOW response. Split state is
impossible (single tx). This composite resolves the prior circular SM2/SM3
dependency.

### 12.3 Terminal REFUSE & hold resolution (status-scoped) (F4)

A `PENDING_HOLD` that does not reach terminal ALLOW is **resolved** (SM-RES) to
`RELEASED`, returning `held` to a bucket **chosen by current token status** —
never increasing spendable `available` on a non-ACTIVE token:

| Token status at resolution | Destination bucket | Effect |
|---|---|---|
| ACTIVE | `available` | `held -= c; available += c` |
| REVOKED | `revoked` | `held -= c; revoked += c` |
| EXPIRED | `expired` | `held -= c; expired += c` |

Resolution is triggered by terminal REFUSE, evaluator abandonment, or a
generation-stale composite abort (§9.3). It is permitted **only** when no durable
`release_consumed` event exists for the reservation (proof execution did not start,
§13); the composite commit and consume protocol guarantee that a resolvable
`PENDING_HOLD` has no consumed release.

### 12.4 Why there is no budget freeze in prepaid v1

Prepaid commits the full charge **atomically at terminal ALLOW, before any
execution** (§12.2). The release artifact is issued in that same transaction and
is **durably consumed before the executor may act** (§13). Therefore:

- A budget hold is **never outstanding across an execution**; its outcome cannot
  depend on whether the irreversible action completed.
- The only ambiguity a crash can create is whether the **atomic composite tx**
  committed — a **binary** fact resolved by SQLite durability (`synchronous=FULL`).
- Hence **no `RECOVERY_REQUIRED` / `frozen` budget state is needed or defined** in
  prepaid v1. Execution-outcome uncertainty (did the side effect finish?) is a
  **separate** concern (§15) that does **not** alter settled budget.

A budget `frozen`/recovery state is a **metered-mode concern and is deferred**
(§22) together with metered settlement.

### 12.5 Conservation proof (per transition)

Each transition changes exactly two buckets by ±c (or issues at genesis), so the
sum is invariant:

| Transition | available | held | committed | revoked | expired | Σ |
|---|---|---|---|---|---|---|
| issue (cap) | +cap | 0 | 0 | 0 | 0 | =issued |
| hold | −c | +c | | | | 0 |
| TERMINAL_ALLOW_COMMIT | | −c | +c | | | 0 |
| resolve (ACTIVE) | +c | −c | | | | 0 |
| resolve (REVOKED) | | −c | | +c | | 0 |
| resolve (EXPIRED) | | −c | | | +c | 0 |
| revoke | −A | | | +A | | 0 |
| expiry | −A | | | | +A | 0 |
| admin correction | see §16 (conservation-preserving, paired) | | | | | 0 |

`committed` never decreases in any row (monotonic). `available` increases only
from `held` while ACTIVE, or via §16 funded issuance.

---

## PART IV — PROTOCOLS

## 13. Executor one-shot release & durable consumption — D5, D26

**Decision: RATIFIED (2026-07-26).**

A **receipt is evidence; it is NOT execution authority.** Execution authority is a
signed, single-use **release artifact** (canonical schema §17.5) binding:
`release_id (unique, single-use), execution_id, request_hash, actor,
budget_token, token_generation, target_executor_or_class, target_constraints,
policy_hash, pricing_basis (cost_basis_ref), authorized_quantity, quantity_unit,
resource_class, region, monetary_maximum, issued_at, expiry`.

### 13.1 One-shot consumption protocol (ordering is normative) (F5)

1. Executor submits the signed release artifact **to the authority owner**.
2. Authority validates: `release_id`; signature + trust chain; `execution_id`;
   `request_hash`; `actor`; `target`/`target_constraints`; `policy_hash`;
   `pricing_basis`; `authorized_quantity`; `token_generation` current (not
   revoked); `expiry` not passed (authenticated time, §9.2); credential live (§4);
   execution.state = ALLOWED and reservation.state = COMMITTED.
3. Authority **atomically** transitions the artifact `ISSUED → CONSUMED` in a
   durable SQLite transaction that emits the **`release_consumed`** event
   (§18) under the token-row predicate (§10).
4. **Only after that transaction is durable may the executor begin the irreversible
   action.**

Normative:

- **Worker/executor-local consumption state is NOT authoritative.** The single
  source of truth for consumption is the authority-owner's SQLite transaction.
- **Executing before durable consumption is prohibited** and nonconformant.
- **Duplicate consume returns a non-executable "duplicate/already-consumed" result**
  (`ERR_RELEASE_ALREADY_CONSUMED`); it **MUST NOT** authorize a second execution.
- **Direct execution without authority-owner consumption is outside MNDe's
  guarantees and is nonconformant.**

### 13.2 Crash behavior (F5)

| Crash point | Execution authority | Budget | Recovery |
|---|---|---|---|
| before durable consume | **none** (artifact still ISSUED) | committed (prepaid) | executor MAY retry consume within expiry; else artifact EXPIRED |
| after durable consume, before action | granted once | committed | artifact remains CONSUMED; retry ⇒ duplicate result; **no second execution** |
| during action | granted | committed | execution-outcome recovery (§15); budget unchanged |
| lost response after consume | — | committed | retry returns duplicate/stored result; **MUST NOT** execute twice |

Executors **MUST** reject: cached receipts presented as authority; reused/replayed
artifacts; mismatched `request_hash`/`actor`/`target`; expired artifacts; artifacts
whose `token_generation` was revoked; any action before durable consume.

## 14. Replay & execution identity — D15

**Decision: RATIFIED (2026-07-26).**

- **One globally authoritative execution record** per `execution_id`, which **MUST**
  be globally unique or from a cryptographically authenticated namespace
  (`H_execid`, §17.2). Every reservation references it.
- Evaluated atomically with `request_hash` comparison:

| Presented | Behavior |
|---|---|
| same `execution_id` + same `request_hash` + terminal state | **return stored terminal information; MUST NOT execute again** |
| same `execution_id` + different `request_hash` | **reject** (collision/forgery) |
| same `execution_id` + INFLIGHT | **reject** / return non-executable status; no second start |
| same `execution_id` + different budget token | **reject** unless defined as the same authoritative record |

A cached ALLOW **is not** execution authority (§13); returning it **MUST NOT**
start execution.

## 15. Execution-outcome recovery (budget-decoupled) — D12, D25

**Decision: RATIFIED (2026-07-26).**

This governs **execution status**, not budget (which is already committed, §12.4).

- **Evaluator dispatch, executor release, and irreversible execution are distinct
  (F6).** Evaluator (worker) work **MUST NOT** consume external authority.
- **Before a release artifact is durably ISSUED and CONSUMED, the absence of a
  durable `release_issued`/`release_consumed` record is authoritative evidence that
  the irreversible action could not have started.** An evaluator crash therefore
  **MUST NOT** freeze authority; the reservation resolves per §12.3.
- Execution status uncertainty is admissible **only after** a durable
  `release_consumed` exists (or another explicitly defined irreversible external
  boundary was crossed and authenticated evidence cannot determine its result). In
  that case SM-EXEC enters `EXEC_UNCERTAIN`.
- Resolving `EXEC_UNCERTAIN` uses **only authenticated evidence** bound to
  `execution_id`/`request_hash`/`release_id` (signed executor completion/non-completion
  attestation, or committed authoritative receipt), under an **exclusive recovery
  lease** and a single **idempotent** conditional transaction (§10).
- **Budget settlement is unchanged** by execution-outcome recovery in prepaid v1;
  it only updates observable execution status.
- **Language implying a consuming action between evaluator dispatch and terminal
  ALLOW is removed;** no such action exists in this protocol.

## 16. Administrative correction protocol & state machine — D29

**Decision: RATIFIED (2026-07-26).**

Corrections are the **only** way to touch terminal state, and are strictly
conservation-preserving and append-only.

Every correction **MUST**:

- be **append-only**: emit a new `administrative_correction` event with a new
  `event_sequence`, preserving all prior receipts/events unchanged (no signature or
  prior receipt is mutated);
- carry a **unique `correction_id`**, an explicit **reason**, and **authenticated
  evidence**;
- name the **compensating funding source/destination** for any capacity movement;
- **preserve the five-bucket conservation equation (§0)** within the same atomic
  transaction;
- require **two distinct authenticated principals** (§6.1);
- be **idempotent** on `correction_id`; a conflicting retry (same id, different
  payload) **MUST** be rejected.

**Allowed correction classes** (each conservation-preserving):

1. **Stuck-hold reclassification** — resolve a `PENDING_HOLD` per §12.3 when the
   normal path failed, with evidence.
2. **Funded compensating transfer** — atomically `debit funding_token.available −=
   x` and `credit target_token.available += x`, both ACTIVE, same tenant, with
   authenticated funding evidence. Net Σ across the two tokens unchanged.
3. **Status reconciliation** — record a `revoked`/`expired` classification an
   automated path missed, with evidence (moves `held`/`available` → `revoked`/`expired`).

**Prohibited corrections** (MUST NOT):

- `committed → released/available` (reducing settled spend) — `ΔC_committed < 0`
  is prohibited;
- increasing any `available` without a matching authenticated funding debit or
  issuance;
- removing/rewriting committed spend, prior event order, or historical actor
  identity;
- reactivating `revoked`/`expired` capacity into `available`;
- treating `frozen` (nonexistent in v1) or another token's committed history as a
  funding source.

---

## PART V — EVENTS, RECEIPTS, VERIFICATION

## 17. Canonical event envelope & signed payload schemas — D38

**Decision: RATIFIED (2026-07-26).** "Canonical" is a defined format, not an
adjective. All signed objects use the canonicalization and domain separation below.

### 17.1 Canonicalization algorithm

All signed/hashed payloads **MUST** be serialized with the repository's existing
deterministic JSON canonicalization (`shared/json.ts` `canonicalizeJson`:
lexicographic key order, no insignificant whitespace, rejection of duplicate keys
and non-finite numbers) **as normatively referenced here**; unknown/duplicate
fields **MUST** be rejected on verification; excluded fields (signatures) are
removed before canonicalization. A signed object's schema **MUST** pin
`schema` + `version`.

### 17.2 Hashes & domain separation

All hashes are SHA-256 over the §17.1 canonical bytes with a **domain-separation
prefix** (label ‖ 0x00 ‖ bytes):

- `owner_actor_id = H("mnde.owner.v1" ‖ issuer ‖ tenant ‖ subject)`
- `request_hash   = H("mnde.request.v1" ‖ canonical_request)`
- `H_execid       = H("mnde.execid.v1" ‖ namespace ‖ issuer ‖ nonce)`
- `current_state_hash_n = H("mnde.state.v1" ‖ current_state_hash_{n-1} ‖ canonical_event_n)`
  (genesis `current_state_hash_0 = H("mnde.state.v1" ‖ token_genesis)`)
- checkpoint roots per §21.

### 17.3–17.8 Canonical signed payloads

Each schema **MUST** define: `schema`/`version`; canonicalization (§17.1);
required fields; excluded fields; signature algorithm (Ed25519 unless stated);
`key_role`; trust chain; expiry/historical-validation rules (§4); duplicate/
unknown-field behavior (reject); domain-separation label.

- **17.3 Pricing envelope** — fields §5; label `mnde.pricing.v1`; `key_role=pricing`.
- **17.4 Authenticated principal evidence** — the credential/assertion proving
  `Principal` (§3); label `mnde.principal.v1`; issuer trust chain; liveness §4.
- **17.5 Release artifact** — fields §13; label `mnde.release.v1`; `key_role=authority`.
- **17.6 Terminal decision receipt** — §19 immutable receipt; label `mnde.receipt.v1`.
- **17.7 Administrative command** — §16; label `mnde.admin.v1`; dual-signed (§6.1).
- **17.8 Recovery evidence** — §15; label `mnde.recovery.v1`; bound to
  `execution_id`/`request_hash`/`release_id`.
- **17.9 Checkpoint** and **17.10 later proof artifact** — §21/§19; labels
  `mnde.checkpoint.v1`, `mnde.proof.v1`.

The generic signed object for **non-execution** events is the **canonical event
envelope** (§18.1), **not** "canonical execution."

## 18. Event & receipt taxonomy — D20

**Decision: RATIFIED (2026-07-26).** Every authority-changing transition emits
exactly one immutable event. Events are totally ordered per token by
`event_sequence` and globally identified by `event_id` (§20).

### 18.1 Canonical event envelope

```
Event = {
  schema: "mnde.event.v1", version,
  event_id,                       // globally unique, immutable (§20)
  event_type,                     // enumerated below
  authority_owner_id,
  token_id?, tenant?,             // when token-scoped
  execution_id?,                  // when execution-scoped
  token_event_sequence?,          // per-token order when token-scoped
  global_publication_sequence?,   // assigned at outbox publication (§20)
  h_before?, h_after?,            // state-hash chain when token-scoped
  payload,                        // type-specific canonical body
  authority_signature             // authority key over canonical envelope
}
```

### 18.2 Event table

| event_type | token-scoped | exec-scoped | signed receipt | outbox | proof-eligible | retry |
|---|---|---|---|---|---|---|
| `token_issued` | ✓ | | ✓ | ✓ | ✓ | idempotent (token_id) |
| `hold_created` | ✓ | ✓ | — | ✓ | ✓ | idempotent (token,exec) |
| `hold_rejected` | ✓ | ✓ | — | ✓ | ✓ | idempotent |
| `hold_committed` | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent |
| `hold_resolved` (RELEASED→bucket) | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent |
| `execution_allowed` | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent |
| `execution_refused` | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent |
| `release_issued` | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent (release_id) |
| `release_consumed` | ✓ | ✓ | ✓ | ✓ | ✓ | duplicate ⇒ non-executable result |
| `release_expired` | ✓ | ✓ | — | ✓ | ✓ | idempotent |
| `release_invalidated` | ✓ | ✓ | — | ✓ | ✓ | idempotent |
| `revoke_requested` | ✓ | | — | ✓ | ✓ | idempotent |
| `token_revoked` | ✓ | | ✓ | ✓ | ✓ | idempotent |
| `expiry_applied` | ✓ | | — | ✓ | ✓ | idempotent |
| `execution_recovery_required` | ✓ | ✓ | — | ✓ | ✓ | idempotent |
| `execution_recovery_resolved` | ✓ | ✓ | ✓ | ✓ | ✓ | idempotent |
| `recovery_lease_acquired` | ✓ | ✓ | — | ✓ | ✓ | one holder |
| `recovery_lease_released` | ✓ | ✓ | — | ✓ | ✓ | idempotent |
| `administrative_correction` | ✓ | | ✓ (dual-signed) | ✓ | ✓ | idempotent (correction_id) |
| `pricing_rejected` | | ✓ | — | ✓ | ✓ | idempotent |
| `credential_rejected` | | ✓ | — | ✓ | ✓ | idempotent |
| `migration_started` | ✓? | | ✓ | ✓ | ✓ | idempotent |
| `migration_committed` | ✓? | | ✓ | ✓ | ✓ | idempotent |
| `migration_failed` | ✓? | | ✓ | ✓ | ✓ | idempotent |

"proof-eligible" means an asynchronous later proof artifact (§19.2) MAY bind to
the event; it does **not** assert a proof exists at commit time.

## 19. Immutable receipts vs later proof artifacts — D34

**Decision: RATIFIED (2026-07-26).** (F14)

### 19.1 Immutable receipt (signed in the authority transaction)

Contains only what exists at commit — **no Merkle proof, no `π`:**
`schema/version, event_id, canonical_event_commitment (= h_after or event hash),
token_id, token_event_sequence, execution_id?, decision/result, h_before, h_after,
timestamp (authenticated time), authority_key_id`. Signed by the authority key.

### 19.2 Later proof artifact (produced asynchronously)

`schema/version, event_id, merkle_leaf, inclusion_path, checkpoint_root,
checkpoint_sequence, checkpoint_signature, consistency_info?`. It **binds to** the
immutable receipt/event commitment (`event_id` + commitment) and **MUST NOT**
mutate the receipt. A receipt formula that signs a not-yet-existing `π` is
**prohibited**. The conserved-receipt chain is
`h_after_n = current_state_hash_n` (§17.2); proof of inclusion is a **separate**
artifact.

## 20. Ledger, transactional outbox & publication — D16, D33

**Decision: RATIFIED (2026-07-26).** (F13)

- **SQLite is the sole authoritative transaction store.** Execution state, budget
  state, canonical event data, and immutable receipt bytes are written in the
  **same** transaction (§12.2). A filesystem/external write **MUST NOT** be
  presented as part of the SQLite transaction.
- **Event identity/ordering:**
  - `event_id` — **globally unique, immutable** — is the **deduplication key**.
    Consumers **MUST** dedup by `event_id`, **not** by per-token `event_sequence`
    (which collides across tokens).
  - `(token_id, token_event_sequence)` — deterministic **per-token** order.
  - `global_publication_sequence` — a monotonic counter assigned **by the outbox
    publisher at publication**, providing a total cross-token publication order; its
    authority/serialization is the single outbox publisher within the authority owner.
- **Transactional outbox** (rows in the authority tx) drives Merkle publication,
  external ledger export, filesystem projection, and checkpoint publication.
- **Outbox semantics:** at-least-once delivery; **idempotent retry** and **duplicate
  delivery** deduped by `event_id`; per-token order by `token_event_sequence`;
  cross-token equal `event_sequence` values are expected and **MUST NOT** be treated
  as duplicates; out-of-order delivery tolerated by consumers keyed on `event_id`;
  **publication gaps** (missing `global_publication_sequence`) **MUST** be detected
  and retried; **outbox replay after crash** re-delivers undelivered rows
  idempotently.
- **Proof publication MUST NOT block an ALLOW response**; ALLOW depends only on the
  authoritative SQLite transaction. Proof-availability status is observable.

## 21. Verification & checkpoint model — v1 vs deferred — D13, D31, D32

**Decision: RATIFIED (2026-07-26).** (F11, F12)

### 21.1 v1 regime (operator-signed checkpoints)

- The authority **MUST** periodically emit an **operator-signed checkpoint**
  `(checkpoint_sequence (monotonic), per_token_latest_state_root, global_root,
  authenticated_time)`.
- Verification is **relative to a trusted checkpoint** obtained out-of-band.
- v1 provides **no independent non-equivocation guarantee**; v1 history **MUST NOT**
  be called "witnessed" (no independent witness participates).
- **Stale-checkpoint rejection:** a checkpoint with `checkpoint_sequence ≤` the
  verifier's last trusted one is rejected; current-authority decisions **MUST NOT**
  rely on stale checkpoints.
- **Per-token latest-state proof:** at a trusted checkpoint, a verifier can obtain a
  token's latest state and that no later spend exists **at that checkpoint**
  (via `token_event_sequence` + latest-state root). This is **relative to the
  checkpoint**, not absolute.

### 21.2 Deferred regime (independent verification) — §22

External witnesses, cross-checkpoint **consistency proofs**, gossip, independent
fork detection / non-equivocation, and transparency-log guarantees are **deferred**.
v1 makes **none** of these claims. (Consistency proofs are therefore **not** a v1
MUST; the earlier "MUST provide consistency proof" is removed.)

### 21.3 Claim scoping (normative)

- **Correct** across supported threads/processes sharing one authoritative local DB
  (§1) — not "all executors," not across hosts.
- **Historical signature integrity is offline-verifiable relative to supplied trust
  roots and validation context** — not "offline, eternal."
- **Current authority** (balance/not-revoked/not-expired) **requires** timeline,
  revocation, expiry, and a **trusted checkpoint** — a Merkle inclusion proof alone
  does not prove remaining balance or absence of later spend.
- **Rollback** is detected only per §11.1 (relative to the latest trusted external
  checkpoint at startup).

---

## PART VI — STATE MACHINES

**Common rules.** Each transition runs under the token-row predicate (§10) unless
noted. **Terminal states are immutable except through §16 administrative
correction.** Unlisted transitions are **prohibited**. Retry that observes the
destination already reached is an idempotent no-op returning the stored result; a
retry observing changed generation/sequence **MUST** abort.

### SM-TOKEN (budget token)

States: `ACTIVE` (initial), `REVOKED` (terminal), `EXPIRED` (terminal).

1. `∅ → ACTIVE` — **issue** — issuer-admin + owner principal (§3), cap≥0, unique
   `token_id`; sets `available=cap`; `generation=1`; emits `token_issued`.
2. `ACTIVE → REVOKED` — **token_revoked** (linearizes at commit) — revocation-admin;
   `available → revoked`; `generation+=1`; prohibited: reducing `committed`.
3. `ACTIVE → EXPIRED` — **expiry_applied** — authenticated time (§9.2);
   `available → expired`; `generation+=1`; prohibited: new holds/ALLOW/release/
   execution after EXPIRED.
4. Terminal → any: prohibited except §16.

### SM-RES (reservation)

States: `PENDING_HOLD` (initial), `COMMITTED` (terminal), `RELEASED` (terminal).

1. `∅ → PENDING_HOLD` — **hold** (§12.1) — `available-=c; held+=c`; emits `hold_created`.
2. `PENDING_HOLD → COMMITTED` — **TERMINAL_ALLOW_COMMIT** (§12.2, composite) —
   `held-=c; committed+=c`; emits `hold_committed`, `execution_allowed`,
   `release_issued`; prohibited: partial commit; commit when token not ACTIVE/gen-stale.
3. `PENDING_HOLD → RELEASED` — **hold_resolved** (§12.3) — destination bucket by
   token status (ACTIVE→available, REVOKED→revoked, EXPIRED→expired); emits
   `hold_resolved`; prohibited when a durable `release_consumed` exists.

No `RECOVERY_REQUIRED`/`frozen` in prepaid v1 (§12.4).

### SM-EXEC (execution)

States: `NONE`, `INFLIGHT`, `ALLOWED` (terminal), `REFUSED` (terminal),
`EXEC_UNCERTAIN` (execution-status only; budget already committed).

1. `NONE → INFLIGHT` — **begin** — unique `execution_id`, `request_hash` recorded.
2. `INFLIGHT → ALLOWED` — via **TERMINAL_ALLOW_COMMIT** (§12.2).
3. `INFLIGHT → REFUSED` — **execution_refused** — reservation resolved (§12.3).
4. `ALLOWED → EXEC_UNCERTAIN` — only after durable `release_consumed` and an
   undeterminable irreversible-action result (§15); **budget unchanged**.
5. `EXEC_UNCERTAIN → ALLOWED_COMPLETED|ALLOWED_INCOMPLETE` — **execution_recovery_resolved**
   — authenticated evidence (§15) under lease; **budget unchanged**.
6. Terminal execution status immutable except §16.

### SM-RELEASE (release artifact)

States: `ISSUED`, `CONSUMED` (terminal), `EXPIRED` (terminal), `INVALIDATED` (terminal).

1. `∅ → ISSUED` — inside **TERMINAL_ALLOW_COMMIT** (§12.2); idempotent on `release_id`.
2. `ISSUED → CONSUMED` — **release_consumed** — authority-owner durable tx (§13.1);
   duplicate consume ⇒ non-executable duplicate result; prohibited: consume before
   issue, or executor-local consumption.
3. `ISSUED → EXPIRED` — **release_expired** — authenticated time.
4. `ISSUED → INVALIDATED` — **release_invalidated** — `token_generation` revoked;
   prohibited: consume after invalidation.

### SM-REVOKE (revocation command)

States: `NONE`, `REVOKE_REQUESTED`, `REVOKED`.

1. `NONE → REVOKE_REQUESTED` — **revoke_requested** — revocation-admin.
2. `REVOKE_REQUESTED → REVOKED` — **token_revoked** (linearization point) —
   `available→revoked`, `generation+=1`; prohibited: altering committed.

### SM-EXEC-RECOVERY (execution-outcome recovery; budget-decoupled, §15)

States: `EXEC_UNCERTAIN`, `RECONCILING` (lease), `RESOLVED_COMPLETED` (terminal),
`RESOLVED_INCOMPLETE` (terminal), `PERMANENT_UNCERTAIN` (escalated).

1. `EXEC_UNCERTAIN → RECONCILING` — **recovery_lease_acquired** — recovery-admin; one holder.
2. `RECONCILING → RESOLVED_COMPLETED|RESOLVED_INCOMPLETE` — authenticated evidence (§15).
3. `RECONCILING → PERMANENT_UNCERTAIN` — evidence unobtainable; escalate; **budget
   remains committed** (no capacity moves).
4. Lease expiry: `RECONCILING → EXEC_UNCERTAIN`.

### SM-CORRECTION (administrative correction, §16)

States: `NONE`, `PROPOSED` (one principal), `AUTHORIZED` (two distinct principals),
`APPLIED` (terminal), `REJECTED` (terminal).

1. `NONE → PROPOSED` — first authenticated admin principal + reason + evidence + `correction_id`.
2. `PROPOSED → AUTHORIZED` — **second, distinct** authenticated principal (§6.1).
3. `AUTHORIZED → APPLIED` — atomic conservation-preserving tx (§16); emits dual-signed
   `administrative_correction`; idempotent on `correction_id`.
4. `PROPOSED/AUTHORIZED → REJECTED` — conflicting retry / withdrawn / expired approval.

### SM-MIGRATION (§23)

States: `NONE`, `STARTED` (lock held), `COMMITTED` (terminal), `FAILED` (terminal).

1. `NONE → STARTED` — **migration_started** — migration-admin ×2 (§6.1) under the
   exclusive migration lock (§11).
2. `STARTED → COMMITTED` — **migration_committed** — transactional; genesis per §23.
3. `STARTED → FAILED` — **migration_failed** — leaves prior consistent state.

---

## PART VII — DELEGATION, MIGRATION

## 22. Strict backing; delegation deferred — D2, D28

**Decision: RATIFIED (2026-07-26).** (F8)

- Every object accepted as **spend authority MUST be fully backed** by issuance;
  **overbooking is prohibited.** In single-tier v1 this means `held + committed ≤
  issued` per token (guaranteed by §12.5).
- Internal **forecasts MAY** exist but **MUST NOT** be called grants, authorize
  spending, appear in conservation as committed authority, or be accepted at the
  execution boundary.
- **Budget delegation / cross-token child grants are DEFERRED beyond v1.** v1
  contains **no** child-authority state machine, accounting, events, or guarantees.
  (`child_authority_*` events are removed from the v1 taxonomy.) If added later,
  delegation **MUST** ship with an explicit delegated bucket, a single
  non-double-counting conservation equation, child issuance/use/reclaim/expiry/
  revocation/recovery transitions, parent+child serialization, and hostile tests.

### Deferred features (v1 non-goals)

Metered settlement & budget freeze/recovery; multidimensional authority (`k>1`);
budget delegation/child tokens; independent transparency-log / witness verification
& consistency proofs; per-transaction external rollback high-water mark; emergency
admin override; authority-side request rewriting; external lease/registry/fencing
for replica detection; cross-currency conversion; concrete SQLite DDL/indexes/
tuning. **Deferred features MUST NOT be presented as current guarantees.**

## 23. Migration — D18, D36

**Decision: RATIFIED (2026-07-26).** (F16)

- **Balance initialization MUST** be one of: (a) legacy remaining balance **derived
  from authenticated historical evidence**; or (b) legacy tokens **invalidated and
  reissued from an explicit separately-funded source** under `issuer-admin`.
  **Caller-supplied identity/balance MUST NOT** initialize an owned token.
- **If authenticated legacy history is unavailable, fresh-install-only v1 is
  acceptable** and MUST be stated in the deployment's migration record.
- Migration **MUST** define: a **genesis event** and **initial state hash** per
  token; an **initial checkpoint**; **committed historical spend** and
  **frozen/in-flight work** handling (in-flight legacy holds are drained or failed
  closed, never silently reinterpreted as owned); **duplicate import** rejection;
  **partial-failure** rollback (transactional, prior consistent state); **restart**
  idempotency; **rollback** detection (§11.1); **downgrade rejection** (refuse
  older schema/state).
- **Legacy bearer tokens MUST NOT gain authenticated ownership from caller-supplied
  identity.**
- Migration runs under `migration-admin` ×2 (§6.1), the exclusive migration lock
  (§11), and emits immutable `migration_*` events.

---

## PART VIII — CONFORMANCE, READINESS, METADATA

## 24. Conformance — normative hostile test matrix — D-Conf

**Decision: RATIFIED (2026-07-26).** Every ratified MUST-level invariant maps to ≥1
hostile test. **No test code is written in this branch (§26);** these specify
required tests. Each test defines setup, concurrent actors/processes, fault-injection
point, expected durable state, expected receipt/event, expected retry result, and
expected refusal reason (recorded in the implementation's test plan).

| # | Hostile scenario | Invariant | Maps to |
|---|---|---|---|
| C01 | simultaneous holds across threads | no overspend; one linear history | §10 |
| C02 | simultaneous holds across processes (same DB) | no overspend | §1,§10 |
| C03 | hold vs revoke | §9.3 | §9 |
| C04 | hold vs expiry | §9.3 | §9 |
| C05 | terminal-ALLOW commit vs revoke | commit-first stands; else PENDING→revoked | §9.3,§12.3 |
| C06 | terminal-ALLOW commit vs expiry | commit-first stands; else PENDING→expired | §9.3,§12.3 |
| C07 | duplicate terminal ALLOW | idempotent; single commit | §12.2 |
| C08 | concurrent REFUSE vs ALLOW | one outcome; composite atomic | §12.2 |
| C09 | crash before composite commit | PENDING_HOLD; no split state | §12.2 |
| C10 | lost response after composite commit | idempotent re-send; no double commit | §12.2 |
| C11 | conflicting request hashes (same exec_id) | reject | §14 |
| C12 | execution-ID reuse across tokens | reject | §14 |
| C13 | cached receipt presented as execution authority | reject; nonconformant | §13 |
| C14 | release-artifact replay | one-shot; duplicate non-executable | §13 |
| C15 | execute before durable consume | prohibited; nonconformant | §13.1 |
| C16 | crash before durable consume | no execution authority | §13.2 |
| C17 | crash after durable consume, before action | committed; no second execution | §13.2 |
| C18 | crash during action | budget committed; execution recovery only | §13.2,§15 |
| C19 | lost response after consume | duplicate result; no double execution | §13.2 |
| C20 | evaluator crash before hold | no state, no leak, no freeze | §15 |
| C21 | evaluator crash after hold, before terminal ALLOW | resolve per §12.3; no freeze | §15,§12.3 |
| C22 | recovery release on ACTIVE token | held→available | §12.3 |
| C23 | recovery/resolution on REVOKED token | held→revoked, never available | §12.3 |
| C24 | recovery/resolution on EXPIRED token | held→expired, never available | §12.3 |
| C25 | release racing revocation | resolved after revoke → revoked | §9.3 |
| C26 | release racing expiry | resolved after expiry → expired | §9.3 |
| C27 | retry of recovery resolution | idempotent | §15 |
| C28 | request above quantity ceiling | REFUSE (no clamp) | §5.1 |
| C29 | request above policy cap | REFUSE | §5.1 |
| C30 | request at exact maximum | ALLOW; charge = exact | §5.1 |
| C31 | charge arithmetic overflow | REFUSE | §5.1,§8 |
| C32 | release-artifact quantity mismatch | reject | §13 |
| C33 | stale pricing envelope | refuse | §5 |
| C34 | pricing rollback (lower version) | refuse | §5 |
| C35 | conflicting same-version price envelopes | fork; fail closed | §5 |
| C36 | wrong environment/resource/region/currency envelope | refuse | §5 |
| C37 | pricing-key revocation during in-flight authority | commit aborts / refuse | §5,§7 |
| C38 | actor spoofing (copied user_id) | reject; not authenticated | §3 |
| C39 | cross-tenant identity collision | distinct owner_actor_id; reject cross-tenant | §3 |
| C40 | credential expired | reject new authority | §4 |
| C41 | credential revoked/deprovisioned | reject new authority | §4 |
| C42 | stale credential status | fail closed | §4 |
| C43 | credential unavailable status | fail closed | §4 |
| C44 | historical receipt verify with later-revoked credential | verifies historically; no new authority | §4 |
| C45 | one principal holding multiple admin roles | counts as one; two-person unmet → reject | §6.1 |
| C46 | two role labels backed by same credential | reject (same principal) | §6.1 |
| C47 | two distinct principals authorize | accept | §6.1 |
| C48 | duplicate approval replay | reject | §6.1 |
| C49 | approval withdrawal/expiry mid-flow | reject | §6.1 |
| C50 | compromised single administrator | cannot self-approve two slots | §6.1 |
| C51 | admin correction preserving conservation | accept; Σ unchanged | §16 |
| C52 | admin correction reducing committed | reject | §16,§0 |
| C53 | admin correction increasing available w/o funding | reject | §16 |
| C54 | admin correction reactivating revoked/expired | reject | §16 |
| C55 | correction retry same id/different payload | reject; idempotent same payload | §16 |
| C56 | frozen replacement-token prohibition (no linked replacement) | reject; independent funding only | §12.4,§16 |
| C57 | independently funded replacement token | accept as new issuance; not "restore" | §16 |
| C58 | worker/parent tuple substitution | authority re-verifies; no TOCTOU | §7 |
| C59 | token issuance retry with conflicting payload | reject; idempotent same payload | SM-TOKEN |
| C60 | cross-token identical token_event_sequence | not a duplicate; dedup by event_id | §20 |
| C61 | outbox duplicate delivery | dedup by event_id | §20 |
| C62 | outbox out-of-order / publication gap | detected; retried; per-token order preserved | §20 |
| C63 | outbox replay after crash | idempotent re-delivery | §20 |
| C64 | receipt available before proof publication | receipt valid; proof pending | §19 |
| C65 | later proof binds correct event | accept | §19 |
| C66 | wrong proof/event pairing | reject | §19 |
| C67 | checkpoint reordering / stale checkpoint | reject stale | §21 |
| C68 | Merkle fork (two roots, same checkpoint seq) | fork; fail closed | §21 |
| C69 | rollback inside checkpoint lag | may be undetectable; documented; startup continuity else fail closed | §11.1 |
| C70 | missing trusted checkpoint at startup | fail closed | §11.1 |
| C71 | DB rollback beyond last trusted checkpoint | detected; fail closed | §11.1 |
| C72 | disk full mid-transaction | atomic refuse; no partial apply | §11 |
| C73 | DB/WAL/SHM corruption or missing at startup | fail closed | §11 |
| C74 | symlinked DB/WAL/SHM path | reject; fail closed | §11 |
| C75 | silent DB recreation attempt | refused; requires provisioning | §11 |
| C76 | network filesystem (NFS/SMB) startup | fail closed | §1,§11 |
| C77 | unsupported multi-host startup | fail closed | §1 |
| C78 | disconnected writable replica | not runtime-detectable; deployment-prohibited (documented) | §1 |
| C79 | migration balance genesis (authenticated history) | derived balance; genesis event | §23 |
| C80 | migration reissue from independent funding | accept; owned token | §23 |
| C81 | partial migration failure | transactional rollback; prior state | §23 |
| C82 | migration downgrade/rollback attempt | refuse | §23,§11 |
| C83 | legacy bearer token presented | reject | §3,§23 |
| C84 | canonical-signature/canonicalization mismatch | reject | §17 |
| C85 | unknown/duplicate field in signed payload | reject | §17.1 |
| C86 | event-taxonomy completeness (every SM event enumerated) | pass | §18 |
| C87 | integer overflow in any accounting op | refuse | §8 |
| C88 | counter approaching 2^63 | fail closed (no wraparound) | §8 |
| C89 | credential minted for another audience presented | reject `ERR_AUDIENCE_MISMATCH`; refusal MUST NOT leak the authorized audiences | §3 |
| C90 | principal below scope `min assurance_level` | reject `ERR_INSUFFICIENT_ASSURANCE`; token uncommitted; succeeds after genuine assurance upgrade (refusal scoped to call-time state) | §3 |
| C91 | forged act-as field (e.g. `X-Act-As`) without signed delegation | act-as NOT inferred; caller's own identity used → `ERR_FORBIDDEN` if it lacks direct authority; forged value MUST NOT appear as effective principal in any audit event | §3 |
| C92 | ambiguous / non-normalizable identifier (`subject`/`execution_id`/namespace) | reject `ERR_AMBIGUOUS_IDENTIFIER` (never guess); malformed (invalid UTF-8 / NFC-fail / null byte) → `ERR_MALFORMED_ID` before any authority check; no bucket change | §3.1 |
| C93 | interrupted migration leaves an in-flight legacy hold | new authority refused `ERR_LEGACY_HOLD_UNCLEARED` until explicit drain or fail-closed; legacy hold never silently re-owned; partial transfer rolls back to `L` held / `0` granted; after a clean drain, `T = available + held` holds exactly | §23 |

## 25. PR dependency & metadata — D21

- **PR #5 MUST remain dormant until PR #4 is resolved.**
- **After PR #4 lands**, the maintainer **MUST** rebase PR #5, re-read the document,
  re-run consistency checks (§29), and verify no foundation language became stale.
- The PR #5 description **MUST** state: D0–D38 ratified; the decision log exists;
  implementation remains blocked; PR #4 remains a dependency; no runtime
  implementation has started.

## 26. Non-goals & implementation boundary

- No runtime code/tests/schemas/packages/generated files changed on this branch.
- Does not re-open PR #4.
- **This document does not authorize implementation.** Implementation is gated on
  §27 and PR #4 (§25).
- The existing 65 runtime tests are **not** evidence that this normative matrix
  (§24) is implemented; §24 tests are unimplemented requirements.

## 27. Implementation-readiness checklist & documentation gate

**Documentation completeness** — all normative sections present:
Deployment (§1), D0 (§2), principal (§3), credential liveness (§4), pricing +
no-clamp (§5), admin + principal-SoD (§6), parent/worker (§7), numeric (§8),
generation/expiry/race (§9), serialization (§10), SQLite + scoped rollback (§11),
storage + composite + hold-resolution (§12), executor consume protocol (§13),
replay/identity (§14), execution recovery decoupled (§15), admin correction (§16),
canonical envelope + payloads (§17), taxonomy (§18), receipt/proof split (§19),
outbox identity/ordering (§20), verification v1/deferred (§21), backing +
delegation deferred (§22), migration genesis (§23), conformance (§24). — **present.**

**Documentation gate:** **FAIL — remediation in progress.** (This value is set to
PASS by §29 only after the final consistency pass verifies every gate criterion
below. It is left FAIL until then.)

Gate criteria (all must hold for PASS): zero Critical findings; zero High
contradictions; conservation mechanically coherent (§12.5); composite transition
implementable (§12.2); release-consumption ordering explicit (§13.1); recovery
cannot duplicate/resurrect authority (§12.3,§15,§16); expiry/revocation races have
one outcome (§9.3); receipts and proofs separated (§19); rollback claims match the
mechanism (§11.1,§21); every MUST-level invariant maps to a hostile test (§24); all
internal references and metadata correct.

**Residual gate blockers (status):**

- *Coverage* — **CLOSED.** The five previously-unmapped MUST invariants now have
  hostile cases C89–C93 (§24): audience validation and assurance minimum and
  impersonation (§3), identifier normalization (§3.1), and in-flight legacy-hold
  drain (§23).
- *Independent re-review* — **OPEN.** This revision was authored and self-checked
  in one pass; the gate **MUST NOT** flip to PASS on author self-certification. A
  second, non-author adversarial reader **MUST** run the §29 consistency checks and
  the cross-machine traces against the current five-bucket model and sign off. Until
  then the gate stays **FAIL**.

**Release gates (external — implementation BLOCKED):** PR #4 merged; architectural
sign-off; implementation + §24 tests + audit — **not started.**

**Overall implementation-readiness verdict:** **BLOCKED.** Documentation gate is
resolved in §29 after the consistency pass.

---

## 28. Decision status & log

| # | Decision | Status | Ruling (section) |
|---|---|---|---|
| D0 | Authenticated cost basis | RATIFIED | §2 |
| D1 | Prepaid settlement (full commit; no freeze in v1) | RATIFIED | §12 |
| D2 | Strict backing; overbooking prohibited | RATIFIED | §22 |
| D3 | Revocation semantics | RATIFIED | §9 |
| D4 | Parent-owned atomic hold | RATIFIED | §7,§10,§12 |
| D5 | Executor one-shot release + durable consume | RATIFIED | §13 |
| D6 | Pricing authority envelope | RATIFIED | §5 |
| D7 | Authenticated principal model | RATIFIED | §3 |
| D8 | Administrative authority | RATIFIED | §6 |
| D9 | Parent/worker boundary; no TOCTOU | RATIFIED | §7 |
| D10 | Token generation & anti-rollback | RATIFIED | §9 |
| D11 | Per-token serialization | RATIFIED | §10 |
| D12 | Execution-outcome recovery (budget-decoupled) | RATIFIED | §15 |
| D13 | Verification claims (v1 vs deferred) | RATIFIED | §21 |
| D14 | Deployment scope | RATIFIED | §1 |
| D15 | Replay & execution identity | RATIFIED | §14 |
| D16 | Ledger & transactional outbox | RATIFIED | §20 |
| D17 | Numeric model | RATIFIED | §8 |
| D18 | Migration | RATIFIED | §23 |
| D19 | SQLite security profile | RATIFIED | §11 |
| D20 | Event & receipt taxonomy | RATIFIED | §18 |
| D21 | PR dependency & metadata | RATIFIED | §25 |
| D22 | Oversized request ⇒ REFUSE (no clamp) | RATIFIED | §5.1 |
| D23 | No linked replacement token; independent funding only | RATIFIED | §12.4,§16 |
| D24 | Expiry linearization + grandfathering | RATIFIED | §9.1 |
| D25 | Status-scoped hold resolution; no budget freeze | RATIFIED | §12.3,§12.4 |
| D26 | Durable release-consume before execution | RATIFIED | §13.1 |
| D27 | Composite TERMINAL_ALLOW_COMMIT | RATIFIED | §12.2 |
| D28 | Budget delegation deferred | RATIFIED | §22 |
| D29 | Administrative-correction state machine | RATIFIED | §16 |
| D30 | Principal-level SoD (MUST, two-person) | RATIFIED | §6.1 |
| D31 | Rollback detection scoped to external checkpoint | RATIFIED | §11.1 |
| D32 | v1 vs deferred checkpoint regimes; not "witnessed" | RATIFIED | §21 |
| D33 | Outbox event_id identity/ordering | RATIFIED | §20 |
| D34 | Receipt vs later proof separation (no signed π) | RATIFIED | §19 |
| D35 | Credential liveness | RATIFIED | §4 |
| D36 | Migration balance genesis | RATIFIED | §23 |
| D37 | Weakened writable-replica detection | RATIFIED | §1 |
| D38 | Canonical event envelope + payload schemas | RATIFIED | §17 |
| R | Replay-hash comparison (cached-response) | Deferred prerequisite | §14 |

### Decision log

| Date | Decision | Ruling | Rationale |
|---|---|---|---|
| 2026-07-26 | D0–D21 | Ratified (prior remediation) | see §28 rows |
| 2026-07-26 | D22 — Quantity ceiling | Ratified: REFUSE, never clamp | Silent clamping undercharges an unchanged executable request. |
| 2026-07-26 | D23 — Replacement token | Ratified: no linked replacement; independent funding only | Linked replacement can make one amount spendable twice. |
| 2026-07-26 | D24 — Expiry linearization | Ratified: linearize at tx commit; pre-ALLOW grandfathering only | One deterministic expiry-vs-commit outcome; committed prepaid preserved. |
| 2026-07-26 | D25 — Hold resolution | Ratified: destination by token status; no budget freeze | Recovery must never restore spendable capacity on revoked/expired tokens. |
| 2026-07-26 | D26 — Release consume | Ratified: durable consume before action | Prevents split-brain double execution. |
| 2026-07-26 | D27 — Composite ALLOW | Ratified: single atomic transition | Removes circular SM2/SM3 precondition. |
| 2026-07-26 | D28 — Delegation | Ratified: deferred | Prior model double-counted child authority; remove rather than expand. |
| 2026-07-26 | D29 — Admin correction | Ratified: append-only, conservation-preserving SM | Correction must never bypass conservation or rewrite history. |
| 2026-07-26 | D30 — SoD | Ratified: principal-level MUST, two-person | Role labels alone do not prevent a single admin self-approving. |
| 2026-07-26 | D31 — Rollback | Ratified: scoped to external checkpoint; else fail closed | Async operator checkpoints cannot detect all rollback. |
| 2026-07-26 | D32 — Checkpoint regimes | Ratified: v1 operator-signed, not witnessed; independent verification deferred | Do not claim non-equivocation without an independent witness. |
| 2026-07-26 | D33 — Outbox identity | Ratified: dedup by global event_id | Per-token sequence collides across tokens. |
| 2026-07-26 | D34 — Receipt/proof split | Ratified: no signed future π | A receipt cannot sign a proof that does not yet exist. |
| 2026-07-26 | D35 — Credential liveness | Ratified: status freshness, fail closed | Well-formed ≠ live; revoked credentials must not grant new authority. |
| 2026-07-26 | D36 — Migration genesis | Ratified: authenticated history or funded reissue; fresh-install-only allowed | Ownership must not derive from caller identity. |
| 2026-07-26 | D37 — Replica detection | Ratified: deployment control, not runtime claim | SQLite cannot detect disconnected writable copies. |
| 2026-07-26 | D38 — Canonical envelope | Ratified: defined envelope + payload schemas | "Canonical" must be a defined format, not an adjective. |

## 29. Editing, validation & final gate

Applied: preserved good material; removed the frozen/RECOVERY_REQUIRED budget model
(replaced by deterministic status-scoped resolution, §12.3–12.4); replaced circular
terminal-ALLOW with the composite transition (§12.2); deferred delegation (§22);
added credential liveness (§4), admin-correction SM (§16), canonical envelope +
payloads (§17), receipt/proof split (§19), outbox identity (§20), scoped rollback
(§11.1) and checkpoint regimes (§21); corrected all internal references and the
D0–D38 metadata; expanded conformance to C01–C93. This revision does **not** claim
implementation, does **not** modify PR #4, and does **not** weaken any fail-closed
rule.

**Final documentation-gate resolution:** set by the post-edit consistency pass
recorded in the PR #5 review notes. Until that pass is complete and every §27 gate
criterion verifies, the gate reads **FAIL — remediation in progress** (§27).
