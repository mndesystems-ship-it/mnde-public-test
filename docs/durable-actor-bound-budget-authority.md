# Durable, Actor-Bound Budget Authority — Normative Design Specification

**Status:** DESIGN — normative, implementation-ready · **no runtime code changes in this branch**
**Branch:** `design/durable-actor-bound-budget` (documentation only)
**Depends on:** PR #4 (`fix/budget-token-hold-finalization`) — see §21. PR #5 stays dormant until PR #4 is resolved.
**Frames:** the MNDe *authority-flow calculus*

> **Trust a fixed cryptographic root and a witnessed append-only history — verify everything else relative to that trust context.**

### Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **MAY**, and **OPTIONAL** are used per RFC 2119/8174.
A statement without a normative keyword is descriptive, not a requirement.

### What this document is

A source-of-truth design for making budget-token authority **durable** (survives
restart), **process-shared and atomic within one authoritative database**, and
**actor-bound** (a token spends only for the authenticated actor it was issued
to). It does **not** change runtime behavior; it does not authorize
implementation (§22). Owner rulings **D0–D19** are ratified (§10). This revision
also removes claim overreach (§17), fixes the numeric model to cents-only (§13),
and removes prepaid PARTIAL settlement (§2, §11).

Nothing here modifies PR #4. The correctness fix (defer the charge to a
post-Ramona commit; release on any terminal refuse) is the *foundation* this
builds on, not something to revisit.

---

## PART I — FOUNDATIONS

## 0. Why budget is special (the calculus)

An authority grant is `A = (Q, C, Θ, D)`: qualitative permissions `Q`, conserved
capacities `C`, temporal/state conditions `Θ`, delegation provenance `D`.
Qualitative authority is a **set** governed by containment (`Q_{i+1} ⪯ Q_i`) and
verifies **statelessly**. Budget is **conserved** authority — it depletes, so its
validity is **ledger-relative**: "is this within budget?" is only answerable
against authenticated history `H`.

The calculus is stated generally for a conserved vector `C ∈ ℤ^k_{≥0}`. **MNDe v1
scopes `C` to a single monetary dimension in checked integer minor units** (§13);
`k = 1`. All balances are non-negative integers. The governing invariant, at
every instant, for every token:

```
C_issued = C_available + C_held + C_committed + C_frozen + C_revoked
```

- `C_available` — spendable now.
- `C_held` — reserved by a live `PENDING_HOLD` reservation.
- `C_committed` — settled spend; monotonically non-decreasing.
- `C_frozen` — capacity attached to a `RECOVERY_REQUIRED` reservation; not
  spendable and not released until reconciliation.
- `C_revoked` — issued capacity permanently removed from circulation; not erased.

Conservation laws (normative):

- The five-bucket sum **MUST** equal `C_issued` after every committed
  authority-changing transaction.
- `ΔC_committed = 0` **unless** an execution validly commits (the no-refund
  invariant PR #4 restored).
- A failure **MUST NOT** reduce or duplicate `C_issued`.

---

## PART II — DEPLOYMENT & TRUST SCOPE

## 1. Deployment scope (v1) — D14

**Decision: RATIFIED (2026-07-26).**

v1 authority is scoped to a single authoritative store on one host:

- The system **MUST** run against exactly **one authoritative SQLite database** on
  **one host**, on a **supported local filesystem** (ext4, xfs, APFS, NTFS).
- Multiple **threads or OS processes on that host MAY** share that exact database
  file as concurrent clients of the same authority.
- The system **MUST NOT** operate in active-active multi-host mode in v1.
- The authoritative database **MUST NOT** be placed on **NFS**, **SMB/CIFS**, or
  any network filesystem, nor on a replicated writable copy.
- On detecting a network/unsupported filesystem, or more than one writable
  replica, the authority **MUST** fail closed at startup (§19).

All claims in this document are scoped to this model. Any statement of
cross-executor correctness means **"correct across supported threads and
processes sharing the one authoritative local database"**, never "correct across
all executors" or across hosts.

## 2. DECISION 0 — Authenticated cost basis (D0)

**Decision: RATIFIED (2026-07-26).**

Every sidecar request is untrusted unless each security-relevant claim is
cryptographically authenticated. "The control plane is trusted" is a deployment
assumption, not an authority proof.

- **Actor identity** **MUST** come from an authenticated principal (§3). A caller
  field such as `execution_request.actor.user_id` is an asserted identifier and
  **MUST NOT** by itself establish identity or ownership.
- **Price** **MUST** come from a signed pricing-authority envelope (§4). Caller
  `pricing_data` **MUST NOT** establish, raise, or reduce a hold or charge.
- **Usage** **MUST NOT** reduce settlement unless authenticated by an approved
  executor/metering authority and bound to the execution, policy, actor, price
  schedule, and ledger event. Caller `runtime_observation` **MAY** be retained as
  diagnostic input but **MUST NOT** be authoritative cost evidence.
- Failure to validate required cost-basis evidence **MUST** fail closed before an
  authoritative hold.

**Rationale:** an unauthenticated price or usage claim lets the spender choose its
own charge, defeating conservation regardless of ledger correctness.

## 3. Authenticated principal model — D7

**Decision: RATIFIED (2026-07-26).**

A principal is the tuple:

```
Principal = (issuer, tenant, subject, audience, assurance_level, delegation_chain)
```

Requirements:

- **Credential type** — the authority **MUST** accept only configured credential
  types (e.g., signed identity assertion / OIDC-style token / mTLS client cert
  bound to the request). A raw string user_id is **NOT** a credential.
- **Canonical principal derivation** — the authority **MUST** derive a canonical
  principal by normalizing `(issuer, tenant, subject)` under §3.1 normalization,
  then binding `audience` and `assurance_level`. A copied `user_id` string
  **MUST NOT** count as authentication.
- **`owner_actor_id` derivation** — `owner_actor_id = H(namespace ‖ issuer ‖
  tenant ‖ subject)` using a domain-separated hash. It **MUST** be stable across
  credential rotation and **MUST** differ across tenants even for identical
  subject strings.
- **Namespace separation & tenant isolation** — every token, reservation, and
  execution record **MUST** carry `tenant`. Cross-tenant access **MUST** be
  rejected; a principal in tenant A **MUST NOT** hold, commit, revoke, or read
  authority in tenant B.
- **Audience validation** — the credential's `audience` **MUST** match this
  authority's configured identifier; mismatched-audience credentials **MUST** be
  rejected.
- **Delegation** — a delegated principal's authority **MUST** be `⪯` its
  delegator (qualitative narrowing) and its budget grant strictly backed (§15).
  `delegation_chain` **MUST** be authenticated end-to-end; a broken or unbacked
  link invalidates the chain.
- **Impersonation** — impersonation (act-as) **MUST** be an explicit,
  authenticated, audited capability; it **MUST NOT** be inferrable from a caller
  field.
- **Assurance level** — the authority **MAY** require a minimum `assurance_level`
  per policy scope; below-minimum principals **MUST** be refused for the affected
  operations.
- **Key rotation** — issuer key rotation **MUST NOT** change `owner_actor_id`;
  validation **MUST** accept keys valid at the credential's authenticated time
  under the issuer's published key set.
- **Deprovisioning** — a deprovisioned principal **MUST** be unable to create new
  holds; existing committed history is immutable (§8).
- **Cross-tenant identity collision** — identical `subject` in different tenants
  **MUST** derive distinct `owner_actor_id` and **MUST NOT** collide.

### 3.1 Normalization

Normalization of `(issuer, tenant, subject)` **MUST** be deterministic:
NFC Unicode, case-folding only where the issuer declares case-insensitivity,
trimming of insignificant whitespace, and rejection of embedded null/control
characters. Ambiguous or non-normalizable identifiers **MUST** be rejected, not
guessed.

**Bearer fallback is prohibited** (§8, §17). A token without an authenticated
owner **MUST NOT** exercise durable budget authority.

## 4. Pricing authority envelope — D6

**Decision: RATIFIED (2026-07-26).**

Price is established only by a signed pricing envelope. Fields:

```
PricingEnvelope = {
  issuer, key_role, tenant_scope, environment_scope, policy_scope,
  resource_class, region, currency, canonical_unit, quantity_ceiling,
  effective_time, expiry, schedule_version (monotonic),
  unit_price_minor_units, canonical_serialization, signature
}
```

Requirements:

- **Signature validation** — the envelope **MUST** be signed by a key whose
  `key_role` is authorized to publish pricing for `(tenant_scope,
  environment_scope, policy_scope)`. Validation **MUST** occur **before** the
  hold transaction. Invalid/absent signature ⇒ fail closed.
- **Canonical serialization** — pricing **MUST** be canonicalized before signing
  and verification; non-canonical encodings **MUST** be rejected.
- **Scope match** — `resource_class`, `region`, `currency`, `policy_scope`,
  `tenant`, and `environment` in the envelope **MUST** match the request's
  authenticated context; any mismatch ⇒ refuse.
- **Effective window** — the envelope **MUST** be valid at the request's
  authenticated decision time (`effective_time ≤ t < expiry`). Expired or
  not-yet-effective envelopes **MUST** be refused.
- **Monotonic schedule version & anti-rollback** — the authority **MUST** persist
  the highest accepted `schedule_version` per `(tenant, environment, policy_scope,
  resource_class, region)` and **MUST** reject any envelope with a lower version
  (rollback). Equal-version envelopes **MUST** be byte-identical or be rejected as
  a fork.
- **Conflicting versions** — if two valid envelopes with the same scope and
  version but different content are seen, the authority **MUST** fail closed and
  raise an administrative alert; it **MUST NOT** silently pick one.
- **Key rotation & revocation** — pricing keys **MUST** support rotation and
  revocation; a revoked pricing key's envelopes **MUST NOT** authorize new holds.
- **Quantity ceiling & worst-case charge** — the authorized maximum for a hold is
  computed as
  `worst_case_charge = unit_price_minor_units × authorized_quantity`, where
  `authorized_quantity = min(requested_quantity, quantity_ceiling, policy_caps)`,
  using checked integer arithmetic (§13). Overflow ⇒ refuse.
- **Caller price is untrusted** — caller `pricing_data` **MUST NOT** feed
  `worst_case_charge`. It **MAY** be logged as diagnostic only.

## 5. Administrative authority & separation of duties — D8

**Decision: RATIFIED (2026-07-26).**

Administrative operations are distinct from spending. Roles (least-privilege):

| Role | May | MUST NOT |
|---|---|---|
| `issuer-admin` | issue tokens, assign owner, set caps/expiry | perform destructive recovery, migrate |
| `pricing-admin` | publish/rotate/revoke pricing envelopes | issue tokens, spend |
| `revocation-admin` | revoke tokens, bump generation | reissue to self, alter committed history |
| `recovery-admin` | reconcile FROZEN holds, resolve RECOVERY_REQUIRED | issue tokens, publish pricing |
| `migration-admin` | run authenticated migrations | issue/spend/price |
| `root-admin` | authority-root & key-set changes | routine issuance/spend/pricing |

Requirements:

- All administrative commands **MUST** be authenticated (§3-grade principal with
  the admin role) and **MUST** emit an immutable audit event (§18).
- **Separation of duties** — issuance, destructive recovery, migration, and
  administrative correction **MUST** require distinct roles; no single role may
  perform two of these classes. Destructive/irreversible operations **SHOULD**
  require two-person authorization.
- **Normal spending authority MUST NOT grant administrative authority.** A budget
  token or spend principal confers no admin capability.
- Terminal-state administrative correction (PART V common rules) **MUST** be a separate,
  dual-authorized, fully audited procedure and **MUST NOT** be reachable by
  normal transitions.

## 6. Parent/worker authority boundary — D9

**Decision: RATIFIED (2026-07-26).**

The **durable authority owner** (the process owning the authoritative SQLite
database) is the only component that mutates authority. Workers are stateless
evaluators.

The **canonical authority tuple** the authority owner **MUST** validate or
cryptographically verify before any authority transaction:

```
AuthTuple = (execution_id, request_hash, actor, budget_token,
             cost_basis_ref, policy_hash, target, expiry, token_generation)
```

- Every worker result **MUST** be bound to this exact tuple (e.g., the worker
  echoes a signed/hashed copy of the tuple it evaluated).
- The authority owner **MUST NOT** trust free-form identity, pricing, cost,
  request, or target values *returned by a worker*; it **MUST** re-derive or
  re-verify each tuple field against authenticated inputs it holds.
- There **MUST** be **no TOCTOU gap**: the tuple validated at evaluation and the
  tuple used in the authority transaction **MUST** be identical, and the hold /
  commit **MUST** execute under the token-row conditional predicate (§9) so any
  concurrent change (generation bump, balance change) invalidates the transaction.
- Workers **MUST NOT** own, reset, reconstruct, or mutate durable authority state.
  A worker-local authority fallback is **prohibited**.

---

## PART III — DATA MODEL & CONCURRENCY

## 7. Numeric model — D17

**Decision: RATIFIED (2026-07-26).**

- v1 accounting **MUST** use a **single monetary dimension** in **checked integer
  minor units** (e.g., cents). Floating-point accounting is **prohibited**.
- Every monetary value **MUST** carry an explicit `currency` identifier; values of
  different currencies **MUST NOT** be added, compared for balance, or netted.
- Integer width **MUST** be a signed 64-bit integer; the enforced domain is
  `0 ≤ value ≤ 2^63 − 1`. Balances **MUST NOT** be negative.
- Addition and subtraction **MUST** be checked; any overflow, underflow, or
  domain violation **MUST** refuse the operation (fail closed), never wrap or
  saturate.
- **No rounding** occurs on integer minor units; any computation that would
  introduce a fraction (e.g., unit conversion) is **prohibited** unless performed
  by a separate, authenticated conversion authority that emits its own signed,
  audited record. Cross-currency conversion is out of scope for v1.
- Incompatible-unit or unknown-currency inputs **MUST** be rejected.

The general `ℤ^k` calculus notation (§0) is retained only as framing; **v1 stores
and enforces `k = 1`**. Multidimensional conserved authority is deferred (§23);
if ever added, each dimension **MUST** have a typed schema and its own
conservation equation, and dimensions **MUST NOT** be netted against each other.

## 8. Token generation, expiry & anti-rollback — D10

**Decision: RATIFIED (2026-07-26).**

- Every token row carries a **monotonically increasing `token_generation`**.
- Revocation and any authority-root/ownership change **MUST** increment
  `token_generation`.
- Every hold, release, commit, recovery, child-grant, and administrative
  transaction **MUST** atomically validate the **expected `token_generation`** in
  its conditional predicate (§9). A mismatch **MUST** abort the transaction
  (fail closed) and return a generation-stale status.
- **Revocation's linearization point is its database commit.** An operation
  linearizes before revocation iff its transaction commits before the revocation
  transaction on the same token row; ordering is total per token via the row's
  `event_sequence` (§9).
- **Expiry enforcement.** `expiry` is enforced, not descriptive. A token past
  `expiry` (by authenticated timeline, §16) **MUST NOT** accept new holds.
- **Hold-before-expiry, commit-after-expiry:** a hold created and still valid
  before `expiry` **MAY** commit after `expiry` **only if** its terminal
  transaction linearizes before any revocation and the hold has not entered
  `RECOVERY_REQUIRED`; otherwise it **MUST** freeze or release per §11. Expiry
  **MUST NOT** silently release a live hold whose consumption is unproven — it
  freezes (fail closed).

### 8.1 Race resolution (normative)

For each pair, the outcome is decided by which transaction commits first on the
token row (the linearization point); the loser observes a changed
`token_generation`/`event_sequence` and **MUST** abort:

| Race | Resolution |
|---|---|
| hold vs revoke | If hold commits first → hold stands, revoke then blocks further holds. If revoke first → hold aborts (generation stale) → refuse. |
| release vs revoke | Independent buckets; both apply in commit order; release never resurrects revoked capacity. |
| commit vs revoke | Commit before revoke → commit stands (settled, immutable). Revoke before commit → commit aborts; reservation → `RECOVERY_REQUIRED` if consumption unproven. |
| recovery vs revoke | Recovery holds an exclusive lease (§12); revoke during recovery is queued behind lease resolution, then applied. |
| child-grant vs revoke | Revoke before child-grant commit → child-grant aborts. Child-grant first → child exists but is transitively revoked by parent generation bump. |
| expiry vs hold | Expiry effective before hold commit → hold aborts. |
| expiry vs release | Release proceeds (returns capacity); expiry blocks new holds. |
| expiry vs commit | Commit linearizing before expiry stands; after expiry with unproven consumption → freeze. |

## 9. Per-token serialization & the authoritative row — D11

**Decision: RATIFIED (2026-07-26).**

One authoritative token row is the serialization point. Minimum columns:

```
token_id, tenant, owner_actor_id, currency,
available_minor, held_minor, committed_minor, frozen_minor, revoked_minor,
token_generation, event_sequence, current_state_hash, latest_event_ref,
status, expiry, schema_version
```

- Every authority-changing transaction **MUST** conditionally update the token row
  using **both** its expected `token_generation` **and** expected `event_sequence`
  (optimistic concurrency): `UPDATE … WHERE token_id = ? AND token_generation = ?
  AND event_sequence = ?`. Zero rows affected ⇒ abort (fail closed) and retry from
  a fresh read or refuse.
- On success the transaction **MUST** increment `event_sequence`, update the
  affected balance buckets, recompute `current_state_hash` (§18 chain), and set
  `latest_event_ref`.
- **Two concurrent transitions MUST NOT extend the same `h_before` into two valid
  histories.** The conditional predicate guarantees exactly one linear successor
  per state; the loser aborts. This is the anti-fork invariant.
- The five-bucket conservation sum (§0) **MUST** hold after every committed
  transaction.

## 10. SQLite minimum security profile — D19

**Decision: RATIFIED (2026-07-26).** (Exact indexes/perf tuning deferred, §23.)

Mandatory invariants:

- **Local filesystem only** (§1); startup **MUST** verify the DB path resolves to
  a supported local filesystem and **MUST** fail closed otherwise.
- **Path validation** — the DB path **MUST** be validated (absolute, normalized,
  no traversal); **symlinks in the path or on the DB/WAL/SHM files MUST be
  rejected** (fail closed).
- **File permissions** — DB, WAL, and SHM files **MUST** be created with
  owner-only permissions (`0600`); world/group access **MUST** cause fail-closed
  startup on POSIX. Windows ACL equivalent required.
- **WAL/SHM protection** — WAL and SHM files **MUST** reside in the same protected
  directory and inherit the same permission and symlink rules.
- **Transaction mode** — authority transactions **MUST** use `BEGIN IMMEDIATE`
  (or `EXCLUSIVE`) to avoid write-skew; `journal_mode=WAL`,
  `synchronous=FULL` (or `EXTRA`) **MUST** be set.
- **Lock contention / busy** — a `busy_timeout` **MUST** be configured; on lock
  timeout the operation **MUST** refuse (fail closed), never proceed unsynchronized.
- **Disk full** — on `SQLITE_FULL`/write failure the authority **MUST** refuse and
  preserve state; it **MUST NOT** partially apply an authority transaction.
- **Corruption detection** — startup **MUST** run an integrity check
  (`PRAGMA integrity_check`/`quick_check`) and **MUST** fail closed on corruption.
- **Fail-closed startup** — any failed invariant above **MUST** prevent the
  authority from serving holds.
- **No silent recreation** — the authority **MUST NOT** silently create or
  re-initialize a missing/empty authoritative DB in a serving role; a missing DB
  **MUST** require an explicit, authenticated provisioning/migration command.
- **Schema versioning & migration locking** — the DB **MUST** carry
  `schema_version`; migrations **MUST** run under an exclusive migration lock
  (§17) and be refused if `schema_version` is unexpected.
- **Backup/restore & rollback detection** — restores **MUST** preserve or advance
  `token_generation`/checkpoint state; a restore to an **older** authoritative
  state (rollback) **MUST** be detected via the witnessed checkpoint (§17)
  and **MUST** fail closed rather than silently accept rolled-back balances.

## 11. Storage & transaction model

A `budget_reservations` record keyed by `(budget_token, execution_id)`:

```
reservation_state ∈ { PENDING_HOLD, COMMITTED, RELEASED, RECOVERY_REQUIRED }
held_minor            // reserved at hold (the authenticated worst-case cost)
committed_minor       // = held_minor in ratified prepaid v1
actual_minor          // NULLABLE schema reservation; NON-AUTHORITATIVE, unused in prepaid v1
released_delta_minor  // NULLABLE schema reservation; NON-AUTHORITATIVE, unused in prepaid v1
owner_actor_id        // authenticated principal (§3)
cost_basis_ref        // pricing envelope reference (§4)
token_generation      // generation observed at hold
h_before, h_after     // ledger state commitments (§18)
```

### 11.1 Prepaid settlement (ratified v1) — D1

Prepaid v1 charges for **released authorization**, not proven execution:

- On **terminal ALLOW**, the reservation **MUST** transition
  `PENDING_HOLD → COMMITTED` **in the same transaction** that records the terminal
  ALLOW execution state, releases execution authority (issues the one-shot release
  artifact, §12), and writes the authoritative receipt bytes.
- On commit, **the full `held_minor` becomes `committed_minor`** (`committed_minor
  = held_minor`). There is **no PARTIAL settlement in prepaid v1**.
- A terminal ALLOW is **fully settled at commit**; it is **not** "unsettled" and is
  **not** "frozen awaiting later settlement." (Freezing applies only to
  *uncertain* outcomes, §11.3, never to a completed terminal ALLOW.)
- Caller-supplied `actual_*` **MUST NOT** reduce settlement (§2). `actual_minor` /
  `released_delta_minor` remain nullable, non-authoritative schema reservations
  for a future metered mode (§2 deferred) and **MUST** be unused in prepaid v1.

### 11.2 Transaction boundary

The terminal decision **MUST** atomically write, in **one SQLite transaction**:
(a) the `execution_id` terminal state, (b) the budget commit-or-release, (c) the
authoritative receipt bytes, and (d) the token-row conditional update (§9). A
failed budget commit **MUST** block the terminal ALLOW response. Split state (one
authority persisted without the other) **MUST** be impossible.

### 11.3 Ambiguity must FREEZE, not release

RELEASE is permitted **only** when the system can **prove** no budget-consuming
action occurred (crash provably before any irreversible execution *and* before the
commit transaction). If it is **unknown** whether a consuming action fired,
recovery **MUST** transition the reservation to **`RECOVERY_REQUIRED`** (a.k.a.
`FROZEN`): the hold is preserved, further spending against the token is blocked,
and the reservation is resolved to `COMMITTED` or `RELEASED` **only** by
authenticated reconciliation (§12). Blind release under uncertainty is a latent
**overspend** and is **prohibited**. Fail-closed here means **freeze and
reconcile**, never auto-refund.

**Recovery table:**

| Crash point | `execution_id` | reservation | Receipt | Recovery |
|---|---|---|---|---|
| before dispatch — no irreversible action possible, before commit tx | INFLIGHT | PENDING_HOLD | none | **provably** no consumption → RELEASE hold |
| dispatched; unknown whether the consuming action fired; commit tx not durable | INFLIGHT/unknown | PENDING_HOLD → **RECOVERY_REQUIRED** | none | **FREEZE**: preserve, block token, reconcile (§12) |
| commit tx durably applied | ALLOWED | **COMMITTED** | persisted | replay-safe; nothing to do |
| after tx, before response | ALLOWED | COMMITTED | persisted | idempotent re-send of receipt |

---

## PART IV — PROTOCOLS

## 12. Executor one-shot release protocol — D5

**Decision: RATIFIED (2026-07-26).**

Execution authority is a **one-shot release artifact**, distinct from a receipt.
A receipt is *evidence of a past decision*; it is **NOT** execution authority.

The release artifact **MUST** be signed by the authority and **MUST** bind:

```
ReleaseArtifact = {
  release_id (unique, single-use), execution_id, request_hash,
  actor (authenticated principal), budget_token, token_generation,
  target_executor_or_class, policy_hash, pricing_basis (cost_basis_ref),
  authorized_maximum_minor, issued_at, expiry
}
```

Issuance:

- A release artifact **MUST** be issued **only** in the same terminal-ALLOW
  transaction that commits the hold (§11.1) — i.e., **after** final authority
  commit, never before.

Executor obligations — an executor **MUST** accept a release artifact only if all
hold:

- signature valid; `expiry` not passed (authenticated timeline, §16);
- `release_id` not previously consumed (one-shot);
- `request_hash` matches the request the executor is about to run;
- `actor` and `target_executor_or_class` match the executing context;
- `token_generation` is current (not revoked, §8);
- the referenced execution has a committed terminal ALLOW.

Executors **MUST** reject:

- **cached terminal receipts presented as execution authority**;
- reused/replayed release artifacts (`release_id` already consumed);
- mismatched `request_hash`;
- mismatched `actor` or `target`;
- expired artifacts;
- artifacts whose `token_generation` has been revoked;
- any execution attempted **before** final authority commit.

**Direct execution outside this protocol is outside MNDe's guarantee.** MNDe
makes no authority or conservation claim over actions taken without a valid,
fresh, execution-bound release artifact.

## 13. Replay & execution identity — D15

**Decision: RATIFIED (2026-07-26).**

- There **MUST** be **one globally authoritative execution record** per execution,
  keyed by `execution_id`.
- `execution_id` **MUST** be either globally unique or drawn from a
  cryptographically authenticated namespace (`H(namespace ‖ issuer ‖ …)`); a bare
  caller-chosen string in a shared namespace is **NOT** acceptable.
- Every reservation **MUST** reference the authoritative execution record.

Idempotency / replay semantics (evaluated atomically with request-hash comparison):

| Presented | Required behavior |
|---|---|
| same `execution_id` + same `request_hash` + terminal state | **Return stored terminal information only; MUST NOT execute again.** |
| same `execution_id` + **different** `request_hash` | **Reject** (collision / forgery). |
| same `execution_id` + INFLIGHT or RECOVERY_REQUIRED | **Reject**, or return the defined non-executable status; **MUST NOT** start a second execution. |
| same `execution_id` + a **different** budget token | **Reject**, unless explicitly defined as the same authoritative execution record. |

Cached-response semantics **MUST** be coupled atomically with `request_hash`
comparison in the same transaction that reads execution state; a cached ALLOW
**MUST NOT** be returned without confirming `request_hash` equality, and a cached
ALLOW **is not** execution authority (§12).

## 14. Revocation & expiry semantics

See §8 (generation, linearization, race table) and §16 (timeline). Normatively:
revocation stops future holds, preserves committed history, and freezes uncertain
in-flight holds (D3, §16 below). Expiry is enforced, not descriptive (§8).

## 15. Crash recovery — D12

**Decision: RATIFIED (2026-07-26).**

Fail-closed rule (retained): **unknown outcomes preserve authority and MUST NOT
auto-release it** (§11.3).

- **Permitted recovery evidence** — only **authenticated** evidence bound to the
  execution may resolve a `RECOVERY_REQUIRED` reservation: a signed executor
  completion/non-execution attestation, a committed authoritative receipt, or a
  signed release-artifact-consumption record. **Unauthenticated logs MUST NOT
  release uncertain capacity.**
- **Evidence authentication & binding** — evidence **MUST** be signed by an
  approved authority and **MUST** bind `execution_id` and `request_hash`
  (and, where relevant, `release_id`); unbound evidence **MUST** be rejected.
- **Evidence priority** — committed authoritative receipt > signed release-consumption
  record > signed executor attestation. Higher-priority evidence wins on conflict.
- **Recovery authority & ownership** — reconciliation is a `recovery-admin`
  operation (§5) executed by the authority owner (§6).
- **Exclusive recovery lease** — a reservation under recovery **MUST** be held
  under an exclusive lease (or a dedicated generation/`event_sequence` guard) so
  two reconcilers cannot both resolve it.
- **Reconciliation transaction & idempotency** — resolution **MUST** be a single
  conditional transaction (§9); re-running it **MUST** be idempotent (no double
  commit/release).
- **Terminal recovery outcomes** — `COMMITTED` (proven consumption) or `RELEASED`
  (proven non-consumption).
- **Permanent uncertainty** — if authenticated evidence is unobtainable, the
  reservation **MUST** remain `FROZEN` (capacity stays out of circulation);
  the authority **MUST** raise operator escalation and **MUST NOT** auto-resolve.
- **Replacement-token procedure** — to restore the owner's spendable capacity
  without releasing uncertain funds, an `issuer-admin` **MAY** issue a
  **replacement token** for the frozen amount under audit; the frozen reservation
  stays frozen and reconciles independently.
- **Observability** — every FROZEN reservation, its age, and escalation status
  **MUST** be observable (metric + audit event).

---

## PART V — NORMATIVE STATE MACHINES (D-SM)

**Decision: RATIFIED (2026-07-26).** Common rules:

- Every transition executes under the token-row conditional predicate (§9) unless
  it does not touch a token (noted per machine).
- **Terminal states are immutable except through the separately authenticated
  administrative correction procedure** (§5); no normal transition may leave a
  terminal state.
- **Duplicate/retry:** unless stated, a retried transition that observes the
  destination already reached **MUST** be a no-op returning the stored result
  (idempotent); a retry observing a changed generation/sequence **MUST** abort.
- Any transition not listed is **prohibited**.

Each transition below lists: **from → to** | **event** | **auth inputs** |
**preconditions** | **transactional predicate** | **balance Δ** | **generation Δ**
| **emitted** | **duplicate/retry** | **prohibited**.

### SM1 — Budget-token state machine

States: `ACTIVE` (initial after issue), `EXPIRED` (terminal), `REVOKED` (terminal).

1. `∅ → ACTIVE` | **issue** | issuer-admin principal, owner principal, currency,
   cap, expiry, pricing scope | owner authenticated; cap ≥ 0; unique `token_id` |
   insert row if absent | set `available=cap`, others 0 | `generation=1` |
   `token_issued` receipt+event | retry with same `token_id` → no-op return existing |
   prohibited: issue with unauthenticated owner / bearer.
2. `ACTIVE → REVOKED` | **revoke** | revocation-admin | token ACTIVE | conditional
   on `(generation, sequence)` | `available → revoked` (moves remaining available
   to `revoked`); `held` frozen per §16 | `generation += 1` | `token_revoked` |
   duplicate revoke → no-op | prohibited: reducing `committed`.
3. `ACTIVE → EXPIRED` | **expiry_applied** (authenticated timeline) | timeline
   witness | `now ≥ expiry` | conditional | `available → revoked`-equivalent
   (blocked for new holds); live holds per §8 | `generation += 1` | `expiry_applied`
   | idempotent | prohibited: new holds after EXPIRED.
4. Terminal `REVOKED`/`EXPIRED` → any | **prohibited** except §5 admin correction.

### SM2 — Reservation state machine

States: `PENDING_HOLD` (initial), `COMMITTED` (terminal), `RELEASED` (terminal),
`RECOVERY_REQUIRED` (frozen, non-terminal until reconciled).

1. `∅ → PENDING_HOLD` | **hold** | AuthTuple (§6) | token ACTIVE; not expired;
   `owner_actor_id` matches; pricing valid (§4); `available ≥ worst_case_charge` |
   `UPDATE … WHERE generation=? AND sequence=? AND available ≥ cost` |
   `available -= cost; held += cost` | `sequence += 1` | `hold_created` +
   `h_after` | retry same `(token,execution_id)` in PENDING_HOLD → no-op return |
   prohibited: hold on REVOKED/EXPIRED; hold exceeding available.
2. `PENDING_HOLD → COMMITTED` | **terminal_allow** | AuthTuple + terminal decision
   | execution terminal ALLOW in same tx; generation current | conditional |
   `held -= cost; committed += cost` (full amount) | `sequence += 1` |
   `hold_committed` receipt + `release_artifact` (§12) | idempotent (return stored
   receipt) | prohibited: partial commit; commit after REVOKED linearized first
   (→ RECOVERY_REQUIRED).
3. `PENDING_HOLD → RELEASED` | **terminal_refuse_proven** | AuthTuple + proof of
   non-consumption | terminal REFUSE with proven non-consumption | conditional |
   `held -= cost; available += cost` | `sequence += 1` | `hold_released` | idempotent
   | prohibited: release under uncertainty.
4. `PENDING_HOLD → RECOVERY_REQUIRED` | **uncertain_outcome** | crash/timeout signal
   | consumption unproven | conditional | `held -= cost; frozen += cost` |
   `sequence += 1` | `recovery_required` | idempotent | prohibited: release.
5. `RECOVERY_REQUIRED → COMMITTED` | **reconcile_consumed** | authenticated evidence
   (§15) + recovery lease | proven consumption | conditional | `frozen -= cost;
   committed += cost` | `sequence += 1` | `recovery_resolved(committed)` | idempotent
   under lease | prohibited: resolution without authenticated evidence.
6. `RECOVERY_REQUIRED → RELEASED` | **reconcile_not_consumed** | authenticated
   evidence + lease | proven non-consumption | conditional | `frozen -= cost;
   available += cost` | `sequence += 1` | `recovery_resolved(released)` | idempotent |
   prohibited: release on unauthenticated logs.
7. `RECOVERY_REQUIRED` (permanent uncertainty) → stays FROZEN; escalate (§15).

### SM3 — Execution state machine

States: `NONE`, `INFLIGHT`, `ALLOWED` (terminal), `REFUSED` (terminal),
`RECOVERY_REQUIRED`.

1. `NONE → INFLIGHT` | **begin** | AuthTuple | unique `execution_id`; request_hash
   recorded | insert execution record | — | — | `execution_begin` | duplicate id →
   §13 table | prohibited: reuse across tokens (§13).
2. `INFLIGHT → ALLOWED` | **commit_allow** | AuthTuple + reservation COMMITTED |
   same tx as reservation commit (§11.2) | conditional | — | — | terminal receipt +
   release artifact | idempotent (return stored) | prohibited: allow without
   reservation commit.
3. `INFLIGHT → REFUSED` | **commit_refuse** | AuthTuple | terminal refuse | conditional
   | reservation released/frozen per §11.3 | — | refuse receipt | idempotent |
   prohibited: refuse after allow.
4. `INFLIGHT → RECOVERY_REQUIRED` | **crash_uncertain** | recovery signal | unproven
   | conditional | reservation → RECOVERY_REQUIRED | — | `recovery_required` | idempotent.
5. `RECOVERY_REQUIRED → ALLOWED|REFUSED` | **reconcile** | authenticated evidence
   (§15) | — | conditional | mirrors reservation reconcile | — | resolved receipt |
   idempotent.
6. Terminal `ALLOWED`/`REFUSED` immutable except §5.

### SM4 — Revocation state machine

States: `NONE`, `REVOKE_REQUESTED`, `REVOKED` (terminal for the generation).

1. `NONE → REVOKE_REQUESTED` | **admin_revoke** | revocation-admin | token exists |
   record intent | — | — | `revoke_requested` audit | duplicate → no-op.
2. `REVOKE_REQUESTED → REVOKED` | **commit_revoke** (linearization point) |
   revocation-admin | conditional on `(generation, sequence)` | move `available →
   revoked`; freeze uncertain holds (§16) | `generation += 1` | `token_revoked` |
   idempotent | prohibited: altering committed.

### SM5 — Recovery state machine

States: `FROZEN` (= RECOVERY_REQUIRED), `RECONCILING` (lease held), `RESOLVED_COMMITTED`
(terminal), `RESOLVED_RELEASED` (terminal), `PERMANENT_UNCERTAIN` (escalated, frozen).

1. `FROZEN → RECONCILING` | **acquire_lease** | recovery-admin | no active lease |
   set exclusive lease/guard | — | — | `recovery_lease_acquired` | duplicate → same
   lease holder no-op; different holder → abort.
2. `RECONCILING → RESOLVED_COMMITTED` | **evidence_consumed** | authenticated
   evidence (§15) | proven consumption | conditional | `frozen→committed` | `+=1` |
   `recovery_resolved` | idempotent.
3. `RECONCILING → RESOLVED_RELEASED` | **evidence_not_consumed** | authenticated
   evidence | proven non-consumption | conditional | `frozen→available` | `+=1` |
   `recovery_resolved` | idempotent.
4. `RECONCILING → PERMANENT_UNCERTAIN` | **evidence_unobtainable** | recovery-admin
   + escalation | evidence unavailable | conditional | stays frozen | — |
   `recovery_escalated` | idempotent | prohibited: release.
5. Lease expiry returns `RECONCILING → FROZEN` (no state resolution without evidence).

### SM6 — Release-capability (artifact) state machine

States: `ISSUED`, `CONSUMED` (terminal), `EXPIRED` (terminal), `INVALIDATED` (terminal).

1. `∅ → ISSUED` | **issue_release** | terminal-ALLOW tx (§12) | reservation COMMITTED
   | same tx as commit | — | — | signed `ReleaseArtifact` | idempotent (same
   `release_id`) | prohibited: issue before commit.
2. `ISSUED → CONSUMED` | **executor_consume** | executor presents artifact | valid,
   fresh, bound (§12); `release_id` unconsumed | conditional single-use claim on
   `release_id` | — | — | `release_consumed` | duplicate consume → reject (one-shot) |
   prohibited: reuse.
3. `ISSUED → EXPIRED` | **expiry** | timeline | `now ≥ expiry` | conditional | — | — |
   `release_expired` | idempotent.
4. `ISSUED → INVALIDATED` | **generation_revoked** | revoke bumps `token_generation`
   | artifact generation stale | conditional | — | — | `release_invalidated` |
   idempotent | prohibited: consume after invalidation.

### SM7 — Receipt / event state machine

States: `DRAFT` (in-tx), `COMMITTED` (terminal, immutable), `PUBLISHED`
(outbox-delivered), `CHECKPOINTED` (in a signed checkpoint).

1. `DRAFT → COMMITTED` | **authority_tx_commit** | inside the authoritative tx
   (§11.2) | tx commits | same tx | — | `sequence += 1` | immutable receipt/event
   bytes + `h_after` | idempotent (same `event_sequence`) | prohibited: mutate after
   COMMITTED.
2. `COMMITTED → PUBLISHED` | **outbox_deliver** | outbox worker (§16) | event
   COMMITTED | outbox conditional | — | — | external projection/Merkle leaf |
   at-least-once → dedup by `event_sequence` | prohibited: publish uncommitted.
3. `PUBLISHED → CHECKPOINTED` | **checkpoint_sign** | checkpoint authority | included
   in signed checkpoint | — | — | — | signed checkpoint entry | idempotent |
   prohibited: checkpoint unpublished/uncommitted.

Deterministic per-token ordering is the strictly increasing `event_sequence`
(§9); receipts/events for one token **MUST** form one linear chain via
`current_state_hash`.

---

## PART VI — EVENTS, RECEIPTS & VERIFICATION

## 16. Ledger, transactional outbox & publication — D16

**Decision: RATIFIED (2026-07-26).**

- **SQLite is the sole authoritative transaction store.** Execution state, budget
  state, canonical event data, and authoritative receipt bytes **MUST** be written
  in the **same** authoritative transaction (§11.2).
- A **transactional outbox** (a table written in that same transaction) **MUST**
  drive all secondary publication: Merkle publication, external ledger export,
  filesystem projection, and checkpoint publication. A filesystem append or
  external write **MUST NOT** be presented as participating in the SQLite
  transaction.
- **Outbox semantics:** delivery is **at-least-once**; consumers **MUST** dedup by
  `event_sequence`; publication order **MUST** follow `event_sequence` per token;
  failed deliveries **MUST** retry with backoff and **MUST NOT** drop events.
- **Proof-availability status** is a first-class, observable field: an event may be
  `COMMITTED` but not yet `PUBLISHED`/`CHECKPOINTED`.
- **Proof publication MUST NOT block an ALLOW response.** An ALLOW depends only on
  the authoritative SQLite transaction; Merkle/checkpoint publication is
  asynchronous. Verifiers requiring proof **MUST** consult proof-availability
  status.

### 16.1 Timeline / revocation / expiry (D3 + D16 timeline)

Revocation and expiry are ordered by the authenticated timeline: the per-token
`event_sequence` provides total local order; cross-token/global order is provided
by signed checkpoints (§17). "Before/after revocation" means **event-order**
relative to the linearization point (§8), not wall-clock. Wall-clock `expiry` is
enforced against an authenticated time source; where only ordering is available,
expiry **MUST** be enforced at the next authenticated timeline observation and
**MUST** fail closed in the interim (no new holds on a token whose expiry cannot be
evaluated).

## 17. Verification & proof model — D13 (claims narrowed)

**Decision: RATIFIED (2026-07-26).** Claims are narrowed to what the mechanism
supports. **Overclaims removed.**

**Defensible v1 claims (normative):**

- The authority is **correct across supported threads and processes sharing the
  one authoritative local database** (§1) — **not** "correct across all executors"
  and **not** across hosts.
- **Historical signature integrity is offline-verifiable relative to supplied
  trust roots and the stated validation context** — **not** "offline, eternal."
  Signature checks require the trust roots and the validity context (issuer key
  sets, validity windows) as inputs.
- **Current authority (remaining balance, not-revoked, not-expired) requires
  timeline, revocation, expiry, and checkpoint evidence** — a Merkle inclusion
  proof alone **does not** prove remaining balance or that no later spend exists.
- The history is **append-only relative to a witnessed signed checkpoint** — not
  "append-only" without qualification.
- Conserved-authority legitimacy is **verifiable relative to an externally trusted
  signed checkpoint**, not "without the operator's word" in the absolute.

**Checkpoint machinery (normative requirements; see deferral note):**

- **Signed checkpoints** — the authority **MUST** periodically emit a checkpoint
  signing `(checkpoint_sequence, per_token_latest_state_root, global_root, time)`.
- **Checkpoint sequence numbers** **MUST** be monotonic; a verifier **MUST** reject
  a checkpoint with a sequence ≤ its last trusted checkpoint (stale/rollback).
- **Trusted checkpoint acquisition** — verifiers **MUST** obtain checkpoints from a
  trusted distribution channel (out of band from the operator's live claims).
- **Consistency proofs** — between checkpoints the authority **MUST** provide an
  append-only consistency proof; a verifier **MUST** reject inconsistent histories.
- **Fork detection** — two signed checkpoints with the same sequence and different
  roots **MUST** be treated as a fork (fail closed, escalate).
- **Per-token latest-state proof** — a verifier **MUST** be able to obtain, for a
  token at a trusted checkpoint, a proof of its latest state and that **no later
  spend exists at that checkpoint** (via `event_sequence` + latest-state root).
- **Stale-checkpoint rejection** — verification against an old checkpoint **MUST**
  be labeled as such; current-authority decisions **MUST NOT** rely on stale
  checkpoints.

**Deferral (explicit):** the **full transparency-log / external witness / consistency-proof
system is DEFERRED beyond v1** (§23). Until it ships, v1 **MUST NOT** claim
third-party verification "without the operator's word"; v1 verification is
**operator-attested via signed checkpoints**, and the stronger independent-witness
claims are removed from this document until the mechanism exists.

## 18. Event & receipt taxonomy — D20

**Decision: RATIFIED (2026-07-26).**

Every authority-changing event **MUST** be recorded as an immutable event with a
per-token `event_sequence` and chained `current_state_hash`. Classification:

| Event | Signed receipt | Immutable event | Merkle leaf | Externally visible proof |
|---|---|---|---|---|
| `token_issued` | ✓ | ✓ | ✓ | via checkpoint |
| `hold_created` | ✓ | ✓ | ✓ | via checkpoint |
| `hold_rejected` | — | ✓ | ✓ | via checkpoint |
| `execution_released` (release artifact) | ✓ | ✓ | ✓ | via checkpoint |
| `hold_committed` | ✓ | ✓ | ✓ | via checkpoint |
| `hold_released` | ✓ | ✓ | ✓ | via checkpoint |
| `token_revoked` | ✓ | ✓ | ✓ | via checkpoint |
| `expiry_applied` | — | ✓ | ✓ | via checkpoint |
| `recovery_required` | — | ✓ | ✓ | via checkpoint |
| `recovery_resolved` | ✓ | ✓ | ✓ | via checkpoint |
| `child_authority_issued` | ✓ | ✓ | ✓ | via checkpoint |
| `child_authority_reclaimed` | ✓ | ✓ | ✓ | via checkpoint |
| `administrative_correction` | ✓ (dual-signed) | ✓ | ✓ | via checkpoint |

- Events **MUST** be totally ordered per token by `event_sequence`.
- Terminal receipts are immutable (SM7); corrections append a new
  `administrative_correction` event, they **MUST NOT** mutate prior receipts.

### 18.1 Conserved receipts as chained state-transition proofs

For a budget token, receipt `n` commits to pre-/post-state:

```
R_n = Sign_k( Canon[ e, g, p, h_before, h_after, o, π ] )
    where  h_after = δ(h_before, e)
           h_before(R_{n+1}) == h_after(R_n)   for the same token
```

- `e` canonical execution; `g` grant id + content hash; `p` authority-path
  commitment; `h_before/h_after` authenticated state commitments; `o` outcome
  (prepaid v1: ALLOW/REFUSE, committed = held); `π` inclusion reference into the
  outbox-published Merkle root **relative to a signed checkpoint** (§17).

Verification regimes (claims per §17):

| Regime | Verifies | Requires |
|---|---|---|
| **Stateless** `V_s` | signature integrity, canonical action, containment, delegation narrowing, policy-hash equality | supplied trust roots + validation context (not "eternal") |
| **Ledger-relative** `V_ℓ` | remaining budget, sibling allocation, hold/commit state, replay | authenticated history commitment at a trusted checkpoint |
| **Timeline** `V_t` | revocation, expiry, ordering | authenticated ordering source + signed checkpoint |

---

## PART VII — DELEGATION, MIGRATION

## 19. Strict reservation & delegation backing — D2 (extended)

**Decision: RATIFIED (2026-07-26).**

- Every object accepted as **spend authority MUST be fully backed**: for any node
  `u`, `Σ_children C_{u→v}(issued) + C_u^held + C_u^committed ≤ C_u^issued`.
  **Overbooking of authoritative grants is prohibited.**
- Internal, non-authoritative **forecasts MAY** exist but **MUST**: not be called
  "grants"; not authorize spending; not appear in conservation equations as
  committed authority; and **MUST NOT** be accepted at the execution boundary.
- A child grant is itself a token row (§9) with its own generation, backed by a
  reservation against the parent; reclaiming a child returns unspent backing to the
  parent atomically.

## 20. Migration — D18

**Decision: RATIFIED (2026-07-26).**

- **Legacy bearer tokens MUST NOT gain authenticated ownership from caller-supplied
  identity.** They are either invalidated or reissued under an authenticated
  `issuer-admin` assignment.
- **Ownership assignment** during migration **MUST** be an authenticated admin act
  (§5), recorded as an immutable `administrative_correction`/migration event.
- **In-flight requests** at migration **MUST** be drained or failed closed; a
  migration **MUST NOT** silently reinterpret an in-flight legacy hold as an owned
  hold.
- **Receipt & API versioning** — receipts and APIs **MUST** carry a version; mixed
  legacy/new deployments **MUST** be explicitly supported or refused, never
  ambiguously mixed.
- **Downgrade prevention** — after migration to an owned-authority schema, the
  authority **MUST** refuse to start against an older schema/state (rollback
  detection, §10, §17).
- **Migration authorization & audit** — migrations run under `migration-admin`
  with SoD (§5), under the exclusive migration lock (§10), and emit immutable
  audit records.
- **Rollback behavior** — a migration **MUST** be transactional; a failed
  migration **MUST** leave the prior consistent state, never a partial mix.

---

## PART VIII — CONFORMANCE, PR METADATA, READINESS

## 21. Conformance — normative hostile test matrix — D-Conf

**Decision: RATIFIED (2026-07-26).** Every ratified invariant **MUST** map to at
least one required test. Tests are specified here; **no test code is written in
this branch** (§22). Implementation **MUST** provide at least these tests:

| # | Hostile scenario | Asserted invariant | Maps to |
|---|---|---|---|
| C01 | simultaneous holds across threads | no overspend; one linear history | §9 |
| C02 | simultaneous holds across processes (same DB) | no overspend | §1, §9 |
| C03 | hold vs revoke | §8.1 resolution | §8 |
| C04 | release vs revoke | correct bucket order | §8 |
| C05 | commit vs revoke | commit-before-revoke stands; else RECOVERY | §8 |
| C06 | expiry races (hold/release/commit) | §8.1 rows | §8 |
| C07 | duplicate finalization | idempotent commit | SM2 |
| C08 | conflicting request hashes (same exec_id) | reject | §13 |
| C09 | execution-ID reuse across tokens | reject | §13 |
| C10 | crash before hold | no state, no leak | §11.3 |
| C11 | crash after hold, before commit | RECOVERY_REQUIRED (freeze) | §11.3 |
| C12 | crash before receipt write | atomic; no split state | §11.2 |
| C13 | crash after receipt write, before response | idempotent re-send | §11.3 |
| C14 | crash before response (ALLOW) | committed, replay-safe | §11.3 |
| C15 | recovery concurrency (two reconcilers) | exclusive lease | §15 |
| C16 | stale pricing envelope | refuse | §6 |
| C17 | pricing rollback (lower schedule_version) | refuse | §6 |
| C18 | actor spoofing (copied user_id) | reject; not authenticated | §3 |
| C19 | cross-tenant identity collision | distinct owner_actor_id; reject cross-tenant | §3 |
| C20 | worker/parent tuple substitution | authority re-verifies tuple; no TOCTOU | §6 |
| C21 | release-artifact replay | one-shot reject | §12 |
| C22 | direct executor bypass (no artifact / cached receipt as authority) | rejected; outside guarantee | §12 |
| C23 | database rollback / restore to older state | detected via checkpoint; fail closed | §10, §17 |
| C24 | disk full mid-transaction | atomic refuse; no partial apply | §10 |
| C25 | DB corruption at startup | fail closed | §10 |
| C26 | outbox delivery failure | retry; no dropped events; ALLOW not blocked | §16 |
| C27 | duplicate outbox delivery | dedup by event_sequence | §16 |
| C28 | Merkle fork (two roots, same checkpoint seq) | fork detected; fail closed | §17 |
| C29 | stale checkpoint used for current authority | rejected/labeled | §17 |
| C30 | integer overflow in charge calc | refuse | §7 |
| C31 | unsupported multi-host startup | fail closed | §1 |
| C32 | network filesystem (NFS/SMB) startup | fail closed | §1, §10 |
| C33 | migration + downgrade attempt | refuse downgrade; transactional | §20 |
| C34 | bearer token presented to durable authority | reject | §3, §20 |
| C35 | metered/`actual_*` used to reduce settlement in prepaid | ignored; full held committed | §2, §11.1 |

## 22. Non-goals & implementation boundary

- **No runtime code changes on this branch.** This is a specification.
- Does not re-open PR #4's correctness fix; it is the foundation.
- **No test code is written here**; §21 specifies required tests for implementation.
- Does not define final SQLite DDL/indexes or operational tuning (§23).
- **This document does not authorize implementation.** Implementation is gated on
  §24 and PR #4 (§25).

## 23. Explicitly deferred beyond v1

- **Metered settlement** (authenticated usage meter) — §2. Prepaid only in v1.
- **Multidimensional conserved authority** (`k > 1`) — §7. One monetary dimension
  in v1.
- **Full external transparency-log / independent-witness verification** — §17. v1
  is operator-attested signed checkpoints; stronger independent claims removed
  until the mechanism ships.
- **Cross-currency conversion** — §7.
- **Active-active multi-host / replicated authority** — §1.
- **Cross-organization delegation & risk-budget dimensions** — beyond naming.
- **Concrete SQLite DDL, indexes, and performance tuning** — §10.

Deferred features **MUST NOT** be presented anywhere as current guarantees.

## 24. Implementation-readiness checklist

**Documentation completeness** (each required normative section present):

- [x] Deployment scope (§1)
- [x] Authenticated cost basis D0 (§2)
- [x] Authenticated principal model (§3)
- [x] Pricing authority envelope (§4)
- [x] Administrative authority & SoD (§5)
- [x] Parent/worker boundary & canonical tuple (§6)
- [x] Numeric model, cents-only (§7)
- [x] Token generation, expiry, anti-rollback, race table (§8)
- [x] Per-token serialization & authoritative row (§9)
- [x] SQLite minimum security profile (§10)
- [x] Storage/transaction model; prepaid full-commit; no PARTIAL; freeze-on-uncertainty (§11)
- [x] Executor one-shot release protocol (§12)
- [x] Replay & execution identity (§13)
- [x] Revocation & expiry semantics (§8, §14, §16.1)
- [x] Crash recovery evidence model (§15)
- [x] Seven normative state machines (SM1–SM7)
- [x] Ledger, transactional outbox, publication (§16)
- [x] Verification & proof model; claims narrowed (§17)
- [x] Event & receipt taxonomy (§18)
- [x] Strict reservation & delegation backing (§19)
- [x] Migration policy (§20)
- [x] Conformance hostile-test matrix (§21)
- [x] Deferred-features list (§23)
- [x] Decision log complete (Decision status, below)

**Documentation gate:** **PASS** — all required normative sections exist and are
internally consistent as of this revision.

**Release gates (external, still OPEN — implementation remains BLOCKED):**

- [ ] PR #4 merged (dependency, §25).
- [ ] Architectural sign-off on the ratified D4 substrate and the state machines.
- [ ] Implementation, tests (§21), and audit — **not started**.

**Overall implementation-readiness verdict:** **BLOCKED.** The specification is
documentation-complete and internally consistent (documentation gate PASS), but
implementation is **not authorized**: it is gated on PR #4 landing, architectural
sign-off, and a build+test cycle that has not begun. No runtime implementation has
started.

## 25. PR dependency & metadata — D21

- **PR #5 MUST remain dormant until PR #4 is resolved.** PR #5 (this spec) depends
  on PR #4 (`fix/budget-token-hold-finalization`), which establishes the
  hold/commit/release foundation.
- **After PR #4 lands**, the maintainer **MUST**: rebase PR #5 onto the resulting
  `main`, re-read the resulting document, re-run all consistency checks (§26), and
  verify no foundation language became stale.
- The PR #5 description **MUST** state: D0–D4 (and the D5–D21 rulings herein) are
  ratified; the decision log exists; implementation remains blocked; PR #4 remains
  a dependency; no runtime implementation has started.

## 26. Editing & validation rules applied

- Preserved useful existing material (calculus, D0–D4 rulings, decision log,
  receipt-chain); expanded rather than rewritten from scratch.
- Removed stale/contradictory language: prepaid `PARTIAL`; "released ALLOW remains
  frozen awaiting settlement"; `ℝ^k` vs cents; "correct across all executors";
  "offline, eternal"; "without the operator's word" (absolute); unqualified
  "append-only".
- Normative MUST / MUST NOT / SHOULD / MAY used consistently.
- Ratified v1 behavior separated from deferred future work (§23).
- No deferred feature is presented as a current guarantee.
- Dated decision-log entries added for every newly ratified choice (below).

---

## Decision status

| # | Decision | Status | Ruling |
|---|---|---|---|
| D0 | Authenticated cost basis | **RATIFIED** | authenticate actor and price; authenticated usage required before metered settlement |
| D1 | Prepaid vs metered | **RATIFIED** | prepaid now (full hold committed in terminal-ALLOW tx, no PARTIAL); metered deferred |
| D2 | Strict reservation vs overbooking | **RATIFIED** | strict, fully backed; overbooking prohibited (§19) |
| D3 | Revocation semantics | **RATIFIED** | stop future holds; preserve committed; freeze uncertain (§8, §16.1) |
| D4 | Atomic shared `hold()` | **RATIFIED** | parent-owned shared SQLite authority; hold is the atomic boundary |
| D5 | Executor one-shot release protocol | **RATIFIED** | signed single-use release artifact; receipts are not authority (§12) |
| D6 | Pricing authority envelope | **RATIFIED** | signed pricing schedule; caller price untrusted; anti-rollback (§4) |
| D7 | Authenticated principal model | **RATIFIED** | principal tuple; owner_actor_id derivation; tenant isolation; no bearer (§3) |
| D8 | Administrative authority & SoD | **RATIFIED** | authenticated admin roles; SoD; spend ≠ admin (§5) |
| D9 | Parent/worker boundary | **RATIFIED** | authority re-verifies canonical tuple; no TOCTOU (§6) |
| D10 | Token generation & anti-rollback | **RATIFIED** | monotonic generation; revocation linearization; enforced expiry (§8) |
| D11 | Per-token serialization | **RATIFIED** | authoritative row; optimistic (generation, sequence); anti-fork (§9) |
| D12 | Crash recovery | **RATIFIED** | authenticated evidence only; exclusive lease; permanent-uncertainty freeze (§15) |
| D13 | Verification & proof claims | **RATIFIED** | claims narrowed; checkpoint machinery; transparency-log deferred (§17) |
| D14 | Deployment scope | **RATIFIED** | one host, one SQLite, local FS; no multi-host/NFS/SMB (§1) |
| D15 | Replay & execution identity | **RATIFIED** | one authoritative execution record; cached-response coupled to request_hash (§13) |
| D16 | Ledger & transactional outbox | **RATIFIED** | SQLite authoritative; outbox for publication; proof never blocks ALLOW (§16) |
| D17 | Numeric model | **RATIFIED** | single monetary dimension, checked integer minor units (§7) |
| D18 | Migration | **RATIFIED** | no bearer→owned via caller identity; authenticated, audited, downgrade-blocked (§20) |
| D19 | SQLite security profile | **RATIFIED** | permissions, symlink, WAL, fail-closed startup, no silent recreate (§10) |
| D20 | Event & receipt taxonomy | **RATIFIED** | enumerated events; per-token ordering; immutable receipts (§18) |
| D21 | PR dependency & metadata | **RATIFIED** | PR #5 dormant until PR #4; rebase/recheck after (§25) |
| P | Owned-token provisioning mechanism | Implementation design | provisioning and enforcement must ship together (§3, §5) |
| R | Replay-hash comparison | Deferred prerequisite | land atomically with cached-response retry semantics (§13) |

### Decision log

| Date | Decision | Ruling | Rationale |
|---|---|---|---|
| 2026-07-26 | D0 — Authenticated cost basis | Ratified | An unauthenticated price or usage claim lets the spender choose its own charge. |
| 2026-07-26 | D1 — Settlement | Ratified: prepaid now, no PARTIAL; metered later | Prepaid enforceable with authenticated pricing; metered needs authenticated usage. |
| 2026-07-26 | D2 — Reservation | Ratified: strict, fully backed | A conserved security limit cannot rely on overbooking. |
| 2026-07-26 | D3 — Revocation/uncertainty | Ratified: freeze uncertain holds | Capacity that may be consumed cannot return to circulation. |
| 2026-07-26 | D4 — Durable ownership | Ratified: parent-owned shared SQLite | Atomic holds prevent cross-worker overspend and split state. |
| 2026-07-26 | D5 — Executor release protocol | Ratified: one-shot signed artifact | A receipt is evidence, not execution authority; prevents replay/bypass. |
| 2026-07-26 | D6 — Pricing authority | Ratified: signed envelope, anti-rollback | Caller-chosen price defeats the cap; price must be authenticated. |
| 2026-07-26 | D7 — Principal model | Ratified: authenticated tuple, no bearer | A copied user_id is not authentication; tenants must isolate. |
| 2026-07-26 | D8 — Admin authority | Ratified: roles + SoD | Spending must never confer administrative power. |
| 2026-07-26 | D9 — Parent/worker boundary | Ratified: authority re-verifies tuple | Worker output is untrusted; close the TOCTOU gap. |
| 2026-07-26 | D10 — Generation/anti-rollback | Ratified: monotonic generation | Revocation/expiry must be enforced, ordered, and rollback-proof. |
| 2026-07-26 | D11 — Per-token serialization | Ratified: optimistic concurrency | One linear history per token; no forks. |
| 2026-07-26 | D12 — Crash recovery | Ratified: authenticated evidence only | Never release uncertain capacity on unauthenticated logs. |
| 2026-07-26 | D13 — Verification claims | Ratified: narrowed + checkpoints; TL deferred | Claim only what the mechanism supports. |
| 2026-07-26 | D14 — Deployment scope | Ratified: single host/DB, local FS | Correctness is scoped to one authoritative database. |
| 2026-07-26 | D15 — Execution identity | Ratified: one authoritative record | Prevent replay and cross-token execution reuse. |
| 2026-07-26 | D16 — Ledger/outbox | Ratified: outbox; proof async | FS/external writes cannot join a SQLite transaction. |
| 2026-07-26 | D17 — Numeric model | Ratified: cents-only checked integers | Remove float/`ℝ^k` contradiction; overflow fails closed. |
| 2026-07-26 | D18 — Migration | Ratified: authenticated, no bearer uplift | Legacy tokens must not gain ownership from caller identity. |
| 2026-07-26 | D19 — SQLite security | Ratified: fail-closed profile | Local, permissioned, corruption/rollback-detecting store. |
| 2026-07-26 | D20 — Event taxonomy | Ratified: enumerated, ordered, immutable | Deterministic per-token event order and immutable receipts. |
| 2026-07-26 | D21 — PR metadata | Ratified: dormant until PR #4 | Keep the fix and the design reviewable independently. |
