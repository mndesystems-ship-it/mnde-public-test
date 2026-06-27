# Execution Request v1 — `mnde.execution_request.v1`

## Purpose

`mnde.execution_request.v1` is the MNDe schema for deploy-pipeline execution
requests. It turns MNDe from an AI-shaped gate into a general execution firewall
for deploy pipelines. A caller submits a structured execution request describing
the action, actor, target resource, environment, risk, cost, approval status, and
evidence. The execution gate validates the request, applies hard-coded policy
gates, and returns a deterministic, tamper-evident receipt.

The receipt is reproducible: given the same request the gate always produces the
same decision and the same `receipt_hash`. This makes offline replay and audit
straightforward.

## Schema

Schema version string: `mnde.execution_request.v1`

## Required Fields Table

| Field | Type | Description |
|---|---|---|
| `schema_version` | `"mnde.execution_request.v1"` | Identifies the schema. Any other value is rejected. |
| `execution_id` | string | Caller-assigned unique ID for this execution attempt. |
| `requested_at` | ISO-8601 datetime with timezone | When the request was created. Used as `decided_at` in the receipt to keep the receipt deterministic. |
| `action` | object | See below. |
| `principal` | object | See below. |
| `resource` | object | See below. |
| `environment` | object | See below. |
| `risk` | object | See below. |
| `cost` | object | See below. |
| `approval` | object | See below. |
| `evidence` | object | See below. |

### action

| Field | Type | Notes |
|---|---|---|
| `type` | `"deploy"` \| `"migrate"` \| `"rollback"` \| `"promote"` | Required. |
| `name` | string | Human-readable action name. Required. |
| `command` | string | Optional. Raw command string. |
| `dry_run` | boolean | Required. |

### principal

| Field | Type | Notes |
|---|---|---|
| `id` | string | Required. Actor identifier (GitHub login, service account name, etc.). |
| `type` | `"github_actor"` \| `"service_account"` \| `"ci_runner"` | Required. |
| `issuer` | string | Required. Identity issuer URL or label. |
| `verified` | boolean | Required. If `false`, the gate immediately refuses with `PRINCIPAL_NOT_VERIFIED`. |
| `claims` | object | Required. Caller-supplied identity claims. May be empty. |

### resource

| Field | Type | Notes |
|---|---|---|
| `kind` | `"repo"` \| `"branch"` \| `"environment"` \| `"cluster"` \| `"database"` \| `"service"` | Required. |
| `id` | string | Required. Machine-readable resource identifier. |
| `name` | string | Required. Human-readable resource name. |
| `owner` | string | Optional. |

### environment

| Field | Type | Notes |
|---|---|---|
| `name` | `"dev"` \| `"staging"` \| `"production"` | Required. |
| `region` | string | Optional. |
| `account` | string | Optional. |
| `cluster` | string | Optional. |

### risk

| Field | Type | Notes |
|---|---|---|
| `level` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` | Required. |
| `destructive` | boolean | Required. Triggers `DESTRUCTIVE_REQUIRES_APPROVAL` gate for production. |
| `reversible` | boolean | Required. |
| `touches_secrets` | boolean | Required. |
| `touches_customer_data` | boolean | Required. |
| `blast_radius` | `"local"` \| `"service"` \| `"environment"` \| `"global"` | Required. |

### cost

| Field | Type | Notes |
|---|---|---|
| `estimated_cents` | number | Required. |
| `dimensions` | object | Required. Arbitrary cost breakdown (e.g. `deploy_minutes`, `services_affected`). |

### approval

| Field | Type | Notes |
|---|---|---|
| `required` | boolean | Required. |
| `approval_id` | string | Optional. Must be present for production deploys that are high-risk or destructive. |
| `approver_principal` | string | Optional. |
| `approval_signature` | string | Optional. |

### evidence

| Field | Type | Notes |
|---|---|---|
| `repo` | string | Required. |
| `commit_sha` | string | Required. |
| `branch` | string | Required. |
| `workflow_run_id` | string | Optional. |
| `workflow_url` | string | Optional. |
| `artifact_digest` | string | Optional. |
| `policy_bundle_id` | string | Optional. |
| `policy_bundle_serial` | number | Optional. |

## Deploy Pipeline Examples

### ALLOW: staging deploy

```json
{
  "schema_version": "mnde.execution_request.v1",
  "execution_id": "gh-run-1234-attempt-1",
  "requested_at": "2026-06-26T12:00:00.000Z",
  "action": {
    "type": "deploy",
    "name": "deploy-api",
    "dry_run": false
  },
  "principal": {
    "id": "octocat",
    "type": "github_actor",
    "issuer": "https://token.actions.githubusercontent.com",
    "verified": true,
    "claims": { "repository": "org/api", "ref": "refs/heads/main" }
  },
  "resource": {
    "kind": "service",
    "id": "api-staging",
    "name": "API (staging)"
  },
  "environment": {
    "name": "staging",
    "region": "us-east-1"
  },
  "risk": {
    "level": "low",
    "destructive": false,
    "reversible": true,
    "touches_secrets": false,
    "touches_customer_data": false,
    "blast_radius": "service"
  },
  "cost": {
    "estimated_cents": 50,
    "dimensions": { "deploy_minutes": 3, "services_affected": 1 }
  },
  "approval": { "required": false },
  "evidence": {
    "repo": "org/api",
    "commit_sha": "a1b2c3d4",
    "branch": "main",
    "workflow_run_id": "7890123456"
  }
}
```

Decision: `ALLOW`

### REFUSE: production migration without approval

```json
{
  "schema_version": "mnde.execution_request.v1",
  "execution_id": "gh-run-5678-attempt-1",
  "requested_at": "2026-06-26T12:05:00.000Z",
  "action": {
    "type": "migrate",
    "name": "add-user-index",
    "dry_run": false
  },
  "principal": {
    "id": "deploy-bot",
    "type": "service_account",
    "issuer": "https://iam.example.com",
    "verified": true,
    "claims": {}
  },
  "resource": {
    "kind": "database",
    "id": "users-db-prod",
    "name": "Users DB (production)"
  },
  "environment": {
    "name": "production",
    "region": "us-east-1"
  },
  "risk": {
    "level": "high",
    "destructive": true,
    "reversible": false,
    "touches_secrets": false,
    "touches_customer_data": true,
    "blast_radius": "environment"
  },
  "cost": {
    "estimated_cents": 1500,
    "dimensions": { "database_rows_touched": 5000000, "deploy_minutes": 15 }
  },
  "approval": { "required": true },
  "evidence": {
    "repo": "org/api",
    "commit_sha": "d4e5f6a7",
    "branch": "migrate/user-index"
  }
}
```

Decision: `REFUSE` — `APPROVAL_REQUIRED` (production + high risk + approval required + no `approval_id`)

## Security Boundaries

1. **Validation is strict.** Unknown `schema_version` values are rejected. Unknown enum values are rejected. Missing required fields are rejected. Floats and unsafe integers in `cost.estimated_cents` are passed through (the schema does not restrict number precision, but `canonicalizeJson` in `shared/json.ts` rejects floats — callers should use safe integers).

2. **Canonicalization is deterministic.** The request hash is `sha256(canonicalizeJson(request))` where `canonicalizeJson` sorts object keys and does not emit floats. Identical requests always produce the same hash on any platform.

3. **Receipt is tamper-evident.** `receipt_hash` is `sha256(canonicalizeJson(receipt_body))` where `receipt_body` is the receipt without `receipt_hash` itself. Any field mutation invalidates the hash.

4. **No wall-clock in the deterministic path.** `decided_at` is copied from `requested_at` — not from the system clock — so the receipt is reproducible.

5. **Hard gates are fail-closed.** `PRINCIPAL_NOT_VERIFIED` is checked before all other gates. A gate that fires refuses; it does not fall through.

## Identity Limitation

MNDe does not prove the GitHub actor or service account identity by itself in this slice. It only consumes a verified identity assertion supplied by the caller. Production use still requires a real identity binding layer such as OIDC, SAML, mTLS, or CI-native signed claims. This slice creates the execution schema and policy gate, not full enterprise IAM.

## Offline Verification Behavior

Because the receipt is self-describing and the decision is deterministic, offline verification requires only:

1. The original request (or its canonical form)
2. The receipt

Re-run `replayExecutionGate(receipt, request)`. It recomputes `request_hash` and re-applies all gates. If the hash and decision match the stored receipt the result is `{ ok: true }`.

No network access, no clock dependency, no authority bundle required for basic replay. For receipts issued with a cryptographic signature over the receipt body (future slice), the verifier also checks the signature against the authority bundle.

## How This Differs from `ecs.receipt.v2`

| Dimension | `ecs.receipt.v2` (AI gate) | `mnde.execution_gate.receipt.v1` (deploy gate) |
|---|---|---|
| Request schema | AI tool-call request | Deploy pipeline execution request |
| Policy matching | Deterministic policy engine (rules, attributes) | Hard-coded gates in this slice; attribute map for future policy engine integration |
| Signing | Ed25519 via shared authority bundle | `receipt_hash` (sha256 of canonical body) — no external key required in this slice |
| Replay | Re-runs deterministic policy engine | Re-runs hard-coded gates |
| Identity | AI principal / authority grant | CI principal — OIDC or mTLS required for production |
| Use case | AI pre-execution gate | Deploy-pipeline pre-execution firewall |

The two schemas coexist on the same repository. Adding this schema does not change `ecs.receipt.v2` behavior or any existing test.
