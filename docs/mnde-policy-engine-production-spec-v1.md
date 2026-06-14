# MNDe Policy Engine Production Specification v1.0

Short name: MNDe PE

Status: Production target specification

Implementation status: Defines the intended production behavior for MNDe PE. The public tester currently demonstrates a smaller deterministic policy path; this specification is the target for the production policy engine.

## Purpose

MNDe PE is the deterministic authority evaluation engine inside MNDe.

It decides whether a requested execution has valid authority before the action reaches a tool.

MNDe PE returns one result:

```text
ALLOW
```

or

```text
REFUSE
```

No warning state.

No soft approval.

No agent override.

No tool override.

## Core Definition

MNDe PE evaluates a canonical execution request against:

- active signed policy
- valid authority chain
- known trust anchors
- current environment facts
- execution constraints

It produces:

- decision
- reason code
- policy hash
- authority chain hash
- decision hash
- replay data

MNDe PE does not execute actions.

MNDe PE does not call tools.

MNDe PE does not infer intent.

MNDe PE does not use AI.

MNDe PE does not repair requests.

MNDe PE does not rewrite policy.

## Core Rule

Nothing executes before `ALLOW`.

Everything else is `REFUSE`.

## System Philosophy

MNDe is not only permission checking.

MNDe proves authority existed before execution.

A normal policy engine asks:

```text
Is this action allowed?
```

MNDe PE asks:

```text
Does valid authority exist for this execution request?
```

That means every decision links to:

- who granted authority
- what authority was granted
- where authority came from
- when authority expires
- which policy used it
- why the request passed or failed

This is the MNDe distinction.

Execution control is the outcome.

Authority is the product.

## Required Inputs

MNDe PE requires one canonical evaluation input.

Request object:

```json
{
  "schema_version": "1.0",
  "request_id": "req_01JZ0000000000000000000000",
  "timestamp": "2026-06-14T15:30:00Z",
  "principal": {
    "principal_id": "user_123",
    "roles": ["operator"]
  },
  "agent": {
    "agent_id": "agent_456",
    "agent_type": "mcp-client",
    "session_id": "sess_789"
  },
  "tool": {
    "tool_server_id": "server_filesystem",
    "tool_name": "delete_file"
  },
  "parameters": {
    "path": "/tmp/cache.txt"
  },
  "environment": {
    "workspace_id": "workspace_prod",
    "environment_name": "production",
    "host_id": "host_001",
    "region": "us-east-1"
  },
  "context": {
    "estimated_cost": 0,
    "risk_label": "destructive"
  }
}
```

Required top-level fields:

- `schema_version`
- `request_id`
- `timestamp`
- `principal`
- `agent`
- `tool`
- `parameters`
- `environment`
- `context`

Missing required field returns:

```text
REFUSE
INVALID_REQUEST
```

## Required Outputs

Decision object:

```json
{
  "schema_version": "1.0",
  "decision": "REFUSE",
  "reason_code": "RESOURCE_SCOPE_DENIED",
  "request_id": "req_01JZ0000000000000000000000",
  "policy_id": "policy_prod_001",
  "policy_version": "1.4.2",
  "policy_hash": "sha256:...",
  "authority_chain_hash": "sha256:...",
  "decision_hash": "sha256:...",
  "evaluated_at": "2026-06-14T15:30:00Z"
}
```

Valid decisions:

- `ALLOW`
- `REFUSE`

Invalid decision state is forbidden.

## Evaluation Order

MNDe PE evaluates in strict order:

1. Parse request.
2. Validate request schema.
3. Canonicalize request.
4. Load active policy bundle.
5. Validate policy schema.
6. Verify policy signature.
7. Validate trust anchor.
8. Validate authority chain.
9. Check authority expiry.
10. Check revocation state.
11. Evaluate policy constraints.
12. Match rules.
13. Resolve conflicts.
14. Generate decision.
15. Generate hashes.
16. Emit receipt data.

First hard failure wins.

All internal errors return:

```text
REFUSE
FAIL_CLOSED
```

## Canonicalization

All PE inputs must become canonical bytes before hashing.

Canonicalization rules:

- UTF-8 only
- sorted object keys
- no duplicate keys
- no floating point values
- no implicit nulls
- no comments
- no trailing commas
- no platform-specific paths without normalization
- timestamps in RFC 3339 UTC
- integers only for numeric values
- strings preserved exactly after validation

Duplicate key returns:

```text
REFUSE
INVALID_CANONICAL_FORM
```

Canonical request hash:

```text
sha256(canonical_request_bytes)
```

Policy hash:

```text
sha256(canonical_policy_bundle_bytes)
```

Authority chain hash:

```text
sha256(canonical_authority_chain_bytes)
```

Decision hash:

```text
sha256(canonical_decision_material)
```

Decision material includes:

- `request_hash`
- `policy_hash`
- `authority_chain_hash`
- `decision`
- `reason_code`
- `evaluated_at`

## Policy Bundle

Policy bundle structure:

```json
{
  "schema_version": "1.0",
  "policy_id": "policy_prod_001",
  "version": "1.4.2",
  "state": "ACTIVE",
  "created_at": "2026-06-01T00:00:00Z",
  "valid_from": "2026-06-01T00:00:00Z",
  "valid_until": "2026-12-01T00:00:00Z",
  "rules": [],
  "limits": {
    "max_rules": 10000,
    "max_depth": 8,
    "max_policy_bytes": 1048576,
    "max_eval_ms": 25
  },
  "signatures": [],
  "required_signers": {
    "mode": "threshold",
    "threshold": 2,
    "eligible_authorities": [
      "security_authority",
      "platform_authority",
      "root_authority"
    ]
  }
}
```

Allowed states:

- `DRAFT`
- `ACTIVE`
- `REVOKED`
- `EXPIRED`
- `LOCKDOWN`

Only `ACTIVE` and `LOCKDOWN` evaluate.

`DRAFT` returns:

```text
REFUSE
POLICY_NOT_ACTIVE
```

`REVOKED` returns:

```text
REFUSE
POLICY_REVOKED
```

`EXPIRED` returns:

```text
REFUSE
POLICY_EXPIRED
```

## Lockdown State

`LOCKDOWN` is an emergency mode.

Default behavior:

```text
All requests REFUSE.
```

Only explicit lockdown exceptions pass.

Example:

```json
{
  "state": "LOCKDOWN",
  "lockdown_exceptions": [
    {
      "tool_name": "read_status",
      "effect": "ALLOW"
    }
  ]
}
```

No matching lockdown exception returns:

```text
REFUSE
LOCKDOWN_ACTIVE
```

## Policy Rule Model

Rule structure:

```json
{
  "rule_id": "rule_001",
  "effect": "ALLOW",
  "description": "Allow operators to read service status",
  "match": {
    "all": [
      { "field": "tool.tool_name", "op": "eq", "value": "read_status" },
      { "field": "principal.roles", "op": "contains", "value": "operator" }
    ]
  },
  "authority_required": [
    "status_read_authority"
  ]
}
```

Valid effects:

- `ALLOW`
- `REFUSE`

Invalid effect returns:

```text
REFUSE
INVALID_POLICY
```

## Policy Grammar

Supported logical operators:

- `all`
- `any`
- `not`

Meaning:

- `all` equals AND
- `any` equals OR
- `not` negates one expression

Example:

```json
{
  "all": [
    {
      "any": [
        { "field": "principal.roles", "op": "contains", "value": "admin" },
        { "field": "principal.roles", "op": "contains", "value": "operator" }
      ]
    },
    { "field": "environment.environment_name", "op": "eq", "value": "staging" }
  ]
}
```

Precedence:

1. `not`
2. `all`
3. `any`

Nesting limit:

```text
8 levels by default
```

Exceeded nesting returns:

```text
REFUSE
POLICY_LIMIT_EXCEEDED
```

## Supported Operators

String operators:

- `eq`
- `neq`
- `prefix`
- `suffix`
- `contains_string`

Array operators:

- `contains`
- `contains_all`
- `contains_any`

Numeric operators:

- `lt`
- `lte`
- `gt`
- `gte`
- `eq`

Time operators:

- `before`
- `after`
- `within_window`

Path operators:

- `path_prefix`
- `path_exact`
- `path_denied_prefix`

Existence operators:

- `exists`
- `missing`

Unsupported operator returns:

```text
REFUSE
INVALID_POLICY
```

## Conflict Resolution

`REFUSE` always wins.

Evaluation rule:

1. If any matching `REFUSE` rule exists, decision is `REFUSE`.
2. Else if any matching `ALLOW` rule exists, decision is `ALLOW`.
3. Else decision is `REFUSE`.

No match returns:

```text
REFUSE
NO_MATCHING_RULE
```

## Authority Framework

Authority is a first-class object.

Authority object:

```json
{
  "authority_id": "prod_deploy_authority",
  "authority_type": "execution_scope",
  "issued_by": "platform_authority",
  "issued_to": "ci_agent_001",
  "scope": {
    "tools": ["deploy_service"],
    "environments": ["production"],
    "regions": ["us-east-1"]
  },
  "valid_from": "2026-06-01T00:00:00Z",
  "valid_until": "2026-07-01T00:00:00Z",
  "constraints": {
    "max_runtime_seconds": 600,
    "allowed_hours_utc": {
      "start": "09:00",
      "end": "17:00"
    }
  },
  "signature": {
    "alg": "Ed25519",
    "key_id": "key_platform_001",
    "signature": "..."
  }
}
```

Expired authority returns:

```text
REFUSE
AUTHORITY_EXPIRED
```

Missing authority returns:

```text
REFUSE
AUTHORITY_REQUIRED
```

Invalid authority signature returns:

```text
REFUSE
AUTHORITY_SIGNATURE_INVALID
```

## Authority Chain

Authority chain example:

```json
{
  "chain": [
    {
      "authority_id": "root_authority",
      "issued_to": "security_authority"
    },
    {
      "authority_id": "security_authority",
      "issued_to": "platform_authority"
    },
    {
      "authority_id": "platform_authority",
      "issued_to": "ci_agent_001"
    }
  ]
}
```

Every link must verify.

Broken chain returns:

```text
REFUSE
AUTHORITY_CHAIN_INVALID
```

Unknown root returns:

```text
REFUSE
TRUST_ANCHOR_UNKNOWN
```

## Delegation

Delegation must be explicit.

Valid delegation requires:

- issuer has delegation authority
- recipient is named
- scope is narrower or equal
- expiry is equal or shorter
- signature is valid

A delegate cannot grant more authority than it received.

Scope expansion returns:

```text
REFUSE
AUTHORITY_SCOPE_ESCALATION
```

## Authority Expiry

Authority expiry is separate from policy expiry.

Policy may remain active while authority expires.

Expired authority is treated as nonexistent.

Result:

```text
REFUSE
AUTHORITY_EXPIRED
```

## Authority Provenance

Every decision records authority provenance.

Required fields:

- `root_authority_id`
- `signing_authority_id`
- `policy_signer_ids`
- `authority_chain_hash`
- `authority_version`
- `authority_origin`

Purpose:

```text
Prove where execution authority came from.
```

## Authority Debt

Authority debt is audit-only.

It never changes `ALLOW` or `REFUSE`.

Authority debt metrics:

- `temporary_exception_count`
- `wildcard_permission_count`
- `orphaned_authority_count`
- `expired_authority_count`
- `broad_scope_authority_count`
- `manual_override_count`
- `lockdown_exception_count`

Example:

```json
{
  "authority_debt": {
    "temporary_exception_count": 2,
    "wildcard_permission_count": 1,
    "orphaned_authority_count": 0,
    "expired_authority_count": 0,
    "broad_scope_authority_count": 3,
    "manual_override_count": 0,
    "lockdown_exception_count": 1
  }
}
```

This gives MNDe a governance signal without corrupting deterministic enforcement.

## Trust Anchor Model

Trust anchor object:

```json
{
  "trust_anchor_id": "root_authority",
  "key_id": "root_key_001",
  "public_key": "...",
  "alg": "Ed25519",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": "2028-01-01T00:00:00Z",
  "state": "ACTIVE"
}
```

Allowed trust anchor states:

- `ACTIVE`
- `REVOKED`
- `EXPIRED`

Revoked root returns:

```text
REFUSE
TRUST_ANCHOR_REVOKED
```

## Signing

Required algorithm for v1:

```text
Ed25519
```

Signature envelope:

```json
{
  "alg": "Ed25519",
  "key_id": "key_security_001",
  "signed_at": "2026-06-14T15:30:00Z",
  "signature": "..."
}
```

Policy activation requires valid signatures.

Threshold examples:

- 1 of 1
- 2 of 2
- 2 of 3

Failed threshold returns:

```text
REFUSE
POLICY_SIGNATURE_THRESHOLD_NOT_MET
```

## Revocation

Revocation lists apply to:

- policies
- authority objects
- signing keys
- trust anchors
- agents
- sessions

Revocation object:

```json
{
  "revoked_id": "prod_deploy_authority",
  "revoked_type": "authority",
  "revoked_at": "2026-06-14T15:00:00Z",
  "reason": "scope retired",
  "signed_by": "security_authority"
}
```

Revoked authority returns:

```text
REFUSE
AUTHORITY_REVOKED
```

## Request Attribute Model

Allowed attribute roots:

- `principal`
- `agent`
- `tool`
- `parameters`
- `environment`
- `context`

Unknown root in policy returns:

```text
REFUSE
INVALID_POLICY
```

Unknown field in request evaluation returns:

```text
REFUSE
ATTRIBUTE_MISSING
```

Unless the rule uses:

```text
missing
```

## Dangerous Defaults

Forbidden defaults:

- allow by default
- trust unknown principal
- trust unknown agent
- trust unsigned policy
- trust stale authority
- trust unbounded wildcard
- ignore missing field
- ignore unknown operator
- ignore invalid timestamp

Any one returns `REFUSE`.

## Wildcards

Wildcards are allowed only when explicitly enabled in policy metadata.

Example:

```json
{
  "wildcards_enabled": false
}
```

Wildcard used while disabled returns:

```text
REFUSE
WILDCARD_DENIED
```

Wildcard usage increases authority debt.

## Expensive Risk Controls

These cover the expensive failures.

Bypass risk:

```text
PE records tool_server_id, agent_id, session_id, policy_hash, authority_chain_hash.
```

Tampering risk:

```text
All inputs hash before decision.
```

Stale policy risk:

```text
Policy has valid_from and valid_until.
```

Compromised signer risk:

```text
Revocation list and threshold signatures.
```

Overbroad access risk:

```text
Authority debt metrics.
```

Bad rollout risk:

```text
Simulation required before activation.
```

Emergency risk:

```text
LOCKDOWN state.
```

Policy abuse risk:

```text
Rule count, depth, size, and evaluation time limits.
```

Replay dispute risk:

```text
Receipts include all hashes needed for offline verification.
```

## Evaluation Limits

Default limits:

- `max_rules`: 10000
- `max_depth`: 8
- `max_policy_bytes`: 1048576
- `max_eval_ms`: 25
- `max_authority_chain_length`: 10
- `max_signatures`: 10

Limit exceeded returns:

```text
REFUSE
LIMIT_EXCEEDED
```

## Policy Simulation

Simulation evaluates without execution.

Simulation output:

- decision
- matching rules
- refuse rules
- authority chain
- reason code
- authority debt impact
- policy hash

Simulation never writes execution receipts.

Simulation result is not execution authority.

## Replay

Replay verifies:

- request canonical hash
- policy canonical hash
- authority chain hash
- decision hash
- policy signatures
- authority signatures
- reason code
- decision result

Replay result:

```text
PASS
FAIL
```

Replay `PASS` means the decision reproduced exactly.

## Receipt Material

PE produces receipt material for MNDe ERS.

Minimum receipt fields:

- `request_id`
- `request_hash`
- `decision`
- `reason_code`
- `policy_id`
- `policy_version`
- `policy_hash`
- `authority_chain_hash`
- `decision_hash`
- `evaluated_at`
- `engine_version`
- `signature`

## Error Behavior

All errors collapse to `REFUSE`.

Malformed request:

```text
REFUSE
INVALID_REQUEST
```

Malformed policy:

```text
REFUSE
INVALID_POLICY
```

Internal crash:

```text
REFUSE
FAIL_CLOSED
```

Timeout:

```text
REFUSE
EVALUATION_TIMEOUT
```

Unknown signer:

```text
REFUSE
SIGNER_UNKNOWN
```

## Versioning

Schema versioning rules:

- patch versions fix wording or test vectors
- minor versions add fields without changing decisions
- major versions alter evaluation behavior

No silent behavior changes.

Policy bundle must declare compatible PE versions.

Example:

```json
{
  "requires_pe": ">=1.0 <2.0"
}
```

Unsupported version returns:

```text
REFUSE
UNSUPPORTED_POLICY_VERSION
```

## Non-Goals

MNDe PE does not:

- execute tools
- store long-term audit logs
- manage users
- create policy
- interpret natural language
- rank risk with AI
- replace IAM
- replace SIEM
- replace KMS
- replace MCP
- repair broken configs
- permit emergency bypass without signed authority

## Production Acceptance Criteria

MNDe PE reaches production-ready v1 when it has:

- formal request schema
- formal policy schema
- formal authority object schema
- canonicalization implementation
- signed policy verification
- authority chain verification
- revocation checking
- deterministic rule evaluator
- conflict resolution
- fail-closed behavior
- evaluation limits
- replay verification
- receipt material output
- conformance tests
- known test vectors
- simulation mode
- lockdown mode

## Required Test Vectors

Minimum production test set:

- `ALLOW` simple `read_status`
- `REFUSE` `recursive_delete`
- `REFUSE` no matching rule
- `REFUSE` invalid request
- `REFUSE` unsigned policy
- `REFUSE` expired policy
- `REFUSE` revoked policy
- `REFUSE` expired authority
- `REFUSE` broken authority chain
- `REFUSE` invalid signature
- `REFUSE` wildcard denied
- `REFUSE` policy limit exceeded
- `REFUSE` lockdown active
- `ALLOW` lockdown exception
- `ALLOW` threshold signatures met
- `REFUSE` threshold signatures missing
- replay `PASS` unchanged receipt
- replay `FAIL` tampered request
- replay `FAIL` tampered policy
- replay `FAIL` tampered authority chain

## Final Production Definition

MNDe PE is a deterministic authority evaluation engine for pre-execution control.

It evaluates canonical execution requests against signed policy and valid authority chains.

It returns `ALLOW` only when valid authority exists.

It returns `REFUSE` for everything else.

It produces replayable proof tied to the request, policy, authority chain, and decision.

MNDe PE does not decide what happened after execution.

MNDe PE decides whether execution had authority before it began.

```text
Authority first. Execution second. Proof always.
```
