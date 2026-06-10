# Execution Firewall Overview

## What is an Execution Firewall?

An Execution Firewall is a pre-execution control layer for software agents, automation systems, and operational tools. It receives a proposed action before execution, evaluates the request against policy and runtime constraints, and returns a decision.

The core decision set is:

- `ALLOW`: execution may continue
- `REFUSE`: execution must not occur

An Execution Firewall is positioned before the executor. The executor must not perform the action until a valid `ALLOW` decision is received.

## Why Monitoring is Insufficient

Monitoring observes behavior after or during execution. Monitoring can detect events, trigger alerts, and support investigation, but it cannot reliably prevent the first unsafe operation from occurring.

For agentic systems, post-execution detection is insufficient when the action is destructive, irreversible, expensive, or regulated. Examples include deleting backups, exporting customer data, disabling monitoring, stopping production databases, or launching excessive compute.

## Why Pre-Execution Control Matters

Pre-execution control changes the enforcement point. The action is evaluated before the executor mutates state. This enables:

- deterministic allow/refuse decisions
- fail-closed behavior
- policy-bound execution
- auditable refusal of unsafe actions
- prevention of destructive shortcuts

The enforcement invariant is:

```text
No action executes unless the Execution Firewall returns ALLOW.
```

## Relationship Between Execution Firewalls and Execution Receipts

An Execution Firewall controls whether execution may proceed. An Execution Receipt records what decision was made and why.

The receipt provides independent evidence for:

- the submitted request
- the policy reference
- the decision
- the reason code
- the decision hash
- the authority-approved signature
- replay verification

Without receipts, an Execution Firewall can enforce policy but cannot provide portable evidence. Without pre-execution enforcement, receipts can document decisions but cannot prevent unsafe actions.

## Example Architecture

```text
Agent or automation
  -> tool request
  -> Execution Firewall decision API
      -> ALLOW: executor runs tool
      -> REFUSE: executor returns denied result
  -> receipt stored for audit and replay
```

The agent does not need direct access to protected systems. The executor or tool wrapper is responsible for calling the Execution Firewall before performing work.

## Reference Implementation: MNDe

MNDe is one implementation of the Execution Firewall model.

The implementation details described in this section are not normative requirements of ERS v1.

MNDe implements the Execution Firewall model with:

- a local sidecar decision service
- deterministic request canonicalization
- policy and runtime decision layers
- `ALLOW` and `REFUSE` decisions
- signed execution receipts
- authority-manifest verification
- offline receipt verification
- replay verification

MNDe receipts are intended to make the decision independently inspectable. A verifier does not need to trust the dashboard, operator, server, or receipt-provided key material. It verifies the receipt against the trusted authority bundle and recomputes the deterministic decision path.
