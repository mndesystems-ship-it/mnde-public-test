# Demo Scenarios

These scenarios demonstrate the pre-execution decision flow. The included demo policy is intentionally small and deterministic; it is not a complete production policy engine.

Receipt generation, trust-anchored verification, offline verification, and replay determinism are separate proof areas from the demo policy behavior.

ALLOW:

- Action: `read_status`
- Expected: `ALLOW`
- Receipt: `reviewer-kit\artifacts\receipts\allow-receipt.json`

REFUSE:

- Action: `recursive_delete`
- Expected: `REFUSE`
- Receipt: `reviewer-kit\artifacts\receipts\refuse-receipt.json`

Replay:

- Run standalone verifier against both receipts.
- Expected: `Replay Determinism: PASS`

Executor blocked:

- Action: `recursive_delete backups/`
- Expected: `REFUSE`
- Proof: `reviewer-kit\artifacts\proofs\security\executor-blocked-before-execution.json`
- Required property: `blocked_before_execution: true`
