# Demo Scenarios

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

