# Tester ID Implementation Plan

Purpose:
Identify test artifacts and feedback without collecting personal information.

Local files:

- `.mnde-test/identity.json`
- `reviewer-kit/artifacts/logs/tester-identity.json`

Fields:

- `tester_id`
- `installation_id`
- `created_at`
- `privacy`

Behavior:

- Tester ID is assigned by the test coordinator or entered by the tester.
- Installation ID is generated locally.
- Tester ID is placed into reviewer-kit request actor metadata.
- Tester ID and Installation ID are also placed into request parameters so they appear in receipts without changing the production actor schema.
- Receipts include that actor metadata through the canonical request.
- Logs and diagnostics include the local tester identity file.

Privacy:

- No personal information is required.
- No browsing activity is tracked.
- No telemetry is transmitted automatically.
- Test artifacts remain local unless the tester chooses to share them.
