# MNDe Public Test

MNDe is a local pre-execution authority layer. Tools, agents, and automation ask MNDe before they execute. MNDe returns `ALLOW` or `REFUSE` and writes a signed receipt that can be verified later.

## What Problem Does It Solve?

AI agents and automation can perform useful work, but they can also take unsafe shortcuts. MNDe places an execution boundary before the action runs. A reviewer can inspect the decision, receipt, policy hash, signature, and replay result.

## Install

Requirements:

- Windows
- Node.js 24 or later
- PowerShell

Run:

```powershell
npm install
npm run tester:init -- TESTER-001
```

The desktop test app is here:

```text
installer\MNDe-Execution-Control.exe
```

## Verify It Works

Run:

```powershell
npm run reviewer-kit
```

Expected final output:

```text
FINAL VERDICT: PASS
```

The reviewer kit is the supported one-command proof path. It starts MNDe, runs the ALLOW and REFUSE examples, verifies receipts, verifies replay, checks hostile input refusal behavior, and proves that a destructive executor action is blocked before execution.

## Known Reviewer Claims Now Proven

- Fresh clone install
- Tester init
- Reviewer kit
- Safe ALLOW
- Unsafe REFUSE
- Offline receipt verification
- Tamper detection
- Deterministic repeat requests
- Executor blocked before execution

## Desktop Smoke Test

Run:

```powershell
npm run desktop-smoke
```

This verifies that the packaged Windows desktop executable exists, launches, stays alive during the smoke test, and can work with the sidecar-facing health, receipt, replay, policy, and logs/metrics surfaces.

## Trigger An ALLOW Decision

```powershell
npm run reviewer-kit:allow
```

The ALLOW example submits:

```text
read_status
```

## Trigger A REFUSE Decision

```powershell
npm run reviewer-kit:refuse
```

The REFUSE example submits:

```text
recursive_delete
```

## Verify A Receipt

```powershell
npm run verify-receipt reviewer-kit\artifacts\receipts\allow-receipt.json
npm run verify-receipt reviewer-kit\artifacts\receipts\refuse-receipt.json
```

An included sample receipt can be verified without starting MNDe:

```powershell
npm run verify-receipt examples\receipts\valid-receipt.json
```

Expected output:

```text
FINAL VERDICT: VERIFIED
```

## Tester ID

Each tester receives a human-readable Tester ID, such as:

```text
TESTER-001
```

Initialize it with:

```powershell
npm run tester:init -- TESTER-001
```

The local installation identifier is generated on this machine and saved under `.mnde-test/`. It is not committed. The Tester ID is included in reviewer-kit requests, generated receipts, logs, and diagnostics so feedback can be tied to a test run without collecting personal information.

MNDe Public Test does not collect personal information, track browsing activity, or transmit data without consent.

## Artifacts

Generated files stay under:

```text
reviewer-kit\artifacts\
.mnde-test\
```

## Feedback

Send:

- Tester ID
- Command run
- Final verdict
- Receipt file, if relevant
- Screenshot or error text
- What you expected
- What happened

See [docs/feedback-workflow.md](docs/feedback-workflow.md).

## More Docs

- [First tester onboarding](docs/first-tester-onboarding.md)
- [Independent receipt verification](docs/independent-verification.md)
- [Demo scenarios](docs/demo-scenarios.md)
- [Tester ID implementation](docs/tester-id-implementation.md)
- [Release checklist](docs/release-checklist.md)
- [Security review checklist](docs/security-review-checklist.md)
