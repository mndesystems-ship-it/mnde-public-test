# MNDe Public Test

MNDe is a local pre-execution authority layer. Tools, agents, and automation ask MNDe before they execute. MNDe returns `ALLOW` or `REFUSE` and writes a signed receipt that can be verified later.

## What Problem Does It Solve?

AI agents and automation can perform useful work, but they can also take unsafe shortcuts. MNDe places an execution boundary before the action runs. A reviewer can inspect the decision, receipt, policy hash, signature, and replay result.

## Enforcement Wedge

**MNDe sits between agent intent and tool execution. If MNDe refuses, the tool call is not forwarded.**

Three layers turn that claim into code anyone can drop in:

- **`@mnde/executor`** ([executor/](executor/)) — wrap any risky function; `ALLOW` runs it once, `REFUSE` never does. `npm run executor-demo`, `npm run test:executor`.
- **MNDe MCP server** ([mcp/](mcp/)) — expose guarded tools over the Model Context Protocol; every `tools/call` is authorized first. `npm run mcp-demo`, `npm run test:mcp`.
- **MNDe MCP proxy** ([mcp/mnde-mcp-proxy.mjs](mcp/mnde-mcp-proxy.mjs)) — put MNDe in front of *any existing* MCP server; tool calls now require authority before execution, with zero changes to the upstream. `npm run mcp-proxy-demo`, `npm run test:mcp-proxy`.

In every layer there is no code path where `REFUSE` executes (or, in the proxy, forwards) the call — proven by tests, including across process boundaries via a destruction marker.

## Quick Start

1. Start MNDe:

   ```bash
   npm run sidecar
   ```

2. Run a protected tool demo (in a second terminal):

   ```bash
   npm run mcp-proxy-demo
   ```

Expected result:

- ALLOW actions execute.
- REFUSE actions do not execute.
- Receipts verify offline.

`npm run sidecar` is a foreground service: it bootstraps local authority keys if needed, validates the environment, prints a `Status: READY` banner, and streams logs until you press Ctrl+C. No manual setup steps are required on a fresh clone.

## Install

Requirements:

- Node.js 24 or later
- Windows, macOS, or Linux

Run:

```bash
npm install
npm run sidecar
npm run mcp-proxy-demo
```

`npm run sidecar` automatically creates the local authority assets it needs on first run, so no separate setup step is required. If you prefer to provision those assets explicitly (e.g. for the reviewer kit without starting a sidecar), `npm run tester:init -- TESTER-001` does the same bootstrap.

`tester:init` creates three local-only things:

- `.mnde-test\identity.json`
- `shared\receipt_keys\receipt_signing_private.pem` and `receipt_signing_public.pem`
- `.mnde-test\authority\authority-manifest.json` signed by the local root authority

The signing keys and local tester authority are generated on your machine, ignored by git, and required for live signed receipts created by the reviewer kit. `tester:init` reuses existing local authority material when present and never modifies the committed demo authority or example receipts.

The repository also includes a committed demo authority under `authority/`. It is stable for documentation examples and committed example receipts only.

Receipts do not trust their own embedded key. The verifier checks the signed authority manifest first, then verifies the receipt with an authority-approved key. If keys or authority evidence are missing or invalid, MNDe refuses to start with a clear `ERR_RECEIPT_SIGNING_KEYS_*` or `ERR_AUTHORITY_MANIFEST_INVALID` error instead of crashing during the first decision.

Production verification requires a stable MNDe-published authority bundle. Receipts are independently verifiable only when the verifier has the trusted authority manifest and root public key. Unknown authority IDs, unknown key IDs, expired keys, and invalid manifests fail closed.

Desktop installers are not committed to this repository. Download release artifacts from GitHub Releases and verify their SHA-256 checksums before running them:

```text
https://github.com/mndesystems-ship-it/mnde-public-test/releases
```

## Verify It Works

Run:

```bash
npm run reviewer-kit
```

Expected final output:

```text
FINAL VERDICT: PASS
```

The reviewer kit is the supported one-command proof path. It starts MNDe, runs the ALLOW and REFUSE examples, verifies receipts, verifies replay, checks hostile input refusal behavior, and proves that a destructive executor action is blocked before execution.

`npm run reviewer-kit` is cross-platform and uses Node.js. Windows PowerShell helper scripts remain available through:

```powershell
npm run reviewer-kit:windows
```

## Known Reviewer Claims Now Proven

- Fresh clone install
- Tester init
- Reviewer kit
- Safe ALLOW
- Unsafe REFUSE
- Offline receipt verification
- Tamper detection
- Trust-anchored receipt origin
- Deterministic repeat requests
- Executor blocked before execution

## Documented Verification Flow

Run:

```bash
npm run verify-receipt examples/receipts/valid-receipt.json
npm run test:receipt-verifier
npm run test:trust-anchor
npm run test:fresh-setup
```

Expected result: every command exits 0 and prints `PASS` or `FINAL VERDICT: VERIFIED`.

Optional desktop smoke testing can be run after downloading a release executable:

```bash
MNDE_DESKTOP_EXE=/path/to/MNDe-Execution-Control.exe npm run desktop-smoke
```

## Integration

See [docs/integration-guide.md](docs/integration-guide.md) for a minimal agent wrapper that calls `POST /v1/decisions` before execution, executes only on `ALLOW`, never executes on `REFUSE`, stores receipts, and verifies them offline.

## Trigger An ALLOW Decision

```bash
npm run reviewer-kit:allow
```

The ALLOW example submits:

```text
read_status
```

## Trigger A REFUSE Decision

```bash
npm run reviewer-kit:refuse
```

The REFUSE example submits:

```text
recursive_delete
```

## Verify A Receipt

```bash
npm run verify-receipt reviewer-kit/artifacts/receipts/allow-receipt.json
npm run verify-receipt reviewer-kit/artifacts/receipts/refuse-receipt.json
```

An included sample receipt can be verified without starting MNDe:

```bash
npm run verify-receipt examples/receipts/valid-receipt.json
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

```bash
npm run tester:init -- TESTER-001
```

The local installation identifier is generated on this machine and saved under `.mnde-test/`. It is not committed. The Tester ID is included in reviewer-kit requests, generated receipts, logs, and diagnostics so feedback can be tied to a test run without collecting personal information.

MNDe Public Test does not collect personal information, track browsing activity, or transmit data without consent.

## Artifacts

Generated files stay under:

```text
reviewer-kit/artifacts/
.mnde-test\
shared/receipt_keys/
```

Committed example receipts are signed by the committed demo authority under `authority/`. Local reviewer-kit receipts are signed by the generated local tester authority under `.mnde-test/authority/`.

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
- [Minimal agent integration](docs/integration-guide.md)
- [Trust-anchored receipt verification](docs/trust-anchored-verification.md)
- [Production readiness notes](docs/production-readiness.md)
- [Demo scenarios](docs/demo-scenarios.md)
- [Tester ID implementation](docs/tester-id-implementation.md)
- [Release checklist](docs/release-checklist.md)
- [Security review checklist](docs/security-review-checklist.md)
