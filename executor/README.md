# @mnde/executor

Authorize a function call through MNDe before running it.

Wrap a function. MNDe is asked first. `ALLOW` runs it; `REFUSE` does not. The call returns a signed receipt either way.

```js
import { createMndeExecutor } from "@mnde/executor";

const mnde = createMndeExecutor({ sidecarUrl: "http://127.0.0.1:8787" });

const result = await mnde.execute({
  action: "delete_backups",
  input: { path: "backups/" },
  run: async () => deleteBackups()
});
```

## Behavior

```
Ask MNDe first.
If ALLOW, execute.
If REFUSE, do not execute.
Always return / store the receipt.
Fail closed on anything ambiguous.
```

## Result shape

```js
{
  decision: "ALLOW" | "REFUSE",
  allowed: boolean,
  refused: boolean,
  executed: boolean,
  reason: string | null,        // reason_code, e.g. "ERR_FORBIDDEN_ACTION_IN_PARAMETERS"
  result: any,                  // the return value of run(), only on ALLOW
  error: string | undefined,    // set if run() threw (the receipt is still stored)
  receipt: object | null,
  receiptPath: string | null,   // "./mnde-receipts/receipt-<id>.json"
  verified: boolean | null,     // offline receipt verification result
  failClosed: boolean           // true when refused due to error, not policy
}
```

## API

### `createMndeExecutor(config)`

| option | default | meaning |
|---|---|---|
| `sidecarUrl` | `http://127.0.0.1:8787` | MNDe sidecar address |
| `receiptsDir` | `./mnde-receipts` | where receipts are written |
| `testerId` / `installationId` | env or `*-UNASSIGNED` | identity stamped into requests |
| `timeoutMs` | `5000` | decision request timeout (then fail closed) |
| `verify` | `true` | verify each stored receipt offline |

Returns `{ execute, wrapTool, verifyReceipt, config }`.

### `mnde.execute({ action, input, run, executionId?, requestOverrides? })`

Asks MNDe for `action` + `input`, then runs `run()` only on `ALLOW`. `executionId`
sets the idempotency key (a repeat is refused). `requestOverrides` deep-merges into
the decision request for advanced shaping (cost, approval state, resources).

### `mnde.wrapTool(name, fn)`

Returns a guarded function: `wrapped(input) -> Promise<result>`. The raw `fn` is
captured in a closure and never exposed — the only way to call it is through MNDe.

## The safety claim

> If a tool is wrapped with MNDe, there is no code path where `REFUSE` executes.

In [`index.mjs`](./index.mjs) there is exactly **one** call site for the wrapped
function, reachable only after a well-formed `ALLOW`. REFUSE, an unreachable
sidecar, a malformed decision, a timeout — all return without calling it.

## ⚠️ The one bypass: direct (unwrapped) execution

Protection comes from **wrapping**, not from importing. Calling a raw function
directly skips MNDe entirely — no decision, no receipt:

```js
// NOT PROTECTED — MNDe is never consulted.
await deleteBackups();

// PROTECTED — MNDe decides first.
await mnde.execute({ action: "delete_backups", input, run: () => deleteBackups() });
```

This is covered explicitly in `tests/test_executor.mjs` (test 8) so it can never
be claimed as protection by accident.

## Try it

```bash
npm run executor-demo     # ALLOW / REFUSE / fail-closed, end to end
npm run test:executor     # the enforcement test suite

node examples/executor-wrapper/read-status.js
node examples/executor-wrapper/delete-backups-blocked.js
node examples/executor-wrapper/deploy-requires-approval.js
node examples/executor-wrapper/agent-tool-wrapper.js
```

## Scope (v0.1)

This version lives inside the MNDe repo and imports the in-repo request builder
and offline verifier. JavaScript only, local sidecar only. Publishing as a
standalone package means vendoring those two pieces — deliberately out of scope
for v0.1.
