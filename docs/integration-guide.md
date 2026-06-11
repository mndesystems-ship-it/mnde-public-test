# Minimal Agent Integration

MNDe is a pre-execution authority layer. An agent can think, plan, and choose tools normally, but every integrated tool call must ask MNDe before execution.

```text
Agent chooses action
  -> POST /v1/decisions
  -> ALLOW: execute tool and persist receipt
  -> REFUSE: do not execute and persist receipt
```

Never execute on `REFUSE`. If an executor bypasses this wrapper, MNDe has not evaluated that action.

## Pseudocode

```text
function guardedToolCall(action):
  decision = POST /v1/decisions with action
  save(decision.receipt)

  if decision.decision == "ALLOW":
    return execute(action)

  return denied(decision.reason_code)
```

## JavaScript Wrapper

```js
import { writeFile } from "node:fs/promises";

async function askMnde(request) {
  const response = await fetch("http://127.0.0.1:8787/v1/decisions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  });
  return response.json();
}

export async function guardedTool({ request, execute, receiptPath }) {
  const decision = await askMnde(request);

  if (decision.receipt) {
    await writeFile(receiptPath, JSON.stringify(decision.receipt, null, 2));
  }

  if (decision.decision === "ALLOW") {
    return execute();
  }

  return {
    status: "REFUSED",
    reason_code: decision.reason_code,
    receipt_path: receiptPath
  };
}
```

## Receipt Verification

```bash
npm run verify-receipt reviewer-kit/artifacts/receipts/allow-receipt.json
```

Verification is offline. It checks hashes, signature, replay determinism, and authority origin through the signed authority manifest.

## Authority Bundle

The public test package has two authority paths:

- committed demo authority for example receipts
- generated local tester authority for reviewer-kit receipts

That makes fresh-clone testing self-contained while keeping documentation examples stable.

For production, MNDe must publish a stable authority bundle:

- root authority public key
- signed authority manifest
- active receipt keys
- retired receipt keys for old receipts

Receipts verify independently only when the verifier has the trusted authority bundle. Unknown authority IDs, unknown key IDs, expired keys, or invalid manifests fail closed.
