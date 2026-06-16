# MNDe Evaluator Guide

Evaluate MNDe end to end **without reading source code, writing API calls, or using the terminal for evaluation**. You run one command to start it; everything else happens in the Authority Console.

Every result you see in the console is a **real** response from the running system — there are no demo screens or simulated states.

## 1. Quick start

```bash
npm run sidecar
```

Then open **http://127.0.0.1:8787/** in a browser. The console loads and the headline answers the only question that matters: *Is MNDe protecting execution right now?*

No login, no signup, no account, no cloud. If the light is red, MNDe isn't running — start it and the console reconnects on its own.

## 2. Guided evaluation (the **Start** tab)

The Start tab walks you through six real steps. Each one acts against the live sidecar and shows the result.

### First successful ALLOW
Click **Run ALLOW decision**. The console submits a benign action (`read_status`). The active policy permits it, so MNDe returns **ALLOW** and signs an Execution Receipt. You'll see the green `ALLOW` verdict and the decision hash.

### First successful REFUSE
Click **Run REFUSE decision**. The console submits an action whose parameters contain a destructive command (`recursive_delete` with `script: "rm -rf ..."`). The active policy refuses it **because of what it does** — the destructive parameter — returning **REFUSE** (`ERR_FORBIDDEN_ACTION_IN_PARAMETERS`) *before anything runs*, and still records a signed receipt as evidence. This is the core guarantee: a refused action never executes.

> The active policy is **limits-based** (cost, GPU count, hours, manual-approval threshold) plus destructive-parameter detection — **not** a tool-name denylist. The same `recursive_delete` tool **without** a destructive parameter may ALLOW. The tool-name lists in `sample-policies/` are examples only and are not the active default policy.

## 3. Receipts (the **Receipts** tab)

Every decision produces a signed receipt. The Receipts tab lists the real receipts from the running system. Click any row to:

- **Inspect** — decision, tool, reason, hashes, and the full raw receipt JSON (no manual extraction).
- **Verify this receipt** — checks the signature and decision integrity against the live authority. `VERIFIED` means the evidence is sound; a tampered receipt fails closed.
- **Export JSON** — download the receipt for your own offline verification (`node tools/verify.mjs <file>`).

## 4. Replay (Receipts tab → Replay)

Click **Run replay over recent receipts**. MNDe re-runs the deterministic engine over the persisted receipts and confirms each decision reproduces exactly. **PASS** = the record is tamper-evident and independently reproducible. Any failure is listed with a plain-English reason.

## 5. Authority & trust (the **Authority** tab)

This shows the live trust state and explains the model:

- **Trust chain** — `LOCAL_DEV` (local development signing root) or `VERIFIED` (a published production custody root). Production custody is opt-in (`MNDE_PROFILE=production`).
- **Signing authority** — the receipt key(s) signing decisions, with validity windows. Keys can be rotated and revoked (`npm run authority -- rotate|revoke`) without breaking historical receipts. See [Key Custody](key-custody.md).
- **Receipt signatures** — verification re-runs the engine and checks the Ed25519 signature against the trusted authority. A tampered request, policy, or decision fails closed. This works fully offline.
- **Authority health** — `HEALTHY`/`DEV`/`ERROR`, so you can see at a glance whether the trust root is sound.

## 6. OpenClaw integration

MNDe authorizes any caller that uses the canonical decision contract. The request format the sidecar accepts is documented and drift-tested in [API Contract](api-contract.md), with runnable examples in [`examples/decisions/`](../examples/decisions/). An OpenClaw (or any) integration:

1. Builds the execution-request envelope (see API Contract).
2. POSTs to `/v1/decisions`.
3. Executes only on `ALLOW`; treats `REFUSE` / any error as a hard stop (fail closed).
4. Persists the returned receipt as evidence.

The same ALLOW/REFUSE/receipt/replay evidence shown above is what an OpenClaw integration produces — verify it identically.

## 7. Troubleshooting

| Symptom | Meaning | Fix |
| --- | --- | --- |
| Headline red, "not reachable" | Sidecar isn't running | `npm run sidecar`; the console reconnects automatically |
| Status `DEGRADED` | Runtime is under stress but still fail-closed (refuses, never wrongly allows) | Check **Settings → Runtime**; reduce load or restart |
| Status `FAIL-CLOSED` | Runtime refused to serve (e.g. watchdog fatal) | Restart MNDe; check stderr |
| A decision returns an unexpected response | Request didn't match the contract | Compare against [API Contract](api-contract.md) / the example files |
| `ERR_UNAUTHORIZED_ORIGIN` | A non-local origin called the sidecar | Use the console (same-origin) on `127.0.0.1` |
| Receipt verify shows `FAILED` | Signature/decision integrity check failed | The receipt was altered or the authority changed — treat as untrusted |
| Production startup refused (`ERR_TRUST_ROOT_*`) | `MNDE_PROFILE=production` without valid custody | Configure file-backed production custody — see [Key Custody](key-custody.md) |

## Acceptance: what you should be able to conclude

After this guide you have, with no assistance: installed and launched MNDe; produced a real ALLOW and a real REFUSE; inspected, verified, and exported receipts; replayed the record; and seen the trust model and authority health — all from the console, against the live system.
