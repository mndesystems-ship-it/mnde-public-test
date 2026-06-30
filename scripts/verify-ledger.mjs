// Execution-ledger CLI: verify / head / export.
//
//   npm run ledger:verify    # verify the whole chain (exit 1 on failure)
//   npm run ledger:head      # print the current chain head
//   npm run ledger:export    # print the ledger as a JSON export object
//
// Resolves the ledger the same way the sidecar does, so by default it inspects
// the live ledger for the current receipt-log configuration. Overrides:
//   --ledger=<path>        explicit ledger file
//   --receipt-root=<dir>   root that receipt_ref paths resolve inside
// or the environment: MNDE_EXECUTION_LEDGER_PATH, MNDE_RECEIPT_LOG.

import { dirname, join, resolve } from "node:path";

import { resolveLedgerRuntime, ledgerHeadResponse, ledgerVerifyResponse, ledgerExportResponse } from "../src/execution-ledger/sidecar.mjs";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (const arg of argv) {
    const match = /^--([^=]+)=(.*)$/.exec(arg);
    if (match) flags[match[1]] = match[2];
    else positional.push(arg);
  }
  return { mode: positional[0] ?? "verify", flags };
}

const { mode, flags } = parseArgs(process.argv.slice(2));

const receiptLog = process.env.MNDE_RECEIPT_LOG ?? join(process.cwd(), "hostile-verifier-proof-bundle", "receipts.jsonl");
const runtime = resolveLedgerRuntime(process.env, receiptLog);
if (flags.ledger) runtime.ledgerPath = resolve(flags.ledger);
if (flags["receipt-root"]) runtime.receiptRoot = resolve(flags["receipt-root"]);
else if (flags.ledger && !process.env.MNDE_RECEIPT_LOG) runtime.receiptRoot = dirname(resolve(flags.ledger));
runtime.enabled = true;

if (mode === "head") {
  console.log(JSON.stringify(ledgerHeadResponse(runtime), null, 2));
  process.exit(0);
}

if (mode === "export") {
  console.log(JSON.stringify(ledgerExportResponse(runtime), null, 2));
  process.exit(0);
}

if (mode === "verify") {
  const result = ledgerVerifyResponse(runtime);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) {
    console.error(`\nFAIL execution-ledger verification (${result.entries_checked} checked) — ${result.errors[0]?.code}: ${result.errors[0]?.message}`);
    process.exit(1);
  }
  console.log(`\nPASS execution-ledger verification (${result.entries_checked} entries, head seq ${result.head?.sequence ?? 0})`);
  process.exit(0);
}

console.error(`Unknown mode '${mode}'. Use: verify | head | export`);
process.exit(2);
