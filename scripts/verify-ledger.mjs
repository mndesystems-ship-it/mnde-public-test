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
//   --bundle=<path>        trusted authority bundle (public) that signs v2 entries
//   --legacy               accept unsigned v1 entries (audit/migration reads)
// or the environment: MNDE_EXECUTION_LEDGER_PATH, MNDE_RECEIPT_LOG,
// MNDE_AUTHORITY_BUNDLE (default trusted bundle path).
//
// Verifying a signed (v2) ledger requires the bundle whose "ledger" keys signed
// it. A ledger written by an ephemeral local-demo key (no published bundle) can
// only be read with --legacy; a production ledger verifies against its published
// MNDE_AUTHORITY_BUNDLE.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { resolveLedgerRuntime, ledgerHeadResponse, ledgerVerifyResponse, ledgerExportResponse } from "../src/execution-ledger/sidecar.mjs";

function loadTrustedBundle(flags) {
  const path = flags.bundle ? resolve(flags.bundle) : (process.env.MNDE_AUTHORITY_BUNDLE ?? null);
  if (!path) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    console.error(`could not read trusted bundle at ${path}: ${error.message}`);
    process.exit(2);
  }
}

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

const trustedBundle = loadTrustedBundle(flags);
const strict = !("legacy" in flags);

if (mode === "head") {
  console.log(JSON.stringify(await ledgerHeadResponse(runtime, trustedBundle, strict), null, 2));
  process.exit(0);
}

if (mode === "export") {
  console.log(JSON.stringify(ledgerExportResponse(runtime), null, 2));
  process.exit(0);
}

if (mode === "verify") {
  const result = await ledgerVerifyResponse(runtime, trustedBundle, strict);
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
