// Execution-ledger inclusion-proof CLI (Phase 1).
//
//   npm run ledger:prove -- --ledger=<file> --checkpoints=<file> \
//       --receipt-store=<file> --bundle=<public-bundle> --receipt-hash=sha256:...
//   npm run ledger:verify-proof -- <proof.json> --bundle=<public-bundle>
//
// `prove` reads an already-anchored ledger (the sidecar produces checkpoints) and
// emits a single-receipt proof bundle — no signing, no custody. `verify-proof` is
// the counterparty's tool: it verifies a proof bundle fully OFFLINE against a
// trusted public authority bundle — no filesystem beyond reading the two inputs,
// no network, no trust in whoever generated the proof.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { readCheckpointHead, buildProofBundle } from "../src/execution-ledger/anchor.mjs";
import { verifyProofBundle } from "../src/execution-ledger/proof.mjs";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (const arg of argv) {
    const m = /^--([^=]+)=(.*)$/.exec(arg);
    if (m) flags[m[1]] = m[2];
    else if (arg.startsWith("--")) flags[arg.slice(2)] = true;
    else positional.push(arg);
  }
  return { positional, flags };
}

function readJson(path) {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const mode = positional[0] ?? "verify-proof";

if (mode === "prove") {
  const ledgerPath = resolve(flags.ledger ?? "");
  const checkpointPath = resolve(flags.checkpoints ?? "");
  const trustedBundle = readJson(flags.bundle);
  const checkpoint = readCheckpointHead(checkpointPath);
  if (!checkpoint) { console.error("no checkpoint found; anchor the ledger first"); process.exit(2); }
  const selector = flags["receipt-id"] ? { receipt_id: flags["receipt-id"] } : { receipt_hash: flags["receipt-hash"] };
  try {
    const bundle = await buildProofBundle(ledgerPath, checkpoint, selector, { receiptStorePath: resolve(flags["receipt-store"] ?? ""), trustedBundle });
    const out = JSON.stringify(bundle, null, 2);
    if (flags.out) { writeFileSync(resolve(flags.out), out + "\n"); console.error(`proof written to ${flags.out}`); }
    else console.log(out);
    process.exit(0);
  } catch (error) {
    console.error(`FAIL prove: ${error?.code ?? ""} ${error?.message ?? error}`);
    process.exit(1);
  }
}

if (mode === "verify-proof") {
  const proofFile = positional[1] ?? flags.proof;
  if (!proofFile) { console.error("usage: verify-proof <proof.json> --bundle=<public-bundle>"); process.exit(2); }
  const proof = readJson(proofFile);
  const trustedBundle = readJson(flags.bundle);
  const res = await verifyProofBundle(proof, trustedBundle, { trustedRootFingerprint: flags["root-fingerprint"] ?? trustedBundle.root_key?.fingerprint });
  console.log(JSON.stringify(res, null, 2));
  if (!res.ok) { console.error(`\nFAIL verify-proof at step '${res.step}': ${res.reason}`); process.exit(1); }
  console.error(`\nPASS verify-proof: ${res.assurance} (seq ${res.sequence}, tree_size ${res.tree_size})`);
  process.exit(0);
}

console.error(`Unknown mode '${mode}'. Use: prove | verify-proof`);
process.exit(2);
