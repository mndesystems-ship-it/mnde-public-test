#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixedReceipts = [
  join(repoRoot, "examples", "receipts", "valid-receipt.json"),
  join(repoRoot, "examples", "receipts", "refuse-receipt.json"),
  join(repoRoot, "tests", "receipts", "valid-receipt.json")
];
const artifactReceiptsDir = join(repoRoot, "reviewer-kit", "artifacts", "receipts");
const artifactReceipts = existsSync(artifactReceiptsDir)
  ? readdirSync(artifactReceiptsDir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => join(artifactReceiptsDir, name))
  : [];

const receipts = [...fixedReceipts, ...artifactReceipts].filter((file) => existsSync(file));
assert.ok(receipts.length > 0, "no receipts available for replay verification");

for (const receiptPath of receipts) {
  const report = verifyReceiptFile(receiptPath);
  assert.equal(verificationPassed(report), true, `${receiptPath} failed verification`);
  assert.equal(report.checks["Replay Determinism"]?.ok, true, `${receiptPath} failed replay determinism`);
}

console.log(`PASS replay verification (${receipts.length}/${receipts.length})`);
