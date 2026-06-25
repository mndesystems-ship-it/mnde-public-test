#!/usr/bin/env node
import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyReceiptPayloadSignature } from "../shared/receipt-signing.ts";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const fixtures = join(repoRoot, "tests", "receipts");

const cases = [
  ["valid-receipt.json", true],
  ["invalid-signature.json", false],
  ["invalid-request-hash.json", false],
  ["invalid-decision-hash.json", false],
  ["invalid-policy-hash.json", false],
  ["corrupted-json.json", false],
  ["missing-field.json", false]
];

for (const [name, expectedVerified] of cases) {
  const report = verifyReceiptFile(join(fixtures, name));
  const verified = verificationPassed(report);
  if (verified !== expectedVerified) {
    console.error(`${name} expected ${expectedVerified ? "PASS" : "FAIL"} but got ${verified ? "PASS" : "FAIL"}`);
    process.exit(1);
  }
}

assert.throws(
  () => verifyReceiptPayloadSignature("payload", "00"),
  /ERR_RECEIPT_VERIFICATION_KEY_REQUIRED/,
  "receipt signature verification must require an explicit public key"
);

console.log("PASS receipt verifier tests");
