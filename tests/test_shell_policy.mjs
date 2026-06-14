// MNDe shell policy + receipt tests.
//
//   npm run test:shell
//
// Proves deny-by-default authorization and that every decision — including the
// refusal of an unknown command — is a signed, offline-verifiable receipt that
// fails closed when tampered.

import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { decideCommand } from "../shell/policy.mjs";
import { buildShellReceipt, verifyShellReceipt } from "../shell/receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function main() {
  console.log("MNDe shell policy + receipt tests\n");
  bootstrapReceiptKeys({ repoRoot });

  test("allowlisted command -> ALLOW", () => {
    assert.deepEqual(decideCommand("ls -la"), { decision: "ALLOW", reason_code: "OK_ALLOWLISTED" });
  });

  test("sensitive command -> APPROVAL_REQUIRED", () => {
    assert.deepEqual(decideCommand("restart_service nginx"), { decision: "APPROVAL_REQUIRED", reason_code: "APPROVAL_REQUIRED" });
  });

  test("known-destructive command -> REFUSE (denylisted)", () => {
    assert.deepEqual(decideCommand("rm -rf /"), { decision: "REFUSE", reason_code: "ERR_DENYLISTED" });
  });

  test("DENY BY DEFAULT: unknown command -> REFUSE (not allowlisted)", () => {
    assert.deepEqual(decideCommand("some-weird-command-never-seen-before"), { decision: "REFUSE", reason_code: "ERR_NOT_ALLOWLISTED" });
  });

  test("empty command -> REFUSE", () => {
    assert.equal(decideCommand("   ").decision, "REFUSE");
  });

  test("ALLOW decision produces a verifiable receipt", () => {
    const receipt = buildShellReceipt("ls -la");
    const result = verifyShellReceipt(receipt);
    assert.equal(result.verified, true);
    assert.equal(result.decision, "ALLOW");
  });

  test("a REFUSED unknown command is ALSO a verifiable receipt", () => {
    const receipt = buildShellReceipt("some-weird-command-never-seen-before");
    const result = verifyShellReceipt(receipt);
    assert.equal(result.verified, true);
    assert.equal(result.decision, "REFUSE");
    assert.equal(result.reason_code, "ERR_NOT_ALLOWLISTED");
  });

  test("tampering the decision fails verification", () => {
    const receipt = buildShellReceipt("some-weird-command-never-seen-before");
    receipt.decision_output.decision = "ALLOW"; // forge an allow
    assert.equal(verifyShellReceipt(receipt).verified, false);
  });

  test("tampering the command fails verification", () => {
    const receipt = buildShellReceipt("ls");
    receipt.canonical_request = receipt.canonical_request.replace("ls", "rm -rf /");
    assert.equal(verifyShellReceipt(receipt).verified, false);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL shell policy tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS shell policy tests (${results.length}/${results.length})`);
}

main();
