#!/usr/bin/env node
// Code parity test for mnde.signed_execution_result.v1 error codes.
//
// Confirms that every error code listed in docs/signed-execution-result-v1.md
// is exported from the verifier, and every exported code is documented.
// Guards against docs drift when new codes are added or renamed.
//
//   npm run test:signed-result-codes

import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";

import { SIGNED_RESULT_ERROR_CODES } from "../src/execution-gate/verify-signed-result.mjs";

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

// Codes listed in docs/signed-execution-result-v1.md ## Stable Error Codes table.
const DOCUMENTED_CODES = new Set([
  "SIGNED_RESULT_SCHEMA_INVALID",
  "SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED",
  "SIGNED_RESULT_SIGNED_AT_FUTURE",
  "SIGNED_RESULT_AUTHORITY_CHAIN_INVALID",
  "SIGNED_RESULT_AUTHORITY_INVALID",
  "SIGNED_RESULT_AUTHORITY_MISMATCH",
  "SIGNED_RESULT_ALGORITHM_UNSUPPORTED",
  "SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID",
  "SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID",
  "SIGNED_RESULT_KEY_NOT_FOUND",
  "SIGNED_RESULT_KEY_REVOKED",
  "SIGNED_RESULT_KEY_EXPIRED",
  "SIGNED_RESULT_KEY_MALFORMED",
  "SIGNED_RESULT_SIGNATURE_MISSING",
  "SIGNED_RESULT_SIGNATURE_INVALID",
  "SIGNED_RESULT_HASH_FORMAT_INVALID",
  "SIGNED_RESULT_PAYLOAD_HASH_INVALID",
  "SIGNED_RESULT_CANONICALIZATION_INVALID",
  "SIGNED_RESULT_RECEIPT_BINDING_INVALID",
  "SIGNED_RESULT_RECEIPT_INVALID",
  "SIGNED_RESULT_RESULT_INVALID",
  "SIGNED_RESULT_KEY_ROLE_INVALID",
  "SIGNED_RESULT_DECISION_STATUS_INVALID",
  "SIGNED_RESULT_STARTED_TOO_OLD",
  "SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD",
]);

console.log("\nCode parity — documented vs reachable:");

test("SIGNED_RESULT_ERROR_CODES is a Set", () => {
  assert.ok(SIGNED_RESULT_ERROR_CODES instanceof Set, "SIGNED_RESULT_ERROR_CODES must be a Set");
  assert.ok(SIGNED_RESULT_ERROR_CODES.size > 0, "SIGNED_RESULT_ERROR_CODES must not be empty");
});

test("all documented codes are present in SIGNED_RESULT_ERROR_CODES", () => {
  for (const code of DOCUMENTED_CODES) {
    assert.ok(
      SIGNED_RESULT_ERROR_CODES.has(code),
      `documented code "${code}" is missing from SIGNED_RESULT_ERROR_CODES — update the verifier export or the docs`
    );
  }
});

test("all codes in SIGNED_RESULT_ERROR_CODES are documented in docs/signed-execution-result-v1.md", () => {
  for (const code of SIGNED_RESULT_ERROR_CODES) {
    assert.ok(
      DOCUMENTED_CODES.has(code),
      `reachable code "${code}" is not listed in docs/signed-execution-result-v1.md ## Stable Error Codes — update the docs`
    );
  }
});

test("all codes follow the SIGNED_RESULT_ naming convention", () => {
  for (const code of SIGNED_RESULT_ERROR_CODES) {
    assert.ok(
      code.startsWith("SIGNED_RESULT_"),
      `code "${code}" does not start with "SIGNED_RESULT_"`
    );
    assert.ok(
      /^[A-Z_]+$/.test(code),
      `code "${code}" must be SCREAMING_SNAKE_CASE`
    );
  }
});

// Static source scan: every fail(checks, "SIGNED_RESULT_...") call site in the verifier
// must be registered in SIGNED_RESULT_ERROR_CODES. Guards against forgotten registrations.
test("all fail() call site codes in verifier source are registered in SIGNED_RESULT_ERROR_CODES", () => {
  const require = createRequire(import.meta.url);
  const src = fs.readFileSync(require.resolve("../src/execution-gate/verify-signed-result.mjs"), "utf8");
  const re = /fail\(checks,\s*"(SIGNED_RESULT_[A-Z_]+)"/g;
  let m;
  const callSiteCodes = new Set();
  while ((m = re.exec(src)) !== null) callSiteCodes.add(m[1]);
  assert.ok(callSiteCodes.size > 0, "no fail() call sites found in verifier source");
  for (const code of callSiteCodes) {
    assert.ok(
      SIGNED_RESULT_ERROR_CODES.has(code),
      `verifier calls fail(checks, "${code}") but it is not in SIGNED_RESULT_ERROR_CODES`
    );
  }
});

const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
