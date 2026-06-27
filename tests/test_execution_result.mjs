#!/usr/bin/env node
// Hostile tests for mnde.execution_result.v2 — schema validation, verifier
// integrity, and decision-status consistency.
//
//   npm run test:execution-result

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { generateKeyPairSync } from "node:crypto";

import { canonicalizeJson } from "../shared/json.ts";
import { fingerprintOf, signCanonical } from "../src/custody/index.mjs";
import { buildExecutionResult, canonicalResultPayload, computeResultHash, validateExecutionResult } from "../src/execution-gate/result.mjs";
import { verifyExecutionResult } from "../src/execution-gate/verify-result.mjs";

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256Hex(obj) {
  return createHash("sha256").update(canonicalizeJson(obj), "utf8").digest("hex");
}

function minimalResult(overrides = {}) {
  const base = {
    schema_version: "mnde.execution_result.v2",
    result_id: "result-abc123",
    execution_request_hash: "a".repeat(64),
    execution_receipt_hash: "b".repeat(64),
    execution_id: "exec-001",
    status: "SUCCEEDED",
    decision: "ALLOW",
    executor: {
      id: "github-actions-runner",
      type: "github_actions",
      identity_evidence: {
        type: "github_oidc",
        subject: "repo:org/repo:ref:refs/heads/main",
        issuer: "https://token.actions.githubusercontent.com"
      },
      identity_evidence_asserted_only: true
    },
    started_at: "2026-06-26T12:00:00.000Z",
    ended_at: "2026-06-26T12:05:00.000Z",
    recorded_at: "2026-06-26T12:05:01.000Z",
    effects: [
      {
        type: "deployment",
        resource_id: "api-service",
        before: "sha256:" + "a".repeat(64),
        after: "sha256:" + "b".repeat(64)
      }
    ],
    evidence: [
      {
        type: "workflow_run",
        identifier: "github-actions://org/repo/runs/123456"
      }
    ]
  };
  const merged = deepMerge(base, overrides);
  return { ...merged, result_hash: computeResultHash(merged) };
}

function deepMerge(base, overrides) {
  const result = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (v && typeof v === "object" && !Array.isArray(v) && typeof result[k] === "object" && !Array.isArray(result[k])) {
      result[k] = deepMerge(result[k], v);
    } else {
      result[k] = v;
    }
  }
  return result;
}

// Generate a test Ed25519 key pair (executor signing key).
const { privateKey: executorPrivKey, publicKey: executorPubKey } = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" }
});

function signResult(result, privateKeyPem) {
  const canonical = canonicalResultPayload(result);
  const value = signCanonical(canonical, privateKeyPem);
  return {
    ...result,
    executor_signature: {
      algorithm: "ED25519",
      key_fingerprint: fingerprintOf(executorPubKey),
      value
    }
  };
}

// ---------------------------------------------------------------------------
// ── Hostile: structural validation ─────────────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — structural validation:");

test("rejects non-object", () => {
  const r = validateExecutionResult("string");
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("must be an object")));
});

test("rejects wrong schema_version", () => {
  const r = validateExecutionResult({ ...minimalResult(), schema_version: "mnde.execution_result.v1" });
  assert.strictEqual(r.ok, false);
});

test("rejects invalid result_id — no prefix", () => {
  const r = validateExecutionResult({ ...minimalResult(), result_id: "abc123" });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("result_id")));
});

test("rejects invalid result_id — path traversal attempt", () => {
  const r = validateExecutionResult({ ...minimalResult(), result_id: "result-../../../etc/passwd" });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("result_id")));
});

test("rejects non-hex execution_request_hash", () => {
  const r = validateExecutionResult({ ...minimalResult(), execution_request_hash: "ZZZZ" });
  assert.strictEqual(r.ok, false);
});

test("rejects short execution_receipt_hash", () => {
  const r = validateExecutionResult({ ...minimalResult(), execution_receipt_hash: "abcd" });
  assert.strictEqual(r.ok, false);
});

test("rejects invalid status", () => {
  const r = validateExecutionResult({ ...minimalResult(), status: "APPROVED" });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("status")));
});

test("rejects invalid decision", () => {
  const r = validateExecutionResult({ ...minimalResult(), decision: "ALLOW_IT" });
  assert.strictEqual(r.ok, false);
});

test("rejects invalid executor.type", () => {
  const r = validateExecutionResult({ ...minimalResult(), executor: { ...minimalResult().executor, type: "unknown_ci" } });
  assert.strictEqual(r.ok, false);
});

test("rejects missing identity_evidence_asserted_only", () => {
  const result = minimalResult();
  const { identity_evidence_asserted_only: _omit, ...executorWithout } = result.executor;
  const r = validateExecutionResult({ ...result, executor: executorWithout });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("identity_evidence_asserted_only")));
});

test("rejects identity_evidence_asserted_only: false", () => {
  const result = minimalResult();
  const r = validateExecutionResult({ ...result, executor: { ...result.executor, identity_evidence_asserted_only: false } });
  assert.strictEqual(r.ok, false);
});

test("rejects invalid identity_evidence.type", () => {
  const result = minimalResult();
  const r = validateExecutionResult({ ...result, executor: { ...result.executor, identity_evidence: { type: "aws_iam", subject: "x", issuer: "y" } } });
  assert.strictEqual(r.ok, false);
});

test("rejects non-OIDC evidence missing subject", () => {
  const result = minimalResult();
  const r = validateExecutionResult({ ...result, executor: { ...result.executor, identity_evidence: { type: "github_oidc", issuer: "https://example.com", identity_evidence_asserted_only: true } } });
  assert.strictEqual(r.ok, false);
});

test("rejects started_at after ended_at", () => {
  const result = minimalResult();
  const r = validateExecutionResult({ ...result, started_at: "2026-06-26T12:10:00.000Z", ended_at: "2026-06-26T12:00:00.000Z" });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("started_at must not be after ended_at")));
});

test("rejects invalid ISO-8601 started_at", () => {
  const result = minimalResult();
  const r = validateExecutionResult({ ...result, started_at: "June 26 2026" });
  assert.strictEqual(r.ok, false);
});

// ---------------------------------------------------------------------------
// ── Hostile: decision-status consistency ───────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — decision-status consistency:");

test("REFUSE + SUCCEEDED is rejected", () => {
  const result = minimalResult({ decision: "REFUSE", status: "SUCCEEDED" });
  const r = validateExecutionResult(result);
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("NOT_EXECUTED")));
});

test("REFUSE + FAILED is rejected", () => {
  const result = minimalResult({ decision: "REFUSE", status: "FAILED" });
  const r = validateExecutionResult(result);
  assert.strictEqual(r.ok, false);
});

test("REFUSE + PARTIALLY_SUCCEEDED is rejected", () => {
  const result = minimalResult({ decision: "REFUSE", status: "PARTIALLY_SUCCEEDED" });
  const r = validateExecutionResult(result);
  assert.strictEqual(r.ok, false);
});

test("REFUSE + ROLLED_BACK is rejected", () => {
  const result = minimalResult({ decision: "REFUSE", status: "ROLLED_BACK" });
  const r = validateExecutionResult(result);
  assert.strictEqual(r.ok, false);
});

test("REFUSE + UNKNOWN is rejected", () => {
  const result = minimalResult({ decision: "REFUSE", status: "UNKNOWN" });
  const r = validateExecutionResult(result);
  assert.strictEqual(r.ok, false);
});

test("REFUSE + NOT_EXECUTED is accepted", () => {
  const result = minimalResult({ decision: "REFUSE", status: "NOT_EXECUTED", effects: [], non_execution_reason: "MANUAL_ABORT" });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, true);
});

test("ALLOW + UNKNOWN is accepted (executor could not determine outcome)", () => {
  const result = minimalResult({ status: "UNKNOWN", effects: [] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, true);
});

// ---------------------------------------------------------------------------
// ── Hostile: effects validation ────────────────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — effects validation:");

test("SUCCEEDED with empty effects is rejected", () => {
  const result = minimalResult({ effects: [] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("non-empty") && e.includes("SUCCEEDED")));
});

test("PARTIALLY_SUCCEEDED with empty effects is rejected", () => {
  const result = minimalResult({ status: "PARTIALLY_SUCCEEDED", effects: [] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

test("effect with invalid type is rejected", () => {
  const result = minimalResult({ effects: [{ type: "rm_rf", resource_id: "x", before: null, after: null }] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

test("effect with malformed before digest is rejected", () => {
  const result = minimalResult({ effects: [{ type: "deployment", resource_id: "x", before: "notadigest", after: null }] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

test("evidence item with invalid type is rejected", () => {
  const result = minimalResult({ evidence: [{ type: "http_request", identifier: "https://example.com" }] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

test("evidence item with malformed digest is rejected", () => {
  const result = minimalResult({ evidence: [{ type: "artifact", identifier: "x", digest: "md5:abcd" }] });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

// ---------------------------------------------------------------------------
// ── Hostile: rollback required for rollback statuses ───────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — rollback required for rollback statuses:");

test("ROLLED_BACK without rollback object is rejected", () => {
  const result = minimalResult({ status: "ROLLED_BACK" });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("rollback is required")));
});

test("ROLLBACK_FAILED without rollback and error is rejected", () => {
  const result = minimalResult({ status: "ROLLBACK_FAILED" });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
});

test("ROLLED_BACK with valid rollback is accepted", () => {
  const result = minimalResult({
    status: "ROLLED_BACK",
    effects: [{ type: "deployment", resource_id: "svc", before: "sha256:" + "a".repeat(64), after: null }],
    rollback: {
      initiated_at: "2026-06-26T12:05:00.000Z",
      completed_at: "2026-06-26T12:06:00.000Z",
      method: "git-revert"
    }
  });
  const withHash = { ...result, result_hash: computeResultHash(result) };
  const r = validateExecutionResult(withHash);
  assert.strictEqual(r.ok, true, r.errors?.join("; "));
});

// ---------------------------------------------------------------------------
// ── Hostile: error required for FAILED statuses ────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — error object required for failure statuses:");

test("FAILED without error object is rejected", () => {
  const result = minimalResult({ status: "FAILED" });
  const r = validateExecutionResult({ ...result, result_hash: computeResultHash(result) });
  assert.strictEqual(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("error object is required")));
});

test("ROLLBACK_FAILED with error and rollback is accepted", () => {
  const result = minimalResult({
    status: "ROLLBACK_FAILED",
    effects: [{ type: "deployment", resource_id: "svc", before: "sha256:" + "a".repeat(64), after: "sha256:" + "b".repeat(64) }],
    rollback: { initiated_at: "2026-06-26T12:05:00.000Z", completed_at: null, method: "git-revert" },
    error: { code: "ROLLBACK_TIMEOUT", message: "rollback timed out after 60s" }
  });
  const withHash = { ...result, result_hash: computeResultHash(result) };
  const r = validateExecutionResult(withHash);
  assert.strictEqual(r.ok, true, r.errors?.join("; "));
});

// ---------------------------------------------------------------------------
// ── Hostile: result_hash tampering ─────────────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — result_hash integrity:");

test("tampered decision field fails result_hash check", () => {
  const result = minimalResult();
  const tampered = { ...result, decision: "REFUSE", status: "NOT_EXECUTED", effects: [], non_execution_reason: "MANUAL_ABORT" };
  // Re-use original result_hash (not recomputed for tampered content).
  const r = verifyExecutionResult({ ...tampered, result_hash: result.result_hash });
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("result_hash"));
});

test("tampered executor.id fails result_hash check", () => {
  const result = minimalResult();
  const tampered = { ...result, executor: { ...result.executor, id: "evil-runner" } };
  const r = verifyExecutionResult({ ...tampered, result_hash: result.result_hash });
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("result_hash"));
});

test("tampered effects array fails result_hash check", () => {
  const result = minimalResult();
  const tampered = {
    ...result,
    effects: [{ type: "deployment", resource_id: "evil-service", before: null, after: "sha256:" + "f".repeat(64) }]
  };
  const r = verifyExecutionResult({ ...tampered, result_hash: result.result_hash });
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("result_hash"));
});

test("recomputed result_hash over tampered content does not pass structure check", () => {
  // Attacker recomputes hash after tampering — but tampered content fails structural validation.
  const result = minimalResult({ decision: "REFUSE", status: "SUCCEEDED" });
  // result_hash is recomputed over the tampered content
  const r = verifyExecutionResult(result);
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("structure") || r.reason.includes("decision_status_consistency"));
});

// ---------------------------------------------------------------------------
// ── Hostile: executor_signature tampering ──────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — executor_signature:");

test("executor_signature present but no public key provided — fails closed", () => {
  const result = signResult(minimalResult(), executorPrivKey);
  const r = verifyExecutionResult(result); // no executorPublicKey
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("executor_signature"));
});

test("executor_signature with wrong key fails", () => {
  const result = signResult(minimalResult(), executorPrivKey);
  const { privateKey: otherPrivKey, publicKey: otherPubKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  // Provide the wrong public key for verification.
  const r = verifyExecutionResult(result, { executorPublicKey: otherPubKey });
  assert.strictEqual(r.verified, false);
});

test("executor_signature with self-reported fingerprint spoofing attempt fails", () => {
  // Attacker signs with their key but claims the fingerprint of the legitimate key.
  const { privateKey: attackerPrivKey, publicKey: attackerPubKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const result = minimalResult();
  const canonical = canonicalResultPayload(result);
  const value = signCanonical(canonical, attackerPrivKey);
  const spoofed = {
    ...result,
    executor_signature: {
      algorithm: "ED25519",
      // Claims legitimate key fingerprint, but was signed with attacker key.
      key_fingerprint: fingerprintOf(executorPubKey),
      value
    }
  };
  // Verifier derives fingerprint from executorPubKey (legitimate), compares to
  // self-reported value in spoofed sig — fingerprints match but Ed25519 verify
  // fails because signature was made with attacker key.
  const r = verifyExecutionResult(spoofed, { executorPublicKey: executorPubKey });
  assert.strictEqual(r.verified, false);
});

test("tampered result body fails executor_signature even with correct key", () => {
  const signed = signResult(minimalResult(), executorPrivKey);
  const tampered = { ...signed, execution_id: "tampered-exec-id" };
  // Recompute result_hash so hash check passes, but sig now fails.
  const withNewHash = { ...tampered, result_hash: computeResultHash(tampered) };
  const r = verifyExecutionResult(withNewHash, { executorPublicKey: executorPubKey });
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("executor_signature"));
});

test("valid signed result verifies successfully", () => {
  const result = minimalResult();
  const signed = signResult(result, executorPrivKey);
  const withHash = { ...signed, result_hash: computeResultHash(signed) };
  const r = verifyExecutionResult(withHash, { executorPublicKey: executorPubKey });
  assert.strictEqual(r.verified, true, r.reason);
  assert.ok(r.checks.executor_signature.ok);
});

// ---------------------------------------------------------------------------
// ── Hostile: receipt hash binding ──────────────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nHostile — receipt hash binding:");

test("mismatched execution_receipt_hash fails when original receipt provided", () => {
  const fakeReceipt = { decision: "ALLOW", execution_id: "exec-001" };
  const result = minimalResult(); // has "b".repeat(64) as receipt hash, not the real hash
  const r = verifyExecutionResult(result, { originalReceipt: fakeReceipt });
  assert.strictEqual(r.verified, false);
  assert.ok(r.reason.includes("receipt_hash_binding"));
});

test("correct execution_receipt_hash passes when original receipt provided", () => {
  const fakeReceipt = { decision: "ALLOW", execution_id: "exec-001" };
  const receiptHash = sha256Hex(fakeReceipt);
  const result = minimalResult({ execution_receipt_hash: receiptHash });
  const r = verifyExecutionResult(result, { originalReceipt: fakeReceipt });
  assert.strictEqual(r.verified, true, r.reason);
  assert.ok(r.checks.receipt_hash_binding.ok);
});

// ---------------------------------------------------------------------------
// ── Behavioral: valid result passes verifier ───────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nBehavioral — valid results:");

test("minimal valid unsigned result verifies", () => {
  const result = minimalResult();
  const r = verifyExecutionResult(result);
  assert.strictEqual(r.verified, true, r.reason);
  // Unsigned result is noted but not a failure.
  assert.ok(r.checks.executor_signature.detail.includes("executor-asserted"));
  // Identity always noted as asserted.
  assert.ok(r.checks.identity_evidence.detail.includes("executor-reported"));
});

test("buildExecutionResult throws on invalid body", () => {
  assert.throws(() => buildExecutionResult({ schema_version: "mnde.execution_result.v2" }), /invalid result/);
});

test("buildExecutionResult produces a verifiable result", () => {
  const base = { ...minimalResult() };
  const { result_hash: _rh, ...withoutHash } = base;
  const built = buildExecutionResult(withoutHash);
  assert.strictEqual(built.schema_version, "mnde.execution_result.v2");
  const r = verifyExecutionResult(built);
  assert.strictEqual(r.verified, true, r.reason);
});

// ---------------------------------------------------------------------------
// ── duration_ms is not a v2 field ──────────────────────────────────────────
// ---------------------------------------------------------------------------
console.log("\nRegression — duration_ms absent from v2:");

test("duration_ms is not defined in validateExecutionResult schema", () => {
  // A result with duration_ms still passes — extra fields are ignored by
  // schema validation, but we confirm the field is not *required*.
  const result = minimalResult();
  // duration_ms must NOT appear in the canonical payload.
  const canonical = JSON.parse(canonicalResultPayload(result));
  assert.strictEqual(canonical.duration_ms, undefined);
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
