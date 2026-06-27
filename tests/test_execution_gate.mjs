#!/usr/bin/env node
// Execution gate tests — hostile cases first, then behavioral cases, then
// integrity and regression checks.
//
//   npm run test:execution-gate

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import { evaluateExecutionGate, replayExecutionGate, validateExecutionRequest } from "../src/execution-gate/index.mjs";

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

// ---------------------------------------------------------------------------
// Minimal valid request builder — sets all required fields, then tests mutate.
// ---------------------------------------------------------------------------
function minimalRequest(overrides = {}) {
  const base = {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-001",
    requested_at: "2026-06-26T12:00:00.000Z",
    action: {
      type: "deploy",
      name: "deploy-api",
      dry_run: false
    },
    principal: {
      id: "octocat",
      type: "github_actor",
      issuer: "https://token.actions.githubusercontent.com",
      verified: true,
      claims: {}
    },
    resource: {
      kind: "service",
      id: "api-service",
      name: "API Service"
    },
    environment: {
      name: "staging"
    },
    risk: {
      level: "low",
      destructive: false,
      reversible: true,
      touches_secrets: false,
      touches_customer_data: false,
      blast_radius: "service"
    },
    cost: {
      estimated_cents: 0,
      dimensions: {}
    },
    approval: {
      required: false
    },
    evidence: {
      repo: "org/repo",
      commit_sha: "abc123",
      branch: "main"
    }
  };

  // Deep merge top-level fields then nested objects.
  const merged = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (typeof v === "object" && v !== null && !Array.isArray(v) &&
        typeof merged[k] === "object" && merged[k] !== null) {
      merged[k] = { ...merged[k], ...v };
    } else {
      merged[k] = v;
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Hostile validation tests — must REJECT
// ---------------------------------------------------------------------------

test("1. Reject missing schema_version", () => {
  const req = minimalRequest();
  delete req.schema_version;
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("schema_version")), `expected schema_version error, got: ${JSON.stringify(result.errors)}`);
});

test("2. Reject unknown schema_version", () => {
  const req = minimalRequest({ schema_version: "mnde.execution_request.v99" });
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("schema_version")), `errors: ${JSON.stringify(result.errors)}`);
});

test("3. Reject missing execution_id", () => {
  const req = minimalRequest();
  delete req.execution_id;
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("execution_id")), `errors: ${JSON.stringify(result.errors)}`);
});

test("4. Reject invalid action.type", () => {
  const req = minimalRequest({ action: { type: "explode", name: "x", dry_run: false } });
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("action.type")), `errors: ${JSON.stringify(result.errors)}`);
});

test("5. Reject invalid environment.name", () => {
  const req = minimalRequest({ environment: { name: "chaos" } });
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("environment.name")), `errors: ${JSON.stringify(result.errors)}`);
});

test("6. Reject invalid risk.level", () => {
  const req = minimalRequest({ risk: { level: "extreme", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "local" } });
  const result = validateExecutionRequest(req);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("risk.level")), `errors: ${JSON.stringify(result.errors)}`);
});

// ---------------------------------------------------------------------------
// Decision gate tests
// ---------------------------------------------------------------------------

test("7. REFUSE: production deploy when principal.verified=false", () => {
  const req = minimalRequest({
    environment: { name: "production" },
    principal: { verified: false }
  });
  const result = evaluateExecutionGate(req);
  assert.equal(result.ok, true);
  assert.equal(result.receipt.decision, "REFUSE");
  assert.equal(result.receipt.refusal_reason, "PRINCIPAL_NOT_VERIFIED");
});

test("8. ALLOW: staging deploy when principal.verified=true and risk.level=low", () => {
  const req = minimalRequest({ environment: { name: "staging" }, risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" } });
  const result = evaluateExecutionGate(req);
  assert.equal(result.ok, true);
  assert.equal(result.receipt.decision, "ALLOW");
  assert.equal(result.receipt.refusal_reason, undefined);
});

test("9. REFUSE: destructive production migration without approval", () => {
  const req = minimalRequest({
    action: { type: "migrate", name: "db-migrate", dry_run: false },
    environment: { name: "production" },
    risk: { level: "high", destructive: true, reversible: false, touches_secrets: false, touches_customer_data: true, blast_radius: "environment" },
    approval: { required: true }
    // approval_id intentionally absent
  });
  const result = evaluateExecutionGate(req);
  assert.equal(result.ok, true);
  assert.equal(result.receipt.decision, "REFUSE");
  // Gate 2 fires first (high + approval required + no approval_id)
  assert.ok(
    result.receipt.refusal_reason === "APPROVAL_REQUIRED" ||
    result.receipt.refusal_reason === "DESTRUCTIVE_REQUIRES_APPROVAL",
    `unexpected reason: ${result.receipt.refusal_reason}`
  );
});

test("10. ALLOW: destructive production migration with approval_id present AND principal.verified=true", () => {
  const req = minimalRequest({
    action: { type: "migrate", name: "db-migrate", dry_run: false },
    environment: { name: "production" },
    risk: { level: "high", destructive: true, reversible: false, touches_secrets: false, touches_customer_data: true, blast_radius: "environment" },
    approval: { required: true, approval_id: "appr-xyz-9999" }
  });
  const result = evaluateExecutionGate(req);
  assert.equal(result.ok, true);
  assert.equal(result.receipt.decision, "ALLOW");
});

test("11. Replay returns same decision for same request", () => {
  const req = minimalRequest();
  const gate = evaluateExecutionGate(req);
  assert.equal(gate.ok, true);
  const replay = replayExecutionGate(gate.receipt, req);
  assert.equal(replay.ok, true, `replay failed: ${replay.reason}`);
});

test("12. Duplicate execution_id: gate evaluates per-request (no cross-request state)", () => {
  // The gate is stateless — each call is independent. Deduplication is the
  // caller's responsibility (e.g. nonce store in the sidecar). This test
  // documents that behavior: two identical requests produce two identical,
  // independent receipts.
  const req = minimalRequest({ execution_id: "dedup-test-001" });
  const r1 = evaluateExecutionGate(req);
  const r2 = evaluateExecutionGate(req);
  assert.equal(r1.ok, true);
  assert.equal(r2.ok, true);
  // Receipts must be identical (deterministic).
  assert.equal(r1.receipt.request_hash, r2.receipt.request_hash);
  assert.equal(r1.receipt.receipt_hash, r2.receipt.receipt_hash);
  assert.equal(r1.receipt.decision, r2.receipt.decision);
  // NOTE: The gate does NOT enforce uniqueness across calls. If replay-protection
  // is needed, wire this into the sidecar nonce store (see test:nonce-replay).
});

test("13. Receipt integrity: receipt_hash matches recomputed hash", () => {
  const req = minimalRequest();
  const gate = evaluateExecutionGate(req);
  assert.equal(gate.ok, true);
  const receipt = gate.receipt;

  // Recompute: body = receipt without receipt_hash
  const { receipt_hash: storedHash, ...body } = receipt;
  const recomputed = createHash("sha256")
    .update(canonicalizeJson(body), "utf8")
    .digest("hex");
  assert.equal(storedHash, recomputed, "receipt_hash does not match recomputed hash");
});

// ---------------------------------------------------------------------------
// Regression: existing test suites must remain green
// ---------------------------------------------------------------------------

test("14. test_policy_receipt.mjs exits 0", () => {
  const result = spawnSync(
    process.execPath,
    ["tests/test_policy_receipt.mjs"],
    { cwd: repoRoot, encoding: "utf8", timeout: 60000 }
  );
  if (result.status !== 0) {
    throw new Error(`test_policy_receipt.mjs exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
});

test("15. test_signed_policy_bundle.mjs exits 0", () => {
  const result = spawnSync(
    process.execPath,
    ["tests/test_signed_policy_bundle.mjs"],
    { cwd: repoRoot, encoding: "utf8", timeout: 60000 }
  );
  if (result.status !== 0) {
    throw new Error(`test_signed_policy_bundle.mjs exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed}/${results.length} tests passed${failed > 0 ? `, ${failed} failed` : ""}`);
if (failed > 0) process.exit(1);
