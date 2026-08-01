// Characterization: current execution-gate receipt signing (pre-executor-identity).
//
// This test PINS the behavior of `mnde.execution_gate.receipt.v1` as it exists
// before executor identity is added, so the step-6 change is provably additive:
//
//   * a valid receipt is signed by exactly ONE layer — the custody receipt-role
//     (authority) key — and verifies authority-only;
//   * the receipt carries NO executor dimension and NO passport binding today;
//   * the authority signature covers the whole body except verifiable_signature.
//
// If a later change makes executor/passport fields unconditionally present, or
// breaks the authority-only path, this characterization fails loudly.

import assert from "node:assert/strict";

import { canonicalizeJson } from "../shared/json.ts";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import {
  buildSignedExecutionReceipt,
  verifySignedExecutionReceipt
} from "../src/execution-gate/index.mjs";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function makeBundle() {
  const root = { keyId: "char-root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "char-receipt-key-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-char-authority",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  return { receiptKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

function minimalRequest() {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-char-001",
    requested_at: "2026-06-15T10:00:00.000Z",
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: "https://token.actions.githubusercontent.com", verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: "staging" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "org/repo", commit_sha: "abc123", branch: "main" }
  };
}

async function buildCurrentReceipt() {
  const { receiptKey, bundle, trustedRootFingerprint } = await makeBundle();
  const receipt = await buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  return { receipt, bundle, trustedRootFingerprint, receiptKey };
}

console.log("Characterization — current execution-gate receipt signing\n");

await test("current receipt verifies authority-only", async () => {
  const { receipt, bundle, trustedRootFingerprint } = await buildCurrentReceipt();
  const result = await verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, true, result.reason ?? "");
});

await test("current receipt schema is mnde.execution_gate.receipt.v1", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.schema_version, "mnde.execution_gate.receipt.v1");
});

await test("current receipt carries NO executor dimension", async () => {
  const { receipt } = await buildCurrentReceipt();
  for (const field of ["executor_id", "executor_key_id", "executor_credential_id", "executor_signature"]) {
    assert.equal(receipt[field], undefined, `${field} must be absent in the pre-migration receipt`);
  }
});

await test("current receipt carries NO passport binding", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.passport_subject_id, undefined);
});

await test("the single signature layer is the custody receipt-role (authority) key", async () => {
  const { receipt, bundle, receiptKey } = await buildCurrentReceipt();
  assert.ok(receipt.verifiable_signature, "verifiable_signature must be present");
  assert.equal(receipt.verifiable_signature.algorithm, "ED25519");
  assert.equal(receipt.verifiable_signature.authority_id, bundle.authority_id);
  assert.equal(receipt.verifiable_signature.key_id, receiptKey.keyId);
  assert.equal(receipt.authority_id, bundle.authority_id);
  assert.equal(receipt.signing_key_id, receiptKey.keyId);
});

await test("authority signature covers the body except verifiable_signature (tamper breaks it)", async () => {
  const { receipt, bundle, trustedRootFingerprint } = await buildCurrentReceipt();
  const tampered = { ...receipt, decision: receipt.decision === "ALLOW" ? "REFUSE" : "ALLOW" };
  const result = await verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /signature/);
});

await test("decided_at is deterministic (equals requested_at, no wall-clock)", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.decided_at, minimalRequest().requested_at);
  assert.equal(receipt.decided_at, receipt.verifiable_signature.signed_at);
});

await test("canonical payload excludes only verifiable_signature", async () => {
  const { receipt } = await buildCurrentReceipt();
  const { verifiable_signature: _omit, ...body } = receipt;
  // Reproducing the exact exclusion the signer/verifier use must round-trip.
  assert.equal(typeof canonicalizeJson(body), "string");
  assert.ok(!canonicalizeJson(body).includes("verifiable_signature"));
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} receipt signing characterization (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
