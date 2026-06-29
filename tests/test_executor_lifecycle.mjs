#!/usr/bin/env node
// Executor lifecycle probe for Execution Passport readiness.
//
// Questions answered:
//   1. Same config, multiple runs — is passport_subject_id stable?
//   2. executor.id changes (restart, container recreate) — subject unchanged?
//   3. Key rotation (new signing key, same OIDC identity) — subject unchanged?
//   4. verified_identity changes (different repo/branch/actor) — subject changes?
//   5. issuer changes — subject changes?
//   6. authority_scope changes (different chain) — subject changes?
//   7. No identity_assertion — passport_subject_id is null?
//   8. Revoked authority — verification fails, no verdict?
//   9. Changed identity in existing assertion (tampered after signing) — fails?
//  10. Multiple assertions on the same run — all produce same subject?
//
// All tests are offline — no live sidecar required.
//
//   npm run test:executor-lifecycle

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair
} from "../src/custody/index.mjs";
import {
  buildIdentityAssertion,
  IDENTITY_ASSERTION_SCHEMA
} from "../src/identity/assertion.mjs";
import { GITHUB_ACTIONS_ISSUER } from "../src/identity/adapters/github-actions.mjs";
import { buildExecutionResult } from "../src/execution-gate/result.mjs";
import { buildSignedExecutionReceipt } from "../src/execution-gate/signed-receipt.mjs";
import { buildSignedExecutionResult } from "../src/execution-gate/signed-result.mjs";
import { verifySignedExecutionResult } from "../src/execution-gate/verify-signed-result.mjs";
import { computePassportSubjectId } from "../src/identity/passport.mjs";

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
// Shared fixtures
// ---------------------------------------------------------------------------

const SIGNED_AT = "2026-06-27T00:01:00.000Z";
const NOW_ISO = "2026-06-27T00:01:00.000Z";
const AUTHORITY_CHAIN_ID = "mnde-acme-prod-chain";
const ALT_CHAIN_ID = "mnde-acme-staging-chain";

function sha256Hex(obj) {
  return createHash("sha256").update(canonicalizeJson(obj), "utf8").digest("hex");
}

function makeBundle({ revoke = [] } = {}) {
  const root = { keyId: "root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "receipt-key", ...generateAuthorityKeyPair() };
  const resultKey = { keyId: "result-key", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-key", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-key", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "mnde-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    resultKeys: [{ keyId: resultKey.keyId, publicPem: resultKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    revocation: revoke
  });
  return { root, receiptKey, resultKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

// Base bundle — stable across all tests that don't need rotation or revocation.
const F = makeBundle();

function minimalRequest(id) {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: id,
    requested_at: "2026-06-27T00:00:00.000Z",
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: GITHUB_ACTIONS_ISSUER, verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: "production" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "acme/infra", commit_sha: "abc123", branch: "main" }
  };
}

function makeSignedReceipt(fixtures, request) {
  return buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: fixtures.bundle,
    signingKeyId: fixtures.receiptKey.keyId,
    signingPrivateKeyPem: fixtures.receiptKey.privatePem
  });
}

function makeAssertion({
  verified_identity = "repo:acme/infra:ref:refs/heads/main",
  identity_issuer = GITHUB_ACTIONS_ISSUER,
  asserted_identity,
  verified_at = "2026-06-27T00:00:00.000Z"
} = {}) {
  return buildIdentityAssertion({
    asserted_identity: asserted_identity ?? verified_identity,
    verified_identity,
    identity_verification_method: "github_actions_oidc",
    identity_issuer,
    identity_subject: verified_identity,
    identity_audience: "https://mnde.example.com",
    identity_token_hash: "sha256:" + "a".repeat(64),
    verifier_name: "mnde-github-actions-verifier",
    verifier_version: "1.0.0",
    verifier_policy_hash: "sha256:" + "b".repeat(64),
    verified_at
  });
}

function makeExecutionResult(signedReceipt, { identityAssertion, executorId = "runner-12345" } = {}) {
  const receiptHash = sha256Hex(signedReceipt);
  const body = {
    schema_version: "mnde.execution_result.v2",
    result_id: "result-lifecycle-001",
    execution_id: signedReceipt.execution_id,
    execution_request_hash: signedReceipt.request_hash,
    execution_receipt_hash: receiptHash,
    decision: "ALLOW",
    status: "SUCCEEDED",
    executor: {
      id: executorId,
      type: "github_actions",
      identity_evidence: {
        type: "github_oidc",
        subject: identityAssertion?.verified_identity ?? "repo:acme/infra:ref:refs/heads/main",
        issuer: identityAssertion?.identity_issuer ?? GITHUB_ACTIONS_ISSUER
      },
      identity_evidence_asserted_only: true,
      ...(identityAssertion !== undefined ? { identity_assertion: identityAssertion } : {})
    },
    started_at: "2026-06-27T00:00:30.000Z",
    ended_at: SIGNED_AT,
    recorded_at: SIGNED_AT,
    effects: [{ type: "deployment", resource_id: "api-service", before: "sha256:" + "a".repeat(64), after: "sha256:" + "b".repeat(64) }],
    evidence: [{ type: "workflow_run", identifier: "run-99999" }]
  };
  return buildExecutionResult(body);
}

function makeSignedResult(fixtures, signedReceipt, executionResult, chainId = AUTHORITY_CHAIN_ID) {
  return buildSignedExecutionResult(executionResult, {
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    signingKeyId: fixtures.resultKey.keyId,
    signingPrivateKeyPem: fixtures.resultKey.privatePem,
    authorityChainId: chainId,
    signedAt: SIGNED_AT,
    now: NOW_ISO,
    signedReceipt
  });
}

function verify(fixtures, envelope, signedReceipt) {
  return verifySignedExecutionResult(envelope, {
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    now: NOW_ISO,
    signedReceipt
  });
}

// ---------------------------------------------------------------------------
// 1. Stability: same config, multiple runs
// ---------------------------------------------------------------------------

console.log("\n1. Same config, multiple runs — passport_subject_id must be stable:");

test("run 1 and run 2 with identical config produce the same passport_subject_id", () => {
  const assertion = makeAssertion();

  const req1 = minimalRequest("exec-lifecycle-run1");
  const receipt1 = makeSignedReceipt(F, req1);
  const result1 = makeExecutionResult(receipt1, { identityAssertion: assertion });
  const env1 = makeSignedResult(F, receipt1, result1);
  const v1 = verify(F, env1, receipt1);

  const req2 = minimalRequest("exec-lifecycle-run2");
  const receipt2 = makeSignedReceipt(F, req2);
  const result2 = makeExecutionResult(receipt2, { identityAssertion: assertion });
  const env2 = makeSignedResult(F, receipt2, result2);
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid, `run 1: ${v1.code}`);
  assert.ok(v2.valid, `run 2: ${v2.code}`);
  assert.ok(v1.passport_subject_id, "run 1 must have a passport_subject_id");
  assert.ok(v2.passport_subject_id, "run 2 must have a passport_subject_id");
  assert.strictEqual(v1.passport_subject_id, v2.passport_subject_id);
});

test("run N times — passport_subject_id is identical across all runs", () => {
  const assertion = makeAssertion();
  const subjectIds = [];
  for (let i = 0; i < 5; i++) {
    const req = minimalRequest(`exec-lifecycle-stable-${i}`);
    const receipt = makeSignedReceipt(F, req);
    const result = makeExecutionResult(receipt, { identityAssertion: assertion });
    const env = makeSignedResult(F, receipt, result);
    const v = verify(F, env, receipt);
    assert.ok(v.valid, `run ${i}: ${v.code}`);
    subjectIds.push(v.passport_subject_id);
  }
  const unique = new Set(subjectIds);
  assert.strictEqual(unique.size, 1, `expected 1 unique subject, got ${unique.size}: ${[...unique].join(", ")}`);
});

// ---------------------------------------------------------------------------
// 2. executor.id changes — passport_subject_id must not change
// ---------------------------------------------------------------------------

console.log("\n2. executor.id changes (restart, container recreate):");

test("different executor.id with same identity produces same passport_subject_id", () => {
  const assertion = makeAssertion();
  const executorIds = ["runner-11111", "runner-22222", "container-abc-def", "github-runner-XYZ"];
  const subjectIds = [];
  let i = 0;
  for (const executorId of executorIds) {
    const req = minimalRequest(`exec-lifecycle-execid-${i++}`);
    const receipt = makeSignedReceipt(F, req);
    const result = makeExecutionResult(receipt, { identityAssertion: assertion, executorId });
    const env = makeSignedResult(F, receipt, result);
    const v = verify(F, env, receipt);
    assert.ok(v.valid, `executor ${executorId}: ${v.code}`);
    subjectIds.push(v.passport_subject_id);
  }
  const unique = new Set(subjectIds);
  assert.strictEqual(unique.size, 1, `executor.id change must not change passport_subject_id, got ${unique.size} unique values`);
});

// ---------------------------------------------------------------------------
// 3. Key rotation — same identity, new result signing key
// ---------------------------------------------------------------------------

console.log("\n3. Key rotation — passport_subject_id must not change:");

test("new result signing key with same OIDC identity produces same passport_subject_id", () => {
  const assertion = makeAssertion(); // verified_identity is unchanged

  // Original bundle + signing
  const req1 = minimalRequest("exec-lifecycle-key-before");
  const receipt1 = makeSignedReceipt(F, req1);
  const result1 = makeExecutionResult(receipt1, { identityAssertion: assertion });
  const env1 = makeSignedResult(F, receipt1, result1);
  const v1 = verify(F, env1, receipt1);

  // Rotated bundle — new result key, same identity assertion
  const F2 = makeBundle();
  const req2 = minimalRequest("exec-lifecycle-key-after");
  const receipt2 = makeSignedReceipt(F2, req2);
  const result2 = makeExecutionResult(receipt2, { identityAssertion: assertion });
  const env2 = makeSignedResult(F2, receipt2, result2);
  const v2 = verify(F2, env2, receipt2);

  assert.ok(v1.valid, `before rotation: ${v1.code}`);
  assert.ok(v2.valid, `after rotation: ${v2.code}`);
  assert.notStrictEqual(v1.signing_key_fingerprint, v2.signing_key_fingerprint, "keys must differ");
  assert.strictEqual(v1.passport_subject_id, v2.passport_subject_id, "subject must be same after key rotation");
});

// ---------------------------------------------------------------------------
// 4. verified_identity changes — passport_subject_id must change
// ---------------------------------------------------------------------------

console.log("\n4. verified_identity changes:");

test("different repo in verified_identity produces different passport_subject_id", () => {
  const a1 = makeAssertion({ verified_identity: "repo:acme/infra:ref:refs/heads/main" });
  const a2 = makeAssertion({ verified_identity: "repo:acme/payments:ref:refs/heads/main" });

  const req1 = minimalRequest("exec-lifecycle-vi1");
  const receipt1 = makeSignedReceipt(F, req1);
  const result1 = makeExecutionResult(receipt1, { identityAssertion: a1 });
  const env1 = makeSignedResult(F, receipt1, result1);
  const v1 = verify(F, env1, receipt1);

  const req2 = minimalRequest("exec-lifecycle-vi2");
  const receipt2 = makeSignedReceipt(F, req2);
  const result2 = makeExecutionResult(receipt2, { identityAssertion: a2 });
  const env2 = makeSignedResult(F, receipt2, result2);
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid && v2.valid, "both must verify");
  assert.notStrictEqual(v1.passport_subject_id, v2.passport_subject_id);
});

test("PR branch vs main branch produces different passport_subject_id", () => {
  const main = makeAssertion({ verified_identity: "repo:acme/infra:ref:refs/heads/main" });
  const pr = makeAssertion({ verified_identity: "repo:acme/infra:ref:refs/pull/42/head" });

  const req1 = minimalRequest("exec-lifecycle-main");
  const receipt1 = makeSignedReceipt(F, req1);
  const env1 = makeSignedResult(F, receipt1, makeExecutionResult(receipt1, { identityAssertion: main }));
  const v1 = verify(F, env1, receipt1);

  const req2 = minimalRequest("exec-lifecycle-pr");
  const receipt2 = makeSignedReceipt(F, req2);
  const env2 = makeSignedResult(F, receipt2, makeExecutionResult(receipt2, { identityAssertion: pr }));
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid && v2.valid, "both must verify");
  assert.notStrictEqual(v1.passport_subject_id, v2.passport_subject_id);
});

// ---------------------------------------------------------------------------
// 5. Issuer changes — passport_subject_id must change
// ---------------------------------------------------------------------------

console.log("\n5. Issuer changes:");

test("GitHub issuer vs GitLab issuer produces different passport_subject_id for same subject", () => {
  // Same verified_identity string, but from different issuers.
  // In practice OIDC subjects would differ too, but the derivation ensures
  // the issuer alone is enough to differentiate.
  const github = makeAssertion({ identity_issuer: GITHUB_ACTIONS_ISSUER });
  const gitlab = makeAssertion({ identity_issuer: "https://gitlab.com" });

  const req1 = minimalRequest("exec-lifecycle-gh");
  const receipt1 = makeSignedReceipt(F, req1);
  const env1 = makeSignedResult(F, receipt1, makeExecutionResult(receipt1, { identityAssertion: github }));
  const v1 = verify(F, env1, receipt1);

  const req2 = minimalRequest("exec-lifecycle-gl");
  const receipt2 = makeSignedReceipt(F, req2);
  const env2 = makeSignedResult(F, receipt2, makeExecutionResult(receipt2, { identityAssertion: gitlab }));
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid && v2.valid, "both must verify");
  assert.notStrictEqual(v1.passport_subject_id, v2.passport_subject_id);
});

// ---------------------------------------------------------------------------
// 6. authority_scope changes — passport_subject_id must change
// ---------------------------------------------------------------------------

console.log("\n6. authority_scope (authority_chain_id) changes:");

test("different authority_chain_id produces different passport_subject_id for same identity", () => {
  const assertion = makeAssertion();

  const req1 = minimalRequest("exec-lifecycle-scope1");
  const receipt1 = makeSignedReceipt(F, req1);
  const env1 = makeSignedResult(F, receipt1, makeExecutionResult(receipt1, { identityAssertion: assertion }), AUTHORITY_CHAIN_ID);

  const req2 = minimalRequest("exec-lifecycle-scope2");
  const receipt2 = makeSignedReceipt(F, req2);
  const env2 = makeSignedResult(F, receipt2, makeExecutionResult(receipt2, { identityAssertion: assertion }), ALT_CHAIN_ID);

  const v1 = verify(F, env1, receipt1);
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid && v2.valid, "both must verify");
  assert.notStrictEqual(v1.passport_subject_id, v2.passport_subject_id);
});

// ---------------------------------------------------------------------------
// 7. No identity_assertion — passport_subject_id is null
// ---------------------------------------------------------------------------

console.log("\n7. No identity_assertion:");

test("result without identity_assertion has passport_subject_id: null", () => {
  const req = minimalRequest("exec-lifecycle-no-assertion");
  const receipt = makeSignedReceipt(F, req);
  const result = makeExecutionResult(receipt, { identityAssertion: undefined });
  const env = makeSignedResult(F, receipt, result);
  const v = verify(F, env, receipt);
  assert.ok(v.valid, `should verify: ${v.code}`);
  assert.strictEqual(v.identity_evidence, "ASSERTED_ONLY");
  assert.strictEqual(v.passport_subject_id, null);
});

// ---------------------------------------------------------------------------
// 8. Revoked authority — verification fails
// ---------------------------------------------------------------------------

console.log("\n8. Revoked authority:");

test("result signed by revoked result key fails verification", () => {
  // Build a bundle identical to F but with the result key revoked.
  // Use the SAME root key so trustedRootFingerprint still matches.
  // Generate fresh keys for policy and approval to avoid fingerprint collisions.
  const policyKey = { keyId: "revoke-test-policy-key", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "revoke-test-approval-key", ...generateAuthorityKeyPair() };

  const revokedBundle = buildAuthorityBundle({
    authorityId: "mnde-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root: F.root,
    receiptKeys: [{ keyId: F.receiptKey.keyId, publicPem: F.receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    resultKeys: [{ keyId: F.resultKey.keyId, publicPem: F.resultKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    revocation: [F.resultKey.keyId]
  });

  const assertion = makeAssertion();
  const req = minimalRequest("exec-lifecycle-revoked");
  const receipt = makeSignedReceipt(F, req);
  const result = makeExecutionResult(receipt, { identityAssertion: assertion });
  // Sign with the original (non-revoked) bundle.
  const env = makeSignedResult(F, receipt, result);

  // Verify against the bundle with the result key revoked.
  const v = verifySignedExecutionResult(env, {
    authorityBundle: revokedBundle,
    trustedRootFingerprint: F.trustedRootFingerprint,
    now: NOW_ISO,
    signedReceipt: receipt
  });
  assert.strictEqual(v.valid, false);
  assert.strictEqual(v.code, "SIGNED_RESULT_KEY_REVOKED");
});

// ---------------------------------------------------------------------------
// 9. Tampered identity_assertion after signing fails
// ---------------------------------------------------------------------------

console.log("\n9. Tampered identity after signing:");

test("identity_assertion tampered post-signing fails verification — no passport_subject_id leaks", () => {
  const assertion = makeAssertion();
  const req = minimalRequest("exec-lifecycle-tamper");
  const receipt = makeSignedReceipt(F, req);
  const result = makeExecutionResult(receipt, { identityAssertion: assertion });
  const env = makeSignedResult(F, receipt, result);

  // Swap verified_identity inside the envelope's assertion (keeps assertion_hash intact
  // so structural check passes, but hash mismatch detected by verifyIdentityAssertion).
  const tampered = {
    ...env,
    execution_result: {
      ...env.execution_result,
      executor: {
        ...env.execution_result.executor,
        identity_assertion: {
          ...assertion,
          verified_identity: "repo:attacker/evil:ref:refs/heads/main"
        }
      }
    }
  };
  const v = verify(F, tampered, receipt);
  assert.strictEqual(v.valid, false);
  // No passport_subject_id must appear in the failed verdict.
  assert.strictEqual(v.passport_subject_id, undefined);
});

// ---------------------------------------------------------------------------
// 10. passport_subject_id matches expected derivation formula
// ---------------------------------------------------------------------------

console.log("\n10. passport_subject_id derivation correctness:");

test("passport_subject_id in verdict matches computePassportSubjectId output", () => {
  const assertion = makeAssertion();
  const req = minimalRequest("exec-lifecycle-formula");
  const receipt = makeSignedReceipt(F, req);
  const result = makeExecutionResult(receipt, { identityAssertion: assertion });
  const env = makeSignedResult(F, receipt, result);
  const v = verify(F, env, receipt);

  assert.ok(v.valid, `should verify: ${v.code}`);
  const expected = computePassportSubjectId({
    issuer: assertion.identity_issuer,
    verified_identity: assertion.verified_identity,
    authority_scope: AUTHORITY_CHAIN_ID
  });
  assert.strictEqual(v.passport_subject_id, expected);
});

test("passport_subject_id does not include executor.id, key_id, or timestamp", () => {
  // Verify by formula: none of these fields appear in the canonical input.
  // The result is that two results with different executor.id, key_id, or
  // timestamps but the same (issuer, verified_identity, authority_scope) produce
  // the same passport_subject_id.
  const assertion1 = makeAssertion({ verified_at: "2026-06-27T00:00:00.000Z" });
  const assertion2 = makeAssertion({ verified_at: "2026-06-27T12:00:00.000Z" });

  const req1 = minimalRequest("exec-lifecycle-ts1");
  const receipt1 = makeSignedReceipt(F, req1);
  const env1 = makeSignedResult(F, receipt1, makeExecutionResult(receipt1, { identityAssertion: assertion1, executorId: "runner-A" }));
  const v1 = verify(F, env1, receipt1);

  const req2 = minimalRequest("exec-lifecycle-ts2");
  const receipt2 = makeSignedReceipt(F, req2);
  const env2 = makeSignedResult(F, receipt2, makeExecutionResult(receipt2, { identityAssertion: assertion2, executorId: "runner-B" }));
  const v2 = verify(F, env2, receipt2);

  assert.ok(v1.valid && v2.valid, "both must verify");
  assert.strictEqual(v1.passport_subject_id, v2.passport_subject_id,
    "different executor.id and verified_at must not change passport_subject_id");
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

const passed = results.filter(Boolean).length;
const failed = results.filter(r => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
