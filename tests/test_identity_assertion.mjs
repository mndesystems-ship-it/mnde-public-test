#!/usr/bin/env node
// Tests for mnde.identity_assertion.v1 — assertion primitives, verifier,
// GitHub Actions OIDC adapter, and signed result integration.
//
//   npm run test:identity-assertion

import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";

import { canonicalizeJson } from "../shared/json.ts";
import { sha256 } from "../src/crypto/provider.mjs";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair
} from "../src/custody/index.mjs";
import {
  buildIdentityAssertion,
  computeAssertionHash,
  IDENTITY_ASSERTION_SCHEMA,
  validateIdentityAssertion
} from "../src/identity/assertion.mjs";
import { verifyIdentityAssertion } from "../src/identity/verify-assertion.mjs";
import {
  GITHUB_ACTIONS_ISSUER,
  verifyGitHubActionsOidc
} from "../src/identity/adapters/github-actions.mjs";
import { buildExecutionResult } from "../src/execution-gate/result.mjs";
import { buildSignedExecutionReceipt } from "../src/execution-gate/signed-receipt.mjs";
import { buildSignedExecutionResult } from "../src/execution-gate/signed-result.mjs";
import { verifyExecutionResult } from "../src/execution-gate/verify-result.mjs";
import { verifySignedExecutionResult } from "../src/execution-gate/verify-signed-result.mjs";

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}

// ---------------------------------------------------------------------------
// RSA key pair for adapter tests
// ---------------------------------------------------------------------------

const KID = "test-key-1";
const { privateKey: RSA_PRIVATE, publicKey: RSA_PUBLIC } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const RSA_PUBLIC_JWK = RSA_PUBLIC.export({ format: "jwk" });
const JWKS = { keys: [{ ...RSA_PUBLIC_JWK, kid: KID, use: "sig", alg: "RS256" }] };

function sha256TaggedObj(obj) {
  return "sha256:" + sha256(canonicalizeJson(obj));
}

function sha256Hex(obj) {
  return sha256(canonicalizeJson(obj));
}

const TRUSTED_JWKS_HASH = sha256TaggedObj(JWKS);

const BASE_POLICY = {
  issuer: GITHUB_ACTIONS_ISSUER,
  audience: "https://mnde.example.com",
  subject_allowlist: ["repo:acme/infra:ref:refs/heads/main"],
  trusted_jwks_hash: TRUSTED_JWKS_HASH,
  max_token_age_seconds: 600,
  clock_skew_seconds: 30
};

// Build a signed JWT.
// Pass null for iat or exp to omit those fields entirely (null = sentinel;
// undefined would trigger the default from destructuring).
function makeJwt({
  iss = GITHUB_ACTIONS_ISSUER,
  aud = "https://mnde.example.com",
  sub = "repo:acme/infra:ref:refs/heads/main",
  iat = 1_750_000_000,
  exp = 1_750_000_600,
  nbf,
  alg = "RS256",
  kid = KID,
  privateKey = RSA_PRIVATE
} = {}) {
  const payloadObj = {
    iss, aud, sub,
    ...(iat !== null ? { iat } : {}),
    ...(exp !== null ? { exp } : {}),
    ...(nbf !== null && nbf !== undefined ? { nbf } : {})
  };
  const header = Buffer.from(JSON.stringify({ alg, typ: "JWT", kid })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const signingInput = header + "." + payload;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput, "ascii");
  return signingInput + "." + signer.sign(privateKey).toString("base64url");
}

// Build a JWT from an arbitrary payload object — for string-claim hostile tests.
function makeJwtFromPayload(payloadObj, { alg = "RS256", kid = KID, privateKey = RSA_PRIVATE } = {}) {
  const header = Buffer.from(JSON.stringify({ alg, typ: "JWT", kid })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const signingInput = header + "." + payload;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput, "ascii");
  return signingInput + "." + signer.sign(privateKey).toString("base64url");
}

// nowMs: token iat=1_750_000_000, now is 100s later — within 600s max age.
const NOW_MS = 1_750_000_100 * 1000;

// A fresh token 40s old — passes even with max_token_age_seconds: 60.
const FRESH_IAT = 1_750_000_060;
const FRESH_EXP = 1_750_001_200;
const FRESH_JWT = makeJwt({ iat: FRESH_IAT, exp: FRESH_EXP });

// ---------------------------------------------------------------------------
// Minimal valid assertion fields (built without the adapter)
// ---------------------------------------------------------------------------

function makeAssertionFields(overrides = {}) {
  return {
    asserted_identity: "repo:acme/infra:ref:refs/heads/main",
    verified_identity: "repo:acme/infra:ref:refs/heads/main",
    identity_verification_method: "github_actions_oidc",
    identity_issuer: GITHUB_ACTIONS_ISSUER,
    identity_subject: "repo:acme/infra:ref:refs/heads/main",
    identity_audience: "https://mnde.example.com",
    identity_token_hash: "sha256:" + "a".repeat(64),
    verifier_name: "mnde-github-actions-verifier",
    verifier_version: "1.0.0",
    verifier_policy_hash: "sha256:" + "b".repeat(64),
    verified_at: "2026-06-26T12:00:00.000Z",
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// E2E fixture helpers (following test_signed_execution_result.mjs pattern)
// ---------------------------------------------------------------------------

const SIGNED_AT = "2026-06-26T12:01:00.000Z";
const NOW_ISO = "2026-06-26T12:01:00.000Z";
const AUTHORITY_CHAIN_ID = "mnde-test-chain-identity-e2e";

async function makeBundle() {
  const root = { keyId: "test-root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "test-receipt-key", ...generateAuthorityKeyPair() };
  const resultKey = { keyId: "test-result-key", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "test-policy-key", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "test-approval-key", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    resultKeys: [{ keyId: resultKey.keyId, publicPem: resultKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }]
  });
  return { root, receiptKey, resultKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

const F = await makeBundle();

function minimalRequest(id = "exec-identity-e2e") {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: id,
    requested_at: "2026-06-26T12:00:00.000Z",
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: GITHUB_ACTIONS_ISSUER, verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: "staging" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "org/repo", commit_sha: "abc123", branch: "main" }
  };
}

async function makeSignedReceipt(fixtures, request) {
  return await buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: fixtures.bundle,
    signingKeyId: fixtures.receiptKey.keyId,
    signingPrivateKeyPem: fixtures.receiptKey.privatePem
  });
}

function makeExecutionResult(signedReceipt, identityAssertion) {
  const receiptHash = sha256Hex(signedReceipt);
  const body = {
    schema_version: "mnde.execution_result.v2",
    result_id: "result-identity-e2e-001",
    execution_id: signedReceipt.execution_id,
    execution_request_hash: signedReceipt.request_hash,
    execution_receipt_hash: receiptHash,
    decision: "ALLOW",
    status: "SUCCEEDED",
    executor: {
      id: "test-runner-1",
      type: "github_actions",
      identity_evidence: { type: "github_oidc", subject: "repo:acme/infra:ref:refs/heads/main", issuer: GITHUB_ACTIONS_ISSUER },
      identity_evidence_asserted_only: true,
      ...(identityAssertion !== undefined ? { identity_assertion: identityAssertion } : {})
    },
    started_at: "2026-06-26T12:00:30.000Z",
    ended_at: SIGNED_AT,
    recorded_at: SIGNED_AT,
    effects: [{ type: "deployment", resource_id: "api-service", before: "sha256:" + "a".repeat(64), after: "sha256:" + "b".repeat(64) }],
    evidence: [{ type: "workflow_run", identifier: "run-12345" }]
  };
  return buildExecutionResult(body);
}

async function makeSignedResult(fixtures, signedReceipt, executionResult) {
  return await buildSignedExecutionResult(executionResult, {
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    signingKeyId: fixtures.resultKey.keyId,
    signingPrivateKeyPem: fixtures.resultKey.privatePem,
    authorityChainId: AUTHORITY_CHAIN_ID,
    signedAt: SIGNED_AT,
    now: NOW_ISO,
    signedReceipt
  });
}

async function verifySR(fixtures, envelope, signedReceipt) {
  return await verifySignedExecutionResult(envelope, {
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    now: NOW_ISO,
    signedReceipt
  });
}

// ---------------------------------------------------------------------------
// validateIdentityAssertion — structured errors
// ---------------------------------------------------------------------------

console.log("\nPrimitives — validateIdentityAssertion (structured errors):");

test("valid assertion fields pass validation", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const result = validateIdentityAssertion(assertion);
  assert.ok(result.ok, JSON.stringify(result.errors));
});

test("wrong schema returns IDENTITY_ASSERTION_SCHEMA_INVALID on field=schema", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const tampered = { ...assertion, schema: "mnde.identity_assertion.v2" };
  const result = validateIdentityAssertion(tampered);
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some(e => e.code === "IDENTITY_ASSERTION_SCHEMA_INVALID"), JSON.stringify(result.errors));
  assert.ok(result.errors.some(e => e.field === "schema"), JSON.stringify(result.errors));
});

test("non-object input returns IDENTITY_ASSERTION_SCHEMA_INVALID", async () => {
  const result = validateIdentityAssertion("not an object");
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.errors[0].code, "IDENTITY_ASSERTION_SCHEMA_INVALID");
});

test("missing required string field returns IDENTITY_ASSERTION_FIELD_REQUIRED with correct field name", async () => {
  const required = [
    "asserted_identity", "verified_identity", "identity_verification_method",
    "identity_issuer", "identity_subject", "identity_audience",
    "verifier_name", "verifier_version"
  ];
  for (const field of required) {
    const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ [field]: "" }) };
    const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
    const result = validateIdentityAssertion(assertion);
    assert.strictEqual(result.ok, false, `expected ${field} to fail`);
    assert.ok(
      result.errors.some(e => e.code === "IDENTITY_ASSERTION_FIELD_REQUIRED" && e.field === field),
      `expected FIELD_REQUIRED for ${field}, got: ${JSON.stringify(result.errors)}`
    );
  }
});

test("malformed identity_token_hash returns IDENTITY_ASSERTION_TOKEN_HASH_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ identity_token_hash: "notahash" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = validateIdentityAssertion(assertion);
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some(e => e.code === "IDENTITY_ASSERTION_TOKEN_HASH_INVALID" && e.field === "identity_token_hash"));
});

test("malformed verifier_policy_hash returns IDENTITY_ASSERTION_POLICY_HASH_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ verifier_policy_hash: "sha256:short" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = validateIdentityAssertion(assertion);
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some(e => e.code === "IDENTITY_ASSERTION_POLICY_HASH_INVALID" && e.field === "verifier_policy_hash"));
});

test("malformed verified_at returns IDENTITY_ASSERTION_VERIFIED_AT_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ verified_at: "not-a-date" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = validateIdentityAssertion(assertion);
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some(e => e.code === "IDENTITY_ASSERTION_VERIFIED_AT_INVALID" && e.field === "verified_at"));
});

test("malformed assertion_hash format returns IDENTITY_ASSERTION_HASH_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields() };
  const assertion = { ...body, assertion_hash: "notahash" };
  const result = validateIdentityAssertion(assertion);
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some(e => e.code === "IDENTITY_ASSERTION_HASH_INVALID" && e.field === "assertion_hash"));
});

test("computeAssertionHash excludes assertion_hash field itself", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const { assertion_hash: _, ...rest } = assertion;
  const expected = "sha256:" + sha256(canonicalizeJson(rest));
  assert.strictEqual(computeAssertionHash(assertion), expected);
});

// ---------------------------------------------------------------------------
// verifyIdentityAssertion — structured error routing
// ---------------------------------------------------------------------------

console.log("\nverifyIdentityAssertion — structured error routing:");

test("valid assertion verifies successfully", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const result = verifyIdentityAssertion(assertion);
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.verified_identity, "repo:acme/infra:ref:refs/heads/main");
  assert.strictEqual(result.identity_verification_method, "github_actions_oidc");
});

test("schema failure routes to IDENTITY_ASSERTION_SCHEMA_INVALID (not by message text)", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  // Use a schema value that does NOT contain the word "schema" to prove
  // routing is on .code, not .message text.
  const tampered = { ...assertion, schema: "wrong_value_without_the_keyword" };
  const result = verifyIdentityAssertion(tampered);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_SCHEMA_INVALID");
});

test("field failure routes to IDENTITY_ASSERTION_FIELD_REQUIRED", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ asserted_identity: "" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = verifyIdentityAssertion(assertion);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_FIELD_REQUIRED");
});

test("token hash failure routes to IDENTITY_ASSERTION_TOKEN_HASH_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ identity_token_hash: "bad" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = verifyIdentityAssertion(assertion);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_TOKEN_HASH_INVALID");
});

test("policy hash failure routes to IDENTITY_ASSERTION_POLICY_HASH_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ verifier_policy_hash: "bad" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = verifyIdentityAssertion(assertion);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_POLICY_HASH_INVALID");
});

test("verified_at failure routes to IDENTITY_ASSERTION_VERIFIED_AT_INVALID", async () => {
  const body = { schema: IDENTITY_ASSERTION_SCHEMA, ...makeAssertionFields({ verified_at: "not-a-date" }) };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const result = verifyIdentityAssertion(assertion);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_VERIFIED_AT_INVALID");
});

test("tampered assertion_hash is rejected with IDENTITY_ASSERTION_HASH_INVALID", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const tampered = { ...assertion, assertion_hash: "sha256:" + "0".repeat(64) };
  const result = verifyIdentityAssertion(tampered);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_HASH_INVALID");
});

test("tampered body field is rejected via hash mismatch", async () => {
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const tampered = { ...assertion, verified_identity: "repo:attacker/evil:ref:refs/heads/main" };
  const result = verifyIdentityAssertion(tampered);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.code, "IDENTITY_ASSERTION_HASH_INVALID");
});

// ---------------------------------------------------------------------------
// Identity level label
// ---------------------------------------------------------------------------

console.log("\nIdentity level label:");

test("fabricated assertion (no adapter) receives ASSERTION_HASH_BOUND not VERIFIED_BY_EXTERNAL_VERIFIER", async () => {
  const fabricated = buildIdentityAssertion(makeAssertionFields({
    verified_identity: "repo:victim/production:ref:refs/heads/main"
  }));
  const request = minimalRequest("exec-fabricated-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const result = makeExecutionResult(signedReceipt, fabricated);
  const check = await verifyExecutionResult(result);
  assert.ok(check.verified, JSON.stringify(check));
  assert.strictEqual(check.identity_level, "ASSERTION_HASH_BOUND");
  assert.notStrictEqual(check.identity_level, "VERIFIED_BY_EXTERNAL_VERIFIER");
});

test("adapter-produced assertion receives ASSERTION_HASH_BOUND (not VERIFIED_BY_EXTERNAL_VERIFIER)", async () => {
  const rawJwt = makeJwt();
  const assertion = verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const request = minimalRequest("exec-adapter-assertion-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const result = makeExecutionResult(signedReceipt, assertion);
  const check = await verifyExecutionResult(result);
  assert.ok(check.verified, JSON.stringify(check));
  assert.strictEqual(check.identity_level, "ASSERTION_HASH_BOUND");
  assert.notStrictEqual(check.identity_level, "VERIFIED_BY_EXTERNAL_VERIFIER");
});

test("result without identity_assertion receives ASSERTED_ONLY", async () => {
  const request = minimalRequest("exec-no-assertion-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const result = makeExecutionResult(signedReceipt, undefined);
  const check = await verifyExecutionResult(result);
  assert.ok(check.verified, JSON.stringify(check));
  assert.strictEqual(check.identity_level, "ASSERTED_ONLY");
});

// ---------------------------------------------------------------------------
// End-to-end — signed result integration
// ---------------------------------------------------------------------------

console.log("\nEnd-to-end — signed result with identity_assertion:");

test("signed result with valid identity_assertion propagates ASSERTION_HASH_BOUND", async () => {
  const request = minimalRequest("exec-e2e-valid-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const result = makeExecutionResult(signedReceipt, assertion);
  const envelope = await makeSignedResult(F, signedReceipt, result);
  const verdict = await verifySR(F, envelope, signedReceipt);
  assert.ok(verdict.valid, JSON.stringify(verdict));
  assert.strictEqual(verdict.identity_evidence, "ASSERTION_HASH_BOUND");
});

test("signed result without identity_assertion propagates ASSERTED_ONLY", async () => {
  const request = minimalRequest("exec-e2e-no-assert-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const result = makeExecutionResult(signedReceipt, undefined);
  const envelope = await makeSignedResult(F, signedReceipt, result);
  const verdict = await verifySR(F, envelope, signedReceipt);
  assert.ok(verdict.valid, JSON.stringify(verdict));
  assert.strictEqual(verdict.identity_evidence, "ASSERTED_ONLY");
});

test("tampered identity_assertion body after signing fails closed", async () => {
  const request = minimalRequest("exec-e2e-tamper-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const assertion = buildIdentityAssertion(makeAssertionFields());
  const result = makeExecutionResult(signedReceipt, assertion);
  const envelope = await makeSignedResult(F, signedReceipt, result);
  // Swap verified_identity but keep assertion_hash — hash mismatch inside
  // verifyIdentityAssertion, plus outer Ed25519 signature also fails.
  const tamperedAssertion = { ...assertion, verified_identity: "repo:attacker/evil:ref:refs/heads/main" };
  const tampered = {
    ...envelope,
    execution_result: {
      ...envelope.execution_result,
      executor: {
        ...envelope.execution_result.executor,
        identity_assertion: tamperedAssertion
      }
    }
  };
  const verdict = await verifySR(F, tampered, signedReceipt);
  assert.strictEqual(verdict.valid, false);
});

test("corrupted assertion_hash in identity_assertion makes verifyExecutionResult fail closed", async () => {
  const request = minimalRequest("exec-e2e-bad-hash-001");
  const signedReceipt = await makeSignedReceipt(F, request);
  const goodAssertion = buildIdentityAssertion(makeAssertionFields());
  // Corrupt assertion_hash after building — structural check passes but hash mismatch rejects.
  const badAssertion = { ...goodAssertion, assertion_hash: "sha256:" + "f".repeat(64) };
  // Build with the good assertion, then patch to bad one in the result.
  const goodResult = makeExecutionResult(signedReceipt, goodAssertion);
  const patchedResult = {
    ...goodResult,
    executor: { ...goodResult.executor, identity_assertion: badAssertion }
  };
  // result_hash also mismatches since we patched executor — verifyExecutionResult rejects.
  const check = await verifyExecutionResult(patchedResult);
  assert.strictEqual(check.verified, false);
});

// ---------------------------------------------------------------------------
// Adapter — require finite exp
// ---------------------------------------------------------------------------

console.log("\nAdapter — require finite exp:");

test("missing exp rejects with OIDC_TOKEN_EXPIRED", async () => {
  const rawJwt = makeJwt({ exp: null }); // null = omit exp from payload
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_EXPIRED" }
  );
});

test("null exp in payload rejects with OIDC_TOKEN_EXPIRED", async () => {
  const rawJwt = makeJwtFromPayload({
    iss: GITHUB_ACTIONS_ISSUER, aud: "https://mnde.example.com",
    sub: "repo:acme/infra:ref:refs/heads/main", iat: 1_750_000_000, exp: null
  });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_EXPIRED" }
  );
});

test("string exp rejects with OIDC_TOKEN_EXPIRED", async () => {
  const rawJwt = makeJwtFromPayload({
    iss: GITHUB_ACTIONS_ISSUER, aud: "https://mnde.example.com",
    sub: "repo:acme/infra:ref:refs/heads/main", iat: 1_750_000_000, exp: "1750000600"
  });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_EXPIRED" }
  );
});

test("valid numeric exp accepts", async () => {
  const rawJwt = makeJwt(); // exp = 1_750_000_600
  const assertion = verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
});

test("expired numeric exp rejects with OIDC_TOKEN_EXPIRED", async () => {
  const rawJwt = makeJwt({ iat: 50, exp: 100 });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: 200_000 }),
    { code: "OIDC_TOKEN_EXPIRED" }
  );
});

// ---------------------------------------------------------------------------
// Adapter — require finite iat
// ---------------------------------------------------------------------------

console.log("\nAdapter — require finite iat:");

test("missing iat rejects with OIDC_TOKEN_TOO_OLD", async () => {
  const rawJwt = makeJwt({ iat: null }); // null = omit iat from payload
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_TOO_OLD" }
  );
});

test("null iat in payload rejects with OIDC_TOKEN_TOO_OLD", async () => {
  const rawJwt = makeJwtFromPayload({
    iss: GITHUB_ACTIONS_ISSUER, aud: "https://mnde.example.com",
    sub: "repo:acme/infra:ref:refs/heads/main", iat: null, exp: 1_750_000_600
  });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_TOO_OLD" }
  );
});

test("string iat rejects with OIDC_TOKEN_TOO_OLD", async () => {
  const rawJwt = makeJwtFromPayload({
    iss: GITHUB_ACTIONS_ISSUER, aud: "https://mnde.example.com",
    sub: "repo:acme/infra:ref:refs/heads/main", iat: "1750000000", exp: 1_750_000_600
  });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_TOKEN_TOO_OLD" }
  );
});

test("token too old (numeric iat, past max_token_age_seconds) rejects with OIDC_TOKEN_TOO_OLD", async () => {
  // iat=1_000_000, now is 700s later, max=600, skew=30 → 700 > 630 → too old
  const rawJwt = makeJwt({ iat: 1_000_000, exp: 9_999_999_999 });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: (1_000_000 + 700) * 1000 }),
    { code: "OIDC_TOKEN_TOO_OLD" }
  );
});

test("fresh numeric iat accepts", async () => {
  const rawJwt = makeJwt(); // iat=1_750_000_000, now 100s later
  const assertion = verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
});

// ---------------------------------------------------------------------------
// Adapter — require audience in verifier policy
// ---------------------------------------------------------------------------

console.log("\nAdapter — require audience in policy:");

test("policy without audience rejects with OIDC_JWT_MALFORMED", async () => {
  const { audience: _, ...noAudPolicy } = BASE_POLICY;
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), noAudPolicy, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("policy with empty string audience rejects with OIDC_JWT_MALFORMED", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), { ...BASE_POLICY, audience: "" }, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("policy with non-string audience (number) rejects with OIDC_JWT_MALFORMED", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), { ...BASE_POLICY, audience: 42 }, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("token with wrong audience rejects with OIDC_AUDIENCE_MISMATCH", async () => {
  const rawJwt = makeJwt({ aud: "https://wrong.example.com" });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_AUDIENCE_MISMATCH" }
  );
});

test("token with correct audience accepts", async () => {
  const rawJwt = makeJwt();
  const assertion = verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
});

// ---------------------------------------------------------------------------
// Adapter — subject allowlist must be explicit
// ---------------------------------------------------------------------------

console.log("\nAdapter — subject allowlist explicit:");

test("policy without subject_allowlist or allow_all_subjects rejects with OIDC_JWT_MALFORMED", async () => {
  const { subject_allowlist: _, ...noSlPolicy } = BASE_POLICY;
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), noSlPolicy, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("policy with empty subject_allowlist without allow_all_subjects rejects with OIDC_JWT_MALFORMED", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), { ...BASE_POLICY, subject_allowlist: [] }, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("allow_all_subjects: true accepts any valid subject", async () => {
  const { subject_allowlist: _, ...noSlPolicy } = BASE_POLICY;
  const openPolicy = { ...noSlPolicy, allow_all_subjects: true };
  const rawJwt = makeJwt({ sub: "repo:anyone/anywhere:ref:refs/heads/main" });
  const assertion = verifyGitHubActionsOidc(rawJwt, openPolicy, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
  assert.strictEqual(assertion.verified_identity, "repo:anyone/anywhere:ref:refs/heads/main");
});

test("non-empty subject_allowlist accepts matching subject", async () => {
  const rawJwt = makeJwt(); // sub = repo:acme/infra:ref:refs/heads/main
  const assertion = verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
});

test("non-empty subject_allowlist rejects non-matching subject with OIDC_SUBJECT_NOT_ALLOWED", async () => {
  const rawJwt = makeJwt({ sub: "repo:attacker/evil:ref:refs/heads/main" });
  assert.throws(
    () => verifyGitHubActionsOidc(rawJwt, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_SUBJECT_NOT_ALLOWED" }
  );
});

test("subject matched by prefix wildcard accepts", async () => {
  const policy = { ...BASE_POLICY, subject_allowlist: ["repo:acme/infra:*"] };
  const rawJwt = makeJwt({ sub: "repo:acme/infra:ref:refs/heads/feature" });
  const assertion = verifyGitHubActionsOidc(rawJwt, policy, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(assertion.schema, IDENTITY_ASSERTION_SCHEMA);
});

// ---------------------------------------------------------------------------
// Adapter — effective policy hash
// ---------------------------------------------------------------------------

console.log("\nAdapter — effective policy hash:");

test("omitting max_token_age_seconds (default 600) produces same hash as explicit 600", async () => {
  const { max_token_age_seconds: _, ...policyWithoutAge } = BASE_POLICY;
  const a1 = verifyGitHubActionsOidc(FRESH_JWT, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const a2 = verifyGitHubActionsOidc(FRESH_JWT, policyWithoutAge, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(a1.verifier_policy_hash, a2.verifier_policy_hash);
});

test("omitting clock_skew_seconds (default 30) produces same hash as explicit 30", async () => {
  const { clock_skew_seconds: _, ...policyWithoutSkew } = BASE_POLICY;
  const a1 = verifyGitHubActionsOidc(FRESH_JWT, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const a2 = verifyGitHubActionsOidc(FRESH_JWT, policyWithoutSkew, JWKS, { nowMs: NOW_MS });
  assert.strictEqual(a1.verifier_policy_hash, a2.verifier_policy_hash);
});

test("changing max_token_age_seconds changes verifier_policy_hash", async () => {
  const shortPolicy = { ...BASE_POLICY, max_token_age_seconds: 60 };
  const a1 = verifyGitHubActionsOidc(FRESH_JWT, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const a2 = verifyGitHubActionsOidc(FRESH_JWT, shortPolicy, JWKS, { nowMs: NOW_MS });
  assert.notStrictEqual(a1.verifier_policy_hash, a2.verifier_policy_hash);
});

test("changing clock_skew_seconds changes verifier_policy_hash", async () => {
  const tightPolicy = { ...BASE_POLICY, clock_skew_seconds: 0 };
  const a1 = verifyGitHubActionsOidc(FRESH_JWT, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const a2 = verifyGitHubActionsOidc(FRESH_JWT, tightPolicy, JWKS, { nowMs: NOW_MS });
  assert.notStrictEqual(a1.verifier_policy_hash, a2.verifier_policy_hash);
});

test("changing audience changes verifier_policy_hash", async () => {
  const otherAudPolicy = { ...BASE_POLICY, audience: "https://other.example.com" };
  const rawJwtOther = makeJwt({ aud: "https://other.example.com" });
  const a1 = verifyGitHubActionsOidc(FRESH_JWT, BASE_POLICY, JWKS, { nowMs: NOW_MS });
  const a2 = verifyGitHubActionsOidc(rawJwtOther, otherAudPolicy, JWKS, { nowMs: NOW_MS });
  assert.notStrictEqual(a1.verifier_policy_hash, a2.verifier_policy_hash);
});

// ---------------------------------------------------------------------------
// Adapter — existing hostile tests (preserved from original suite)
// ---------------------------------------------------------------------------

console.log("\nAdapter — existing hostile tests:");

test("JWKS hash mismatch throws OIDC_JWKS_HASH_MISMATCH", async () => {
  const badJwks = { keys: [{ ...RSA_PUBLIC_JWK, kid: KID, use: "sig", alg: "RS256", extra: "injected" }] };
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), BASE_POLICY, badJwks, { nowMs: NOW_MS }),
    { code: "OIDC_JWKS_HASH_MISMATCH" }
  );
});

test("missing trusted_jwks_hash in policy throws OIDC_JWT_MALFORMED", async () => {
  const { trusted_jwks_hash: _, ...badPolicy } = BASE_POLICY;
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt(), badPolicy, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("malformed JWT (not three parts) throws OIDC_JWT_MALFORMED", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc("header.payload", BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("unsupported algorithm (HS256) throws OIDC_ALGORITHM_UNSUPPORTED", async () => {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT", kid: KID })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: GITHUB_ACTIONS_ISSUER })).toString("base64url");
  assert.throws(
    () => verifyGitHubActionsOidc(header + "." + payload + ".fakesig", BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_ALGORITHM_UNSUPPORTED" }
  );
});

test("JWT with unknown kid throws OIDC_KEY_NOT_FOUND", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt({ kid: "unknown-kid" }), BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_KEY_NOT_FOUND" }
  );
});

test("JWT with missing kid throws OIDC_KEY_NOT_FOUND", async () => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: GITHUB_ACTIONS_ISSUER, aud: "https://mnde.example.com",
    sub: "repo:acme/infra:ref:refs/heads/main", iat: 1_750_000_000, exp: 1_750_000_600
  })).toString("base64url");
  const signer = createSign("RSA-SHA256");
  signer.update(header + "." + payload, "ascii");
  const raw = header + "." + payload + "." + signer.sign(RSA_PRIVATE).toString("base64url");
  assert.throws(
    () => verifyGitHubActionsOidc(raw, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_KEY_NOT_FOUND" }
  );
});

test("tampered JWT signature (bit flip in signature component) throws OIDC_SIGNATURE_INVALID", async () => {
  const parts = makeJwt().split(".");
  const s = parts[2];
  // Flip a character mid-string (not the last, which may only affect padding bits).
  const pos = Math.floor(s.length / 2);
  parts[2] = s.slice(0, pos) + (s[pos] === "A" ? "B" : "A") + s.slice(pos + 1);
  assert.throws(
    () => verifyGitHubActionsOidc(parts.join("."), BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_SIGNATURE_INVALID" }
  );
});

test("wrong issuer throws OIDC_ISSUER_MISMATCH", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt({ iss: "https://attacker.example.com" }), BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_ISSUER_MISMATCH" }
  );
});

test("nbf in the future throws OIDC_TOKEN_NOT_YET_VALID", async () => {
  const futureNbf = 1_750_000_000 + 3600;
  assert.throws(
    () => verifyGitHubActionsOidc(
      makeJwt({ nbf: futureNbf, iat: 1_750_000_000, exp: 1_750_010_000 }),
      BASE_POLICY, JWKS, { nowMs: (futureNbf - 120) * 1000 }
    ),
    { code: "OIDC_TOKEN_NOT_YET_VALID" }
  );
});

test("attacker key substituted for known kid throws OIDC_SIGNATURE_INVALID", async () => {
  const { privateKey: attackerPrivate } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(
    () => verifyGitHubActionsOidc(makeJwt({ privateKey: attackerPrivate }), BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_SIGNATURE_INVALID" }
  );
});

test("null rawJwt throws OIDC_JWT_MALFORMED", async () => {
  assert.throws(
    () => verifyGitHubActionsOidc(null, BASE_POLICY, JWKS, { nowMs: NOW_MS }),
    { code: "OIDC_JWT_MALFORMED" }
  );
});

test("assertedIdentity option overrides asserted_identity while preserving verified_identity", async () => {
  const assertion = verifyGitHubActionsOidc(makeJwt(), BASE_POLICY, JWKS, {
    nowMs: NOW_MS,
    assertedIdentity: "custom-executor-id"
  });
  assert.strictEqual(assertion.asserted_identity, "custom-executor-id");
  assert.strictEqual(assertion.verified_identity, "repo:acme/infra:ref:refs/heads/main");
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

await testChain;
const passed = results.filter(Boolean).length;
const failed = results.filter(r => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
