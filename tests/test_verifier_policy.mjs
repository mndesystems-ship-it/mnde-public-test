#!/usr/bin/env node
// Tests for mnde.verifier_policy.v1 — signature/root binding, rollback high-water
// mark, fail-closed decisions, canonical hash membership, schema-version pinning,
// and the operational-vs-replay verification split.
//
//   npm run test:verifier-policy

import assert from "node:assert/strict";

import {
  buildAuthorityBundle,
  generateAuthorityKeyPair
} from "../src/custody/index.mjs";
import {
  signVerifierPolicy,
  loadVerifierPolicy,
  verifyPolicySignature,
  effectiveVerifierPolicyHash,
  IDENTITY_LEVELS
} from "../src/identity/verifier-policy.mjs";

const results = [];
let chain = Promise.resolve();
function test(name, fn) {
  chain = chain.then(async () => {
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

// ── Fixtures ────────────────────────────────────────────────────────────────
const root = { keyId: "root-2026", ...generateAuthorityKeyPair() };
const receipt = { keyId: "receipt-1", ...generateAuthorityKeyPair() };

const bundle = await buildAuthorityBundle({
  authorityId: "mnde-acme-authority",
  issuedAt: "2026-01-01T00:00:00.000Z",
  notAfter: "2028-01-01T00:00:00.000Z",
  root,
  receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }]
});
const trustedRootFingerprint = bundle.root_key.fingerprint;

const entry = {
  issuer: "https://token.actions.githubusercontent.com",
  audience: "https://mnde.example.com",
  subject_allowlist: ["repo:acme/infra:ref:refs/heads/main"],
  trusted_jwks_hash: "sha256:" + "a".repeat(64)
};

function baseInput(overrides = {}) {
  return {
    authorityId: "mnde-acme-authority",
    rootKeyId: "root-2026",
    policyVersion: 7,
    issuedAt: "2026-07-05T00:00:00.000Z",
    notAfter: null,
    rootPrivatePem: root.privatePem,
    rootPublicPem: root.publicPem,
    verifierPolicies: [entry],
    minLevelTable: [{ environment: "production", authority_scope: "chain-1", min_level: "ASSERTION_HASH_BOUND" }],
    ...overrides
  };
}

const signed = await signVerifierPolicy(baseInput());
const loadOpts = { authorityBundle: bundle, trustedRootFingerprint, highWaterMark: 6 };

// ── Load + approved-hash membership ──────────────────────────────────────────
console.log("\nLoad + approved-hash membership:");

test("valid policy loads with correct version and authority", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  assert.ok(p.ok, JSON.stringify(p));
  assert.equal(p.version, 7);
  assert.equal(p.authority_id, "mnde-acme-authority");
});

test("isApprovedPolicyHash matches the adapter's effective hash", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  assert.ok(p.isApprovedPolicyHash(effectiveVerifierPolicyHash(entry)));
});

test("isApprovedPolicyHash rejects an unknown hash", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  assert.ok(!p.isApprovedPolicyHash("sha256:" + "b".repeat(64)));
});

// ── Trust anchor comes from the bundle (point 2) ─────────────────────────────
console.log("\nTrust anchor from bundle:");

test("authority_id mismatch against bundle → AUTHORITY_MISMATCH", async () => {
  const wrong = { ...bundle, authority_id: "someone-else" };
  const p = await loadVerifierPolicy(signed, { authorityBundle: wrong, trustedRootFingerprint, highWaterMark: 6 });
  assert.equal(p.reason, "AUTHORITY_MISMATCH");
});

test("wrong trusted root fingerprint → UNTRUSTED_ROOT", async () => {
  const p = await loadVerifierPolicy(signed, { authorityBundle: bundle, trustedRootFingerprint: "deadbeef", highWaterMark: 6 });
  assert.equal(p.reason, "UNTRUSTED_ROOT");
});

test("root_key_id mismatch → ROOT_KEY_MISMATCH", async () => {
  const mism = await signVerifierPolicy(baseInput({ rootKeyId: "not-the-root", policyVersion: 8 }));
  const p = await loadVerifierPolicy(mism, { authorityBundle: bundle, trustedRootFingerprint, highWaterMark: 7 });
  assert.equal(p.reason, "ROOT_KEY_MISMATCH");
});

// ── Signature integrity ──────────────────────────────────────────────────────
console.log("\nSignature integrity:");

test("tampered body after signing → POLICY_SIGNATURE_INVALID", async () => {
  const tampered = { ...signed, min_level_table: [{ environment: "production", authority_scope: "chain-1", min_level: "ASSERTED_ONLY" }] };
  const p = await loadVerifierPolicy(tampered, loadOpts);
  assert.equal(p.reason, "POLICY_SIGNATURE_INVALID");
});

// ── Rollback protection ──────────────────────────────────────────────────────
console.log("\nRollback protection:");

test("policy_version <= high-water mark → POLICY_ROLLBACK", async () => {
  const p = await loadVerifierPolicy(signed, { authorityBundle: bundle, trustedRootFingerprint, highWaterMark: 7 });
  assert.equal(p.reason, "POLICY_ROLLBACK");
});

// ── requiredDecisionPolicy — frozen + fail closed (point 4) ──────────────────
console.log("\nrequiredDecisionPolicy — frozen + fail closed:");

test("returns a frozen decision object", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  const d = p.requiredDecisionPolicy("production", "chain-1");
  assert.ok(Object.isFrozen(d));
  assert.equal(d.level, "ASSERTION_HASH_BOUND");
  assert.equal(d.policy_version, 7);
  assert.equal(d.authority_scope, "chain-1");
});

test("accepts an equal-or-higher achieved level, rejects lower", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  const d = p.requiredDecisionPolicy("production", "chain-1");
  assert.ok(d.accepts("ASSERTION_HASH_BOUND"));
  assert.ok(!d.accepts("ASSERTED_ONLY"));
});

test("missing (environment, authority_scope) rule → DENY, accepts() always false", async () => {
  const p = await loadVerifierPolicy(signed, loadOpts);
  const d = p.requiredDecisionPolicy("production", "unknown-scope");
  assert.equal(d.level, "DENY");
  assert.ok(!d.accepts("ASSERTION_HASH_BOUND"));
  assert.ok(!d.accepts("ASSERTED_ONLY"));
});

// ── Schema-version pinning (point 6) ─────────────────────────────────────────
console.log("\nSchema-version pinning:");

test("mnde.verifier_policy.v2 is rejected → POLICY_MALFORMED", async () => {
  const future = { ...signed, schema_version: "mnde.verifier_policy.v2" };
  const p = await loadVerifierPolicy(future, loadOpts);
  assert.equal(p.reason, "POLICY_MALFORMED");
});

// ── Operational vs replay split (point 1) ────────────────────────────────────
console.log("\nOperational vs replay split:");

test("verifyPolicySignature holds regardless of version/expiry (replay path)", async () => {
  const r = await verifyPolicySignature(signed, { rootPublicKey: bundle.root_key.public_key });
  assert.ok(r.ok, JSON.stringify(r));
});

test("not_after does NOT gate the decision when no `now` is supplied", async () => {
  const expiring = await signVerifierPolicy(baseInput({ policyVersion: 9, notAfter: "2000-01-01T00:00:00.000Z" }));
  const p = await loadVerifierPolicy(expiring, { authorityBundle: bundle, trustedRootFingerprint, highWaterMark: 8 });
  assert.ok(p.ok, JSON.stringify(p));
});

test("not_after DOES gate operationally when `now` is past it → POLICY_EXPIRED", async () => {
  const expiring = await signVerifierPolicy(baseInput({ policyVersion: 10, notAfter: "2000-01-01T00:00:00.000Z" }));
  const p = await loadVerifierPolicy(expiring, { authorityBundle: bundle, trustedRootFingerprint, highWaterMark: 9, now: "2026-07-05T00:00:00.000Z" });
  assert.equal(p.reason, "POLICY_EXPIRED");
});

// ── Enum sanity ──────────────────────────────────────────────────────────────
console.log("\nEnum sanity:");

test("IDENTITY_LEVELS is the ordered ladder, ASSERTED_ONLY < ASSERTION_HASH_BOUND", async () => {
  assert.deepEqual(IDENTITY_LEVELS, ["ASSERTED_ONLY", "ASSERTION_HASH_BOUND"]);
});

// ── Summary ──────────────────────────────────────────────────────────────────
await chain;
const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
