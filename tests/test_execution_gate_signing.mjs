#!/usr/bin/env node
// Custody-signed execution gate receipt — hostile tests first, then behavioral.
//
//   npm run test:execution-gate-signing

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  fingerprintOf
} from "../src/custody/index.mjs";
import {
  authorizeAndSign,
  buildSignedExecutionReceipt,
  verifySignedExecutionReceipt
} from "../src/execution-gate/index.mjs";

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

// ── Test fixtures ─────────────────────────────────────────────────────────────

// Build a minimal authority bundle with one receipt key.
// Returns { root, receiptKey, bundle, trustedRootFingerprint }.
function makeBundle({
  now = "2026-06-01T00:00:00.000Z",
  validFrom = "2025-01-01T00:00:00.000Z",
  validUntil = "2027-01-01T00:00:00.000Z",
  notAfter = "2028-01-01T00:00:00.000Z",
  revoke = false,
  authorityId = "mnde-test-authority"
} = {}) {
  const root = { keyId: "test-root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "test-receipt-key-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId,
    issuedAt: now,
    notAfter,
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom, validUntil }],
    policyKeys: [],
    approvalKeys: [],
    revocation: revoke ? [receiptKey.keyId] : []
  });
  return { root, receiptKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

// A minimal valid execution request.
function minimalRequest(overrides = {}) {
  const base = {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-sign-001",
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
  const merged = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (typeof v === "object" && v !== null && !Array.isArray(v) && typeof merged[k] === "object" && merged[k] !== null) {
      merged[k] = { ...merged[k], ...v };
    } else {
      merged[k] = v;
    }
  }
  return merged;
}

// Build a valid signed receipt and the bundle used to sign it.
function buildValidReceipt(reqOverrides = {}) {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const request = minimalRequest(reqOverrides);
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  return { receipt, bundle, trustedRootFingerprint, receiptKey, request };
}

// ── Hostile tests ─────────────────────────────────────────────────────────────

test("1. Valid signed receipt verifies successfully", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const result = verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, true, result.reason ?? "");
  assert.equal(result.checks.schema.ok, true);
  assert.equal(result.checks.signature.ok, true);
  assert.equal(result.checks.fingerprint_match.ok, true);
});

test("2. Tampered decision field fails verification (signature mismatch)", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const tampered = { ...receipt, decision: "REFUSE" };
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  // signature check must fail because we changed the signed body
  assert.match(result.reason, /signature/);
});

test("3. Tampered request_hash field fails verification", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const tampered = { ...receipt, request_hash: "0".repeat(64) };
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /signature/);
});

test("4. Tampered verifiable_signature.value fails verification", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const tampered = structuredClone(receipt);
  // Flip first two bytes of the signature.
  tampered.verifiable_signature.value = "0000" + tampered.verifiable_signature.value.slice(4);
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /signature/);
});

test("5. Wrong trustedRootFingerprint fails authority bundle verification", () => {
  const { receipt, bundle } = buildValidReceipt();
  const result = verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint: "deadbeef".repeat(8) });
  assert.equal(result.verified, false);
  assert.match(result.reason, /authority_bundle/);
});

test("6. Revoked signing key fails verification", () => {
  // Build receipt with a key, then present a bundle that has it revoked.
  const { receiptKey, bundle: origBundle, trustedRootFingerprint: _ } = makeBundle();
  const request = minimalRequest();
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: origBundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  // Rebuild the bundle with revocation, re-signed by same root.
  const root = { keyId: "test-root", ...generateAuthorityKeyPair() };
  const revokedBundle = buildAuthorityBundle({
    authorityId: origBundle.authority_id,
    issuedAt: origBundle.issued_at,
    notAfter: origBundle.not_after,
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [],
    approvalKeys: [],
    revocation: [receiptKey.keyId]
  });
  const result = verifySignedExecutionReceipt(receipt, { authorityBundle: revokedBundle, trustedRootFingerprint: revokedBundle.root_key.fingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /key_lookup/);
  assert.equal(result.checks.key_lookup.detail, "KEY_REVOKED");
});

test("7. Expired signing key fails verification (key valid_until in the past)", () => {
  // Build bundle with key that is already expired at signing time.
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle({
    validFrom: "2020-01-01T00:00:00.000Z",
    validUntil: "2021-01-01T00:00:00.000Z"
    // requested_at = "2026-06-15T..." which is after valid_until
  });
  const request = minimalRequest();
  // buildSignedExecutionReceipt should throw because findBundleKey returns KEY_EXPIRED
  assert.throws(() => {
    buildSignedExecutionReceipt(request, "ALLOW", {
      authorityBundle: bundle,
      signingKeyId: receiptKey.keyId,
      signingPrivateKeyPem: receiptKey.privatePem
    });
  }, /KEY_EXPIRED/);
  // And even if we had a receipt from this key, verifying it would fail.
});

test("8. Substituted authority bundle (different authority) fails verification", () => {
  const { receipt } = buildValidReceipt();
  // Build a completely different bundle with its own root.
  const { bundle: otherBundle, trustedRootFingerprint: otherFp } = makeBundle({ authorityId: "other-authority" });
  const result = verifySignedExecutionReceipt(receipt, { authorityBundle: otherBundle, trustedRootFingerprint: otherFp });
  assert.equal(result.verified, false);
  // Either authority_id mismatch or key not found in the substituted bundle.
  assert.ok(result.reason, "must have a reason");
});

test("9. Missing verifiable_signature field fails verification", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const { verifiable_signature: _removed, ...noSig } = receipt;
  const result = verifySignedExecutionReceipt(noSig, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /required_fields|algorithm/);
});

test("10. Wrong signing_key_id (key not in bundle) fails verification", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const tampered = structuredClone(receipt);
  tampered.verifiable_signature.key_id = "nonexistent-key-id";
  tampered.signing_key_id = "nonexistent-key-id";
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /key_lookup/);
});

test("11. Fingerprint mismatch (receipt claims wrong fingerprint) fails verification", () => {
  const { receipt, bundle, trustedRootFingerprint } = buildValidReceipt();
  const tampered = structuredClone(receipt);
  tampered.verifiable_signature.public_key_fingerprint = "a".repeat(64);
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  // signature check will also fail since we modified signed body; but fingerprint_match fires first
  assert.match(result.reason, /fingerprint_match/);
});

// ── Behavioral / integrity tests ──────────────────────────────────────────────

test("12. decided_at equals requested_at — no wall-clock used", () => {
  const { receipt } = buildValidReceipt();
  assert.equal(receipt.decided_at, receipt.verifiable_signature.signed_at);
  assert.equal(receipt.decided_at, minimalRequest().requested_at);
});

test("13. Replay: re-running gate on original request produces same request_hash", () => {
  const { receipt, request } = buildValidReceipt();
  const recomputed = createHash("sha256").update(canonicalizeJson(request), "utf8").digest("hex");
  assert.equal(receipt.request_hash, recomputed);
  // Verifier with original request also confirms the hash.
  const { bundle, trustedRootFingerprint } = makeBundle();
  // Use the same bundle/key that built the receipt.
  const { receipt: r2, bundle: b2, trustedRootFingerprint: fp2 } = buildValidReceipt();
  const result = verifySignedExecutionReceipt(r2, { authorityBundle: b2, trustedRootFingerprint: fp2, originalRequest: request });
  // originalRequest is a DIFFERENT request so hash check may fail — that's OK, we just
  // verify the request_hash field of the receipt matches what we'd compute from the
  // actual original request.
  const { receipt: r3, bundle: b3, trustedRootFingerprint: fp3, request: req3 } = buildValidReceipt();
  const result3 = verifySignedExecutionReceipt(r3, { authorityBundle: b3, trustedRootFingerprint: fp3, originalRequest: req3 });
  assert.equal(result3.verified, true, result3.reason ?? "");
  assert.equal(result3.checks.request_hash.ok, true);
});

test("14. Cross-request: two different requests produce different request_hash and different signatures", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const req1 = minimalRequest({ execution_id: "exec-a" });
  const req2 = minimalRequest({ execution_id: "exec-b" });
  const r1 = buildSignedExecutionReceipt(req1, "ALLOW", { authorityBundle: bundle, signingKeyId: receiptKey.keyId, signingPrivateKeyPem: receiptKey.privatePem });
  const r2 = buildSignedExecutionReceipt(req2, "ALLOW", { authorityBundle: bundle, signingKeyId: receiptKey.keyId, signingPrivateKeyPem: receiptKey.privatePem });
  assert.notEqual(r1.request_hash, r2.request_hash);
  assert.notEqual(r1.verifiable_signature.value, r2.verifiable_signature.value);
});

test("15. Unsigned path (no signing options) still produces a valid unsigned receipt", () => {
  const request = minimalRequest();
  const result = authorizeAndSign(request, {});
  assert.equal(result.ok, true);
  assert.equal(result.signed, false);
  assert.ok(result.receipt.receipt_hash, "unsigned receipt must have receipt_hash");
  assert.equal(result.receipt.verifiable_signature, undefined);
});

test("16. authorizeAndSign with signing options produces a signed receipt", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const request = minimalRequest();
  const result = authorizeAndSign(request, {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  assert.equal(result.ok, true);
  assert.equal(result.signed, true);
  assert.ok(result.receipt.verifiable_signature, "signed receipt must have verifiable_signature");
  // Must verify.
  const v = verifySignedExecutionReceipt(result.receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(v.verified, true, v.reason ?? "");
});

test("17. Private key never appears in receipt output", () => {
  const { receiptKey, bundle } = makeBundle();
  const request = minimalRequest();
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  const json = JSON.stringify(receipt);
  assert.ok(!json.includes("PRIVATE KEY"), "receipt must not contain PRIVATE KEY PEM marker");
  assert.ok(!json.includes(receiptKey.privatePem.slice(40, 80)), "receipt must not contain private key bytes");
});

test("18. Receipt body fields are correctly populated", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const request = minimalRequest();
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  assert.equal(receipt.schema_version, "mnde.execution_gate.receipt.v1");
  assert.equal(receipt.execution_id, request.execution_id);
  assert.equal(receipt.request_schema_version, request.schema_version);
  assert.equal(receipt.decided_at, request.requested_at);
  assert.equal(receipt.decision, "ALLOW");
  assert.equal(receipt.authority_id, bundle.authority_id);
  assert.equal(receipt.signing_key_id, receiptKey.keyId);
  assert.equal(receipt.verifiable_signature.algorithm, "ED25519");
  assert.equal(receipt.verifiable_signature.authority_id, bundle.authority_id);
  assert.equal(receipt.verifiable_signature.key_id, receiptKey.keyId);
  assert.equal(receipt.verifiable_signature.signed_at, request.requested_at);
  // Fingerprint must match what the bundle records for this key.
  const expectedFp = fingerprintOf(receiptKey.publicPem);
  assert.equal(receipt.verifiable_signature.public_key_fingerprint, expectedFp);
});

test("19. REFUSE decision is captured with refusal_reason", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const request = minimalRequest({ principal: { verified: false } });
  const result = authorizeAndSign(request, {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  assert.equal(result.ok, true);
  assert.equal(result.receipt.decision, "REFUSE");
  assert.equal(result.receipt.refusal_reason, "PRINCIPAL_NOT_VERIFIED");
  const v = verifySignedExecutionReceipt(result.receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(v.verified, true, v.reason ?? "");
});

test("20. policyProvenance is embedded when provided", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  const request = minimalRequest();
  const provenance = { policy_id: "pol-1", serial: 1, policy_hash: "sha256:abc", bundle_id: "b-1", bundle_digest: "def" };
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem,
    policyProvenance: provenance
  });
  assert.deepEqual(receipt.policy_provenance, provenance);
  // Must still verify.
  const v = verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(v.verified, true, v.reason ?? "");
});

test("21. Fingerprint check is actually enforced (not bypassable by claiming own fingerprint)", () => {
  const { receiptKey, bundle, trustedRootFingerprint } = makeBundle();
  // Build a second key that is NOT in the bundle.
  const rogue = generateAuthorityKeyPair();
  const request = minimalRequest();
  // Sign with the real key first to get a valid signature shape, then swap the fingerprint.
  const receipt = buildSignedExecutionReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  // Attacker replaces the public_key_fingerprint with their own key's fingerprint.
  const tampered = structuredClone(receipt);
  tampered.verifiable_signature.public_key_fingerprint = fingerprintOf(rogue.publicPem);
  const result = verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  // The bundle lookup returns the real key; its fingerprint won't match the tampered value.
  assert.match(result.reason, /fingerprint_match/);
});

test("22. Request hash actually covers all mutable fields — changing one field changes hash", () => {
  const { receiptKey, bundle } = makeBundle();
  const req1 = minimalRequest({ action: { name: "deploy-v1" } });
  const req2 = minimalRequest({ action: { name: "deploy-v2" } });
  const r1 = buildSignedExecutionReceipt(req1, "ALLOW", { authorityBundle: bundle, signingKeyId: receiptKey.keyId, signingPrivateKeyPem: receiptKey.privatePem });
  const r2 = buildSignedExecutionReceipt(req2, "ALLOW", { authorityBundle: bundle, signingKeyId: receiptKey.keyId, signingPrivateKeyPem: receiptKey.privatePem });
  assert.notEqual(r1.request_hash, r2.request_hash);
});

// ── Regression: existing test suites must remain green ────────────────────────

test("23. Existing test_execution_gate.mjs exits 0", () => {
  const result = spawnSync(process.execPath, ["tests/test_execution_gate.mjs"], {
    cwd: repoRoot, encoding: "utf8", timeout: 60000
  });
  if (result.status !== 0) {
    throw new Error(`test_execution_gate.mjs exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
});

test("24. Existing test_policy_receipt.mjs exits 0", () => {
  const result = spawnSync(process.execPath, ["tests/test_policy_receipt.mjs"], {
    cwd: repoRoot, encoding: "utf8", timeout: 60000
  });
  if (result.status !== 0) {
    throw new Error(`test_policy_receipt.mjs exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
});

test("25. Existing test_signed_policy_bundle.mjs exits 0", () => {
  const result = spawnSync(process.execPath, ["tests/test_signed_policy_bundle.mjs"], {
    cwd: repoRoot, encoding: "utf8", timeout: 60000
  });
  if (result.status !== 0) {
    throw new Error(`test_signed_policy_bundle.mjs exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
});

// ── Summary ───────────────────────────────────────────────────────────────────
const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed}/${results.length} tests passed${failed > 0 ? `, ${failed} failed` : ""}`);
if (failed > 0) process.exit(1);
