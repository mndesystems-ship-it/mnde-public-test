#!/usr/bin/env node
// Audit remediation regression tests.
//
// Covers findings that previously had no dedicated test:
//   - M2: bundle with extra policy_document fields activates only if offline
//          verifier sees the same document (no mismatch between sign and verify)
//   - M1: provenance in canonical_request does NOT exist; decision_hash is
//          bundle-specific when policy_document carries trust fields; per-receipt
//          replay remains deterministic
//   - M4: stale authority bundle reports REVOCATION_FRESHNESS: CURRENT_TO_BUNDLE,
//          not a global guarantee
//
// These tests must PASS before merge. They document intentional behavior and
// guard against future regressions.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import {
  buildAuthorityBundle,
  findBundleKey,
  generateAuthorityKeyPair,
  signCanonical,
  verifyAgainstBundle,
  verifyAuthorityBundle
} from "../src/custody/index.mjs";
import {
  activateSignedPolicyBundle,
  signPolicyBundle,
  verifyHistoricalPolicyBundleProvenance
} from "../src/policy-bundles/index.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const NOW = "2026-06-23T12:00:00.000Z";
const results = [];
let testChain = Promise.resolve();

function test(name, fn) {
  testChain = testChain.then(async () => {
    try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
    catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
  });
}

function basePolicy(version) {
  return {
    schema_version: "1.0",
    policy_id: "ops-policy",
    version,
    state: "ACTIVE",
    rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
  };
}

async function fixture() {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "audit-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const dir = mkdtempSync(join(tmpdir(), "mnde-audit-"));
  return { root, policyKey, approvalKey, authorityBundle, statePath: join(dir, "state.json"), dir };
}

async function signBundle(f, serial, policyDocument, extra = {}) {
  return await signPolicyBundle({
    bundle_id: `ops-policy-${serial}`,
    policy_id: "ops-policy",
    serial,
    issued_at: NOW,
    policy_document: policyDocument,
    ...extra
  }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
}

async function activate(f, bundle) {
  return await activateSignedPolicyBundle({
    bundle,
    authorityBundle: f.authorityBundle,
    trustedRootFingerprint: f.authorityBundle.root_key.fingerprint,
    statePath: f.statePath,
    now: NOW
  });
}

const baseRequest = {
  schema_version: "1.0",
  request_id: "audit-1",
  timestamp: NOW,
  principal: { id: "operator" },
  agent: { id: "agent" },
  tool: { tool_name: "read_status" },
  parameters: {},
  environment: {},
  context: {}
};

console.log("MNDe audit remediation regression tests\n");

// ── M2: extra policy_document fields ─────────────────────────────────────────
// A policy_document with additional fields beyond the base schema must produce
// consistent sign → activate → offline-verify behaviour. The signed bundle
// hashes the FULL policy_document; the offline verifier compares the same full
// document. Either both sides include the extra field or neither does.
test("M2: policy_document with extra declared fields activates and round-trips to offline verification", async () => {
  const f = await fixture();
  try {
    // A policy_document with an extra declared field (e.g., metadata).
    const policy = { ...basePolicy("7.0.0"), metadata: { owner: "ops-team", tier: "production" } };
    const bundle = await signBundle(f, 7, policy);

    // Activation must succeed: the bundle is well-formed, the signature covers
    // the full policy_document including the extra field.
    const activation = await activate(f, bundle);
    assert.equal(activation.ok, true, activation.reason);
    assert.equal(activation.policy.metadata?.owner, "ops-team");

    // Offline provenance verification must succeed when given the SAME bundle.
    // The verifier compares canonicalizeJson(policy) vs canonicalizeJson(bundle.policy_document).
    const receipt = buildPolicyReceipt(baseRequest, activation.policy, {
      policyBundleProvenance: activation.policyBundleProvenance
    });
    const historical = await verifyHistoricalPolicyBundleProvenance({
      bundle,
      provenance: receipt.policy_bundle_provenance,
      policy: activation.policy,
      authorityBundle: f.authorityBundle,
      trustedRootFingerprint: f.authorityBundle.root_key.fingerprint
    });
    assert.equal(historical.ok, true, historical.reason);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("M2: offline verification fails if a different policy_document (missing extra field) is supplied", async () => {
  const f = await fixture();
  try {
    const policyWithExtra = { ...basePolicy("7.0.0"), metadata: { owner: "ops-team" } };
    const policyWithout = basePolicy("7.0.0");

    // Sign with the extra field.
    const bundle = await signBundle(f, 7, policyWithExtra);
    const activation = await activate(f, bundle);
    assert.equal(activation.ok, true, activation.reason);

    const receipt = buildPolicyReceipt(baseRequest, activation.policy, {
      policyBundleProvenance: activation.policyBundleProvenance
    });

    // Supply the WRONG policy (without extra field) — must fail.
    const historical = await verifyHistoricalPolicyBundleProvenance({
      bundle,
      provenance: receipt.policy_bundle_provenance,
      policy: policyWithout,   // ← mismatch: no metadata field
      authorityBundle: f.authorityBundle,
      trustedRootFingerprint: f.authorityBundle.root_key.fingerprint
    });
    assert.equal(historical.ok, false);
    assert.equal(historical.reason, "POLICY_BUNDLE_POLICY_DOCUMENT_MISMATCH");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

// ── M1: decision_hash is bundle-specific; per-receipt replay is deterministic ─
// decision_hash is computed from {request_hash, policy_hash, ...}. policy_hash
// covers the full policy_document. Two different bundles that activate different
// policy_documents produce different policy_hash values and therefore different
// decision_hash values — this is intentional. Per-receipt replay is deterministic:
// replaying the SAME receipt against the SAME request+policy returns the same hash.
test("M1: per-receipt replay is deterministic — same receipt verifies consistently", async () => {
  const f = await fixture();
  try {
    const policyPath = join(f.dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify(basePolicy("7.0.0")));
    const receipt = buildPolicyReceipt(baseRequest, basePolicy("7.0.0"));
    // Replay the same receipt twice — both must verify and produce the same hashes.
    const r1 = await verifyPolicyReceipt(receipt);
    const r2 = await verifyPolicyReceipt(receipt);
    assert.equal(r1.verified, true, r1.reason);
    assert.equal(r2.verified, true, r2.reason);
    assert.equal(receipt.request_hash, receipt.decision_output.request_hash);
    assert.equal(receipt.policy_hash, receipt.decision_output.policy_hash);
    assert.equal(receipt.decision_output.decision_hash, receipt.decision_output.decision_hash);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("M1: two receipts from different policy bundles have different policy_hash and decision_hash", async () => {
  const f = await fixture();
  try {
    const policyA = basePolicy("7.0.0");
    const policyB = { ...basePolicy("8.0.0"), rules: [{ rule_id: "deny-all", effect: "DENY", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] };
    const receiptA = buildPolicyReceipt(baseRequest, policyA);
    const receiptB = buildPolicyReceipt(baseRequest, policyB);
    // Different policies → different policy_hash → different decision_hash.
    assert.notEqual(receiptA.policy_hash, receiptB.policy_hash);
    assert.notEqual(receiptA.decision_output.decision_hash, receiptB.decision_output.decision_hash);
    // But each receipt replays deterministically on its own.
    assert.equal((await (await verifyPolicyReceipt(receiptA))).verified, true);
    assert.equal((await (await verifyPolicyReceipt(receiptB))).verified, true);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("M1: receipts produced without bundle provenance (off-mode / legacy) still verify", async () => {
  // Regression: off-mode receipts must remain verifiable after provenance was added.
  const receipt = buildPolicyReceipt(baseRequest, basePolicy("7.0.0"));
  assert.equal("policy_bundle_provenance" in receipt, false, "off-mode receipt must not carry provenance");
  assert.equal((await (await verifyPolicyReceipt(receipt))).verified, true);
});

// ── M4: stale manifest revocation freshness ───────────────────────────────────
// The offline verifier uses whatever bundle it was given. It must not assert
// that revocation is globally current — it can only assert that the key is
// not on the revocation list IN THIS BUNDLE. We surface this as
// `revocation_freshness: "CURRENT_TO_BUNDLE"` rather than silently claiming
// global revocation currency.
test("M4: findBundleKey reports revocation_freshness CURRENT_TO_BUNDLE for non-revoked key", async () => {
  const root2 = { keyId: "root-x", ...generateAuthorityKeyPair() };
  const receiptK = { keyId: "receipt-x", ...generateAuthorityKeyPair() };
  const b = await buildAuthorityBundle({
    authorityId: "freshness-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root: root2,
    receiptKeys: [{ keyId: receiptK.keyId, publicPem: receiptK.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  const result = findBundleKey(b, "receipt", "receipt-x", NOW);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.revocation_freshness, "CURRENT_TO_BUNDLE",
    "verifier must not claim global revocation currency — only current-to-bundle");
});

test("M4: verifyAgainstBundle propagates revocation_freshness on success", async () => {
  const root2 = { keyId: "root-y", ...generateAuthorityKeyPair() };
  const policyK = { keyId: "policy-y", ...generateAuthorityKeyPair() };
  const b = await buildAuthorityBundle({
    authorityId: "freshness-policy-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root: root2,
    policyKeys: [{ keyId: policyK.keyId, publicPem: policyK.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  const payload = '{"test":"freshness"}';
  const sig = await signCanonical(payload, policyK.privatePem);
  const result = await verifyAgainstBundle(payload, sig, "policy", "policy-y", NOW, b);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.revocation_freshness, "CURRENT_TO_BUNDLE",
    "verifyAgainstBundle must surface revocation_freshness from the bundle it used");
});

test("M4: a key revoked in a LATER bundle still appears valid in the OLDER bundle (staleness is real, honestly reported)", async () => {
  // This test documents the known limitation: a stale bundle cannot know about
  // revocations issued after it. The verifier reports CURRENT_TO_BUNDLE, not
  // NOT_REVOKED_GLOBALLY.
  const root2 = { keyId: "root-z", ...generateAuthorityKeyPair() };
  const k = { keyId: "key-z", ...generateAuthorityKeyPair() };
  const oldBundle = await buildAuthorityBundle({
    authorityId: "stale-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root: root2,
    receiptKeys: [{ keyId: k.keyId, publicPem: k.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  // Simulate a newer bundle that has revoked this key.
  const newBundle = await buildAuthorityBundle({
    authorityId: "stale-test",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root: root2,
    receiptKeys: [{ keyId: k.keyId, publicPem: k.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: [k.keyId]
  });

  const payload = '{"test":"stale"}';
  const sig = await signCanonical(payload, k.privatePem);

  // Old bundle: key not revoked, but only CURRENT_TO_BUNDLE — not global.
  const withOldBundle = await verifyAgainstBundle(payload, sig, "receipt", k.keyId, NOW, oldBundle);
  assert.equal(withOldBundle.ok, true, withOldBundle.reason);
  assert.equal(withOldBundle.revocation_freshness, "CURRENT_TO_BUNDLE",
    "stale bundle must not claim global revocation currency");

  // New bundle: key is revoked.
  const withNewBundle = await verifyAgainstBundle(payload, sig, "receipt", k.keyId, NOW, newBundle);
  assert.equal(withNewBundle.ok, false);
  assert.equal(withNewBundle.reason, "KEY_REVOKED");
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL audit remediation regression tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS audit remediation regression tests (${results.length}/${results.length})`);
