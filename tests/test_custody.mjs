// Production authority bundle + key-custody tests.
//
//   npm run test:custody
//
// All offline. Verifies: local-demo works by default and is unchanged; a
// file-backed production bundle verifies offline; expired / revoked / unknown
// keys fail; a tampered bundle fails; a missing bundle fails closed; a stale
// bundle is rejected; and no private key material ever appears in a bundle, a
// signature object, or an error message.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  createCustody,
  createFileBackedProductionCustody,
  createLocalDemoCustody,
  findBundleKey,
  generateAuthorityKeyPair,
  signCanonical,
  verifyAgainstBundle,
  verifyAuthorityBundle
} from "../src/custody/index.mjs";

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

// A reusable production-shaped bundle with a known root + one valid receipt key.
function makeProductionFixture({ now = "2026-06-14T00:00:00.000Z" } = {}) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const expired = { keyId: "prod-receipt-old", ...generateAuthorityKeyPair() };
  const revoked = { keyId: "prod-receipt-bad", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "mnde-prod",
    issuedAt: now,
    notAfter: "2027-06-14T00:00:00.000Z",
    root,
    receiptKeys: [
      { keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" },
      { keyId: expired.keyId, publicPem: expired.publicPem, validFrom: "2024-01-01T00:00:00.000Z", validUntil: "2025-01-01T00:00:00.000Z" },
      { keyId: revoked.keyId, publicPem: revoked.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }
    ],
    revocation: ["prod-receipt-bad"]
  });
  return { root, receipt, expired, revoked, bundle, now };
}

// ── local-demo (default, unchanged) ──────────────────────────────────────────
test("default custody is local-demo and signs + self-verifies offline", () => {
  const { ok, provider } = createCustody({});
  assert.equal(ok, true);
  assert.equal(provider.mode, "local-demo");
  assert.equal(provider.production, false);

  const bundle = provider.getPublicBundle();
  assert.equal(verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint }).ok, true);

  const payload = canonicalizeJson({ hello: "world" });
  const sig = provider.signReceipt(payload);
  const check = verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, "2026-06-14T00:00:00.000Z", bundle);
  assert.equal(check.ok, true);
});

test("createLocalDemoCustody can sign policy + approval and they verify", () => {
  const p = createLocalDemoCustody();
  const bundle = p.getPublicBundle();
  const at = "2026-06-14T00:00:00.000Z";
  for (const role of ["policy", "approval"]) {
    const payload = canonicalizeJson({ role });
    const sig = role === "policy" ? p.signPolicy(payload) : p.signApproval(payload);
    assert.equal(verifyAgainstBundle(payload, sig.value, role, sig.key_id, at, bundle).ok, true, role);
  }
});

// ── production bundle verifies offline ───────────────────────────────────────
test("production bundle verifies offline against trusted root fingerprint", () => {
  const { bundle, root, now } = makeProductionFixture();
  const trusted = bundle.root_key.fingerprint;
  assert.equal(verifyAuthorityBundle(bundle, { trustedRootFingerprint: trusted, now }).ok, true);
  // Wrong trust anchor → rejected.
  assert.equal(verifyAuthorityBundle(bundle, { trustedRootFingerprint: "deadbeef", now }).reason, "UNTRUSTED_ROOT");
  // Sanity: root fingerprint is derived from the published root public key.
  assert.equal(typeof root.publicPem, "string");
});

test("receipt signed by a production key verifies against the published bundle", () => {
  const { bundle, receipt, now } = makeProductionFixture();
  const payload = canonicalizeJson({ decision: "ALLOW", n: 1 });
  const value = signCanonical(payload, receipt.privatePem);
  assert.equal(verifyAgainstBundle(payload, value, "receipt", receipt.keyId, now, bundle).ok, true);
});

// ── expired / revoked / unknown ──────────────────────────────────────────────
test("expired key fails", () => {
  const { bundle, expired } = makeProductionFixture();
  // signedAt is after the key's valid_until window.
  const res = findBundleKey(bundle, "receipt", expired.keyId, "2026-06-14T00:00:00.000Z");
  assert.equal(res.ok, false);
  assert.equal(res.reason, "KEY_EXPIRED");
});

test("revoked key fails even within its validity window", () => {
  const { bundle, revoked } = makeProductionFixture();
  const res = findBundleKey(bundle, "receipt", revoked.keyId, "2026-06-14T00:00:00.000Z");
  assert.equal(res.ok, false);
  assert.equal(res.reason, "KEY_REVOKED");
});

test("receipt signed by unknown key fails", () => {
  const { bundle, now } = makeProductionFixture();
  const stranger = generateAuthorityKeyPair();
  const payload = canonicalizeJson({ decision: "ALLOW" });
  const value = signCanonical(payload, stranger.privatePem);
  const res = verifyAgainstBundle(payload, value, "receipt", "not-in-bundle", now, bundle);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "UNKNOWN_KEY");
});

test("valid key id but wrong signing material fails with SIGNATURE_INVALID", () => {
  const { bundle, receipt, now } = makeProductionFixture();
  const stranger = generateAuthorityKeyPair();
  const payload = canonicalizeJson({ decision: "ALLOW" });
  const value = signCanonical(payload, stranger.privatePem); // signed by the wrong key
  const res = verifyAgainstBundle(payload, value, "receipt", receipt.keyId, now, bundle);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "SIGNATURE_INVALID");
});

// ── tampered / stale ─────────────────────────────────────────────────────────
test("tampered bundle fails signature verification", () => {
  const { bundle, now } = makeProductionFixture();
  const tampered = structuredClone(bundle);
  tampered.authority_id = "attacker-controlled";
  const res = verifyAuthorityBundle(tampered, { trustedRootFingerprint: bundle.root_key.fingerprint, now });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_SIGNATURE_INVALID");
});

test("swapped root key (fingerprint mismatch) fails", () => {
  const { bundle, now } = makeProductionFixture();
  const tampered = structuredClone(bundle);
  tampered.root_key.public_key = generateAuthorityKeyPair().publicPem; // fingerprint no longer matches
  const res = verifyAuthorityBundle(tampered, { now });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "ROOT_FINGERPRINT_MISMATCH");
});

test("verifier rejects a stale bundle (past not_after)", () => {
  const { bundle } = makeProductionFixture();
  const res = verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: "2028-01-01T00:00:00.000Z" });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_STALE");
});

test("verifier rejects a bundle older than maxAgeMs", () => {
  const { bundle, now } = makeProductionFixture();
  const dayLater = "2026-06-15T00:01:00.000Z";
  const res = verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: dayLater, maxAgeMs: 24 * 60 * 60 * 1000 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_STALE");
  // Within maxAge it still passes.
  assert.equal(verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now, maxAgeMs: 24 * 60 * 60 * 1000 }).ok, true);
});

// ── file-backed-production: missing/malformed config fails closed ────────────
test("missing bundle fails closed (createCustody returns ok:false)", () => {
  const res = createCustody({ MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "does-not-exist-xyz.json") });
  assert.equal(res.ok, false);
  assert.match(res.reason, /cannot read MNDE_AUTHORITY_BUNDLE/);
});

test("unknown custody mode fails closed", () => {
  const res = createCustody({ MNDE_KEY_CUSTODY: "magic-vault" });
  assert.equal(res.ok, false);
  assert.match(res.reason, /unknown MNDE_KEY_CUSTODY/);
});

test("file-backed-production loads a real bundle + key and signs verifiably", () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-custody-"));
  try {
    const { bundle, receipt } = makeProductionFixture();
    const bundlePath = join(dir, "authority.bundle.json");
    const keyPath = join(dir, "receipt.key.pem");
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    writeFileSync(keyPath, receipt.privatePem, "utf8");

    const provider = createFileBackedProductionCustody({
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: keyPath,
      MNDE_RECEIPT_KEY_ID: receipt.keyId
    });
    assert.equal(provider.mode, "file-backed-production");
    assert.equal(provider.production, true);

    const payload = canonicalizeJson({ decision: "ALLOW", from: "file-backed" });
    const sig = provider.signReceipt(payload);
    const pub = provider.getPublicBundle();
    assert.equal(verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, "2026-06-14T00:00:00.000Z", pub).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── no secrets anywhere ──────────────────────────────────────────────────────
test("no private key material in bundle, signature, or error output", () => {
  // Published bundle has zero private keys.
  const demo = createLocalDemoCustody();
  const bundleJson = JSON.stringify(demo.getPublicBundle());
  assert.ok(!bundleJson.includes("PRIVATE KEY"), "bundle must not contain private keys");

  // Signature objects carry only key id + signature + fingerprint.
  const sig = demo.signReceipt(canonicalizeJson({ a: 1 }));
  assert.deepEqual(Object.keys(sig).sort(), ["fingerprint", "key_id", "value"]);
  assert.ok(!JSON.stringify(sig).includes("PRIVATE KEY"));

  // Fail-closed error messages reference paths/reasons, never key bytes.
  const dir = mkdtempSync(join(tmpdir(), "mnde-custody-"));
  try {
    const bundlePath = join(dir, "authority.bundle.json");
    const keyPath = join(dir, "secret.key.pem");
    const secret = generateAuthorityKeyPair().privatePem;
    const { bundle } = makeProductionFixture();
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    writeFileSync(keyPath, secret, "utf8");
    // Wrong key id → error, and the error must not echo the private key.
    const res = createCustody({
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: keyPath,
      MNDE_RECEIPT_KEY_ID: "no-such-key"
    });
    assert.equal(res.ok, false);
    assert.ok(!res.reason.includes("PRIVATE KEY"), "error must not contain key material");
    assert.ok(!res.reason.includes(secret.slice(40, 80)), "error must not contain key bytes");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL custody tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS custody tests (${results.length}/${results.length})`);
