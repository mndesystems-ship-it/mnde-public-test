// Authority key lifecycle tests — rotation, retirement, revocation.
//
//   npm run test:custody-lifecycle
//
// Proves production trust roots are operable: a signing key can be rotated and
// revoked while (a) the bundle stays root-signed and offline-verifiable, (b)
// receipts signed by a retired key BEFORE rotation stay verifiable, (c) the
// retired key cannot sign anything dated after rotation, and (d) a revoked key
// is rejected immediately. All offline; fail-closed on bad input.

import assert from "node:assert/strict";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  signCanonical,
  verifyAuthorityBundle,
  verifyAgainstBundle,
  findBundleKey
} from "../src/custody/index.mjs";
import { rotateSigningKey, revokeKey, rootKeyMatches } from "../src/custody/lifecycle.mjs";

const results = [];
function test(name, fn) {
  try { fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

const T0 = "2026-03-01T00:00:00.000Z"; // before rotation — old key signs here
const T_ROT = "2026-06-01T00:00:00.000Z"; // rotation moment
const T2 = "2026-09-01T00:00:00.000Z"; // after rotation — new key signs here

function fixture() {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const k1 = { keyId: "receipt-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "acme-prod",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: k1.keyId, publicPem: k1.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  return { root, k1, bundle };
}
const payload = (n) => canonicalizeJson({ decision: "ALLOW", n });

function main() {
  console.log("MNDe authority key lifecycle\n");

  // ── rotation preserves history + activates the new key ──────────────────────
  test("rotation: bundle stays root-signed and offline-verifiable", () => {
    const { root, bundle } = fixture();
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT });
    assert.equal(r.ok, true, r.reason);
    assert.equal(verifyAuthorityBundle(r.bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: T2 }).ok, true);
    assert.equal(r.newKeyId, "receipt-2");
    assert.deepEqual(r.retiredKeyIds, ["receipt-1"]);
  });

  test("rotation: a receipt signed by the OLD key BEFORE rotation stays verifiable", () => {
    const { root, k1, bundle } = fixture();
    const sig = signCanonical(payload(1), k1.privatePem); // signed at T0 conceptually
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT });
    // T0 < T_ROT -> still inside receipt-1's (now-closed) window
    assert.equal(verifyAgainstBundle(payload(1), sig, "receipt", "receipt-1", T0, r.bundle).ok, true);
  });

  test("rotation: the retired key CANNOT sign anything dated at/after rotation", () => {
    const { root, k1, bundle } = fixture();
    const sig = signCanonical(payload(2), k1.privatePem);
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT });
    const v = verifyAgainstBundle(payload(2), sig, "receipt", "receipt-1", T2, r.bundle);
    assert.equal(v.ok, false);
    assert.equal(v.reason, "KEY_EXPIRED");
  });

  test("rotation: the NEW key signs and verifies after rotation", () => {
    const { root, bundle } = fixture();
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT });
    const sig = signCanonical(payload(3), k2.privatePem);
    assert.equal(verifyAgainstBundle(payload(3), sig, "receipt", "receipt-2", T2, r.bundle).ok, true);
  });

  // ── revocation fails closed immediately ─────────────────────────────────────
  test("revocation: a revoked key is rejected even inside its validity window", () => {
    const { root, k1, bundle } = fixture();
    const sig = signCanonical(payload(4), k1.privatePem);
    const r = revokeKey(bundle, { rootPrivateKeyPem: root.privatePem, keyId: "receipt-1", now: T_ROT });
    assert.equal(r.ok, true, r.reason);
    assert.equal(verifyAuthorityBundle(r.bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: T2 }).ok, true);
    const v = verifyAgainstBundle(payload(4), sig, "receipt", "receipt-1", T0, r.bundle);
    assert.equal(v.ok, false);
    assert.equal(v.reason, "KEY_REVOKED");
  });

  // ── fail-closed guards ──────────────────────────────────────────────────────
  test("rotation/revocation refuse a non-matching root private key", () => {
    const { bundle } = fixture();
    const wrongRoot = generateAuthorityKeyPair();
    const k2 = generateAuthorityKeyPair();
    assert.equal(rotateSigningKey(bundle, { rootPrivateKeyPem: wrongRoot.privatePem, newKey: { keyId: "x", publicPem: k2.publicPem }, now: T_ROT }).reason, "ROOT_KEY_MISMATCH");
    assert.equal(revokeKey(bundle, { rootPrivateKeyPem: wrongRoot.privatePem, keyId: "receipt-1", now: T_ROT }).reason, "ROOT_KEY_MISMATCH");
    assert.equal(rootKeyMatches(bundle, wrongRoot.privatePem), false);
  });

  test("rotation refuses a duplicate key id; revoke refuses unknown/already-revoked", () => {
    const { root, k1, bundle } = fixture();
    assert.equal(rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-1", publicPem: k1.publicPem }, now: T_ROT }).reason, "DUPLICATE_KEY_ID");
    assert.equal(revokeKey(bundle, { rootPrivateKeyPem: root.privatePem, keyId: "nope", now: T_ROT }).reason, "UNKNOWN_KEY_ID");
    const once = revokeKey(bundle, { rootPrivateKeyPem: root.privatePem, keyId: "receipt-1", now: T_ROT });
    assert.equal(revokeKey(once.bundle, { rootPrivateKeyPem: root.privatePem, keyId: "receipt-1", now: T2 }).reason, "ALREADY_REVOKED");
  });

  test("rotation with retire=false keeps both keys active (overlap window)", () => {
    const { root, k1, bundle } = fixture();
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT, retire: false });
    assert.equal(r.ok, true, r.reason);
    // old key still valid after rotation when not retired
    assert.equal(findBundleKey(r.bundle, "receipt", "receipt-1", T2).ok, true);
    assert.equal(findBundleKey(r.bundle, "receipt", "receipt-2", T2).ok, true);
  });

  test("monotonic re-issue: rotated bundle issued_at advances", () => {
    const { root, bundle } = fixture();
    const k2 = generateAuthorityKeyPair();
    const r = rotateSigningKey(bundle, { rootPrivateKeyPem: root.privatePem, newKey: { keyId: "receipt-2", publicPem: k2.publicPem }, now: T_ROT });
    assert.equal(r.bundle.issued_at, T_ROT);
    assert.ok(Date.parse(r.bundle.issued_at) > Date.parse(bundle.issued_at));
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL custody-lifecycle tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS custody-lifecycle tests (${results.length}/${results.length})`);
}

main();
