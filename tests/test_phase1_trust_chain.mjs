// Phase 1 production trust-chain regression.
//
//   npm run test:phase1-trust-chain
//
// Exercises the END-TO-END production trust chain with production formats only:
//
//   pinned root  ->  mnde.authority.bundle.v1  ->  receipt-role key authorization
//                ->  mnde.execution_gate.receipt.v1 signature  ->  VERIFIED
//
// using src/custody/bundle.mjs (buildAuthorityBundle / verifyAuthorityBundle /
// findBundleKey) and src/execution-gate (buildSignedExecutionReceipt /
// verifySignedExecutionReceipt). The demo manifest (shared/authority-manifest.mjs)
// is explicitly proven NOT to be accepted as a production authority bundle.
//
// All keys here are EPHEMERAL TEST keys generated per-run. Nothing in this file
// is, or resembles, production trust material.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  verifyAuthorityBundle,
  signCanonical
} from "../src/custody/index.mjs";
import { buildSignedExecutionReceipt } from "../src/execution-gate/signed-receipt.mjs";
import { verifySignedExecutionReceipt } from "../src/execution-gate/verify-signed-receipt.mjs";
import { canonicalizeJson } from "../shared/json.ts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

// ── Fixed timeline (deterministic; never wall-clock) ────────────────────────
const ISSUED_AT = "2026-06-14T00:00:00.000Z";
const NOT_AFTER = "2026-09-12T00:00:00.000Z";      // issued + 90d
const KEY_VALID_FROM = "2026-06-14T00:00:00.000Z";
const KEY_VALID_UNTIL = "2027-06-14T00:00:00.000Z";
const SIGNED_AT = "2026-06-15T00:00:00.000Z";       // within key window + bundle
const NOW_OK = "2026-06-16T00:00:00.000Z";          // before NOT_AFTER
const AUTHORITY_ID = "mnde-systems-production";
const RECEIPT_KEY_ID = "receipt-1";
const LEDGER_KEY_ID = "ledger-1";

// ── Keys (ephemeral test material) ──────────────────────────────────────────
const rootKp = generateAuthorityKeyPair();
const receiptKp = generateAuthorityKeyPair();
const ledgerKp = generateAuthorityKeyPair();

async function buildBundle(overrides = {}) {
  return buildAuthorityBundle({
    authorityId: overrides.authorityId ?? AUTHORITY_ID,
    issuedAt: overrides.issuedAt ?? ISSUED_AT,
    notAfter: overrides.notAfter ?? NOT_AFTER,
    root: { keyId: "root-1", publicPem: rootKp.publicPem, privatePem: rootKp.privatePem },
    receiptKeys: overrides.receiptKeys ?? [{
      keyId: RECEIPT_KEY_ID, publicPem: receiptKp.publicPem,
      validFrom: overrides.keyValidFrom ?? KEY_VALID_FROM,
      validUntil: overrides.keyValidUntil ?? KEY_VALID_UNTIL
    }],
    ledgerKeys: overrides.ledgerKeys ?? [{
      keyId: LEDGER_KEY_ID, publicPem: ledgerKp.publicPem,
      validFrom: KEY_VALID_FROM, validUntil: KEY_VALID_UNTIL
    }],
    revocation: overrides.revocation ?? []
  });
}

function sampleRequest() {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-phase1-0001",
    requested_at: SIGNED_AT,
    principal: { id: "agent://ci-runner", type: "agent", verified: true },
    action: { type: "delete", name: "recursive_delete", dry_run: false },
    resource: { kind: "database", id: "prod/orders", name: "orders" },
    environment: { name: "production" },
    risk: { level: "high", destructive: true, reversible: false, blast_radius: "table" },
    evidence: { repo: "mndesystems-ship-it/mnde-public-test", commit_sha: "deadbeef", branch: "main" }
  };
}

async function mintReceipt(bundle, { keyId = RECEIPT_KEY_ID, privatePem = receiptKp.privatePem } = {}) {
  return buildSignedExecutionReceipt(sampleRequest(), "REFUSE", {
    authorityBundle: bundle,
    signingKeyId: keyId,
    signingPrivateKeyPem: privatePem,
    refusalReason: "policy denied recursive_delete on production"
  });
}

async function main() {
  console.log("MNDe Phase 1 production trust-chain regression\n");

  const bundle = await buildBundle();
  const rootFp = bundle.root_key.fingerprint;
  const receipt = await mintReceipt(bundle);

  // 12 / 1. Happy path: valid production receipt verifies against valid bundle.
  await test("valid production receipt verifies against valid production bundle", async () => {
    const r = await verifySignedExecutionReceipt(receipt, {
      authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK, originalRequest: sampleRequest()
    });
    assert.equal(r.verified, true, r.reason);
  });

  await test("valid authority bundle verifies against its pinned root", async () => {
    const r = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, true, r.reason);
  });

  // 2. Wrong pinned root.
  await test("wrong pinned root fails closed (UNTRUSTED_ROOT)", async () => {
    const otherFp = "0".repeat(64);
    const b = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: otherFp, now: NOW_OK });
    assert.equal(b.ok, false); assert.equal(b.reason, "UNTRUSTED_ROOT");
    const r = await verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint: otherFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /UNTRUSTED_ROOT/);
  });

  await test("missing pinned root fails closed (MISSING_TRUSTED_ROOT)", async () => {
    const b = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: "", now: NOW_OK });
    assert.equal(b.ok, false); assert.equal(b.reason, "MISSING_TRUSTED_ROOT");
  });

  // 3. Modified bundle (signed field mutated) breaks the root signature.
  await test("modified bundle fails closed (BUNDLE_SIGNATURE_INVALID)", async () => {
    const tampered = structuredClone(bundle); tampered.authority_id = "attacker-authority";
    const r = await verifyAuthorityBundle(tampered, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, false); assert.equal(r.reason, "BUNDLE_SIGNATURE_INVALID");
  });

  // 4. Invalid root signature.
  await test("invalid root signature fails closed (BUNDLE_SIGNATURE_INVALID)", async () => {
    const tampered = structuredClone(bundle); tampered.signature.value = "ab".repeat(32);
    const r = await verifyAuthorityBundle(tampered, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, false); assert.match(r.reason, /BUNDLE_SIGNATURE_INVALID|UNSIGNED_BUNDLE/);
  });

  await test("unsigned bundle fails closed (UNSIGNED_BUNDLE)", async () => {
    const nosig = structuredClone(bundle); delete nosig.signature;
    const r = await verifyAuthorityBundle(nosig, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, false); assert.equal(r.reason, "UNSIGNED_BUNDLE");
  });

  // 5. Expired bundle.
  await test("expired bundle fails closed (BUNDLE_STALE)", async () => {
    const r = await verifySignedExecutionReceipt(receipt, {
      authorityBundle: bundle, trustedRootFingerprint: rootFp, now: "2026-10-01T00:00:00.000Z"
    });
    assert.equal(r.verified, false); assert.match(r.reason, /BUNDLE_STALE/);
  });

  // 6. Receipt key not yet valid (signed before its validity window opens).
  await test("receipt key not-yet-valid fails closed (KEY_EXPIRED window)", async () => {
    const future = await buildBundle({ keyValidFrom: "2026-07-01T00:00:00.000Z" });
    const r = await verifySignedExecutionReceipt(receipt, {
      authorityBundle: future, trustedRootFingerprint: future.root_key.fingerprint, now: NOW_OK
    });
    assert.equal(r.verified, false); assert.match(r.reason, /key_lookup: KEY_EXPIRED/);
  });

  // 7. Unknown receipt signing key.
  await test("unknown receipt signing key fails closed (UNKNOWN_KEY)", async () => {
    const forged = structuredClone(receipt); forged.verifiable_signature.key_id = "ghost-key";
    const r = await verifySignedExecutionReceipt(forged, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /key_lookup: UNKNOWN_KEY/);
  });

  // 8. Revoked receipt signing key.
  await test("revoked receipt signing key fails closed (KEY_REVOKED)", async () => {
    const revoked = await buildBundle({ revocation: [{ key_id: RECEIPT_KEY_ID, revoked_at: "2026-06-14T12:00:00.000Z" }] });
    const r = await verifySignedExecutionReceipt(receipt, {
      authorityBundle: revoked, trustedRootFingerprint: revoked.root_key.fingerprint, now: NOW_OK
    });
    assert.equal(r.verified, false); assert.match(r.reason, /key_lookup: KEY_REVOKED/);
  });

  // 9. Wrong-role key: a ledger key cannot act as a receipt key.
  await test("wrong-role key fails closed (ledger key not accepted as receipt)", async () => {
    // Receipt claims the ledger key_id and is signed by the ledger private key —
    // only the ROLE is wrong. Role-scoped lookup must reject it.
    const wrong = structuredClone(receipt);
    wrong.signing_key_id = LEDGER_KEY_ID;
    wrong.authority_id = bundle.authority_id;
    const { verifiable_signature: _drop, ...body } = wrong;
    const value = await signCanonical(canonicalizeJson(body), ledgerKp.privatePem);
    wrong.verifiable_signature = {
      algorithm: "ED25519", authority_id: bundle.authority_id, key_id: LEDGER_KEY_ID,
      signed_at: SIGNED_AT, public_key_fingerprint: "x", value
    };
    const r = await verifySignedExecutionReceipt(wrong, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /key_lookup: UNKNOWN_KEY/);
  });

  // 9b. Authority-id mismatch: a receipt naming a different authority than the
  //     bundle must not verify (no mixing trust material across authorities).
  await test("authority_id mismatch fails closed", async () => {
    const forged = structuredClone(receipt); forged.verifiable_signature.authority_id = "other-authority";
    const r = await verifySignedExecutionReceipt(forged, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /authority_id_match|signature/);
  });

  // 10. Modified receipt body.
  await test("modified receipt body fails closed (signature)", async () => {
    const forged = structuredClone(receipt); forged.decision = "ALLOW";
    const r = await verifySignedExecutionReceipt(forged, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /signature/);
  });

  // 11. Invalid receipt signature.
  await test("invalid receipt signature fails closed", async () => {
    const forged = structuredClone(receipt); forged.verifiable_signature.value = "cd".repeat(32);
    const r = await verifySignedExecutionReceipt(forged, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.verified, false); assert.match(r.reason, /signature/);
  });

  // 13. Demo manifest must NOT be accepted as a production authority bundle.
  await test("demo manifest is rejected as a production bundle (UNSUPPORTED_BUNDLE)", async () => {
    const demo = JSON.parse(readFileSync(join(repoRoot, "authority", "authority-manifest.json"), "utf8"));
    const r = await verifyAuthorityBundle(demo, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, false); assert.equal(r.reason, "UNSUPPORTED_BUNDLE");
    // And a demo-shaped object can never satisfy the production receipt verifier.
    const rr = await verifySignedExecutionReceipt(receipt, { authorityBundle: demo, trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(rr.verified, false);
  });

  // 14. Malformed bundle fails closed (no uncontrolled throw).
  await test("malformed bundle fails closed without throwing", async () => {
    for (const bad of [null, undefined, {}, { schema_version: "mnde.authority.bundle.v1" }, 42, "nope", []]) {
      const r = await verifyAuthorityBundle(bad, { trustedRootFingerprint: rootFp, now: NOW_OK });
      assert.equal(r.ok, false, `expected fail for ${JSON.stringify(bad)}`);
    }
  });

  // 15. Malformed receipt fails closed (no uncontrolled throw).
  await test("malformed receipt fails closed without throwing", async () => {
    for (const bad of [null, undefined, {}, { schema_version: "mnde.execution_gate.receipt.v1" }, 7, "x", []]) {
      const r = await verifySignedExecutionReceipt(bad, { authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK });
      assert.equal(r.verified, false, `expected fail for ${JSON.stringify(bad)}`);
    }
  });

  // 16. Unsupported bundle schema.
  await test("unsupported bundle schema fails closed (UNSUPPORTED_BUNDLE)", async () => {
    const b = structuredClone(bundle); b.schema_version = "mnde.authority.bundle.v2";
    const r = await verifyAuthorityBundle(b, { trustedRootFingerprint: rootFp, now: NOW_OK });
    assert.equal(r.ok, false); assert.equal(r.reason, "UNSUPPORTED_BUNDLE");
  });

  // 17. Unsupported receipt schema.
  await test("unsupported receipt schema fails closed", async () => {
    const r = await verifySignedExecutionReceipt({ ...receipt, schema_version: "ecs.receipt.v2" }, {
      authorityBundle: bundle, trustedRootFingerprint: rootFp, now: NOW_OK
    });
    assert.equal(r.verified, false); assert.match(r.reason, /schema/);
  });

  // 18/19. Ceremony: overwrite refusal + no private key material in reported output.
  await test("no private-key material appears in a verified receipt or bundle", () => {
    assert.ok(!JSON.stringify(bundle).includes("PRIVATE KEY"), "bundle carries no private key");
    assert.ok(!JSON.stringify(receipt).includes("PRIVATE KEY"), "receipt carries no private key");
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL phase1-trust-chain (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS phase1-trust-chain (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
