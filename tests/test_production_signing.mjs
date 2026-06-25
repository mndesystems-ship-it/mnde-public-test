// Production trust signing for live traffic.
//
//   npm run test:production-signing
//
// Proves the end-to-end custody signing path: a built receipt is wrapped in a
// custody attestation, delivered over live sidecar traffic, and verified offline
// against a published authority bundle. Legacy signing remains the default and
// is unchanged. Custody failures fail closed with distinct reason codes. No key
// material appears in receipts, logs, or error responses.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../src/custody/index.mjs";
import {
  loadSigningConfig,
  signReceiptForDelivery,
  verifyCustodyAttestation,
  SIGNED_RECEIPT_SCHEMA
} from "../src/authority-signing/index.mjs";
import { buildPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { verifyAnyReceiptObject, verifyAnyReceiptFile } from "../tools/verify.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
bootstrapReceiptKeys({ repoRoot });

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

const NOW = "2026-06-14T00:00:00.000Z";

// A custody provider backed by a generated production bundle whose key validity
// and revocation we control.
function makeProvider({ now = NOW, validFrom = "2026-01-01T00:00:00.000Z", validUntil = "2027-01-01T00:00:00.000Z", notAfter = "2027-06-14T00:00:00.000Z", revoke = false } = {}) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "mnde-prod",
    issuedAt: now,
    notAfter,
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom, validUntil }],
    revocation: revoke ? [receipt.keyId] : []
  });
  const provider = {
    mode: "file-backed-production",
    production: true,
    trustedRootFingerprint: bundle.root_key.fingerprint,
    signReceipt: (payload) => ({ key_id: receipt.keyId, value: signCanonical(payload, receipt.privatePem), fingerprint: bundle.keys.receipt[0].fingerprint }),
    signPolicy: () => { throw new Error("n/a"); },
    signApproval: () => { throw new Error("n/a"); },
    getPublicBundle: () => structuredClone(bundle)
  };
  return { provider, bundle, root, receipt };
}

function sampleInner() {
  return { schema_version: "mnde.pe.receipt.v1", decision_output: { decision: "ALLOW" }, request_hash: "abc" };
}
function realPolicyReceipt() {
  const request = { schema_version: "1.0", request_id: "req-1", timestamp: NOW, principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} };
  const policy = JSON.parse(readFileSync(samplePolicy, "utf8"));
  return buildPolicyReceipt(request, policy, { now: NOW });
}

async function main() {
  console.log("MNDe production trust signing\n");

  // ── default legacy behavior unchanged ──────────────────────────────────────
  await test("default signing mode is legacy and passes the receipt through unchanged", () => {
    const cfg = loadSigningConfig({});
    assert.equal(cfg.mode, "legacy");
    const inner = sampleInner();
    const out = signReceiptForDelivery(inner, cfg);
    assert.equal(out.ok, true);
    assert.equal(out.receipt, inner, "legacy mode must return the same receipt object");
  });

  // ── custody signs + verifies ───────────────────────────────────────────────
  await test("custody receipt signs successfully and carries all required fields", () => {
    const { provider } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    assert.equal(out.ok, true);
    assert.equal(out.receipt.schema_version, SIGNED_RECEIPT_SCHEMA);
    const a = out.receipt.custody_attestation;
    for (const f of ["receipt_type", "receipt_version", "decision", "receipt_hash", "signing_key_id", "authority_bundle_fingerprint", "signed_at"]) {
      assert.ok(a[f] !== undefined, `missing ${f}`);
    }
    assert.equal(a.signature.algorithm, "ED25519");
    assert.equal(a.decision, "ALLOW");
  });

  await test("custody receipt verifies successfully against its bundle (attestation)", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const v = verifyCustodyAttestation(out.receipt, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW });
    assert.equal(v.ok, true);
    assert.equal(v.signing_key_id, "prod-receipt-1");
  });

  await test("custody verification without a trusted root pin fails closed", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(realPolicyReceipt(), { mode: "custody", provider }, { now: NOW });
    const v = verifyAnyReceiptObject(out.receipt, { authorityBundle: bundle, now: NOW });
    assert.equal(v.kind, "custody-signed");
    assert.equal(v.verified, false);
    assert.match(v.reason, /MISSING_TRUSTED_ROOT/);
    assert.notEqual(v.custody.trust_chain, "VALID");
  });

  await test("full custody envelope (real PE inner) verifies through the unified verifier", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(realPolicyReceipt(), { mode: "custody", provider }, { now: NOW });
    const v = verifyAnyReceiptObject(out.receipt, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW });
    assert.equal(v.kind, "custody-signed");
    assert.equal(v.verified, true, v.reason ?? "");
    assert.equal(v.custody.trust_chain, "VALID");
    assert.equal(v.custody.trust_source, "ROOT_PINNED_AUTHORITY_BUNDLE");
  });

  await test("receipt verifies against the exported published bundle", () => {
    const { provider } = makeProvider();
    const exported = provider.getPublicBundle(); // what `authority-bundle:export` writes
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    assert.equal(verifyCustodyAttestation(out.receipt, { authorityBundle: exported, trustedRootFingerprint: exported.root_key.fingerprint, now: NOW }).ok, true);
  });

  // ── failure matrix ─────────────────────────────────────────────────────────
  await test("receipt fails against the wrong bundle", () => {
    const { provider } = makeProvider();
    const other = makeProvider().bundle;
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const v = verifyCustodyAttestation(out.receipt, { authorityBundle: other, trustedRootFingerprint: other.root_key.fingerprint, now: NOW });
    assert.equal(v.ok, false);
    assert.match(v.reason, /fingerprint mismatch|UNKNOWN_KEY|bundle:/);
  });

  await test("receipt fails against a revoked key", () => {
    const { provider, bundle } = makeProvider({ revoke: true });
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    // Signing itself fails closed because the key is revoked in the bundle.
    assert.equal(out.ok, false);
    assert.equal(out.reason_code, "ERR_CUSTODY_KEY_REVOKED");
    // And a previously-signed receipt is rejected at verify time too.
    const { provider: p2, root, receipt } = makeProvider();
    const good = signReceiptForDelivery(sampleInner(), { mode: "custody", provider: p2 }, { now: NOW });
    const revokedBundle = buildAuthorityBundle({
      authorityId: "mnde-prod",
      issuedAt: NOW,
      notAfter: "2027-06-14T00:00:00.000Z",
      root,
      receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
      revocation: [good.receipt.custody_attestation.signing_key_id]
    });
    assert.equal(verifyCustodyAttestation(good.receipt, { authorityBundle: revokedBundle, trustedRootFingerprint: revokedBundle.root_key.fingerprint, now: NOW }).reason, "KEY_REVOKED");
  });

  await test("receipt fails against an expired key", () => {
    const { provider } = makeProvider({ validUntil: "2026-02-01T00:00:00.000Z" });
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: "2026-06-14T00:00:00.000Z" });
    assert.equal(out.ok, false);
    assert.equal(out.reason_code, "ERR_CUSTODY_KEY_EXPIRED");
  });

  await test("receipt fails against a stale bundle", () => {
    const { provider } = makeProvider({ notAfter: "2026-03-01T00:00:00.000Z" });
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    assert.equal(out.ok, false);
    assert.equal(out.reason_code, "ERR_CUSTODY_BUNDLE_STALE");
  });

  await test("receipt fails against a tampered bundle", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const tampered = structuredClone(bundle);
    tampered.authority_id = "attacker";
    const v = verifyCustodyAttestation(out.receipt, { authorityBundle: tampered, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW });
    assert.equal(v.ok, false);
    assert.match(v.reason, /BUNDLE_SIGNATURE_INVALID/);
  });

  await test("receipt fails against an invalid signature (tampered attestation)", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    out.receipt.custody_attestation.signature.value = out.receipt.custody_attestation.signature.value.replace(/^../, "00");
    assert.equal(verifyCustodyAttestation(out.receipt, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW }).reason, "SIGNATURE_INVALID");
  });

  await test("receipt fails when the inner receipt is tampered (hash mismatch)", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    out.receipt.receipt.request_hash = "tampered";
    assert.equal(verifyCustodyAttestation(out.receipt, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW }).reason, "receipt hash mismatch");
  });

  // ── fail closed on config ──────────────────────────────────────────────────
  await test("custody provider failure fails closed (unknown provider)", () => {
    const cfg = loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "magic-vault" });
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason_code, "ERR_CUSTODY_MISCONFIGURED");
  });

  await test("missing bundle fails closed", () => {
    const cfg = loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "nope-xyz.json") });
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason_code, "ERR_CUSTODY_BUNDLE_MISSING");
  });

  await test("missing signing key fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-sign-"));
    try {
      const { bundle } = makeProvider();
      const bundlePath = join(dir, "b.json");
      writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
      const cfg = loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: bundlePath });
      assert.equal(cfg.ok, false);
      assert.equal(cfg.reason_code, "ERR_CUSTODY_KEY_MISSING");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await test("verifying a custody envelope without a bundle fails closed", () => {
    const { provider } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const v = verifyCustodyAttestation(out.receipt, { now: NOW });
    assert.equal(v.ok, false);
    assert.match(v.reason, /authority bundle required/);
  });

  await test("custody envelope with malformed inner receipt fails closed", () => {
    const { provider, bundle } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const v = verifyAnyReceiptObject(out.receipt, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint, now: NOW });
    assert.equal(v.kind, "custody-signed");
    assert.equal(v.verified, false);
    assert.match(v.reason, /inner receipt: verification error/);
  });

  // ── no secrets ─────────────────────────────────────────────────────────────
  await test("key material never appears in receipts or error responses", () => {
    const { provider, receipt } = makeProvider();
    const out = signReceiptForDelivery(sampleInner(), { mode: "custody", provider }, { now: NOW });
    const json = JSON.stringify(out.receipt);
    assert.ok(!json.includes("PRIVATE KEY"));
    assert.ok(!json.includes(receipt.privatePem.slice(40, 90)));
    // Error responses (reason codes) carry no key bytes.
    const cfg = loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "nope.json") });
    assert.ok(!JSON.stringify(cfg).includes("PRIVATE KEY"));
  });

  // ── live end-to-end through the sidecar ────────────────────────────────────
  // file-backed production custody + PE engine + custody signing mode.
  const dir = mkdtempSync(join(tmpdir(), "mnde-e2e-"));
  try {
    const { bundle, receipt } = makeProvider({ validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z" });
    const bundlePath = join(dir, "authority.bundle.json");
    const keyPath = join(dir, "receipt.key.pem");
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    writeFileSync(keyPath, receipt.privatePem, "utf8");

    const custodyEnv = {
      MNDE_DECISION_ENGINE: "policy-engine",
      MNDE_PE_POLICY: samplePolicy,
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: keyPath,
      MNDE_RECEIPT_KEY_ID: receipt.keyId,
      MNDE_BIND_PORT: "8796"
    };
    const sc = await startMndeSidecar({ url: "http://127.0.0.1:8796", env: custodyEnv });
    try {
      await test("PE mode + custody: live traffic produces a custody-signed receipt that verifies offline", async () => {
        const res = await fetch(`${sc.url}/v1/decisions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ schema_version: "1.0", request_id: "live-1", timestamp: NOW, principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
        });
        const body = await res.json();
        assert.equal(body.decision, "ALLOW");
        assert.equal(body.receipt_signing, "custody");
        assert.equal(body.receipt.schema_version, SIGNED_RECEIPT_SCHEMA);

        // Verify offline against the published bundle (as a third party would).
        const rPath = join(dir, "live-receipt.json");
        writeFileSync(rPath, JSON.stringify(body.receipt), "utf8");
        const v = verifyAnyReceiptFile(rPath, { authorityBundle: bundle, trustedRootFingerprint: bundle.root_key.fingerprint });
        assert.equal(v.kind, "custody-signed");
        assert.equal(v.verified, true, v.reason ?? "");

        // No key material in the receipt or the sidecar logs.
        assert.ok(!JSON.stringify(body).includes("PRIVATE KEY"));
        assert.ok(!sc.getStderr().includes("PRIVATE KEY"), "private key must not appear in sidecar logs");
        assert.ok(!sc.getStderr().includes(receipt.privatePem.slice(40, 90)));
      });
    } finally {
      await sc.stop();
    }

    const missingConfig = await startMndeSidecar({
      url: "http://127.0.0.1:8794",
      env: {
        MNDE_DECISION_ENGINE: "policy-engine",
        MNDE_PE_POLICY: samplePolicy,
        MNDE_RECEIPT_SIGNING_MODE: "custody",
        MNDE_KEY_CUSTODY: "file-backed-production",
        MNDE_AUTHORITY_BUNDLE: join(dir, "missing-authority.bundle.json"),
        MNDE_BIND_PORT: "8794"
      }
    });
    try {
      await test("custody config failure: live traffic fails closed with no receipt", async () => {
        const res = await fetch(`${missingConfig.url}/v1/decisions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ schema_version: "1.0", request_id: "live-missing-config", timestamp: NOW, principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
        });
        const body = await res.json();
        assert.equal(body.decision, "REFUSE");
        assert.equal(body.reason_code, "ERR_CUSTODY_BUNDLE_MISSING");
        assert.equal(body.receipt, null);
        assert.equal(body.receipt_persisted, false);
        assert.ok(!JSON.stringify(body).includes("PRIVATE KEY"));
        assert.ok(!missingConfig.getStderr().includes("PRIVATE KEY"));
      });
    } finally {
      await missingConfig.stop();
    }

    // Default legacy signing through the same engine — receipt is a plain PE
    // receipt (no envelope), proving legacy signing is unchanged.
    const legacy = await startMndeSidecar({ url: "http://127.0.0.1:8795", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: "8795" } });
    try {
      await test("default signing through the sidecar yields an unchanged (non-envelope) receipt", async () => {
        const res = await fetch(`${legacy.url}/v1/decisions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ schema_version: "1.0", request_id: "live-2", timestamp: NOW, principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
        });
        const body = await res.json();
        assert.equal(body.decision, "ALLOW");
        assert.equal(body.receipt_signing, undefined);
        assert.equal(body.receipt.schema_version, "mnde.pe.receipt.v1");
      });
    } finally {
      await legacy.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL production-signing tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS production-signing tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
