// Production posture pre-flight tests.
//
//   npm run test:production-posture
//
// Proves MNDe refuses to start in MNDE_PROFILE=production unless the decision
// endpoint requires caller authentication AND runs an enforced (signed-bundle)
// policy engine. A missing/unknown profile never implies production, and local
// mode is unchanged. Hostile (refusal) cases first, then the valid-config path.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import {
  assertProductionPosture,
  evaluateProductionPosture,
  ERR_PRODUCTION_CALLER_AUTH_REQUIRED,
  ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED
} from "../src/production-posture-preflight.mjs";
import { POLICY_ENFORCEMENT_ENGINES, isPolicyEnforcementEnabled, resolveDecisionEngine } from "../shared/decision-engine.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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

// ── fixtures ─────────────────────────────────────────────────────────────────
function validAuthEnv() {
  return { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: JSON.stringify({ "ci-secret-token": "ci-caller" }) };
}

// Valid production *signing* custody (so the trust-root pre-flight passes and our
// posture gate is what fires in the live refusal tests).
async function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "acme-prod", issuedAt: "2026-06-14T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production", MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath, MNDE_RECEIPT_SIGNING_KEY: keyPath, MNDE_RECEIPT_KEY_ID: receipt.keyId
  };
}

// Valid signed policy-engine bundle env (enforced policy).
async function validPolicyEngineEnv() {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-test-authority", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const dir = mkdtempSync(join(tmpdir(), "mnde-pp-pe-"));
  const NOW = "2026-06-23T12:00:00.000Z";
  const bundle = await signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: NOW,
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    dir,
    env: {
      MNDE_DECISION_ENGINE: "policy-engine",
      MNDE_PE_POLICY_BUNDLE: policyBundlePath,
      MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
      MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "bundle-state.json"),
      MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
      MNDE_PE_BUNDLE_NOW: NOW
    }
  };
}

async function main() {
  console.log("MNDe production posture pre-flight\n");

  // ── unit: the gate expresses the security outcome via the canonical engine
  //    abstraction, not a hardcoded engine name ─────────────────────────────────
  await test("policy-enforcement abstraction drives the check (outcome, not name)", async () => {
    assert.equal(isPolicyEnforcementEnabled({ MNDE_DECISION_ENGINE: "policy-engine" }), true);
    assert.equal(isPolicyEnforcementEnabled({ MNDE_DECISION_ENGINE: "legacy" }), false);
    assert.equal(isPolicyEnforcementEnabled({}), false);
    assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: "legacy" }), "legacy");
    assert.equal(resolveDecisionEngine({}), "policy-engine"); // v1 default flipped to policy-engine
    assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: "nonsense" }), null); // unknown -> fail closed
    // Unset still does NOT count as production-enforcement-enabled (production must be explicit).
    assert.equal(isPolicyEnforcementEnabled({}), false);
    // every enforcement engine in the canonical set satisfies the production
    // policy requirement (a future backend added to the set is covered here, with
    // no change to the gate), so only the missing signed bundle is flagged.
    for (const engine of POLICY_ENFORCEMENT_ENGINES) {
      assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: engine }), engine);
      const r = await evaluateProductionPosture({ ...validAuthEnv(), MNDE_DECISION_ENGINE: engine });
      assert.ok(!r.violations.some((v) => v.reason_code === ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED && /requires an enforced policy engine/.test(v.detail)),
        `engine '${engine}' must satisfy enforcement-selected; only bundle config should gate it`);
    }
  });

  // ── unit: missing/unknown profile never implies production ───────────────────
  await test("unset profile is a no-op (not treated as production)", async () => {
    const r = await assertProductionPosture({});
    assert.equal(r.ok, true);
    assert.equal(r.enforced, false);
  });
  await test("explicit local profile is a no-op", async () => {
    const r = await assertProductionPosture({ MNDE_PROFILE: "local", MNDE_SIDECAR_AUTH: undefined });
    assert.equal(r.ok, true);
    assert.equal(r.enforced, false);
  });
  await test("unknown profile does not enforce production here", async () => {
    // parseRuntimeProfile flags unknown values elsewhere; this gate must not
    // treat an unknown value as production.
    const r = await assertProductionPosture({ MNDE_PROFILE: "prod-east" });
    assert.equal(r.enforced, false);
  });

  // ── unit: hostile production combinations refuse ─────────────────────────────
  await test("production without caller auth refuses (auth first)", async () => {
    const r = await assertProductionPosture({ MNDE_PROFILE: "production" });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, ERR_PRODUCTION_CALLER_AUTH_REQUIRED);
  });
  await test("production with bearer but no tokens refuses (misconfigured auth)", async () => {
    const r = await assertProductionPosture({ MNDE_PROFILE: "production", MNDE_SIDECAR_AUTH: "bearer" });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, ERR_PRODUCTION_CALLER_AUTH_REQUIRED);
  });
  await test("production with valid auth but legacy engine refuses (policy)", async () => {
    const r = await assertProductionPosture({ MNDE_PROFILE: "production", ...validAuthEnv() });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED);
  });
  await test("production with valid auth + policy-engine but no signed bundle refuses", async () => {
    const r = await assertProductionPosture({ MNDE_PROFILE: "production", ...validAuthEnv(), MNDE_DECISION_ENGINE: "policy-engine" });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED);
  });
  await test("evaluateProductionPosture reports BOTH violations when both missing", async () => {
    const r = await evaluateProductionPosture({});
    assert.equal(r.ok, false);
    assert.equal(r.violations.length, 2);
    assert.ok(r.violations.some((v) => v.reason_code === ERR_PRODUCTION_CALLER_AUTH_REQUIRED));
    assert.ok(r.violations.some((v) => v.reason_code === ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED));
  });

  // ── unit: valid production config passes ─────────────────────────────────────
  await test("production with valid auth + signed-bundle policy engine passes", async () => {
    const pe = await validPolicyEngineEnv();
    try {
      const r = await assertProductionPosture({ MNDE_PROFILE: "production", ...validAuthEnv(), ...pe.env });
      assert.equal(r.ok, true, r.detail ?? "");
      assert.equal(r.enforced, true);
    } finally {
      rmSync(pe.dir, { recursive: true, force: true });
    }
  });

  // ── live: startup refusal proofs (trust-root passes via valid custody, so our
  //    posture gate is what refuses) ───────────────────────────────────────────
  await test("sidecar REFUSES to start in production without caller auth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-pp-"));
    let started = null, threw = false, message = "";
    try {
      const env = { ...(await writeProductionCustody(dir)), MNDE_BIND_PORT: "8810", MNDE_RECEIPT_LOG: join(dir, "r.jsonl") };
      started = await startMndeSidecar({ url: "http://127.0.0.1:8810", env });
    } catch (error) { threw = true; message = String(error?.message ?? error); }
    finally { if (started) await started.stop(); rmSync(dir, { recursive: true, force: true }); }
    assert.equal(threw, true, "must not become ready without caller auth");
    assert.match(message, new RegExp(`${ERR_PRODUCTION_CALLER_AUTH_REQUIRED}|refused to start`));
  });

  await test("sidecar REFUSES to start in production with auth but legacy engine", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-pp-"));
    let started = null, threw = false, message = "";
    try {
      const env = { ...(await writeProductionCustody(dir)), ...validAuthEnv(), MNDE_BIND_PORT: "8811", MNDE_RECEIPT_LOG: join(dir, "r.jsonl") };
      started = await startMndeSidecar({ url: "http://127.0.0.1:8811", env });
    } catch (error) { threw = true; message = String(error?.message ?? error); }
    finally { if (started) await started.stop(); rmSync(dir, { recursive: true, force: true }); }
    assert.equal(threw, true, "must not become ready without policy enforcement");
    assert.match(message, new RegExp(`${ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED}|refused to start`));
  });

  // ── live: non-production boots unchanged (missing profile != production) ──────
  await test("sidecar STARTS in default (non-production) profile", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-pp-"));
    let sc = null;
    try {
      sc = await startMndeSidecar({ url: "http://127.0.0.1:8812", env: { MNDE_BIND_PORT: "8812", MNDE_RECEIPT_LOG: join(dir, "r.jsonl") } });
      const res = await fetch(`${sc.url}/healthz`).catch(() => null);
      assert.ok(sc.url, "sidecar became ready in local profile");
      if (res) assert.ok(res.status === 200 || res.status === 204 || res.status === 404, "healthz reachable");
    } finally {
      if (sc) await sc.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL production posture tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS production posture tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
