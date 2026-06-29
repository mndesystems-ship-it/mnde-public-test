// Trust-root pre-flight tests (S-02 / P-01).
//
//   npm run test:trust-root
//
// Proves MNDe refuses to start in production profile unless a real production
// custody provider is configured, and never anchors production trust on
// demo/dev keys. Local/demo mode is unchanged. Includes a live startup-refusal
// proof against the sidecar.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";
import { assertTrustRoot, detectDevKeyPath } from "../src/authority-signing/preflight.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

// A real, non-demo production custody fixture written to disk.
function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "acme-prod",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    revocation: []
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId
  };
}

// Production now ALSO requires caller auth + an enforced signed-bundle policy
// engine (production posture pre-flight). These extras make a fully-configured
// production sidecar boot under the stricter posture.
const PROD_AUTH_TOKEN = "tr-caller-token";
function productionEnforcementExtras(dir) {
  const root = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = buildAuthorityBundle({
    authorityId: "mnde-tr-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundle = signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "pe-authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    MNDE_SIDECAR_AUTH: "bearer",
    MNDE_SIDECAR_AUTH_TOKENS: JSON.stringify({ [PROD_AUTH_TOKEN]: "tr-caller" }),
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z"
  };
}

async function main() {
  console.log("MNDe trust-root pre-flight (S-02)\n");

  // ── local/demo mode unchanged ──────────────────────────────────────────────
  await test("local profile (default) passes — demo custody allowed", async () => {
    assert.equal((await assertTrustRoot({})).ok, true);
    assert.equal((await assertTrustRoot({ MNDE_KEY_CUSTODY: "local-demo" })).profile, "local");
    // legacy signing in local mode is fine
    assert.equal((await assertTrustRoot({ MNDE_PROFILE: "local", MNDE_RECEIPT_SIGNING_MODE: "legacy" })).ok, true);
  });

  // ── production fail-closed matrix ────────────────────────────────────────────
  await test("production mode without custody fails startup", async () => {
    const r = await assertTrustRoot({ MNDE_PROFILE: "production" });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_TRUST_ROOT_REQUIRES_CUSTODY");
    assert.match(r.detail, /MNDE_RECEIPT_SIGNING_MODE=custody/);
  });

  await test("production mode with demo custody fails startup", async () => {
    const r = await assertTrustRoot({ MNDE_PROFILE: "production", MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "local-demo" });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_TRUST_ROOT_DEMO_CUSTODY");
  });

  await test("production mode pointing at repo dev keys fails startup", async () => {
    const r = await assertTrustRoot({
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: join(repoRoot, "shared", "receipt_keys", "bundle.json"),
      MNDE_RECEIPT_SIGNING_KEY: join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem")
    }, { repoRoot });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_TRUST_ROOT_DEV_KEY");
  });

  await test("production mode with missing bundle fails closed", async () => {
    const r = await assertTrustRoot({
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "nope-trust-root.json"),
      MNDE_RECEIPT_SIGNING_KEY: join(tmpdir(), "nope.pem")
    }, { repoRoot });
    assert.equal(r.ok, false);
    assert.match(r.reason_code, /ERR_CUSTODY_/);
  });

  await test("production mode pointed at an exported demo bundle fails closed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-tr-"));
    try {
      const root = { keyId: "local-demo-root", ...generateAuthorityKeyPair() };
      const receipt = { keyId: "local-demo-receipt", ...generateAuthorityKeyPair() };
      const bundle = buildAuthorityBundle({
        authorityId: "mnde-local-demo",
        issuedAt: "2026-06-14T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
        receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
        revocation: []
      });
      const bundlePath = join(dir, "b.json"); const keyPath = join(dir, "k.pem");
      writeFileSync(bundlePath, JSON.stringify(bundle), "utf8"); writeFileSync(keyPath, receipt.privatePem, "utf8");
      const r = await assertTrustRoot({
        MNDE_PROFILE: "production", MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production",
        MNDE_AUTHORITY_BUNDLE: bundlePath, MNDE_RECEIPT_SIGNING_KEY: keyPath, MNDE_RECEIPT_KEY_ID: receipt.keyId
      }, { repoRoot });
      assert.equal(r.ok, false);
      assert.equal(r.reason_code, "ERR_TRUST_ROOT_DEV_KEY");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  await test("production mode with explicit valid custody passes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-tr-"));
    try {
      const env = writeProductionCustody(dir);
      const r = await assertTrustRoot(env, { repoRoot });
      assert.equal(r.ok, true, r.detail ?? "");
      assert.equal(r.profile, "production");
      assert.equal(r.authority_id, "acme-prod");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  await test("detectDevKeyPath flags repo key paths, ignores external paths", () => {
    assert.ok(detectDevKeyPath({ MNDE_RECEIPT_SIGNING_KEY: join(repoRoot, "shared", "receipt_keys", "x.pem") }, repoRoot));
    assert.equal(detectDevKeyPath({ MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "prod", "authority.bundle.json") }, repoRoot), null);
  });

  // ── live startup refusal proof ───────────────────────────────────────────────
  await test("sidecar REFUSES to start in production profile without custody", async () => {
    let started = null;
    let threw = false;
    let message = "";
    try {
      started = await startMndeSidecar({ url: "http://127.0.0.1:8793", env: { MNDE_PROFILE: "production", MNDE_BIND_PORT: "8793" } });
    } catch (error) {
      threw = true;
      message = String(error?.message ?? error);
    } finally {
      if (started) await started.stop();
    }
    assert.equal(threw, true, "sidecar must not become ready in production profile without custody");
    assert.match(message, /ERR_TRUST_ROOT_REQUIRES_CUSTODY|refused to start/);
  });

  await test("sidecar STARTS in production with valid custody + caller auth + enforced policy", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-tr-"));
    let sc = null;
    try {
      const env = { ...writeProductionCustody(dir), ...productionEnforcementExtras(dir), MNDE_BIND_PORT: "8792" };
      sc = await startMndeSidecar({ url: "http://127.0.0.1:8792", env });
      const res = await fetch(`${sc.url}/v1/decisions`, {
        method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${PROD_AUTH_TOKEN}` },
        body: JSON.stringify({ schema_version: "1.0", request_id: "tr-1", timestamp: "2026-06-14T00:00:00.000Z", principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
      });
      const body = await res.json();
      assert.ok(body.decision === "ALLOW" || body.decision === "REFUSE", "sidecar serves decisions under a fully-configured production profile");
    } finally {
      if (sc) await sc.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL trust-root tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS trust-root tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
