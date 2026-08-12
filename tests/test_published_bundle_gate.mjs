// Published-bundle acceptance gate tests.
//
//   npm run test:published-bundle
//
// Exercises scripts/verify-published-bundle.mjs — the repository side of the
// future clean-machine acceptance test — using production formats and ephemeral
// TEST keys. Proves: (a) it SKIPS cleanly when unconfigured (so CI never depends
// on trust.mnde.com), (b) it FAILS CLOSED when partially configured, (c) the full
// root -> bundle -> receipt chain verifies for a real production-format artifact,
// and (d) every hostile mutation of that chain fails closed.

import assert from "node:assert/strict";

import { resolveConfig, verifyPublishedChain, GATE_ENV } from "../scripts/verify-published-bundle.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { buildSignedExecutionReceipt } from "../src/execution-gate/signed-receipt.mjs";

const NOW = "2026-06-16T00:00:00.000Z";
const SIGNED_AT = "2026-06-15T00:00:00.000Z";

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

const rootKp = generateAuthorityKeyPair();
const receiptKp = generateAuthorityKeyPair();

async function buildFixture() {
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-systems-production",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2026-09-12T00:00:00.000Z",
    root: { keyId: "root-1", publicPem: rootKp.publicPem, privatePem: rootKp.privatePem },
    receiptKeys: [{ keyId: "receipt-1", publicPem: receiptKp.publicPem, validFrom: "2026-06-14T00:00:00.000Z", validUntil: "2027-06-14T00:00:00.000Z" }],
    revocation: []
  });
  const request = {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-gate-1",
    requested_at: SIGNED_AT,
    principal: { id: "agent://ci", type: "agent", verified: true },
    action: { type: "delete", name: "recursive_delete", dry_run: false },
    resource: { kind: "database", id: "prod/orders", name: "orders" },
    environment: { name: "production" },
    risk: { level: "high", destructive: true, reversible: false, blast_radius: "table" },
    evidence: { repo: "mndesystems-ship-it/mnde-public-test", commit_sha: "abc123", branch: "main" }
  };
  const receipt = await buildSignedExecutionReceipt(request, "REFUSE", {
    authorityBundle: bundle, signingKeyId: "receipt-1", signingPrivateKeyPem: receiptKp.privatePem, refusalReason: "denied"
  });
  return { bundle, receipt, request, pinnedRootFingerprint: bundle.root_key.fingerprint };
}

async function main() {
  console.log("MNDe published-bundle acceptance gate\n");

  await test("skips cleanly when nothing is configured", () => {
    const cfg = resolveConfig({});
    assert.equal(cfg.state, "skip");
  });

  await test("fails closed when only partially configured", () => {
    const cfg = resolveConfig({ [GATE_ENV.fingerprint]: "abc" });
    assert.equal(cfg.state, "misconfigured");
    assert.ok(cfg.missing.includes(GATE_ENV.bundle));
    assert.ok(cfg.missing.includes(GATE_ENV.receipt));
  });

  await test("reports ready when fully configured", () => {
    const cfg = resolveConfig({ [GATE_ENV.fingerprint]: "fp", [GATE_ENV.bundle]: "/b.json", [GATE_ENV.receipt]: "/r.json" });
    assert.equal(cfg.state, "ready");
    assert.equal(cfg.fingerprint, "fp");
  });

  const fx = await buildFixture();

  await test("full production chain verifies (root -> bundle -> receipt)", async () => {
    const r = await verifyPublishedChain({ ...fx, originalRequest: fx.request, now: NOW });
    assert.equal(r.ok, true, r.reason);
    assert.deepEqual(r.steps.map((s) => s.name), ["authenticate_bundle", "verify_receipt"]);
  });

  await test("wrong pinned root fails closed", async () => {
    const r = await verifyPublishedChain({ ...fx, pinnedRootFingerprint: "0".repeat(64), now: NOW });
    assert.equal(r.ok, false); assert.match(r.reason, /bundle authentication failed/);
  });

  await test("tampered bundle fails closed", async () => {
    const bundle = structuredClone(fx.bundle); bundle.authority_id = "evil";
    const r = await verifyPublishedChain({ ...fx, bundle, now: NOW });
    assert.equal(r.ok, false); assert.match(r.reason, /bundle authentication failed/);
  });

  await test("tampered receipt fails closed", async () => {
    const receipt = structuredClone(fx.receipt); receipt.decision = "ALLOW";
    const r = await verifyPublishedChain({ ...fx, receipt, now: NOW });
    assert.equal(r.ok, false); assert.match(r.reason, /receipt verification failed/);
  });

  await test("expired bundle fails closed", async () => {
    const r = await verifyPublishedChain({ ...fx, now: "2026-12-01T00:00:00.000Z" });
    assert.equal(r.ok, false); assert.match(r.reason, /bundle authentication failed/);
  });

  await test("exotic bundle value never throws — returns controlled failure", async () => {
    // A float carrying the real root public key would break canonicalization.
    // The gate must return { ok:false }, never throw and never report ok:true.
    const bundle = structuredClone(fx.bundle); bundle.tamper_number = 1.5;
    const r = await verifyPublishedChain({ ...fx, bundle, now: NOW });
    assert.equal(r.ok, false);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL published-bundle gate (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS published-bundle gate (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
