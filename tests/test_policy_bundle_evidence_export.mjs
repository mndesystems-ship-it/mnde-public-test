#!/usr/bin/env node
// Reviewer-facing Signed Policy Bundle evidence export gate.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { buildPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { activateSignedPolicyBundle, signPolicyBundle } from "../src/policy-bundles/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });
const NOW = "2026-06-23T12:00:00.000Z";
const results = [];

function test(name, fn) {
  try { fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

function fixture() {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = buildAuthorityBundle({
    authorityId: "evidence-authority", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const policy = {
    schema_version: "1.0", policy_id: "ops-policy", version: "7.0.0", state: "ACTIVE",
    rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
  };
  const signedBundle = signPolicyBundle({
    bundle_id: "ops-7-evidence", policy_id: "ops-policy", serial: 7, issued_at: NOW, policy_document: policy
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const dir = mkdtempSync(join(tmpdir(), "mnde-evidence-export-"));
  const statePath = join(dir, "state.json");
  const activated = activateSignedPolicyBundle({ bundle: signedBundle, authorityBundle, trustedRootFingerprint: authorityBundle.root_key.fingerprint, statePath, now: NOW });
  assert.equal(activated.ok, true, activated.reason);
  const receipt = buildPolicyReceipt({
    schema_version: "1.0", request_id: "evidence-1", timestamp: NOW,
    principal: { id: "operator" }, agent: { id: "agent" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {}
  }, policy, { policyBundleProvenance: activated.policyBundleProvenance });
  const receiptPath = join(dir, "receipt.json");
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "authority-bundle.json");
  writeFileSync(receiptPath, JSON.stringify(receipt));
  writeFileSync(policyBundlePath, JSON.stringify(signedBundle));
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle));
  return { dir, statePath, receiptPath, policyBundlePath, authorityBundlePath, rootFingerprint: authorityBundle.root_key.fingerprint };
}

console.log("MNDe policy bundle evidence export\n");

test("exported evidence is public-only and verifies offline", () => {
  const f = fixture();
  try {
    const out = join(f.dir, "review-evidence");
    const exported = spawnSync(process.execPath, [
      "tools/export-policy-bundle-evidence.mjs",
      "--receipt", f.receiptPath,
      "--policy-bundle", f.policyBundlePath,
      "--policy-authority-bundle", f.authorityBundlePath,
      "--state", f.statePath,
      "--out", out
    ], { cwd: repoRoot, encoding: "utf8" });
    assert.equal(exported.status, 0, exported.stderr || exported.stdout);
    for (const name of ["receipt.json", "policy-bundle.json", "policy-authority-bundle.json", "trusted-root-fingerprint.txt", "serial-floor-snapshot.json"]) {
      assert.equal(existsSync(join(out, name)), true, `${name} was not exported`);
    }
    const allText = ["receipt.json", "policy-bundle.json", "policy-authority-bundle.json", "serial-floor-snapshot.json"]
      .map((name) => readFileSync(join(out, name), "utf8")).join("\n");
    assert.doesNotMatch(allText, /BEGIN (?:[A-Z ]+ )?PRIVATE KEY|privatePem|private_key|bearer|token/i);
    const snapshot = JSON.parse(readFileSync(join(out, "serial-floor-snapshot.json"), "utf8"));
    assert.deepEqual(Object.keys(snapshot).sort(), ["mode", "schema_version", "serial_floors"]);
    assert.equal(snapshot.serial_floors["ops-policy"], 7);
    const verified = spawnSync(process.execPath, [
      "tools/verify.mjs", join(out, "receipt.json"),
      "--policy-bundle", join(out, "policy-bundle.json"),
      "--policy-authority-bundle", join(out, "policy-authority-bundle.json"),
      "--policy-root-fingerprint", readFileSync(join(out, "trusted-root-fingerprint.txt"), "utf8").trim()
    ], { cwd: repoRoot, encoding: "utf8" });
    assert.equal(verified.status, 0, verified.stderr || verified.stdout);
    assert.match(verified.stdout, /FINAL VERDICT: VERIFIED/);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("evidence export refuses private-key or secret-like input and writes nothing", () => {
  const f = fixture();
  const runExport = (receiptPath, policyBundlePath, outName) => spawnSync(process.execPath, [
    "tools/export-policy-bundle-evidence.mjs",
    "--receipt", receiptPath,
    "--policy-bundle", policyBundlePath,
    "--policy-authority-bundle", f.authorityBundlePath,
    "--state", f.statePath,
    "--out", join(f.dir, outName)
  ], { cwd: repoRoot, encoding: "utf8" });
  try {
    // (a) PEM private key embedded in the policy bundle's policy document
    const poisonedBundle = JSON.parse(readFileSync(f.policyBundlePath, "utf8"));
    poisonedBundle.policy_document.note = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg\n-----END PRIVATE KEY-----";
    const pbPath = join(f.dir, "poisoned-bundle.json");
    writeFileSync(pbPath, JSON.stringify(poisonedBundle));
    const r1 = runExport(f.receiptPath, pbPath, "refused-pem");
    assert.notEqual(r1.status, 0, "export must fail on embedded private key");
    assert.match(r1.stderr, /private or credential material/i);
    assert.equal(existsSync(join(f.dir, "refused-pem")), false, "no output dir on refusal");

    // (b) a secret-named field in the receipt
    const poisonedReceipt = JSON.parse(readFileSync(f.receiptPath, "utf8"));
    poisonedReceipt.secret_token = "abc123-not-allowed";
    const rcPath = join(f.dir, "poisoned-receipt.json");
    writeFileSync(rcPath, JSON.stringify(poisonedReceipt));
    const r2 = runExport(rcPath, f.policyBundlePath, "refused-secret");
    assert.notEqual(r2.status, 0, "export must fail on secret-named field");
    assert.match(r2.stderr, /private or credential material/i);
    assert.equal(existsSync(join(f.dir, "refused-secret")), false, "no output dir on refusal");

    // control: untampered inputs still export successfully
    const r3 = runExport(f.receiptPath, f.policyBundlePath, "allowed");
    assert.equal(r3.status, 0, r3.stderr || r3.stdout);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL policy bundle evidence export (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS policy bundle evidence export (${results.length}/${results.length})`);
