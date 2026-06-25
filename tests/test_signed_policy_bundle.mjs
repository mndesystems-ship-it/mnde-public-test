#!/usr/bin/env node
// Signed Policy Bundle gates. These tests exercise activation state only; the
// deterministic policy engine remains isolated from wall-clock and filesystem
// concerns.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorityBundle,
  generateAuthorityKeyPair
} from "../src/custody/index.mjs";
import {
  activateSignedPolicyBundle,
  signPolicyBundle,
  signRollbackAuthorization
} from "../src/policy-bundles/index.mjs";
import { loadPolicyEngineConfig } from "../src/policy-engine/sidecar-adapter.mjs";
import { decidePolicyEngine } from "../src/policy-engine/sidecar-adapter.mjs";
import { signAuthorityGrant, signPolicy } from "../src/policy-engine/trust.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";

const NOW = "2026-06-23T12:00:00.000Z";
const LATER = "2026-06-24T12:00:00.000Z";
const results = [];
bootstrapReceiptKeys({ repoRoot: resolve(dirname(fileURLToPath(import.meta.url)), "..") });

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

function policy(version, rules = [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]) {
  return {
    schema_version: "1.0",
    policy_id: "ops-policy",
    version,
    state: "ACTIVE",
    rules
  };
}

function fixture() {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-1", ...generateAuthorityKeyPair() };
  const authorityBundle = buildAuthorityBundle({
    authorityId: "mnde-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const dir = mkdtempSync(join(tmpdir(), "mnde-policy-bundle-"));
  return { root, policyKey, approvalKey, authorityBundle, statePath: join(dir, "bundle-state.json"), dir };
}

function signedBundle(serial, version, f, policyDocument = policy(version)) {
  return signPolicyBundle({
    bundle_id: `ops-policy-${serial}-${version}`,
    policy_id: "ops-policy",
    serial,
    issued_at: NOW,
    policy_document: policyDocument
  }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
}

function writeSignedConfig(f, bundle = signedBundle(10, "10.0.0", f), extra = {}) {
  const policyBundlePath = join(f.dir, "policy-bundle.json");
  const authorityBundlePath = join(f.dir, "authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(f.authorityBundle), "utf8");
  return {
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: f.statePath,
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: f.authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: NOW,
    ...extra
  };
}

function authorityPolicy(version, signed = false, f = null) {
  const document = policy(version, [{
    rule_id: "allow-temp-delete",
    effect: "ALLOW",
    match: {
      all: [
        { field: "tool.tool_name", op: "eq", value: "delete_file" },
        { field: "parameters.path", op: "path_prefix", value: "/tmp/" }
      ]
    },
    authority_required: ["tmp_file_delete_authority"]
  }]);
  return signed ? signPolicy(document, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem }) : document;
}

function deleteRequest(extra = {}) {
  return {
    schema_version: "1.0",
    request_id: "delete-prod-1",
    timestamp: NOW,
    principal: { id: "operator" },
    agent: { id: "agent" },
    tool: { tool_name: "delete_file" },
    parameters: { path: "/tmp/cache.txt" },
    environment: {},
    context: {},
    ...extra
  };
}

function authorityGrant(f) {
  return signAuthorityGrant({
    authority_id: "tmp_file_delete_authority",
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_until: "2026-12-31T00:00:00.000Z"
  }, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem });
}

function activate(bundle, f, extra = {}) {
  return activateSignedPolicyBundle({
    bundle,
    authorityBundle: f.authorityBundle,
    trustedRootFingerprint: f.authorityBundle.root_key.fingerprint,
    statePath: f.statePath,
    now: NOW,
    ...extra
  });
}

console.log("MNDe Signed Policy Bundle gates\n");

test("valid signed bundle activates and persists its serial floor", () => {
  const f = fixture();
  try {
    const bundle = signedBundle(7, "7.0.0", f);
    const result = activate(bundle, f);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.policy.version, "7.0.0");
    const state = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.equal(state.serial_floors["ops-policy"], 7);
    assert.equal(state.mode, "enforce");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("invalid bundle signature refuses without creating activation state", () => {
  const f = fixture();
  try {
    const bundle = signedBundle(7, "7.0.0", f);
    bundle.signature.value = bundle.signature.value.replace(/.$/, bundle.signature.value.endsWith("0") ? "1" : "0");
    const result = activate(bundle, f);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SIGNATURE_INVALID");
    assert.throws(() => readFileSync(f.statePath, "utf8"));
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("stale serial refuses after a higher serial is active", () => {
  const f = fixture();
  try {
    assert.equal(activate(signedBundle(7, "7.0.0", f), f).ok, true);
    const result = activate(signedBundle(6, "6.0.0", f), f);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SERIAL_ROLLBACK_REFUSED");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("a different bundle cannot reuse an already accepted serial", () => {
  const f = fixture();
  try {
    assert.equal(activate(signedBundle(7, "7.0.0", f), f).ok, true);
    const replacement = signedBundle(7, "7.0.1", f);
    const result = activate(replacement, f);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SERIAL_REUSE_REFUSED");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("rollback below the serial floor requires a valid, scoped signed authorization", () => {
  const f = fixture();
  try {
    assert.equal(activate(signedBundle(7, "7.0.0", f), f).ok, true);
    const older = signPolicyBundle({
      bundle_id: "ops-policy-6-rollback", policy_id: "ops-policy", serial: 6, issued_at: NOW, allow_rollback: true,
      policy_document: policy("6.0.0")
    }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
    assert.equal(activate(older, f).reason, "POLICY_BUNDLE_ROLLBACK_AUTH_INVALID");

    const rollback = signRollbackAuthorization({
      policy_id: "ops-policy", from_serial: 7, to_serial: 6,
      issued_at: NOW, expires_at: LATER, authorization_id: "rollback-7-to-6"
    }, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem });
    const rollbackBundle = signPolicyBundle({
      bundle_id: "ops-policy-6-rollback-approved", policy_id: "ops-policy", serial: 6, issued_at: NOW, allow_rollback: true,
      policy_document: policy("6.0.0")
    }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
    const result = activate({ ...rollbackBundle, rollback_authorization: rollback }, f);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.policyBundleProvenance.rollback_authorization_id, "rollback-7-to-6");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("default policy-engine file configuration remains legacy-compatible", () => {
  const f = fixture();
  try {
    const policyPath = join(f.dir, "legacy-policy.json");
    writeFileSync(policyPath, JSON.stringify(policy("legacy-1")));
    const config = loadPolicyEngineConfig({ MNDE_PE_POLICY: policyPath });
    assert.equal(config.ok, true, config.reason);
    assert.equal(config.policy.version, "legacy-1");
    assert.equal(config.signedPolicyBundle, undefined);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("production refuses unsigned policy-engine file configuration", () => {
  const f = fixture();
  try {
    const policyPath = join(f.dir, "legacy-policy.json");
    writeFileSync(policyPath, JSON.stringify(policy("legacy-prod")), "utf8");
    const config = loadPolicyEngineConfig({ MNDE_PROFILE: "production", MNDE_PE_POLICY: policyPath });
    assert.equal(config.ok, false);
    assert.equal(config.reason, "ERR_PE_PRODUCTION_REQUIRES_SIGNED_POLICY_BUNDLE");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("production refuses request-body legacy authority without trusted anchors", () => {
  const f = fixture();
  try {
    const config = loadPolicyEngineConfig({
      MNDE_PROFILE: "production",
      ...writeSignedConfig(f, signedBundle(10, "10.0.0", f, authorityPolicy("10.0.0")))
    });
    assert.equal(config.ok, true, config.reason);
    const decision = decidePolicyEngine({
      ...deleteRequest(),
      mnde_authorities: [{
        authority_id: "tmp_file_delete_authority",
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_until: "2026-12-31T00:00:00.000Z"
      }]
    }, config, { now: NOW });
    assert.equal(decision.decision, "REFUSE");
    assert.equal(decision.reason_code, "ERR_PE_LEGACY_AUTHORITY_REFUSED");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("production accepts signed policy bundle plus signed trusted authority grant", () => {
  const f = fixture();
  try {
    const anchorsPath = join(f.dir, "trust-anchors.json");
    writeFileSync(anchorsPath, JSON.stringify({
      policy_keys: [{ key_id: f.policyKey.keyId, public_key: f.policyKey.publicPem }],
      authority_keys: [{ key_id: f.approvalKey.keyId, public_key: f.approvalKey.publicPem }]
    }), "utf8");
    const config = loadPolicyEngineConfig({
      MNDE_PROFILE: "production",
      ...writeSignedConfig(f, signedBundle(11, "11.0.0", f, authorityPolicy("11.0.0", true, f)), { MNDE_PE_TRUST_ANCHORS: anchorsPath })
    });
    assert.equal(config.ok, true, config.reason);
    const decision = decidePolicyEngine({ ...deleteRequest({ request_id: "delete-prod-signed" }), mnde_authorities: [authorityGrant(f)] }, config, { now: NOW });
    assert.equal(decision.decision, "ALLOW");
    assert.equal(decision.reason_code, "OK_ALLOW");
    assert.equal(decision.receipt.trust_enforced, true);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("policy-engine configuration activates a signed bundle before exposing its policy", () => {
  const f = fixture();
  try {
    const policyBundlePath = join(f.dir, "policy-bundle.json");
    const authorityBundlePath = join(f.dir, "authority-bundle.json");
    writeFileSync(policyBundlePath, JSON.stringify(signedBundle(4, "4.0.0", f)));
    writeFileSync(authorityBundlePath, JSON.stringify(f.authorityBundle));
    const config = loadPolicyEngineConfig({
      MNDE_PE_POLICY_BUNDLE: policyBundlePath,
      MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
      MNDE_PE_POLICY_BUNDLE_STATE: f.statePath,
      MNDE_PE_TRUSTED_ROOT_FINGERPRINT: f.authorityBundle.root_key.fingerprint,
      MNDE_PE_BUNDLE_NOW: NOW
    });
    assert.equal(config.ok, true, config.reason);
    assert.equal(config.policy.version, "4.0.0");
    assert.deepEqual(config.signedPolicyBundle, { policy_id: "ops-policy", serial: 4 });
    const decision = decidePolicyEngine({
      schema_version: "1.0", request_id: "signed-bundle-config", timestamp: NOW,
      principal: { id: "operator" }, agent: { id: "agent" }, tool: { tool_name: "read_status" },
      parameters: {}, environment: {}, context: {}
    }, config, { now: NOW });
    assert.equal(decision.receipt.policy_bundle_provenance.bundle_id, "ops-policy-4-4.0.0");
    assert.equal(decision.receipt.policy_bundle_provenance.policy_hash, decision.receipt.policy_hash);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("persisted serial floor refuses an older bundle after simulated restart", () => {
  const f = fixture();
  try {
    assert.equal(activate(signedBundle(9, "9.0.0", f), f).ok, true);
    const restarted = activateSignedPolicyBundle({
      bundle: signedBundle(8, "8.0.0", f), authorityBundle: f.authorityBundle,
      trustedRootFingerprint: f.authorityBundle.root_key.fingerprint, statePath: f.statePath, now: NOW
    });
    assert.equal(restarted.ok, false);
    assert.equal(restarted.reason, "POLICY_BUNDLE_SERIAL_ROLLBACK_REFUSED");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("enforce mode refuses state written by a different mode", () => {
  const f = fixture();
  try {
    writeFileSync(f.statePath, JSON.stringify({ schema_version: "mnde.policy.bundle.state.v1", mode: "warn", serial_floors: { "ops-policy": 99 } }));
    const result = activate(signedBundle(100, "100.0.0", f), f);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_STATE_MODE_MISMATCH");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("a rollback authorization is single-use and cannot be replayed", () => {
  const f = fixture();
  try {
    assert.equal(activate(signedBundle(7, "7.0.0", f), f).ok, true);
    const grant = signRollbackAuthorization({
      policy_id: "ops-policy", from_serial: 7, to_serial: 6, issued_at: NOW, expires_at: LATER, authorization_id: "rb-7-to-6"
    }, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem });
    const rollbackBundle = signPolicyBundle({
      bundle_id: "ops-policy-6-single-use", policy_id: "ops-policy", serial: 6, issued_at: NOW, allow_rollback: true,
      policy_document: policy("6.0.0")
    }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });

    const first = activate({ ...rollbackBundle, rollback_authorization: grant }, f);
    assert.equal(first.ok, true, first.reason);
    const state = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.deepEqual(state.consumed_rollback_authorizations, ["rb-7-to-6"]);

    // Re-presenting the exact same bundle + grant (digest matches, so the
    // serial-reuse gate passes) is refused by the single-use check.
    const second = activate({ ...rollbackBundle, rollback_authorization: grant }, f);
    assert.equal(second.ok, false);
    assert.equal(second.reason, "POLICY_BUNDLE_ROLLBACK_AUTH_REUSED");
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("pre-existing v1 state without a consumed list migrates safely and supports rollback", () => {
  const f = fixture();
  try {
    // An older v1 state file predates single-use tracking (no consumed list).
    writeFileSync(f.statePath, JSON.stringify({
      schema_version: "mnde.policy.bundle.state.v1", mode: "enforce",
      serial_floors: { "ops-policy": 7 }, serial_digests: { "ops-policy": {} }, activation_events: []
    }));
    const grant = signRollbackAuthorization({
      policy_id: "ops-policy", from_serial: 7, to_serial: 6, issued_at: NOW, expires_at: LATER, authorization_id: "migrated-rb"
    }, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem });
    const rollbackBundle = signPolicyBundle({
      bundle_id: "ops-policy-6-migrated", policy_id: "ops-policy", serial: 6, issued_at: NOW, allow_rollback: true,
      policy_document: policy("6.0.0")
    }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
    const result = activate({ ...rollbackBundle, rollback_authorization: grant }, f);
    assert.equal(result.ok, true, result.reason);
    const state = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.deepEqual(state.consumed_rollback_authorizations, ["migrated-rb"]);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("legacy bundle-off receipts carry no policy_bundle_provenance", () => {
  const f = fixture();
  try {
    const policyPath = join(f.dir, "legacy-policy.json");
    writeFileSync(policyPath, JSON.stringify(policy("legacy-9")));
    const config = loadPolicyEngineConfig({ MNDE_PE_POLICY: policyPath });
    assert.equal(config.ok, true, config.reason);
    assert.equal(config.policyBundleProvenance, undefined);
    const decision = decidePolicyEngine({
      schema_version: "1.0", request_id: "legacy-receipt", timestamp: NOW,
      principal: { id: "operator" }, agent: { id: "agent" }, tool: { tool_name: "read_status" },
      parameters: {}, environment: {}, context: {}
    }, config, { now: NOW });
    assert.equal(decision.receipt.policy_bundle_provenance, undefined);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL signed policy bundle gates (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS signed policy bundle gates (${results.length}/${results.length})`);
