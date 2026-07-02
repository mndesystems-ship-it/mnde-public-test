// Hostile tests: authority grants are BOUND statements, not bearer tokens.
//
//   npm run test:authority-binding
//
// Proves that a signed, in-window authority grant only satisfies an authority
// requirement for the exact subject, tenant, tool, resource, and request it is
// bound to — and that a nonce-bearing grant cannot be replayed. A stolen grant
// (lifted from a receipt or request body) must REFUSE for any other principal,
// tenant, tool, resource, or request. No external services.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import { signPolicy, signAuthorityGrant } from "../src/policy-engine/trust.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { decidePolicyEngine } from "../src/policy-engine/sidecar-adapter.mjs";
import { _resetGrantNonceMemoryForTest } from "../src/policy-engine/grant-nonce-store.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

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

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ type: "spki", format: "pem" }), priv: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

const policyKey = keypair();
const authorityKey = keypair();
const attackerKey = keypair();
const NOW = "2026-06-14T00:00:00.000Z";

const trustAnchors = {
  policy_keys: [{ key_id: "policy-key-1", public_key: policyKey.pub }],
  authority_keys: [{ key_id: "authority-key-1", public_key: authorityKey.pub }]
};

// Rule requires a "grant-deploy" authority for tool "deploy".
function deployPolicy() {
  return signPolicy({
    schema_version: "1.0", policy_id: "pol-1", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "deploy" }, authority_required: ["grant-deploy"] }]
  }, { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
}

function request({ principal = "alice", tool = "deploy", tenant, resource, request_id = "req-1" } = {}) {
  const p = { id: principal };
  if (tenant !== undefined) p.tenant_id = tenant;
  const parameters = {};
  if (resource !== undefined) parameters.resource = resource;
  return { schema_version: "1.0", request_id, timestamp: NOW, principal: p, agent: { id: "agent-1" }, tool: { tool_name: tool }, parameters, environment: {}, context: {} };
}

function boundGrant(scope, extra = {}) {
  return signAuthorityGrant({
    authority_id: "grant-deploy",
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_until: "2026-12-31T00:00:00.000Z",
    scope,
    ...extra
  }, { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
}

function decideAt(req, grant, now = NOW) {
  return evaluatePolicyRequest(req, deployPolicy(), { trustAnchors, now, authorities: [grant] });
}

console.log("MNDe authority-grant binding (hostile)\n");

test("valid bound grant succeeds for the correct principal, tool, request", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" });
  const d = decideAt(request({ principal: "alice" }), grant);
  assert.equal(d.decision, "ALLOW");
  assert.equal(d.reason_code, "OK_ALLOW");
});

test("stolen grant FAILS for another principal", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" }); // issued to alice
  const d = decideAt(request({ principal: "bob" }), grant);            // bob reuses it
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_SUBJECT_MISMATCH");
});

test("stolen grant FAILS for another tenant", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy", tenant: "tenant-a" });
  const ok = decideAt(request({ principal: "alice", tenant: "tenant-a" }), grant);
  assert.equal(ok.decision, "ALLOW");
  const d = decideAt(request({ principal: "alice", tenant: "tenant-b" }), grant);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_TENANT_MISMATCH");
});

test("tenant-less grant cannot be reused inside a tenant context", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" }); // no tenant
  const d = decideAt(request({ principal: "alice", tenant: "tenant-a" }), grant);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_TENANT_MISMATCH");
});

test("stolen grant FAILS for another tool", () => {
  // Grant bound to a different tool; policy rule matches deploy but the grant's
  // tool scope does not cover it.
  const grant = boundGrant({ subject: "alice", tool_name: "read_status" });
  const d = decideAt(request({ principal: "alice", tool: "deploy" }), grant);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_TOOL_MISMATCH");
});

test("stolen grant FAILS for another resource", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy", resource: "cluster-1" });
  const ok = decideAt(request({ principal: "alice", resource: "cluster-1" }), grant);
  assert.equal(ok.decision, "ALLOW");
  const d = decideAt(request({ principal: "alice", resource: "cluster-2" }), grant);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_RESOURCE_MISMATCH");
});

test("one-shot grant FAILS on request_id mismatch", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy", request_id: "req-1" });
  const ok = decideAt(request({ principal: "alice", request_id: "req-1" }), grant);
  assert.equal(ok.decision, "ALLOW");
  const d = decideAt(request({ principal: "alice", request_id: "req-2" }), grant);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_REQUEST_MISMATCH");
});

test("expired grant FAILS (time checked before binding)", () => {
  const grant = signAuthorityGrant({
    authority_id: "grant-deploy", valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2026-02-01T00:00:00.000Z",
    scope: { subject: "alice", tool_name: "deploy" }
  }, { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
  const d = decideAt(request({ principal: "alice" }), grant, NOW);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_EXPIRED");
});

test("tampered grant FAILS the signature (scope changed post-signing)", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" });
  const tampered = { ...grant, scope: { subject: "bob", tool_name: "deploy" } }; // attacker rebinds to self
  const d = decideAt(request({ principal: "bob" }), tampered);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_SIGNATURE_INVALID");
});

test("OLD unbound grant does NOT satisfy a protected authority requirement", () => {
  const unbound = signAuthorityGrant({
    authority_id: "grant-deploy", valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2026-12-31T00:00:00.000Z"
  }, { keyId: "authority-key-1", privateKeyPem: authorityKey.priv }); // legacy shape, no scope
  const d = decideAt(request({ principal: "alice" }), unbound);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_UNBOUND");
});

test("bound grant forged by an untrusted key still fails on signature", () => {
  const forged = signAuthorityGrant({
    authority_id: "grant-deploy", valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2026-12-31T00:00:00.000Z",
    scope: { subject: "alice", tool_name: "deploy" }
  }, { keyId: "authority-key-1", privateKeyPem: attackerKey.priv });
  const d = decideAt(request({ principal: "alice" }), forged);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_SIGNATURE_INVALID");
});

test("receipt verification still works offline for a valid bound grant", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" });
  const receipt = buildPolicyReceipt(request({ principal: "alice" }), deployPolicy(), { authorities: [grant], trustAnchors, now: NOW });
  assert.equal(receipt.decision_output.decision, "ALLOW");
  assert.equal(verifyPolicyReceipt(receipt, { trustAnchors }).verified, true);
});

test("a receipt built from a STOLEN grant does not verify as ALLOW", () => {
  // Attacker forges a receipt embedding alice's grant but bob's request.
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" });
  const receipt = buildPolicyReceipt(request({ principal: "bob" }), deployPolicy(), { authorities: [grant], trustAnchors, now: NOW });
  assert.equal(receipt.decision_output.decision, "REFUSE");
  assert.equal(receipt.decision_output.reason_code, "AUTHORITY_SUBJECT_MISMATCH");
  // And it verifies AS a refusal — replay reproduces the REFUSE deterministically.
  assert.equal(verifyPolicyReceipt(receipt, { trustAnchors }).verified, true);
  assert.equal(verifyPolicyReceipt(receipt, { trustAnchors }).decision, "REFUSE");
});

test("deterministic replay: same request yields identical decision hash", () => {
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" });
  const a = decideAt(request({ principal: "alice" }), grant);
  const b = decideAt(request({ principal: "alice" }), grant);
  assert.equal(a.decision_hash, b.decision_hash);
  assert.equal(a.decision, "ALLOW");
});

test("reused nonce FAILS at the runtime decision layer", () => {
  _resetGrantNonceMemoryForTest();
  const config = { production: false, policy: deployPolicy(), trustAnchors, grantNonceDir: null };
  const grant = boundGrant({ subject: "alice", tool_name: "deploy" }, { nonce: "nonce-abcdefabcdef01" });
  const body = { ...request({ principal: "alice" }), mnde_authorities: [grant] };
  const first = decidePolicyEngine(body, config, { now: NOW });
  assert.equal(first.decision, "ALLOW");
  assert.equal(first.reason_code, "OK_ALLOW");
  const second = decidePolicyEngine(body, config, { now: NOW });
  assert.equal(second.decision, "REFUSE");
  assert.equal(second.reason_code, "AUTHORITY_NONCE_REUSED");
  // The refusal receipt is reproducible offline (consumed grant is dropped).
  assert.equal(verifyPolicyReceipt(second.receipt, { trustAnchors }).verified, true);
  assert.equal(second.receipt.decision_output.decision, "REFUSE");
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL authority-binding tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS authority-binding tests (${results.length}/${results.length})`);
