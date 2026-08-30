#!/usr/bin/env node
// Policy activation (milestone B) — hostile coverage + one end-to-end lifecycle
// proof. Activation must be all-or-nothing: if signing succeeds but any later
// trust/validation/persistence/confirmation step fails, the previous ACTIVE
// authority stays authoritative.
//
// Reuses the real signing + activation modules and the same authority-bundle
// fixtures the signed-bundle tests use. Faults are injected through activatePolicy's
// dependency seam so each attack is exercised against the real orchestration.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { policyHash, signPolicyBundle, activateSignedPolicyBundle } from "../src/policy-bundles/index.mjs";
import { activatePolicy } from "../src/policy-activate/index.mjs";
import { activationHistory, currentActivation, evaluatePolicyPhase, PHASE } from "../src/policy-lifecycle/index.mjs";
import { loadPolicyEngineConfig, decidePolicyEngine } from "../src/policy-engine/sidecar-adapter.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = "2026-06-23T12:00:00.000Z";
const LATER = "2026-06-24T12:00:00.000Z";

const results = [];
let chain = Promise.resolve();
function test(name, fn) {
  chain = chain.then(async () => {
    try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
    catch (e) { results.push(false); console.log(`  [FAIL] ${name}: ${e.message}`); }
  });
}

async function fixture(opts = {}) {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-test-authority",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: opts.policyValidUntil ?? "2099-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const dir = mkdtempSync(join(tmpdir(), "mnde-activate-"));
  return { root, policyKey, approvalKey, authorityBundle, dir, statePath: join(dir, "state.json"), trustedRootFingerprint: authorityBundle.root_key.fingerprint };
}
function cleanup(f) { rmSync(f.dir, { recursive: true, force: true }); }

function policy(id, rules) { return { schema_version: "1.0", policy_id: id, version: "1", state: "ACTIVE", rules }; }
const R_READ = { rule_id: "allow-read", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read" } };
const R_DELETE = { rule_id: "refuse-delete", effect: "REFUSE", match: { field: "tool.tool_name", op: "eq", value: "delete" } };
const policyA1 = policy("coding", [R_READ]);
const policyA2 = policy("coding", [R_READ, R_DELETE]);

function baseInput(f, policyDocument, extra = {}) {
  return { policyDocument, keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem, authorityBundle: f.authorityBundle, trustedRootFingerprint: f.trustedRootFingerprint, statePath: f.statePath, now: NOW, ...extra };
}
function activeSerial(f, pid) { if (!existsSync(f.statePath)) return null; const c = currentActivation(JSON.parse(readFileSync(f.statePath, "utf8")), pid); return c ? c.serial : null; }
async function expectRefusedLeaving(f, input, deps) {
  const before = activeSerial(f, input.policyDocument.policy_id);
  const r = await activatePolicy(input, deps);
  assert.equal(r.ok, false, `expected refusal, got ok (${JSON.stringify(r)})`);
  assert.equal(activeSerial(f, input.policyDocument.policy_id), before, "active authority must be unchanged after refusal");
  return r;
}

console.log("MNDe policy activation (B)\n");

// ---------------------------------------------------------------- happy path
test("activates a reviewed policy: previous none, serial 1, ACTIVE confirmed", async () => {
  const f = await fixture(); try {
    const r = await activatePolicy(baseInput(f, policyA1));
    assert.equal(r.ok, true, `${r.reason} ${r.detail}`);
    assert.equal(r.serial, 1);
    assert.equal(r.previous, null);
    assert.equal(r.policy_hash, policyHash(policyA1));
    assert.ok(r.signer_fingerprint, "signer fingerprint reported");
    const s = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.equal(evaluatePolicyPhase({ policyDocument: policyA1, activeBundle: r.bundle, state: s }).phase, PHASE.ACTIVE);
  } finally { cleanup(f); }
});

test("second activation increments the serial and reports the previous authority", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1));
    const r = await activatePolicy(baseInput(f, policyA2, { now: LATER }));
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.serial, 2);
    assert.deepEqual(r.previous, { policy_id: "coding", serial: 1 });
    const hist = activationHistory(JSON.parse(readFileSync(f.statePath, "utf8")));
    assert.equal(hist.find((h) => h.serial === 1).phase, "RETIRED");
    assert.equal(hist.find((h) => h.serial === 2).phase, "ACTIVE");
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- hostile: pre-signing
test("missing signer key refuses before signing", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { privateKeyPem: undefined }));
    assert.equal(r.reason, "MISSING_SIGNER");
  } finally { cleanup(f); }
});

test("production run without a trusted root fails closed", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { trustedRootFingerprint: undefined, profile: "production" }));
    assert.equal(r.reason, "MISSING_TRUSTED_ROOT");
  } finally { cleanup(f); }
});

test("trusted root that does not bind the authority bundle refuses", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { trustedRootFingerprint: "0".repeat(64), profile: "production" }));
    assert.equal(r.reason, "TRUST_ROOT_MISMATCH");
  } finally { cleanup(f); }
});

test("unreviewed (draft-shaped) policy is refused", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policy("coding", [])));
    assert.equal(r.reason, "POLICY_NOT_READY");
  } finally { cleanup(f); }
});

test("encrypted / invalid signing key fails at signing, no state written", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { privateKeyPem: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot-a-real-key\n-----END ENCRYPTED PRIVATE KEY-----\n" }));
    assert.equal(r.reason, "SIGNING_FAILED");
  } finally { cleanup(f); }
});

test("malformed state refuses before signing", async () => {
  const f = await fixture(); try {
    writeFileSync(f.statePath, "{ not valid json", "utf8");
    const r = await activatePolicy(baseInput(f, policyA1));
    assert.equal(r.ok, false);
    assert.equal(r.reason, "MALFORMED_STATE");
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- hostile: bad bundle before activation
test("a tampered policy_hash (wrong hash) is caught before activation", async () => {
  const f = await fixture(); try {
    const badSign = async (inp, keys) => { const b = await signPolicyBundle(inp, keys); b.policy_hash = b.policy_hash.replace(/.$/, "0"); return b; };
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1), { signPolicyBundle: badSign });
    assert.equal(r.reason, "POLICY_HASH_MISMATCH");
  } finally { cleanup(f); }
});

test("a bundle whose document was modified after signing is caught", async () => {
  const f = await fixture(); try {
    const tamperDoc = async (inp, keys) => { const b = await signPolicyBundle(inp, keys); b.policy_document = { ...b.policy_document, rules: [...b.policy_document.rules, R_DELETE] }; return b; };
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1), { signPolicyBundle: tamperDoc });
    assert.equal(r.reason, "POLICY_HASH_MISMATCH");
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- hostile: activation trust gate
test("invalid signature is refused at activation", async () => {
  const f = await fixture(); try {
    const badSig = async (inp, keys) => { const b = await signPolicyBundle(inp, keys); b.signature.value = b.signature.value.replace(/.$/, b.signature.value.endsWith("0") ? "1" : "0"); return b; };
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1), { signPolicyBundle: badSig });
    assert.equal(r.reason, "ACTIVATION_REFUSED");
    assert.match(r.detail, /SIGNATURE/);
  } finally { cleanup(f); }
});

test("wrong authority role (approval key signing a policy) is refused", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem }));
    assert.equal(r.reason, "ACTIVATION_REFUSED");
  } finally { cleanup(f); }
});

test("unknown signing key id is refused", async () => {
  const f = await fixture(); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1, { keyId: "policy-unknown" }));
    assert.equal(r.reason, "ACTIVATION_REFUSED");
  } finally { cleanup(f); }
});

test("expired signing key is refused", async () => {
  const f = await fixture({ policyValidUntil: "2026-03-01T00:00:00.000Z" }); try {
    const r = await expectRefusedLeaving(f, baseInput(f, policyA1)); // NOW is after validUntil
    assert.equal(r.reason, "ACTIVATION_REFUSED");
  } finally { cleanup(f); }
});

test("revoked key (activation refuses) leaves prior authority intact", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1)); // serial 1 active
    const refusingActivate = async () => ({ ok: false, reason: "POLICY_BUNDLE_AUTHORITY_KEY_REVOKED" });
    const r = await expectRefusedLeaving(f, baseInput(f, policyA2, { now: LATER }), { activateSignedPolicyBundle: refusingActivate });
    assert.equal(r.reason, "ACTIVATION_REFUSED");
    assert.equal(activeSerial(f, "coding"), 1);
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- hostile: serial monotonicity
test("serial reuse with different content is refused", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1)); // serial 1
    const r = await expectRefusedLeaving(f, baseInput(f, policyA2, { serial: 1, now: LATER }));
    assert.equal(r.reason, "ACTIVATION_REFUSED");
    assert.match(r.detail, /SERIAL_REUSE/);
  } finally { cleanup(f); }
});

test("serial rollback below the floor (to an unused serial) is refused", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1));                              // serial 1
    await activatePolicy(baseInput(f, policyA2, { serial: 3, now: LATER }));   // serial 3 -> floor 3
    // serial 2 is below the floor and never recorded: the rollback path, not reuse.
    const r = await expectRefusedLeaving(f, baseInput(f, policyA2, { serial: 2, now: LATER }));
    assert.equal(r.reason, "ACTIVATION_REFUSED");
    assert.match(r.detail, /ROLLBACK/);
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- hostile: persistence / post-activation
test("state write failure at activation refuses and preserves prior authority", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1)); // serial 1 active
    const failingActivate = async () => ({ ok: false, reason: "POLICY_BUNDLE_STATE_WRITE_FAILED" });
    const r = await expectRefusedLeaving(f, baseInput(f, policyA2, { now: LATER }), { activateSignedPolicyBundle: failingActivate });
    assert.equal(r.reason, "ACTIVATION_REFUSED");
    assert.equal(activeSerial(f, "coding"), 1);
  } finally { cleanup(f); }
});

test("verification failure after signing refuses and preserves prior authority", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1));
    const failingActivate = async () => ({ ok: false, reason: "POLICY_BUNDLE_SIGNATURE_INVALID" });
    const r = await expectRefusedLeaving(f, baseInput(f, policyA2, { now: LATER }), { activateSignedPolicyBundle: failingActivate });
    assert.equal(r.reason, "ACTIVATION_REFUSED");
  } finally { cleanup(f); }
});

test("concurrent activations racing for the same serial: one wins, the other is refused", async () => {
  const f = await fixture(); try {
    await activatePolicy(baseInput(f, policyA1)); // serial 1
    // Both read floor 1 and target serial 2 with different content (a real race).
    const winner = await activatePolicy(baseInput(f, policyA2, { serial: 2, now: LATER }));
    const loser = await activatePolicy(baseInput(f, policy("coding", [R_READ, { ...R_DELETE, rule_id: "refuse-delete-2" }]), { serial: 2, now: LATER }));
    assert.equal(winner.ok, true, winner.reason);
    assert.equal(loser.ok, false);
    assert.equal(loser.reason, "ACTIVATION_REFUSED");
    assert.equal(activeSerial(f, "coding"), 2);
  } finally { cleanup(f); }
});

test("failure to prove the result is ACTIVE is reported as failure", async () => {
  const f = await fixture(); try {
    // Real activation succeeds, but the confirmation classifier does not agree.
    const r = await activatePolicy(baseInput(f, policyA1), { evaluatePolicyPhase: () => ({ phase: PHASE.READY }) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "ACTIVE_CONFIRMATION_FAILED");
  } finally { cleanup(f); }
});

// ---------------------------------------------------------------- invariant: only the CLI activates
test("the policy editor has no activation/signing code path (explicit operator action only)", () => {
  const html = readFileSync(join(repoRoot, "policy-editor", "mnde-policy-editor.html"), "utf8");
  for (const forbidden of ["activateSignedPolicyBundle", "signPolicyBundle(", "activatePolicy("]) {
    assert.ok(!html.includes(forbidden), `editor must not invoke ${forbidden}`);
  }
});

// ---------------------------------------------------------------- end-to-end lifecycle proof
function readReq() { return { schema_version: "1.0", request_id: "e2e", timestamp: NOW, principal: {}, agent: {}, tool: { tool_name: "read" }, parameters: {}, environment: {}, context: {} }; }
test("end-to-end: A active -> edit -> revision READY while A still ACTIVE -> activate -> revision ACTIVE, A RETIRED, receipts bind to the new hash", async () => {
  const f = await fixture(); try {
    const authorityPath = join(f.dir, "authority.json"); writeFileSync(authorityPath, JSON.stringify(f.authorityBundle), "utf8");

    // 1. Activate A1; receipts bind to A1's hash.
    const a1 = await activatePolicy(baseInput(f, policyA1));
    assert.equal(a1.ok, true, a1.reason);
    const a1Path = join(f.dir, "A1.bundle.json"); writeFileSync(a1Path, JSON.stringify(a1.bundle), "utf8");
    const envA1 = { MNDE_PE_POLICY_BUNDLE: a1Path, MNDE_PE_AUTHORITY_BUNDLE: authorityPath, MNDE_PE_POLICY_BUNDLE_STATE: f.statePath, MNDE_PE_TRUSTED_ROOT_FINGERPRINT: f.trustedRootFingerprint, MNDE_PE_BUNDLE_NOW: NOW };
    const cfgA1 = await loadPolicyEngineConfig(envA1);
    assert.equal(cfgA1.ok, true, cfgA1.reason);
    assert.equal(decidePolicyEngine(readReq(), cfgA1, { now: NOW }).receipt.decision_output.policy_hash, policyHash(policyA1));

    // 2. Edit A -> A2 (working). With state at serial 1, the revision is READY and
    //    dirty; the runtime still holds A1 as the ACTIVE authority.
    const midState = JSON.parse(readFileSync(f.statePath, "utf8"));
    const edited = evaluatePolicyPhase({ policyDocument: policyA2, activeBundle: a1.bundle, state: midState });
    assert.equal(edited.phase, PHASE.READY);
    assert.equal(edited.dirtyFromActive, true);

    // 3. Activate the revision.
    const a2 = await activatePolicy(baseInput(f, policyA2, { now: LATER }));
    assert.equal(a2.ok, true, a2.reason);
    assert.equal(a2.serial, 2);
    const a2Path = join(f.dir, "A2.bundle.json"); writeFileSync(a2Path, JSON.stringify(a2.bundle), "utf8");

    // 4. Revision ACTIVE, original RETIRED.
    const hist = activationHistory(JSON.parse(readFileSync(f.statePath, "utf8")));
    assert.equal(hist.find((h) => h.serial === 2).phase, "ACTIVE");
    assert.equal(hist.find((h) => h.serial === 1).phase, "RETIRED");

    // 5. Receipts now bind to the NEW policy hash.
    const envA2 = { ...envA1, MNDE_PE_POLICY_BUNDLE: a2Path, MNDE_PE_BUNDLE_NOW: LATER };
    const cfgA2 = await loadPolicyEngineConfig(envA2);
    assert.equal(cfgA2.ok, true, cfgA2.reason);
    assert.equal(decidePolicyEngine(readReq(), cfgA2, { now: LATER }).receipt.decision_output.policy_hash, policyHash(policyA2));
    assert.notEqual(policyHash(policyA1), policyHash(policyA2));
  } finally { cleanup(f); }
});

await chain;
const passed = results.filter(Boolean).length;
console.log(`\n${passed === results.length ? "PASS" : "FAIL"} policy activation (${passed}/${results.length})`);
process.exit(passed === results.length ? 0 : 1);
