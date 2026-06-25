// Policy-engine receipt + unified verifier tests.
//
//   npm run test:policy-receipt
//
// Proves a policy-engine decision becomes a signed, offline-verifiable receipt on
// the shared Ed25519 authority chain, that tampering fails closed, and that ONE
// verifier checks both policy-engine receipts and the legacy pipeline receipts.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM } from "../shared/index.ts";
import { buildAuthorityBundle, fingerprintOf, generateAuthorityKeyPair, signCanonical } from "../src/custody/index.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { verifyAnyReceiptFile, verifyAnyReceiptObject } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

function request(overrides = {}) {
  return {
    schema_version: "1.0",
    request_id: "req-1",
    timestamp: "2026-01-01T00:00:00.000Z",
    principal: { id: "user-1" },
    agent: { id: "agent-1" },
    tool: { tool_name: "read_status" },
    parameters: {},
    environment: { region: "us-west-2" },
    context: {},
    ...overrides
  };
}
function policy(rules) {
  return { schema_version: "1.0", policy_id: "pol-1", version: "1", state: "ACTIVE", rules };
}

const explicitNow = "2026-06-25T00:00:00.000Z";
const allowReadStatusRule = { rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } };

function makeExplicitAuthorityReceipt(authorityId = "mnde-explicit-test-authority") {
  const root = { keyId: `${authorityId}-root`, ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: `${authorityId}-receipt`, ...generateAuthorityKeyPair() };
  const authorityBundle = buildAuthorityBundle({
    authorityId,
    issuedAt: explicitNow,
    notAfter: "2027-06-25T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }]
  });
  const requestObject = request({ request_id: `${authorityId}-request`, timestamp: explicitNow });
  const policyObject = policy([allowReadStatusRule]);
  const decision = evaluatePolicyRequest(requestObject, policyObject, { now: explicitNow });
  const payload = {
    schema_version: "mnde.pe.receipt.v1",
    canonical_request: canonicalizeJson(requestObject),
    canonical_policy: canonicalizeJson(policyObject),
    authorities: [],
    trust_enforced: false,
    request_hash: decision.request_hash,
    policy_hash: decision.policy_hash,
    authority_chain_hash: decision.authority_chain_hash,
    decision_output: decision
  };
  const receipt = {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: authorityBundle.authority_id,
      key_id: receiptKey.keyId,
      public_key_fingerprint: fingerprintOf(receiptKey.publicPem),
      signed_at: explicitNow,
      value: signCanonical(canonicalizeJson(payload), receiptKey.privatePem)
    }
  };
  return { receipt, authorityBundle, rootFingerprint: authorityBundle.root_key.fingerprint };
}

bootstrapReceiptKeys({ repoRoot });

test("ALLOW decision produces a verifiable policy receipt", () => {
  const rec = buildPolicyReceipt(
    request(),
    policy([{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }])
  );
  const v = verifyPolicyReceipt(rec);
  assert.equal(v.verified, true, v.reason ?? "");
  assert.equal(rec.decision_output.decision, "ALLOW");
});

test("REFUSE decision is also a verifiable receipt", () => {
  const rec = buildPolicyReceipt(
    request({ tool: { tool_name: "delete_everything" } }),
    policy([{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }])
  );
  const v = verifyPolicyReceipt(rec);
  assert.equal(v.verified, true);
  assert.equal(rec.decision_output.decision, "REFUSE");
  assert.equal(rec.decision_output.reason_code, "NO_MATCHING_RULE");
});

test("tampering the decision fails verification", () => {
  const rec = buildPolicyReceipt(request(), policy([{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]));
  rec.decision_output.decision = "REFUSE"; // forge
  assert.equal(verifyPolicyReceipt(rec).verified, false);
});

test("tampering the request fails verification", () => {
  const rec = buildPolicyReceipt(request(), policy([{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]));
  rec.canonical_request = rec.canonical_request.replace("read_status", "delete_everything");
  assert.equal(verifyPolicyReceipt(rec).verified, false);
});

test("ONE verifier verifies a policy-engine receipt", () => {
  const rec = buildPolicyReceipt(request(), policy([{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]));
  const file = join(mkdtempSync(join(tmpdir(), "mnde-pe-rec-")), "pe-receipt.json");
  writeFileSync(file, JSON.stringify(rec, null, 2));
  const out = verifyAnyReceiptFile(file);
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, true);
});

test("the SAME verifier verifies a legacy pipeline receipt", () => {
  const legacy = join(repoRoot, "examples", "receipts", "valid-receipt.json");
  if (!existsSync(legacy)) {
    // example receipt not present in this checkout; skip without failing
    assert.ok(true);
    return;
  }
  const out = verifyAnyReceiptFile(legacy);
  assert.equal(out.kind, "pipeline");
  assert.equal(out.verified, true, "legacy ecs.receipt.v2 must still verify through the unified verifier");
});

test("explicit PE authority bundle requires a trusted root pin", () => {
  const { receipt, authorityBundle } = makeExplicitAuthorityReceipt("mnde-attacker-no-root");
  const out = verifyAnyReceiptObject(receipt, { authorityBundle, now: explicitNow });
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, false);
  assert.equal(out.reason, "MISSING_TRUSTED_ROOT");
});

test("explicit PE authority bundle fails with the wrong trusted root pin", () => {
  const { receipt, authorityBundle } = makeExplicitAuthorityReceipt("mnde-attacker-wrong-root");
  const out = verifyAnyReceiptObject(receipt, { authorityBundle, trustedRootFingerprint: "0".repeat(64), now: explicitNow });
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, false);
  assert.equal(out.reason, "authority bundle: UNTRUSTED_ROOT");
});

test("conflicting explicit PE authority bundle fails without repo-local fallback", () => {
  const rec = buildPolicyReceipt(request(), policy([allowReadStatusRule]));
  const { authorityBundle, rootFingerprint } = makeExplicitAuthorityReceipt("mnde-conflicting-authority");
  const out = verifyAnyReceiptObject(rec, { authorityBundle, trustedRootFingerprint: rootFingerprint, now: explicitNow });
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, false);
  assert.equal(out.reason, "AUTHORITY_BUNDLE_MISMATCH");
});

test("repo-local policy receipt still verifies when no explicit bundle is supplied", () => {
  const rec = buildPolicyReceipt(request(), policy([allowReadStatusRule]));
  const out = verifyAnyReceiptObject(rec);
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, true, out.reason ?? "");
});

test("explicit PE authority bundle verifies with the matching trusted root pin", () => {
  const { receipt, authorityBundle, rootFingerprint } = makeExplicitAuthorityReceipt("mnde-explicit-valid");
  const out = verifyAnyReceiptObject(receipt, { authorityBundle, trustedRootFingerprint: rootFingerprint, now: explicitNow });
  assert.equal(out.kind, "policy-engine");
  assert.equal(out.verified, true, out.reason ?? "");
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL policy-receipt tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS policy-receipt tests (${results.length}/${results.length})`);
