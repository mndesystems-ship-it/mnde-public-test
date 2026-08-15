// mnde.execution-grant.v1 — conformance + hostile tests (CAP-1).
//
//   npm run test:execution-grant
//
// Proves the CAP-1 statement: MNDe can MINT and INDEPENDENTLY VERIFY a
// cryptographically signed capability representing permission for ONE bounded
// execution, cryptographically bound to a specific ALLOW decision receipt.
// Redemption / single-use is NOT part of CAP-1 (later rungs) and is not tested
// here — verifying a valid grant twice legitimately succeeds twice.
//
// Issuance now REQUIRES a cryptographically verified receipt (an unsigned or
// forged object cannot mint a grant) and a DB-egress grant may not widen the
// action the receipt approved. Receipts below are therefore genuine custody
// envelopes over real policy-engine decisions, not hand-authored objects.

import assert from "node:assert/strict";

import { createLocalDemoCustody } from "../src/custody/index.mjs";
import { signReceiptForDelivery } from "../src/authority-signing/index.mjs";
import { buildPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { issueExecutionGrant } from "../src/grants/issue.mjs";
import { verifyExecutionGrant } from "../src/grants/verify.mjs";
import { canonicalGrantPayload } from "../src/grants/grant.mjs";
import { canonicalizeJson } from "../shared/json.ts";

const NOW = "2026-08-10T00:00:00.000Z";
const NOT_AFTER = "2026-08-10T00:01:00.000Z"; // +60s
const AFTER_EXPIRY = "2026-08-10T00:02:00.000Z";

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failures += 1;
    console.log(`  [FAIL] ${name}: ${error?.message ?? error}`);
  }
}

// A minimal ACTIVE policy that ALLOWs a db.execute tool. The DB action lives in
// the request parameters, which the signed receipt binds via request_hash — that
// is the trusted source issuance uses to bound a grant's DB scope.
const DB_POLICY = {
  schema_version: "1.0",
  policy_id: "grant-test-policy",
  version: "1",
  state: "ACTIVE",
  rules: [{ rule_id: "allow-db-execute", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "db.execute" } }]
};

function dbRequest({ requestId = "exec-db-del-1", toolName = "db.execute", parameters = { database: "prod", operation: "DELETE", table: "orders" } } = {}) {
  return {
    schema_version: "1.0",
    request_id: requestId,
    timestamp: NOW,
    principal: { id: "u" },
    agent: { id: "a" },
    tool: { tool_name: toolName },
    parameters,
    environment: {},
    context: {}
  };
}

// Build a GENUINE custody-signed receipt envelope over a real policy decision.
async function signedReceipt(provider, request = dbRequest()) {
  const inner = buildPolicyReceipt(request, DB_POLICY, { now: NOW });
  const out = await signReceiptForDelivery(inner, { mode: "custody", provider }, { now: NOW });
  assert.equal(out.ok, true, `receipt signing failed: ${out.reason_code}`);
  return out.receipt;
}

function dbGrantRequest(overrides = {}) {
  return {
    grant_id: "grn-test-1",
    scope: { protocol: "postgres", resource: "db/prod/orders", target: { database: "prod", table: "orders", operation: "DELETE" } },
    limits: { max_cost_cents: 0, not_after: NOT_AFTER },
    ...overrides
  };
}

async function main() {
  console.log("mnde.execution-grant.v1 — conformance + hostile\n");

  const provider = await createLocalDemoCustody({ now: "2025-01-01T00:00:00.000Z" });
  const signer = provider.signReceipt;
  const bundle = provider.getPublicBundle();
  const fp = provider.trustedRootFingerprint;
  const verifyOpts = { authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW };
  // Receipt-verification context threaded into issuance (GRANT-1).
  const verify = { trustedRootFingerprint: fp };

  const receipt = await signedReceipt(provider);

  // Capture one valid grant for the reuse/tamper tests.
  let goodGrant = null;

  await test("issue: a verified ALLOW receipt + DB scope produces a signed grant", async () => {
    const r = await issueExecutionGrant({ receipt, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    assert.equal(r.ok, true, `issue failed: ${r.reason_code}`);
    assert.equal(r.grant.schema_version, "mnde.execution-grant.v1");
    assert.equal(r.grant.execution_id, "exec-db-del-1");
    assert.equal(r.grant.scope.target.operation, "DELETE");
    assert.equal(r.grant.signature.algorithm, "ED25519");
    assert.ok(r.grant.signature.value && r.grant.issuer_key_id);
    assert.ok(r.grant.decision_hash && r.grant.request_hash && r.grant.policy_hash);
    goodGrant = r.grant;
  });

  await test("verify: the issued grant verifies independently against the bundle", async () => {
    const v = await verifyExecutionGrant(goodGrant, verifyOpts);
    assert.equal(v.ok, true, `verify failed: ${v.reason_code}`);
    assert.equal(v.verified, true);
    assert.equal(v.grant_id, "grn-test-1");
    assert.equal(v.execution_id, "exec-db-del-1");
  });

  await test("verify: with the SAME receipt, binding checks pass", async () => {
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, receipt });
    assert.equal(v.ok, true, `verify+receipt failed: ${v.reason_code}`);
  });

  // --- GRANT-1 (regression): issuance authenticates the receipt ---
  await test("SEC/GRANT-1: an unsigned, fabricated receipt cannot mint a grant", async () => {
    const forged = {
      decision_output: { decision: "ALLOW", execution_id: "exec-ATTACKER", decision_hash: "dh", request_hash: "rh", policy_hash: "ph" }
    };
    const r = await issueExecutionGrant({ receipt: forged, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_UNVERIFIED");
  });

  await test("SEC/GRANT-1: a receipt from a DIFFERENT authority cannot mint a grant", async () => {
    const other = await createLocalDemoCustody({ now: "2025-01-01T00:00:00.000Z" });
    const foreign = await signedReceipt(other);
    const r = await issueExecutionGrant({ receipt: foreign, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_UNVERIFIED");
  });

  await test("SEC/GRANT-1: with no trusted-root context issuance fails closed", async () => {
    const r = await issueExecutionGrant({ receipt, request: dbGrantRequest(), signer, bundle, verify: {}, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_UNVERIFIED");
  });

  // --- GRANT-2 (regression): scope cannot exceed the approved receipt ---
  await test("SEC/GRANT-2: a grant broader than the approved action is refused (DELETE->DROP)", async () => {
    const escalate = dbGrantRequest({ scope: { protocol: "postgres", resource: "db/prod", target: { database: "prod", operation: "DROP", table: "orders" } } });
    const r = await issueExecutionGrant({ receipt, request: escalate, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_SCOPE_EXCEEDS_RECEIPT");
  });

  await test("SEC/GRANT-2: a table-scoped approval cannot mint a whole-database grant", async () => {
    const wholeDb = dbGrantRequest({ scope: { protocol: "postgres", resource: "db/prod", target: { database: "prod", operation: "DELETE" } } });
    const r = await issueExecutionGrant({ receipt, request: wholeDb, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_SCOPE_EXCEEDS_RECEIPT");
  });

  await test("SEC/GRANT-2: a wrong-database grant is refused", async () => {
    const wrongDb = dbGrantRequest({ scope: { protocol: "postgres", resource: "db/other", target: { database: "other", operation: "DELETE", table: "orders" } } });
    const r = await issueExecutionGrant({ receipt, request: wrongDb, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_SCOPE_EXCEEDS_RECEIPT");
  });

  // --- GRANT-3 (regression): the TTL window is bounded ---
  await test("SEC/GRANT-3: an over-long validity window is refused", async () => {
    const longTtl = dbGrantRequest({ limits: { max_cost_cents: 0, not_before: NOW, not_after: "2126-08-10T00:00:00.000Z" } });
    const r = await issueExecutionGrant({ receipt, request: longTtl, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_LIMITS_INVALID");
  });

  await test("SEC/GRANT-3: a window at the 5-minute ceiling is accepted", async () => {
    const r = await issueExecutionGrant({
      receipt, request: dbGrantRequest({ limits: { max_cost_cents: 0, not_before: NOW, not_after: "2026-08-10T00:05:00.000Z" } }),
      signer, bundle, verify, now: NOW
    });
    assert.equal(r.ok, true, `issue failed: ${r.reason_code}`);
  });

  // --- Hostile: signature integrity ---
  await test("tamper: mutating the scope operation after signing fails signature", async () => {
    const t = structuredClone(goodGrant);
    t.scope.target.operation = "DROP"; // escalate DELETE -> DROP
    const v = await verifyExecutionGrant(t, verifyOpts);
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_INVALID_SIGNATURE");
  });

  await test("tamper: mutating a binding hash after signing fails signature", async () => {
    const t = structuredClone(goodGrant);
    t.decision_hash = "dh-EVIL";
    const v = await verifyExecutionGrant(t, verifyOpts);
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_INVALID_SIGNATURE");
  });

  await test("tamper: raising the cost cap after signing fails signature", async () => {
    const t = structuredClone(goodGrant);
    t.limits.max_cost_cents = 1_000_000;
    const v = await verifyExecutionGrant(t, verifyOpts);
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_INVALID_SIGNATURE");
  });

  // --- Hostile: receipt binding ---
  await test("mismatch: a valid grant verified against a DIFFERENT receipt is refused", async () => {
    const other = await signedReceipt(provider, dbRequest({ requestId: "exec-OTHER" }));
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, receipt: other });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_REQUEST_MISMATCH");
  });

  // --- GRANT-4 (regression): the verify-side receipt is authenticated, not just compared ---
  await test("SEC/GRANT-4: a forged receipt whose facts MATCH the grant is still refused", async () => {
    // Same four hashes as the grant, but never signed by anyone. Pure field-equality
    // would pass; authentication must catch it.
    const forged = {
      decision_output: {
        decision: "ALLOW",
        execution_id: goodGrant.execution_id,
        decision_hash: goodGrant.decision_hash,
        request_hash: goodGrant.request_hash,
        policy_hash: goodGrant.policy_hash
      }
    };
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, receipt: forged });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_RECEIPT_UNVERIFIED");
  });

  // --- GRANT-5 (regression): a non-serializable grant fails closed, never throws ---
  await test("SEC/GRANT-5: a grant with a non-serializable field is MALFORMED, not an exception", async () => {
    const t = structuredClone(goodGrant);
    t.scope.target.table = undefined; // passes validateScope, but canonicalization would throw
    const v = await verifyExecutionGrant(t, verifyOpts); // must return, not throw
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_MALFORMED");
  });

  // --- Hostile: TTL ---
  await test("ttl: verifying after not_after is EXPIRED", async () => {
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, now: AFTER_EXPIRY });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_EXPIRED");
  });

  await test("ttl: a grant whose window has not opened is NOT_YET_VALID", async () => {
    const future = await issueExecutionGrant({
      receipt,
      request: dbGrantRequest({ limits: { max_cost_cents: 0, not_before: "2026-08-10T00:05:00.000Z", not_after: "2026-08-10T00:06:00.000Z" } }),
      signer, bundle, verify, now: NOW
    });
    assert.equal(future.ok, true, `issue failed: ${future.reason_code}`);
    const v = await verifyExecutionGrant(future.grant, verifyOpts);
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_NOT_YET_VALID");
  });

  // --- Hostile: bundle / trust ---
  await test("trust: verifying without an authority bundle is refused", async () => {
    const v = await verifyExecutionGrant(goodGrant, { trustedRootFingerprint: fp, now: NOW });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_BUNDLE_REQUIRED");
  });

  await test("trust: a wrong trusted root fingerprint rejects the bundle", async () => {
    const v = await verifyExecutionGrant(goodGrant, { authorityBundle: bundle, trustedRootFingerprint: "0".repeat(64), now: NOW });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_BUNDLE_UNTRUSTED");
  });

  await test("trust: a grant signed by one authority does not verify under another", async () => {
    const other = await createLocalDemoCustody({ now: "2025-01-01T00:00:00.000Z" });
    const v = await verifyExecutionGrant(goodGrant, { authorityBundle: other.getPublicBundle(), trustedRootFingerprint: other.trustedRootFingerprint, now: NOW });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_INVALID_SIGNATURE");
  });

  // --- Hostile: issuance guards ---
  await test("issue: a non-ALLOW receipt cannot mint a grant", async () => {
    const refuse = await signedReceipt(provider, dbRequest({ toolName: "unknown.tool" })); // no matching ALLOW rule -> REFUSE
    const r = await issueExecutionGrant({ receipt: refuse, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_NOT_ALLOW");
  });

  await test("issue: a DB scope missing the operation is refused", async () => {
    const bad = dbGrantRequest({ scope: { protocol: "postgres", resource: "db/prod/orders", target: { database: "prod" } } });
    const r = await issueExecutionGrant({ receipt, request: bad, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_SCOPE_INVALID");
  });

  await test("issue: invalid limits (negative cost) are refused", async () => {
    const bad = dbGrantRequest({ limits: { max_cost_cents: -1, not_after: NOT_AFTER } });
    const r = await issueExecutionGrant({ receipt, request: bad, signer, bundle, verify, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_LIMITS_INVALID");
  });

  // --- Determinism ---
  await test("determinism: canonical serialization + Ed25519 signing are stable", async () => {
    const a = await issueExecutionGrant({ receipt, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    const b = await issueExecutionGrant({ receipt, request: dbGrantRequest(), signer, bundle, verify, now: NOW });
    assert.equal(a.ok && b.ok, true, `issue failed: ${a.reason_code ?? ""} ${b.reason_code ?? ""}`);
    assert.equal(canonicalizeJson(canonicalGrantPayload(a.grant)), canonicalizeJson(canonicalGrantPayload(b.grant)), "same inputs must canonicalize identically");
    assert.equal(a.grant.signature.value, b.grant.signature.value, "same canonical payload must produce the same Ed25519 signature");
  });

  console.log("");
  if (failures > 0) {
    console.log(`FAIL execution-grant tests (${failures} failing)`);
    process.exit(1);
  }
  console.log("PASS execution-grant tests");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
