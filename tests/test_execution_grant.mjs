// mnde.execution-grant.v1 — conformance + hostile tests (CAP-1).
//
//   npm run test:execution-grant
//
// Proves the CAP-1 statement: MNDe can MINT and INDEPENDENTLY VERIFY a
// cryptographically signed capability representing permission for ONE bounded
// execution, cryptographically bound to a specific ALLOW decision receipt.
// Redemption / single-use is NOT part of CAP-1 (later rungs) and is not tested
// here — verifying a valid grant twice legitimately succeeds twice.

import assert from "node:assert/strict";

import { createLocalDemoCustody } from "../src/custody/index.mjs";
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

// An ALLOW receipt carrying the four binding facts a grant pins.
function allowReceipt(overrides = {}) {
  return {
    schema_version: "ecs.receipt.v2",
    request_hash: "rh-1",
    decision_output: {
      decision: "ALLOW",
      execution_id: "exec-db-del-1",
      decision_hash: "dh-1",
      request_hash: "rh-1",
      policy_hash: "ph-1",
      ...overrides
    }
  };
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

  // Capture one valid grant for the reuse/tamper tests.
  let goodGrant = null;

  await test("issue: a valid ALLOW receipt + DB scope produces a signed grant", async () => {
    const r = await issueExecutionGrant({ receipt: allowReceipt(), request: dbGrantRequest(), signer, bundle, now: NOW });
    assert.equal(r.ok, true, `issue failed: ${r.reason_code}`);
    assert.equal(r.grant.schema_version, "mnde.execution-grant.v1");
    assert.equal(r.grant.execution_id, "exec-db-del-1");
    assert.equal(r.grant.decision_hash, "dh-1");
    assert.equal(r.grant.request_hash, "rh-1");
    assert.equal(r.grant.policy_hash, "ph-1");
    assert.equal(r.grant.scope.target.operation, "DELETE");
    assert.equal(r.grant.signature.algorithm, "ED25519");
    assert.ok(r.grant.signature.value && r.grant.issuer_key_id);
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
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, receipt: allowReceipt() });
    assert.equal(v.ok, true, `verify+receipt failed: ${v.reason_code}`);
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
    const other = allowReceipt({ execution_id: "exec-OTHER" });
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, receipt: other });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_REQUEST_MISMATCH");
  });

  // --- Hostile: TTL ---
  await test("ttl: verifying after not_after is EXPIRED", async () => {
    const v = await verifyExecutionGrant(goodGrant, { ...verifyOpts, now: AFTER_EXPIRY });
    assert.equal(v.ok, false);
    assert.equal(v.reason_code, "ERR_GRANT_EXPIRED");
  });

  await test("ttl: a grant whose window has not opened is NOT_YET_VALID", async () => {
    const future = await issueExecutionGrant({
      receipt: allowReceipt(),
      request: dbGrantRequest({ limits: { max_cost_cents: 0, not_before: "2026-08-10T00:05:00.000Z", not_after: "2026-08-10T00:06:00.000Z" } }),
      signer, bundle, now: NOW
    });
    assert.equal(future.ok, true);
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
    const refuse = allowReceipt({ decision: "REFUSE" });
    const r = await issueExecutionGrant({ receipt: refuse, request: dbGrantRequest(), signer, bundle, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_NOT_ALLOW");
  });

  await test("issue: a receipt missing binding facts cannot mint a grant", async () => {
    const partial = { schema_version: "ecs.receipt.v2", decision_output: { decision: "ALLOW", execution_id: "x" } };
    const r = await issueExecutionGrant({ receipt: partial, request: dbGrantRequest(), signer, bundle, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_RECEIPT_UNBINDABLE");
  });

  await test("issue: a DB scope missing the operation is refused", async () => {
    const bad = dbGrantRequest({ scope: { protocol: "postgres", resource: "db/prod/orders", target: { database: "prod" } } });
    const r = await issueExecutionGrant({ receipt: allowReceipt(), request: bad, signer, bundle, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_SCOPE_INVALID");
  });

  await test("issue: invalid limits (negative cost) are refused", async () => {
    const bad = dbGrantRequest({ limits: { max_cost_cents: -1, not_after: NOT_AFTER } });
    const r = await issueExecutionGrant({ receipt: allowReceipt(), request: bad, signer, bundle, now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_GRANT_LIMITS_INVALID");
  });

  // --- Determinism ---
  await test("determinism: canonical serialization + Ed25519 signing are stable", async () => {
    const a = await issueExecutionGrant({ receipt: allowReceipt(), request: dbGrantRequest(), signer, bundle, now: NOW });
    const b = await issueExecutionGrant({ receipt: allowReceipt(), request: dbGrantRequest(), signer, bundle, now: NOW });
    assert.equal(a.ok && b.ok, true);
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
