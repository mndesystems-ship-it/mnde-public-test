// Live vs archival key verification hostile test (H2).
//
//   npm run test:live-verification
//
// Live (authorize-now) verification must reject RETIRED and REVOKED receipt keys,
// even when the attacker supplies an authenticated decision time inside the key's
// former validity window. Archival (historical audit) verification may still
// validate an old decision under explicit historical semantics — it is never
// authorization.

import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { findAuthorityReceiptKey } from "../shared/authority-manifest.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const results = [];
function test(name, fn) {
  try { fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

const DECISION_TIME = "2026-06-14T12:00:00.000Z";

function manifest({ retired = false, revokedAt = undefined } = {}) {
  const key = {
    key_id: "receipt-key-1",
    public_key: "-----PEM-----",
    public_key_fingerprint: "fp",
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_to: "2027-01-01T00:00:00.000Z",
    ...(revokedAt ? { revoked_at: revokedAt } : {})
  };
  return {
    authority_id: "auth-1",
    active_keys: retired ? [] : [key],
    retired_keys: retired ? [key] : []
  };
}

console.log("Live vs archival verification hostile test (H2)\n");

test("a RETIRED key is rejected under live (activeOnly) verification", () => {
  const r = findAuthorityReceiptKey(manifest({ retired: true }), { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: true });
  assert.equal(r.ok, false, "a retired key must not authorize live execution");
});

test("archival verification still accepts a retired key within its window", () => {
  const r = findAuthorityReceiptKey(manifest({ retired: true }), { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(r.ok, true, "historical audit may validate an old decision");
});

test("a REVOKED key is rejected when the decision time is at/after revoked_at (even archival)", () => {
  const m = manifest({ revokedAt: "2026-03-01T00:00:00.000Z" });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(r.ok, false, "a decision timestamped after revocation must never validate");
});

test("a revoked key still validates decisions timestamped BEFORE revoked_at (archival)", () => {
  const m = manifest({ revokedAt: "2026-12-01T00:00:00.000Z" });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(r.ok, true, "a pre-revocation decision remains historically valid");
});

test("live verification rejects a revoked-but-active key regardless of decision time", () => {
  // A key revoked while still 'active' must be refused for live execution.
  const m = manifest({ revokedAt: "2026-12-01T00:00:00.000Z" });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: true });
  assert.equal(r.ok, false, "a revoked key must not authorize live execution");
});

test("an unparseable revoked_at fails closed rather than silently ignoring revocation", () => {
  const m = manifest({ revokedAt: "not-a-date" });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(r.ok, false, "an unparseable revocation timestamp must not be treated as no revocation");
});

test("boundary: a decision timestamped exactly AT revoked_at is treated as revoked, not valid", () => {
  // revoked_at is the instant revocation takes effect; the key must not still
  // authorize a decision claiming to have happened at that exact instant.
  const m = manifest({ revokedAt: DECISION_TIME });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(r.ok, false, "a decision timestamped exactly at revoked_at must be rejected, not grandfathered in");
});

test("boundary: a decision one millisecond BEFORE revoked_at still validates (archival)", () => {
  const revokedAt = new Date(DECISION_TIME);
  const justBefore = new Date(revokedAt.getTime() - 1).toISOString();
  const m = manifest({ revokedAt: revokedAt.toISOString() });
  const r = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: justBefore, activeOnly: false });
  assert.equal(r.ok, true, "a decision strictly before revoked_at must still be historically valid");
});

test("a manifest key with no revoked_at field at all is unaffected by revocation logic (no regression)", () => {
  const m = manifest({}); // no revokedAt passed -> key has no revoked_at property whatsoever
  assert.equal("revoked_at" in m.active_keys[0], false, "test setup sanity: key truly has no revoked_at field");
  const live = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: true });
  assert.equal(live.ok, true, "a key with no revoked_at must validate exactly as before this change, live");
  const archival = findAuthorityReceiptKey(m, { authorityId: "auth-1", keyId: "receipt-key-1", validAt: DECISION_TIME, activeOnly: false });
  assert.equal(archival.ok, true, "a key with no revoked_at must validate exactly as before this change, archival");
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) { console.log(`FAIL live-verification tests (${results.length - failed}/${results.length})`); process.exit(1); }
console.log(`PASS live-verification tests (${results.length}/${results.length})`);
