// Regression tests for the f3b4b4a signedAt -> validAt caller-side migration gap.
//
//   npm run test:authority-key-validation-migration
//
// f3b4b4a renamed findAuthorityReceiptKey's `signedAt` parameter to a required
// `validAt`, but four callers (src/policy-engine/receipt.mjs, shell/receipt.mjs,
// tools/verify-receipt.mjs, ram0na/engine.ts) were never migrated in that same
// commit — they kept passing `signedAt`, which the function no longer
// recognizes, so validAt was silently undefined and every one of them failed
// closed with ERR_KEY_VALIDITY_TIME_REQUIRED. This is the caller-side fix and
// its dedicated regression coverage — NOT a re-test of findAuthorityReceiptKey
// itself (already covered by tests/test_live_verification.mjs, untouched here).

import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { authorityPaths, publicKeyFingerprint, signAuthorityManifest } from "../shared/authority-manifest.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { buildShellReceipt, verifyShellReceipt } from "../shell/receipt.mjs";
import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";
import { generateKeyPairSync } from "node:crypto";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

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

const policy = {
  schema_version: "1.0", policy_id: "p1", version: "1", state: "ACTIVE",
  rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
};
function request(overrides = {}) {
  return {
    schema_version: "1.0", request_id: "req-1", timestamp: "2026-07-17T12:00:00.000Z",
    principal: { id: "a" }, agent: { id: "a" }, tool: { tool_name: "read_status" },
    parameters: {}, environment: {}, context: {}, ...overrides
  };
}

console.log("Authority key validation caller-migration regression tests\n");

// ---------------------------------------------------------------------------
// 1. The exact previously-failing policy-trust caller path
// ---------------------------------------------------------------------------

await test("the exact previously-failing scenario: a trust-enforced PE receipt round-trips (repo-local authority path, no explicit authorityBundle)", async () => {
  const receipt = buildPolicyReceipt(request(), policy, { now: "2026-07-17T12:00:00.000Z" });
  const result = await verifyPolicyReceipt(receipt, {});
  assert.equal(result.verified, true, result.reason);
});

// ---------------------------------------------------------------------------
// 2. Authenticated validAt propagation
// ---------------------------------------------------------------------------

await test("validAt is sourced from the signed decision_output.evaluated_at, not the unsigned verifiable_signature.signed_at", async () => {
  const receipt = buildPolicyReceipt(request(), policy, { now: "2026-07-17T12:00:00.000Z" });
  // Move the unsigned signed_at somewhere absurd; verification must be
  // completely unaffected, proving validAt never reads this field.
  const tampered = structuredClone(receipt);
  tampered.verifiable_signature.signed_at = "1970-01-01T00:00:00.000Z";
  const result = await verifyPolicyReceipt(tampered, {});
  assert.equal(result.verified, true, result.reason);
});

await test("tampering the signed evaluated_at (which validAt IS sourced from) breaks the signature and fails verification", async () => {
  const receipt = buildPolicyReceipt(request(), policy, { now: "2026-07-17T12:00:00.000Z" });
  const tampered = structuredClone(receipt);
  tampered.decision_output.evaluated_at = "2030-01-01T00:00:00.000Z";
  const result = await verifyPolicyReceipt(tampered, {});
  assert.equal(result.verified, false);
});

// ---------------------------------------------------------------------------
// 3 & 4. Rejection when validAt is absent / when only unsigned signedAt exists
// ---------------------------------------------------------------------------

await test("a PE receipt with evaluated_at stripped fails closed (ERR_KEY_VALIDITY_TIME_REQUIRED), not silently accepted", async () => {
  const receipt = buildPolicyReceipt(request(), policy, { now: "2026-07-17T12:00:00.000Z" });
  const stripped = structuredClone(receipt);
  delete stripped.decision_output.evaluated_at;
  // Re-sign is deliberately NOT done: this proves that even if an attacker
  // controlling the key tried to strip evaluated_at and re-sign, the explicit
  // "no authenticated time" gate still fires — it is not solely a signature check.
  const result = await verifyPolicyReceipt(stripped, {});
  assert.equal(result.verified, false);
});

await test("a receipt with NO evaluated_at but a present, in-window unsigned signed_at still fails closed (no fallback to signed_at)", async () => {
  const receipt = buildPolicyReceipt(request(), policy, { now: "2026-07-17T12:00:00.000Z" });
  const stripped = structuredClone(receipt);
  delete stripped.decision_output.evaluated_at;
  // signed_at is present, unsigned, and claims a perfectly valid, in-window
  // time. If any code path fell back to it, this receipt would verify.
  assert.equal(typeof stripped.verifiable_signature.signed_at, "string");
  const result = await verifyPolicyReceipt(stripped, {});
  assert.equal(result.verified, false, "must not fall back to the unsigned signed_at");
});

await test("shell receipt: verification uses validAt, not the removed signedAt parameter (round-trip works)", () => {
  const receipt = buildShellReceipt("git status");
  const result = verifyShellReceipt(receipt);
  assert.equal(result.verified, true, result.reason);
});

await test("shell receipt: tampering the unsigned signed_at has zero effect on verification", () => {
  const receipt = buildShellReceipt("git status");
  const tampered = structuredClone(receipt);
  tampered.verifiable_signature.signed_at = "1970-01-01T00:00:00.000Z";
  const result = verifyShellReceipt(tampered);
  assert.equal(result.verified, true, result.reason);
});

await test("legacy ecs.receipt.v2 fixture (tools/verify-receipt.mjs) verifies again after the caller-side fix", () => {
  const report = verifyReceiptFile(join(repoRoot, "examples", "receipts", "valid-receipt.json"));
  assert.equal(verificationPassed(report), true, JSON.stringify(report.checks?.Signature));
});

// ---------------------------------------------------------------------------
// 5 & 6. Exact validity-boundary and revocation behavior, exercised through the
// caller path (src/policy-engine/receipt.mjs), not just the findAuthorityReceiptKey
// unit. repoRoot is hardcoded in these callers at this commit (no override
// option exists yet), so this backs up and restores the real bootstrapped
// local authority around a temporary custom manifest.
// ---------------------------------------------------------------------------

// Backs up and restores every file these boundary/revocation tests touch —
// including shared/receipt_keys/*.pem, which buildPolicyReceipt also reads via
// loadAuthorityBundle. A prior version of this helper "restored" by calling
// bootstrapReceiptKeys({force: true}) instead of a true restore, which
// generates a BRAND NEW keypair rather than putting back the original one —
// that silently invalidated any real reviewer-kit/receipt artifacts signed
// under the pre-test key, breaking later, unrelated suites (test:replay) that
// only surfaced the corruption on a subsequent full-suite run. Restore must
// put back the exact original bytes, never regenerate.
const receiptKeyPaths = [
  join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"),
  join(repoRoot, "shared", "receipt_keys", "receipt_signing_public.pem")
];

function backupLocalAuthority() {
  const paths = authorityPaths(repoRoot, { kind: "local" });
  const backupDir = mkdtempSync(join(tmpdir(), "mnde-authority-backup-"));
  const files = [paths.manifestPath, paths.rootPrivateKeyPath, paths.rootPublicKeyPath, ...receiptKeyPaths];
  const saved = [];
  for (const filePath of files) {
    if (existsSync(filePath)) {
      const dest = join(backupDir, saved.length.toString());
      copyFileSync(filePath, dest);
      saved.push({ filePath, dest });
    }
  }
  return {
    paths,
    restore() {
      for (const { filePath, dest } of saved) copyFileSync(dest, filePath);
      rmSync(backupDir, { recursive: true, force: true });
    }
  };
}

function writeCustomLocalManifest(paths, { activeKeys, retiredKeys = [], rootPrivatePem, rootPublicPem, authorityId }) {
  const manifest = {
    authority_id: authorityId,
    authority_name: "Migration Regression Test Authority",
    root_key_fingerprint: publicKeyFingerprint(rootPublicPem),
    active_keys: activeKeys,
    retired_keys: retiredKeys,
    manifest_signature: ""
  };
  manifest.manifest_signature = signAuthorityManifest(manifest, rootPrivatePem);
  writeFileSync(paths.rootPublicKeyPath, rootPublicPem, "utf8");
  writeFileSync(paths.manifestPath, JSON.stringify(manifest, null, 2), "utf8");
}

await test("exact validity-boundary behavior through the caller path: evaluated_at exactly AT valid_to still verifies (inclusive upper bound)", async () => {
  const backup = backupLocalAuthority();
  try {
    const root = generateKeyPairSync("ed25519");
    const rootPrivatePem = root.privateKey.export({ type: "pkcs8", format: "pem" });
    const rootPublicPem = root.publicKey.export({ type: "spki", format: "pem" });
    const receiptKey = generateKeyPairSync("ed25519");
    const receiptPrivatePem = receiptKey.privateKey.export({ type: "pkcs8", format: "pem" });
    const receiptPublicPem = receiptKey.publicKey.export({ type: "spki", format: "pem" });
    const VALID_TO = "2026-07-17T12:05:00.000Z";
    writeCustomLocalManifest(backup.paths, {
      authorityId: "mnde-public-test-local",
      activeKeys: [{
        key_id: "receipt-key-local", public_key: receiptPublicPem, public_key_fingerprint: publicKeyFingerprint(receiptPublicPem),
        valid_from: "2020-01-01T00:00:00.000Z", valid_to: VALID_TO
      }],
      rootPrivatePem, rootPublicPem
    });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"), receiptPrivatePem, { mode: 0o600 });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_public.pem"), receiptPublicPem, { mode: 0o644 });

    const receipt = buildPolicyReceipt(request(), policy, { now: VALID_TO });
    const result = await verifyPolicyReceipt(receipt, {});
    assert.equal(result.verified, true, result.reason);
  } finally {
    backup.restore();
  }
});

await test("exact validity-boundary behavior through the caller path: evaluated_at one millisecond AFTER valid_to fails closed", async () => {
  const backup = backupLocalAuthority();
  try {
    const root = generateKeyPairSync("ed25519");
    const rootPrivatePem = root.privateKey.export({ type: "pkcs8", format: "pem" });
    const rootPublicPem = root.publicKey.export({ type: "spki", format: "pem" });
    const receiptKey = generateKeyPairSync("ed25519");
    const receiptPrivatePem = receiptKey.privateKey.export({ type: "pkcs8", format: "pem" });
    const receiptPublicPem = receiptKey.publicKey.export({ type: "spki", format: "pem" });
    const VALID_TO = "2026-07-17T12:05:00.000Z";
    const AFTER = new Date(Date.parse(VALID_TO) + 1).toISOString();
    writeCustomLocalManifest(backup.paths, {
      authorityId: "mnde-public-test-local",
      activeKeys: [{
        key_id: "receipt-key-local", public_key: receiptPublicPem, public_key_fingerprint: publicKeyFingerprint(receiptPublicPem),
        valid_from: "2020-01-01T00:00:00.000Z", valid_to: VALID_TO
      }],
      rootPrivatePem, rootPublicPem
    });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"), receiptPrivatePem, { mode: 0o600 });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_public.pem"), receiptPublicPem, { mode: 0o644 });

    const receipt = buildPolicyReceipt(request(), policy, { now: AFTER });
    const result = await verifyPolicyReceipt(receipt, {});
    assert.equal(result.verified, false, "a decision one millisecond past the key window must not verify");
  } finally {
    backup.restore();
  }
});

await test("revocation behavior through the caller path: a receipt whose evaluated_at is at/after the key's revoked_at fails closed", async () => {
  const backup = backupLocalAuthority();
  try {
    const root = generateKeyPairSync("ed25519");
    const rootPrivatePem = root.privateKey.export({ type: "pkcs8", format: "pem" });
    const rootPublicPem = root.publicKey.export({ type: "spki", format: "pem" });
    const receiptKey = generateKeyPairSync("ed25519");
    const receiptPrivatePem = receiptKey.privateKey.export({ type: "pkcs8", format: "pem" });
    const receiptPublicPem = receiptKey.publicKey.export({ type: "spki", format: "pem" });
    const REVOKED_AT = "2026-07-17T12:00:00.000Z";
    writeCustomLocalManifest(backup.paths, {
      authorityId: "mnde-public-test-local",
      activeKeys: [{
        key_id: "receipt-key-local", public_key: receiptPublicPem, public_key_fingerprint: publicKeyFingerprint(receiptPublicPem),
        valid_from: "2020-01-01T00:00:00.000Z", valid_to: "2099-01-01T00:00:00.000Z", revoked_at: REVOKED_AT
      }],
      rootPrivatePem, rootPublicPem
    });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"), receiptPrivatePem, { mode: 0o600 });
    writeFileSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_public.pem"), receiptPublicPem, { mode: 0o644 });

    // Decided exactly at the revocation instant — inclusive, per f3b4b4a.
    const receiptAtRevocation = buildPolicyReceipt(request({ request_id: "req-revoked" }), policy, { now: REVOKED_AT });
    const resultAtRevocation = await verifyPolicyReceipt(receiptAtRevocation, {});
    assert.equal(resultAtRevocation.verified, false, "a decision at the exact revocation instant must not verify");

    // Decided one millisecond before — must still verify (archival, pre-revocation).
    const before = new Date(Date.parse(REVOKED_AT) - 1).toISOString();
    const receiptBeforeRevocation = buildPolicyReceipt(request({ request_id: "req-pre-revoked" }), policy, { now: before });
    const resultBeforeRevocation = await verifyPolicyReceipt(receiptBeforeRevocation, {});
    assert.equal(resultBeforeRevocation.verified, true, resultBeforeRevocation.reason);
  } finally {
    backup.restore();
  }
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL authority-key-validation-migration tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS authority-key-validation-migration tests (${results.length}/${results.length})`);
