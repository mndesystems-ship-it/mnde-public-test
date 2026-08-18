// Production preflight with passphrase-protected keys (CUSTODY-ENC-1).
//
//   npm run test:production-custody-passphrase
//
// assertTrustRoot() is the single deterministic gate the sidecar runs BEFORE the
// decision server accepts traffic. These tests prove it starts with encrypted
// receipt + ledger keys and correct passphrases, and refuses readiness (ok:false,
// stable reason code) on any missing / empty / wrong passphrase — so no decision
// or signing request can reach the server after a failed preflight. No failure
// surface may echo passphrase or PEM material.

import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSigningConfig } from "../src/authority-signing/index.mjs";
import { assertTrustRoot } from "../src/authority-signing/preflight.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  verifyAgainstBundle
} from "../src/custody/index.mjs";

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

const SECRET_MARKER = "CUSTODY_ENC_1_SECRET_DO_NOT_PRINT_7f29";
const RECEIPT_PASS = `receipt-${SECRET_MARKER}`;
const LEDGER_PASS = `ledger-${SECRET_MARKER}`;
const POLICY_PASS = `policy-${SECRET_MARKER}`;
const PEM_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const NOW = "2026-06-14T00:00:00.000Z";

function encryptPem(privatePem, passphrase) {
  return createPrivateKey(privatePem).export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase });
}

// Build a production authority bundle (receipt + ledger + policy) and lay the
// encrypted key files into a temp dir. Returns { dir, env, bundle }. The caller
// sets/omits the *_PASSPHRASE vars to shape each case.
async function setupProductionCustody({ includePolicy = false } = {}) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "prod-ledger-1", ...generateAuthorityKeyPair() };
  const policy = { keyId: "prod-policy-1", ...generateAuthorityKeyPair() };
  const window = { validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-prod",
    issuedAt: NOW,
    notAfter: "2027-06-14T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, ...window }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, ...window }],
    policyKeys: [{ keyId: policy.keyId, publicPem: policy.publicPem, ...window }],
    revocation: []
  });

  const dir = mkdtempSync(join(tmpdir(), "mnde-prod-enc-"));
  const bundlePath = join(dir, "authority.bundle.json");
  const receiptPath = join(dir, "receipt.key.pem");
  const ledgerPath = join(dir, "ledger.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(receiptPath, encryptPem(receipt.privatePem, RECEIPT_PASS), "utf8");
  writeFileSync(ledgerPath, encryptPem(ledger.privatePem, LEDGER_PASS), "utf8");

  const env = {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: receiptPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId,
    MNDE_LEDGER_SIGNING_KEY: ledgerPath,
    MNDE_LEDGER_KEY_ID: ledger.keyId
  };
  if (includePolicy) {
    const policyPath = join(dir, "policy.key.pem");
    writeFileSync(policyPath, encryptPem(policy.privatePem, POLICY_PASS), "utf8");
    env.MNDE_POLICY_SIGNING_KEY = policyPath;
    env.MNDE_POLICY_KEY_ID = policy.keyId;
  }
  return { dir, env, bundle };
}

function assertNoSecret(...surfaces) {
  const joined = surfaces.map((s) => (typeof s === "string" ? s : JSON.stringify(s))).join("\n");
  assert.ok(!joined.includes(SECRET_MARKER), "must not contain passphrase marker");
  assert.ok(!joined.includes(PEM_HEADER), "must not contain PEM header");
  assert.ok(!joined.includes("aes-256-cbc"), "must not contain cipher detail");
}

// Happy path: preflight passes; encrypted keys actually sign verifiably.
await test("production preflight PASSES with encrypted receipt + ledger keys and correct passphrases", async () => {
  const { dir, env, bundle } = await setupProductionCustody();
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  env.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS;
  try {
    const gate = await assertTrustRoot(env, { now: NOW });
    assert.equal(gate.ok, true, gate.detail);
    assert.equal(gate.profile, "production");

    // A receipt signed through the imported encrypted key verifies offline.
    const cfg = await loadSigningConfig(env);
    assert.equal(cfg.ok, true);
    const payload = canonicalizeJson({ decision: "ALLOW", prod: true });
    const sig = await cfg.provider.signReceipt(payload);
    assert.equal((await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, NOW, bundle)).ok, true);
    // Ledger self-test is part of assertTrustRoot; prove it directly too.
    const lsig = await cfg.provider.signLedger('{"x":1}');
    assert.equal((await verifyAgainstBundle('{"x":1}', lsig.value, "ledger", lsig.key_id, NOW, bundle)).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Each of these must PREVENT readiness (ok:false) with the correct reason code.
const failures = [
  { name: "missing receipt passphrase", mutate: (e) => { e.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS; }, code: "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED" },
  { name: "empty receipt passphrase", mutate: (e) => { e.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = ""; e.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS; }, code: "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED" },
  { name: "wrong receipt passphrase", mutate: (e) => { e.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = "nope"; e.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS; }, code: "ERR_CUSTODY_KEY_PASSPHRASE_INVALID" },
  { name: "missing ledger passphrase", mutate: (e) => { e.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS; }, code: "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED" },
  { name: "wrong ledger passphrase", mutate: (e) => { e.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS; e.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = "nope"; }, code: "ERR_CUSTODY_KEY_PASSPHRASE_INVALID" }
];

for (const f of failures) {
  await test(`production preflight REFUSES readiness: ${f.name} (${f.code})`, async () => {
    const { dir, env } = await setupProductionCustody();
    f.mutate(env);
    try {
      const gate = await assertTrustRoot(env, { now: NOW });
      assert.equal(gate.ok, false, "preflight must fail closed");
      assert.equal(gate.reason_code, f.code);
      assertNoSecret(gate.reason_code, gate.detail, gate);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// A configured (optional) encrypted policy key with a missing passphrase also
// prevents readiness.
await test("production preflight REFUSES readiness: configured encrypted policy key without passphrase", async () => {
  const { dir, env } = await setupProductionCustody({ includePolicy: true });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  env.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS;
  // MNDE_POLICY_SIGNING_KEY_PASSPHRASE deliberately unset.
  try {
    const gate = await assertTrustRoot(env, { now: NOW });
    assert.equal(gate.ok, false);
    assert.equal(gate.reason_code, "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED");
    assertNoSecret(gate.reason_code, gate.detail);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL production custody passphrase tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS production custody passphrase tests (${results.length}/${results.length})`);
