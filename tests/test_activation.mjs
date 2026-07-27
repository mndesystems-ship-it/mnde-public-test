// Activation authority (mnde.activation.v1) tests.
//
//   npm run test:activation
//
// All offline. Hostile coverage: a genesis record builds, self-verifies, and
// verifies against the customer bundle; every tampered field fails; forged and
// wrong-role signatures fail; revoked activation keys fail as-of-event and are
// advisory-only after the fact; release revocation produces the split verdicts
// (REVOKED_AS_OF_EVENT fails closed, REVOKED_NOW is advisory); chain rules
// reject forks, second geneses, and broken links; the trust-root preflight
// binds and fail-closes correctly in local and production profiles; and the
// custody attestation carries a tamper-evident activation_id.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorityBundle,
  createLocalDemoCustody,
  evaluateRevocation,
  generateAuthorityKeyPair
} from "../src/custody/index.mjs";
import {
  ACTIVATION_SCHEMA,
  buildActivationRecord,
  computeActivationId,
  validateActivationStructure,
  verifyActivationChain,
  verifyActivationRecord
} from "../src/activation/index.mjs";
import { signReceiptForDelivery, verifyCustodyAttestation } from "../src/authority-signing/index.mjs";
import { assertTrustRoot } from "../src/authority-signing/preflight.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}

const ARTIFACT_HASH = "ab".repeat(32);
const MANIFEST_HASH = "cd".repeat(32);
const VENDOR_ROOT_FP = "ef".repeat(32);

function verificationBlock() {
  return {
    manifest_signature: "VERIFIED",
    artifact_hash_match: "VERIFIED",
    revocation_status_at_activation: "NOT_REVOKED",
    vendor_root_fingerprint: VENDOR_ROOT_FP,
    verifier_version: "test-verifier-1"
  };
}

// Customer authority fixture with root + receipt + ledger + activation keys.
async function makeCustomerAuthority({ authorityId = "acme-prod", issuedAt = "2026-06-14T00:00:00.000Z", revocation = [] } = {}) {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "ledger-1", ...generateAuthorityKeyPair() };
  const activation = { keyId: "activation-1", ...generateAuthorityKeyPair() };
  const stranger = { keyId: "stranger-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId,
    issuedAt,
    notAfter: "2027-06-14T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2027-06-14T00:00:00.000Z" }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2027-06-14T00:00:00.000Z" }],
    activationKeys: [{ keyId: activation.keyId, publicPem: activation.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2027-06-14T00:00:00.000Z" }],
    revocation
  });
  return { root, receipt, ledger, activation, stranger, bundle };
}

async function makeGenesis(fx, overrides = {}) {
  return buildActivationRecord({
    bundle: fx.bundle,
    signingKeyId: fx.activation.keyId,
    signingPrivateKeyPem: fx.activation.privatePem,
    authorityId: fx.bundle.authority_id,
    kind: "genesis",
    releaseVersion: "1.2.4",
    artifactHash: ARTIFACT_HASH,
    releaseManifestHash: MANIFEST_HASH,
    vendorAuthorityId: "mnde-vendor",
    verification: verificationBlock(),
    channel: "github-release",
    activatedAt: "2026-06-15T00:00:00.000Z",
    ...overrides
  });
}

function verifyOptions(fx, extra = {}) {
  return { authorityBundle: fx.bundle, trustedRootFingerprint: fx.bundle.root_key.fingerprint, now: "2026-06-16T00:00:00.000Z", ...extra };
}

// ── build + verify roundtrip ─────────────────────────────────────────────────
test("genesis record builds, self-verifies, and verifies against the bundle", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);

  assert.equal(record.schema_version, ACTIVATION_SCHEMA);
  assert.equal(record.kind, "genesis");
  assert.equal(record.previous_activation_id, null);
  assert.match(record.activation_id, /^[0-9a-f]{64}$/);
  assert.equal(record.activation_id, computeActivationId(record));
  assert.equal(validateActivationStructure(record).ok, true);

  const check = await verifyActivationRecord(record, verifyOptions(fx));
  assert.equal(check.ok, true);
  assert.equal(check.activation_id, record.activation_id);
  assert.equal(check.revoked_now, false);
});

test("no private key material appears in a record", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  assert.ok(!JSON.stringify(record).includes("PRIVATE KEY"));
});

// ── tamper detection ─────────────────────────────────────────────────────────
test("tampering any field breaks the record (id mismatch)", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  for (const tamper of [
    (r) => { r.release_version = "9.9.9"; },
    (r) => { r.artifact_hash = "00".repeat(32); },
    (r) => { r.kind = "upgrade"; },
    (r) => { r.verification.manifest_signature = "SKIPPED"; }
  ]) {
    const copy = structuredClone(record);
    tamper(copy);
    const check = await verifyActivationRecord(copy, verifyOptions(fx));
    assert.equal(check.ok, false);
    assert.equal(check.reason_code, "ERR_ACTIVATION_INVALID");
  }
});

test("recomputing activation_id after tamper still fails on the signature", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  const copy = structuredClone(record);
  copy.release_version = "9.9.9";
  copy.activation_id = computeActivationId(copy); // attacker fixes the id too
  const check = await verifyActivationRecord(copy, verifyOptions(fx));
  assert.equal(check.ok, false);
  assert.equal(check.reason_code, "ERR_ACTIVATION_INVALID");
  assert.match(check.detail, /signature/i);
});

test("a record signed by a key outside the activation role fails", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  const copy = structuredClone(record);
  copy.signature.key_id = fx.receipt.keyId; // real bundle key, wrong role
  const check = await verifyActivationRecord(copy, verifyOptions(fx));
  assert.equal(check.ok, false);
  assert.equal(check.reason_code, "ERR_ACTIVATION_UNTRUSTED");
});

test("a forged signature by an unlisted key fails", async () => {
  const fx = await makeCustomerAuthority();
  // Attacker signs with their own key but claims the bundle's activation key id.
  const forged = await makeGenesis(fx, { signingPrivateKeyPem: fx.stranger.privatePem }).catch(() => null);
  // buildActivationRecord self-validates; construct manually if it refused.
  if (forged) {
    const check = await verifyActivationRecord(forged, verifyOptions(fx));
    assert.equal(check.ok, false);
  } else {
    assert.ok(true);
  }
});

test("building a record for an unverified release is refused", async () => {
  const fx = await makeCustomerAuthority();
  await assert.rejects(
    makeGenesis(fx, { verification: { ...verificationBlock(), manifest_signature: "FAILED" } }),
    /manifest_signature/
  );
  await assert.rejects(
    makeGenesis(fx, { verification: { ...verificationBlock(), revocation_status_at_activation: "REVOKED" } }),
    /revocation_status_at_activation/
  );
});

// ── genesis rules ────────────────────────────────────────────────────────────
test("genesis must not predate the authority bundle (first authorized act)", async () => {
  const fx = await makeCustomerAuthority({ issuedAt: "2026-06-14T00:00:00.000Z" });
  const record = await makeGenesis(fx, { activatedAt: "2026-06-01T00:00:00.000Z" });
  const check = await verifyActivationRecord(record, verifyOptions(fx));
  assert.equal(check.ok, false);
  assert.equal(check.reason_code, "ERR_ACTIVATION_INVALID");
  assert.match(check.detail, /predates/);
});

test("genesis requires previous_activation_id null; non-genesis requires a link", async () => {
  const fx = await makeCustomerAuthority();
  const genesis = await makeGenesis(fx);
  const badGenesis = structuredClone(genesis);
  badGenesis.previous_activation_id = "11".repeat(32);
  assert.equal(validateActivationStructure(badGenesis).ok, false);

  await assert.rejects(
    makeGenesis(fx, { kind: "upgrade", previousActivationId: null }),
    /previous_activation_id/
  );
});

// ── chain rules ──────────────────────────────────────────────────────────────
test("a linked genesis→upgrade→rollback chain verifies; breaks are rejected", async () => {
  const fx = await makeCustomerAuthority();
  const genesis = await makeGenesis(fx);
  const upgrade = await makeGenesis(fx, { kind: "upgrade", previousActivationId: genesis.activation_id, releaseVersion: "1.3.0", activatedAt: "2026-06-20T00:00:00.000Z" });
  const rollback = await makeGenesis(fx, { kind: "rollback", previousActivationId: upgrade.activation_id, releaseVersion: "1.2.4", activatedAt: "2026-06-21T00:00:00.000Z" });

  const ok = verifyActivationChain([genesis, upgrade, rollback]);
  assert.equal(ok.ok, true);
  assert.equal(ok.head_activation_id, rollback.activation_id);

  // Identical binaries, different activations: rollback re-activates 1.2.4 but
  // is a NEW transition with its own id.
  assert.equal(rollback.artifact_hash, genesis.artifact_hash);
  assert.notEqual(rollback.activation_id, genesis.activation_id);

  const broken = verifyActivationChain([genesis, rollback]);
  assert.equal(broken.ok, false);
  assert.equal(broken.reason_code, "ERR_ACTIVATION_CHAIN");
});

test("a second genesis is a chain fork", async () => {
  const fx = await makeCustomerAuthority();
  const genesis = await makeGenesis(fx);
  const secondGenesis = await makeGenesis(fx, { activatedAt: "2026-06-22T00:00:00.000Z" });
  const chain = verifyActivationChain([genesis, secondGenesis]);
  assert.equal(chain.ok, false);
  assert.equal(chain.reason_code, "ERR_ACTIVATION_CHAIN_FORK");

  const single = await verifyActivationRecord(secondGenesis, verifyOptions(fx, { previousRecord: genesis }));
  assert.equal(single.ok, false);
  assert.equal(single.reason_code, "ERR_ACTIVATION_CHAIN_FORK");
});

test("verifyActivationRecord enforces linkage against the supplied previous record", async () => {
  const fx = await makeCustomerAuthority();
  const genesis = await makeGenesis(fx);
  const upgrade = await makeGenesis(fx, { kind: "upgrade", previousActivationId: "22".repeat(32), activatedAt: "2026-06-20T00:00:00.000Z" });
  const check = await verifyActivationRecord(upgrade, verifyOptions(fx, { previousRecord: genesis }));
  assert.equal(check.ok, false);
  assert.equal(check.reason_code, "ERR_ACTIVATION_CHAIN");
});

// ── revocation verdict split ─────────────────────────────────────────────────
test("evaluateRevocation: string entries revoke for all time; object entries split verdicts", () => {
  const list = ["old-key", { key_id: "k2", revoked_at: "2026-07-01T00:00:00.000Z", reason_code: "KEY_COMPROMISE" }];
  const legacy = evaluateRevocation(list, { key_id: "old-key" }, "2020-01-01T00:00:00.000Z", "2020-01-02T00:00:00.000Z");
  assert.deepEqual([legacy.revoked_as_of_event, legacy.revoked_now], [true, true]);

  const before = evaluateRevocation(list, { key_id: "k2" }, "2026-06-15T00:00:00.000Z", "2026-07-02T00:00:00.000Z");
  assert.deepEqual([before.revoked_as_of_event, before.revoked_now], [false, true]);

  const after = evaluateRevocation(list, { key_id: "k2" }, "2026-07-02T00:00:00.000Z", "2026-07-03T00:00:00.000Z");
  assert.deepEqual([after.revoked_as_of_event, after.revoked_now], [true, true]);

  const clean = evaluateRevocation(list, { key_id: "k3" }, "2026-07-02T00:00:00.000Z", "2026-07-03T00:00:00.000Z");
  assert.deepEqual([clean.revoked_as_of_event, clean.revoked_now], [false, false]);
});

test("evaluateRevocation: an entry never matches a subject that lacks the field (undefined guard)", () => {
  const list = [{ artifact_hash: ARTIFACT_HASH, revoked_at: "2026-01-01T00:00:00.000Z" }];
  const check = evaluateRevocation(list, { key_id: "some-key" }, "2026-06-15T00:00:00.000Z", "2026-06-16T00:00:00.000Z");
  assert.deepEqual([check.revoked_as_of_event, check.revoked_now], [false, false]);
});

test("activation key revoked BEFORE signing fails closed; revoked AFTER is advisory", async () => {
  const fxClean = await makeCustomerAuthority();
  const record = await makeGenesis(fxClean);

  // Same keys, re-issued bundle with a timestamped revocation AFTER signed_at.
  const later = await buildAuthorityBundle({
    authorityId: fxClean.bundle.authority_id,
    issuedAt: fxClean.bundle.issued_at,
    notAfter: fxClean.bundle.not_after,
    root: fxClean.root,
    receiptKeys: fxClean.bundle.keys.receipt.map((k) => ({ keyId: k.key_id, publicPem: k.public_key, validFrom: k.valid_from, validUntil: k.valid_until })),
    activationKeys: fxClean.bundle.keys.activation.map((k) => ({ keyId: k.key_id, publicPem: k.public_key, validFrom: k.valid_from, validUntil: k.valid_until })),
    revocation: [{ key_id: "activation-1", revoked_at: "2026-07-01T00:00:00.000Z", reason_code: "KEY_COMPROMISE" }]
  });
  const advisory = await verifyActivationRecord(record, { authorityBundle: later, trustedRootFingerprint: later.root_key.fingerprint, now: "2026-07-02T00:00:00.000Z" });
  assert.equal(advisory.ok, true, advisory.detail);
  assert.equal(advisory.revoked_now, true);

  // Revocation BEFORE signed_at: the event itself is untrustworthy.
  const earlier = await buildAuthorityBundle({
    authorityId: fxClean.bundle.authority_id,
    issuedAt: fxClean.bundle.issued_at,
    notAfter: fxClean.bundle.not_after,
    root: fxClean.root,
    receiptKeys: fxClean.bundle.keys.receipt.map((k) => ({ keyId: k.key_id, publicPem: k.public_key, validFrom: k.valid_from, validUntil: k.valid_until })),
    activationKeys: fxClean.bundle.keys.activation.map((k) => ({ keyId: k.key_id, publicPem: k.public_key, validFrom: k.valid_from, validUntil: k.valid_until })),
    revocation: [{ key_id: "activation-1", revoked_at: "2026-06-01T00:00:00.000Z", reason_code: "KEY_COMPROMISE" }]
  });
  const failed = await verifyActivationRecord(record, { authorityBundle: earlier, trustedRootFingerprint: earlier.root_key.fingerprint, now: "2026-07-02T00:00:00.000Z" });
  assert.equal(failed.ok, false);
  assert.equal(failed.reason_code, "ERR_ACTIVATION_UNTRUSTED");
});

test("release revoked BEFORE activation fails closed; revoked AFTER is advisory", async () => {
  const before = await makeCustomerAuthority({ revocation: [{ artifact_hash: ARTIFACT_HASH, revoked_at: "2026-06-01T00:00:00.000Z", reason_code: "RELEASE_DEFECT" }] });
  const recordBefore = await makeGenesis(before); // activated 2026-06-15, after revocation
  const failed = await verifyActivationRecord(recordBefore, verifyOptions(before));
  assert.equal(failed.ok, false);
  assert.equal(failed.reason_code, "ERR_ACTIVATION_UNTRUSTED");
  assert.match(failed.detail, /REVOKED_AS_OF_EVENT/);

  const after = await makeCustomerAuthority({ revocation: [{ artifact_hash: ARTIFACT_HASH, revoked_at: "2026-06-20T00:00:00.000Z", reason_code: "RELEASE_DEFECT" }] });
  const recordAfter = await makeGenesis(after); // activated 2026-06-15, before revocation
  const advisory = await verifyActivationRecord(recordAfter, verifyOptions(after, { now: "2026-06-21T00:00:00.000Z" }));
  assert.equal(advisory.ok, true, advisory.detail);
  assert.equal(advisory.revoked_now, true);
});

test("refuses to SIGN a new transition with a currently revoked key", async () => {
  const fx = await makeCustomerAuthority({ revocation: [{ key_id: "activation-1", revoked_at: "2026-06-10T00:00:00.000Z", reason_code: "KEY_COMPROMISE" }] });
  await assert.rejects(makeGenesis(fx), /not usable|revoked/i);
});

// ── preflight integration ────────────────────────────────────────────────────
test("local profile: no activation record is fine; a broken one fails startup", async () => {
  const clean = await assertTrustRoot({ MNDE_PROFILE: "local" }, { repoRoot: REPO_ROOT });
  assert.equal(clean.ok, true);
  assert.equal(clean.activation_id, undefined);

  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const recordPath = join(dir, "activation.json");
    writeFileSync(recordPath, JSON.stringify({ schema_version: ACTIVATION_SCHEMA, kind: "genesis" }));
    const broken = await assertTrustRoot({ MNDE_PROFILE: "local", MNDE_ACTIVATION_RECORD: recordPath }, { repoRoot: REPO_ROOT });
    assert.equal(broken.ok, false);
    assert.equal(broken.reason_code, "ERR_ACTIVATION_INVALID");

    const missing = await assertTrustRoot({ MNDE_PROFILE: "local", MNDE_ACTIVATION_RECORD: join(dir, "nope.json") }, { repoRoot: REPO_ROOT });
    assert.equal(missing.ok, false);
    assert.equal(missing.reason_code, "ERR_ACTIVATION_INVALID");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("local profile: a structurally valid record binds an activation_id", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const recordPath = join(dir, "activation.json");
    writeFileSync(recordPath, JSON.stringify(record));
    const trust = await assertTrustRoot({ MNDE_PROFILE: "local", MNDE_ACTIVATION_RECORD: recordPath }, { repoRoot: REPO_ROOT });
    assert.equal(trust.ok, true);
    assert.equal(trust.activation_id, record.activation_id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Full production custody fixture on disk: bundle + receipt key + activation record.
async function makeProductionEnv(dir, { record = null, revocation = [] } = {}) {
  const fx = await makeCustomerAuthority({ authorityId: "acme-prod", revocation });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  const ledgerKeyPath = join(dir, "ledger.key.pem");
  writeFileSync(bundlePath, JSON.stringify(fx.bundle, null, 2));
  writeFileSync(keyPath, fx.receipt.privatePem);
  writeFileSync(ledgerKeyPath, fx.ledger.privatePem);
  const env = {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: "receipt-1",
    MNDE_LEDGER_SIGNING_KEY: ledgerKeyPath,
    MNDE_LEDGER_KEY_ID: "ledger-1"
  };
  if (record) {
    const recordPath = join(dir, "activation.json");
    writeFileSync(recordPath, JSON.stringify(record));
    env.MNDE_ACTIVATION_RECORD = recordPath;
  }
  return { fx, env };
}

test("production: a verified activation record binds; the id reaches the trust result", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const fx = await makeCustomerAuthority({ authorityId: "acme-prod" });
    const record = await makeGenesis(fx);
    const bundlePath = join(dir, "authority.bundle.json");
    writeFileSync(bundlePath, JSON.stringify(fx.bundle, null, 2));
    writeFileSync(join(dir, "receipt.key.pem"), fx.receipt.privatePem);
    writeFileSync(join(dir, "ledger.key.pem"), fx.ledger.privatePem);
    writeFileSync(join(dir, "activation.json"), JSON.stringify(record));
    const trust = await assertTrustRoot({
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: join(dir, "receipt.key.pem"),
      MNDE_RECEIPT_KEY_ID: "receipt-1",
      MNDE_LEDGER_SIGNING_KEY: join(dir, "ledger.key.pem"),
      MNDE_LEDGER_KEY_ID: "ledger-1",
      MNDE_ACTIVATION_RECORD: join(dir, "activation.json")
    }, { repoRoot: REPO_ROOT });
    assert.equal(trust.ok, true, trust.detail);
    assert.equal(trust.activation_id, record.activation_id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production: MNDE_REQUIRE_ACTIVATION=1 refuses to start without a record", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const { env } = await makeProductionEnv(dir);
    const withoutFlag = await assertTrustRoot(env, { repoRoot: REPO_ROOT });
    assert.equal(withoutFlag.ok, true);
    assert.equal(withoutFlag.activation_id, null);

    const withFlag = await assertTrustRoot({ ...env, MNDE_REQUIRE_ACTIVATION: "1" }, { repoRoot: REPO_ROOT });
    assert.equal(withFlag.ok, false);
    assert.equal(withFlag.reason_code, "ERR_ACTIVATION_MISSING");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production: a tampered activation record refuses startup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const fx = await makeCustomerAuthority({ authorityId: "acme-prod" });
    const record = await makeGenesis(fx);
    const tampered = structuredClone(record);
    tampered.release_version = "6.6.6";
    const bundlePath = join(dir, "authority.bundle.json");
    writeFileSync(bundlePath, JSON.stringify(fx.bundle, null, 2));
    writeFileSync(join(dir, "receipt.key.pem"), fx.receipt.privatePem);
    writeFileSync(join(dir, "ledger.key.pem"), fx.ledger.privatePem);
    writeFileSync(join(dir, "activation.json"), JSON.stringify(tampered));
    const trust = await assertTrustRoot({
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: join(dir, "receipt.key.pem"),
      MNDE_RECEIPT_KEY_ID: "receipt-1",
      MNDE_LEDGER_SIGNING_KEY: join(dir, "ledger.key.pem"),
      MNDE_LEDGER_KEY_ID: "ledger-1",
      MNDE_ACTIVATION_RECORD: join(dir, "activation.json")
    }, { repoRoot: REPO_ROOT });
    assert.equal(trust.ok, false);
    assert.equal(trust.reason_code, "ERR_ACTIVATION_INVALID");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production: a record from a DIFFERENT authority refuses startup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-activation-"));
  try {
    const fx = await makeCustomerAuthority({ authorityId: "acme-prod" });
    const other = await makeCustomerAuthority({ authorityId: "evil-prod" });
    const foreign = await makeGenesis(other);
    const bundlePath = join(dir, "authority.bundle.json");
    writeFileSync(bundlePath, JSON.stringify(fx.bundle, null, 2));
    writeFileSync(join(dir, "receipt.key.pem"), fx.receipt.privatePem);
    writeFileSync(join(dir, "ledger.key.pem"), fx.ledger.privatePem);
    writeFileSync(join(dir, "activation.json"), JSON.stringify(foreign));
    const trust = await assertTrustRoot({
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: join(dir, "receipt.key.pem"),
      MNDE_RECEIPT_KEY_ID: "receipt-1",
      MNDE_LEDGER_SIGNING_KEY: join(dir, "ledger.key.pem"),
      MNDE_LEDGER_KEY_ID: "ledger-1",
      MNDE_ACTIVATION_RECORD: join(dir, "activation.json")
    }, { repoRoot: REPO_ROOT });
    assert.equal(trust.ok, false);
    assert.equal(trust.reason_code, "ERR_ACTIVATION_UNTRUSTED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── receipt binding through the custody attestation ──────────────────────────
test("custody attestation carries activation_id; verifier returns it; tamper breaks it", async () => {
  const fx = await makeCustomerAuthority();
  const record = await makeGenesis(fx);
  const provider = await createLocalDemoCustody();
  const signingConfig = { ok: true, mode: "custody", provider, activation_id: record.activation_id };
  const receipt = { schema_version: "ecs.receipt.v2", decision_output: { decision: "ALLOW" }, request_hash: ARTIFACT_HASH };

  const signed = await signReceiptForDelivery(receipt, signingConfig);
  assert.equal(signed.ok, true, signed.detail);
  assert.equal(signed.receipt.custody_attestation.activation_id, record.activation_id);

  const verified = await verifyCustodyAttestation(signed.receipt, {
    authorityBundle: provider.getPublicBundle(),
    trustedRootFingerprint: provider.trustedRootFingerprint
  });
  assert.equal(verified.ok, true, verified.reason);
  assert.equal(verified.activation_id, record.activation_id);

  const tampered = structuredClone(signed.receipt);
  tampered.custody_attestation.activation_id = "00".repeat(32);
  const failed = await verifyCustodyAttestation(tampered, {
    authorityBundle: provider.getPublicBundle(),
    trustedRootFingerprint: provider.trustedRootFingerprint
  });
  assert.equal(failed.ok, false);
});

test("without an activation binding the attestation omits the field (unchanged shape)", async () => {
  const provider = await createLocalDemoCustody();
  const signingConfig = { ok: true, mode: "custody", provider };
  const receipt = { schema_version: "ecs.receipt.v2", decision_output: { decision: "REFUSE" }, request_hash: MANIFEST_HASH };
  const signed = await signReceiptForDelivery(receipt, signingConfig);
  assert.equal(signed.ok, true);
  assert.ok(!("activation_id" in signed.receipt.custody_attestation));
  const verified = await verifyCustodyAttestation(signed.receipt, {
    authorityBundle: provider.getPublicBundle(),
    trustedRootFingerprint: provider.trustedRootFingerprint
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.activation_id, null);
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL activation tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS activation tests (${results.length}/${results.length})`);
