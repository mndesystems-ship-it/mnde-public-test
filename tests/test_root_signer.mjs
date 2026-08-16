// RootSigner capability and hostile-boundary tests.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  verifyAuthorityBundle,
  verifyCanonical
} from "../src/custody/bundle.mjs";
import { issueExecutorCredential, verifyExecutorCredential } from "../src/custody/executor-credential.mjs";
import { revokeKey, rotateSigningKey } from "../src/custody/lifecycle.mjs";
import { signVerifierPolicy, verifyPolicySignature } from "../src/identity/verifier-policy.mjs";
import {
  ROOT_SIGNER_ERRORS,
  assertRootSignerIdentity,
  createExternalRootSigner,
  createFileRootSigner,
  resolveRootSigner,
  signWithRootSigner
} from "../src/custody/root-signer.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MOCK_SIGNER = join(repoRoot, "tests", "fixtures", "mock-ed25519-signer.mjs");
const NOW = "2026-06-14T00:00:00.000Z";
const LATER = "2026-07-01T00:00:00.000Z";
const FAR = "2099-01-01T00:00:00.000Z";

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

async function rejectsCode(fn, code) {
  await assert.rejects(fn, (error) => error?.code === code, `expected ${code}`);
}

function rootIdentity(root) {
  return { keyId: root.keyId, publicPem: root.publicPem };
}

function bundleInput(root, receipt, signer) {
  return {
    authorityId: "acme-prod",
    issuedAt: NOW,
    notAfter: FAR,
    root: signer ? { ...rootIdentity(root), signer } : root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: NOW, validUntil: FAR }],
    revocation: []
  };
}

function externalEnv(root, publicPath, privatePath, overrides = {}) {
  return {
    MNDE_EXTERNAL_ROOT_SIGNER_CMD: JSON.stringify(["node", MOCK_SIGNER, privatePath]),
    MNDE_EXTERNAL_ROOT_SIGNER_KEY_ID: root.keyId,
    MNDE_EXTERNAL_ROOT_SIGNER_PUBLIC_KEY: publicPath,
    ...overrides
  };
}

function processEnvWithExternalRoot(root, publicPath, privatePath, overrides = {}) {
  return { ...process.env, ...externalEnv(root, publicPath, privatePath), MOCK_SIGNER_MODE: "ok", ...overrides };
}

function processEnvWithoutExternalRoot() {
  const env = { ...process.env };
  delete env.MNDE_EXTERNAL_ROOT_SIGNER_CMD;
  delete env.MNDE_EXTERNAL_ROOT_SIGNER_KEY_ID;
  delete env.MNDE_EXTERNAL_ROOT_SIGNER_PUBLIC_KEY;
  delete env.MNDE_EXTERNAL_ROOT_SIGNER_TIMEOUT_MS;
  return env;
}

async function main() {
  console.log("MNDe RootSigner capability\n");
  const dir = mkdtempSync(join(tmpdir(), "mnde-root-signer-"));
  const priorMode = process.env.MOCK_SIGNER_MODE;
  try {
    const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
    const receipt = { keyId: "receipt-1", ...generateAuthorityKeyPair() };
    const nextReceipt = { keyId: "receipt-2", ...generateAuthorityKeyPair() };
    const stranger = { keyId: "stranger", ...generateAuthorityKeyPair() };
    const rootPublicPath = join(dir, "root.pub.pem");
    const rootPrivatePath = join(dir, "root.key.pem");
    const strangerPrivatePath = join(dir, "stranger.key.pem");
    writeFileSync(rootPublicPath, root.publicPem);
    writeFileSync(rootPrivatePath, root.privatePem);
    writeFileSync(strangerPrivatePath, stranger.privatePem);

    const fileSigner = createFileRootSigner({
      keyId: root.keyId,
      publicKeyPem: root.publicPem,
      privateKeyPem: root.privatePem
    });

    await test("file adapter exposes the expected root identity", () => {
      assert.equal(fileSigner.mode, "file-root-signer");
      assert.equal(fileSigner.keyId, root.keyId);
      assertRootSignerIdentity(fileSigner, rootIdentity(root));
    });

    await test("file adapter emits a verifiable Ed25519 signature", async () => {
      const payload = canonicalizeJson({ root_signer: "file" });
      const signature = await fileSigner.sign(payload);
      assert.equal(await verifyCanonical(payload, signature.value, root.publicPem), true);
    });

    await test("file adapter rejects a mismatched private key after signing", async () => {
      const signer = createFileRootSigner({ keyId: root.keyId, publicKeyPem: root.publicPem, privateKeyPem: stranger.privatePem });
      await rejectsCode(() => signer.sign("mismatch"), ROOT_SIGNER_ERRORS.SIGNATURE_INVALID);
    });

    await test("file adapter rejects a missing private key", () => {
      assert.throws(
        () => createFileRootSigner({ keyId: root.keyId, publicKeyPem: root.publicPem }),
        (error) => error?.code === ROOT_SIGNER_ERRORS.INVALID
      );
    });

    process.env.MOCK_SIGNER_MODE = "ok";
    const external = createExternalRootSigner(externalEnv(root, rootPublicPath, rootPrivatePath));
    await test("external adapter invokes the signer without holding its PEM", async () => {
      const payload = canonicalizeJson({ root_signer: "external" });
      const signature = await external.sign(payload);
      assert.equal(await verifyCanonical(payload, signature.value, root.publicPem), true);
    });

    await test("external adapter fails closed on nonzero exit", async () => {
      process.env.MOCK_SIGNER_MODE = "exit1";
      await rejectsCode(() => external.sign("exit"), ROOT_SIGNER_ERRORS.SIGNING_FAILED);
      process.env.MOCK_SIGNER_MODE = "ok";
    });

    await test("external adapter fails closed on non-hex output", async () => {
      process.env.MOCK_SIGNER_MODE = "badhex";
      await rejectsCode(() => external.sign("badhex"), ROOT_SIGNER_ERRORS.SIGNATURE_INVALID);
      process.env.MOCK_SIGNER_MODE = "ok";
    });

    await test("external adapter fails closed on a short signature", async () => {
      process.env.MOCK_SIGNER_MODE = "short";
      await rejectsCode(() => external.sign("short"), ROOT_SIGNER_ERRORS.SIGNATURE_INVALID);
      process.env.MOCK_SIGNER_MODE = "ok";
    });

    await test("external adapter rejects a valid signature from the wrong key", async () => {
      const wrong = createExternalRootSigner(externalEnv(root, rootPublicPath, strangerPrivatePath));
      await rejectsCode(() => wrong.sign("wrong-key"), ROOT_SIGNER_ERRORS.SIGNATURE_INVALID);
    });

    await test("external adapter fails closed on timeout", async () => {
      process.env.MOCK_SIGNER_MODE = "timeout";
      const timed = createExternalRootSigner(externalEnv(root, rootPublicPath, rootPrivatePath, {
        MNDE_EXTERNAL_ROOT_SIGNER_TIMEOUT_MS: "100"
      }));
      await rejectsCode(() => timed.sign("timeout"), ROOT_SIGNER_ERRORS.SIGNING_FAILED);
      process.env.MOCK_SIGNER_MODE = "ok";
    });

    await test("external adapter rejects malformed argv configuration", () => {
      assert.throws(
        () => createExternalRootSigner(externalEnv(root, rootPublicPath, rootPrivatePath, { MNDE_EXTERNAL_ROOT_SIGNER_CMD: "[not-json" })),
        (error) => error?.code === ROOT_SIGNER_ERRORS.INVALID
      );
    });

    await test("external adapter rejects a public key that is not parseable", () => {
      assert.throws(
        () => createExternalRootSigner(externalEnv(root, "not-a-key", rootPrivatePath)),
        (error) => error?.code === ROOT_SIGNER_ERRORS.INVALID
      );
    });

    await test("identity check rejects the wrong root key id", () => {
      assert.throws(
        () => assertRootSignerIdentity(fileSigner, { keyId: "other-root", publicPem: root.publicPem }),
        (error) => error?.code === ROOT_SIGNER_ERRORS.KEY_MISMATCH
      );
    });

    await test("identity check rejects the wrong root public key", () => {
      assert.throws(
        () => assertRootSignerIdentity(fileSigner, { keyId: root.keyId, publicPem: stranger.publicPem }),
        (error) => error?.code === ROOT_SIGNER_ERRORS.KEY_MISMATCH
      );
    });

    await test("capability boundary rejects malformed signature metadata", async () => {
      const malformed = { ...fileSigner, sign: async () => ({ key_id: "other", value: "00".repeat(64), fingerprint: fileSigner.fingerprint }) };
      await rejectsCode(() => signWithRootSigner(malformed, "payload", rootIdentity(root)), ROOT_SIGNER_ERRORS.SIGNATURE_INVALID);
    });

    await test("resolver selects the file adapter when external mode is absent", () => {
      const resolved = resolveRootSigner({ env: {}, root: rootIdentity(root), rootPrivateKeyPem: root.privatePem });
      assert.equal(resolved.mode, "file-root-signer");
    });

    await test("resolver accepts an explicitly supplied matching capability", () => {
      assert.equal(resolveRootSigner({ env: {}, root: rootIdentity(root), rootSigner: fileSigner }), fileSigner);
    });

    await test("external-root mode forbids raw PEM fallback", () => {
      assert.throws(
        () => resolveRootSigner({ env: externalEnv(root, rootPublicPath, rootPrivatePath), root: rootIdentity(root), rootPrivateKeyPem: root.privatePem }),
        (error) => error?.code === ROOT_SIGNER_ERRORS.PEM_FALLBACK_FORBIDDEN
      );
    });

    await test("external-root mode forbids a file-backed capability", () => {
      assert.throws(
        () => resolveRootSigner({ env: externalEnv(root, rootPublicPath, rootPrivatePath), root: rootIdentity(root), rootSigner: fileSigner }),
        (error) => error?.code === ROOT_SIGNER_ERRORS.PEM_FALLBACK_FORBIDDEN
      );
    });

    const legacyBundle = await buildAuthorityBundle(bundleInput(root, receipt));
    await test("bundle format and signature are byte-identical through the file capability", async () => {
      const capabilityBundle = await buildAuthorityBundle(bundleInput(root, receipt, fileSigner));
      assert.deepEqual(capabilityBundle, legacyBundle);
    });

    await test("external capability builds the same offline-verifiable bundle", async () => {
      const externalBundle = await buildAuthorityBundle(bundleInput(root, receipt, external));
      assert.deepEqual(externalBundle, legacyBundle);
      assert.equal((await verifyAuthorityBundle(externalBundle, { trustedRootFingerprint: externalBundle.root_key.fingerprint, now: NOW })).ok, true);
    });

    await test("rotation accepts a RootSigner capability", async () => {
      const rotated = await rotateSigningKey(legacyBundle, {
        rootSigner: external,
        newKey: { keyId: nextReceipt.keyId, publicPem: nextReceipt.publicPem },
        now: LATER
      });
      assert.equal(rotated.ok, true, rotated.reason);
      assert.equal((await verifyAuthorityBundle(rotated.bundle, { trustedRootFingerprint: legacyBundle.root_key.fingerprint, now: LATER })).ok, true);
    });

    await test("revocation accepts a RootSigner capability", async () => {
      const revoked = await revokeKey(legacyBundle, { rootSigner: external, keyId: receipt.keyId, now: LATER });
      assert.equal(revoked.ok, true, revoked.reason);
      assert.equal((await verifyAuthorityBundle(revoked.bundle, { trustedRootFingerprint: legacyBundle.root_key.fingerprint, now: LATER })).ok, true);
    });

    const bundlePath = join(dir, "authority.bundle.json");
    const nextReceiptPublicPath = join(dir, "receipt-2.pub.pem");
    writeFileSync(bundlePath, JSON.stringify(legacyBundle));
    writeFileSync(nextReceiptPublicPath, nextReceipt.publicPem);

    await test("authority CLI rotates and revokes through external-root mode without --root-key", async () => {
      const rotateOut = join(dir, "rotated.bundle.json");
      const rotate = spawnSync(process.execPath, [
        join(repoRoot, "bin", "mnde-authority.mjs"), "rotate",
        "--bundle", bundlePath,
        "--key-id", nextReceipt.keyId,
        "--new-public", nextReceiptPublicPath,
        "--now", LATER,
        "--out", rotateOut
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.equal(rotate.status, 0, rotate.stderr);
      const rotated = JSON.parse(readFileSync(rotateOut, "utf8"));
      assert.equal((await verifyAuthorityBundle(rotated, { trustedRootFingerprint: legacyBundle.root_key.fingerprint, now: LATER })).ok, true);

      const revokeOut = join(dir, "revoked.bundle.json");
      const revoke = spawnSync(process.execPath, [
        join(repoRoot, "bin", "mnde-authority.mjs"), "revoke",
        "--bundle", bundlePath,
        "--key-id", receipt.keyId,
        "--now", LATER,
        "--out", revokeOut
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.equal(revoke.status, 0, revoke.stderr);
      const revoked = JSON.parse(readFileSync(revokeOut, "utf8"));
      assert.ok(revoked.revocation.includes(receipt.keyId));
    });

    await test("authority CLI rejects --root-key before reading it in external mode", () => {
      const run = spawnSync(process.execPath, [
        join(repoRoot, "bin", "mnde-authority.mjs"), "revoke",
        "--bundle", bundlePath,
        "--root-key", join(dir, "must-not-be-read.pem"),
        "--key-id", receipt.keyId,
        "--out", join(dir, "forbidden.bundle.json")
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, /ERR_ROOT_PEM_FALLBACK_FORBIDDEN/u);
      assert.doesNotMatch(run.stderr, /cannot read root key/u);
    });

    await test("authority CLI preserves legacy --root-key operation", async () => {
      const out = join(dir, "legacy-rotated.bundle.json");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "bin", "mnde-authority.mjs"), "rotate",
        "--bundle", bundlePath,
        "--root-key", rootPrivatePath,
        "--key-id", nextReceipt.keyId,
        "--new-public", nextReceiptPublicPath,
        "--now", LATER,
        "--out", out
      ], { encoding: "utf8", env: processEnvWithoutExternalRoot() });
      assert.equal(run.status, 0, run.stderr);
      const rotated = JSON.parse(readFileSync(out, "utf8"));
      assert.equal((await verifyAuthorityBundle(rotated, { trustedRootFingerprint: legacyBundle.root_key.fingerprint, now: LATER })).ok, true);
    });

    await test("authority CLI fails closed without external mode or --root-key", () => {
      const out = join(dir, "missing-root.bundle.json");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "bin", "mnde-authority.mjs"), "revoke",
        "--bundle", bundlePath,
        "--key-id", receipt.keyId,
        "--out", out
      ], { encoding: "utf8", env: processEnvWithoutExternalRoot() });
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, /ERR_ROOT_SIGNER_INVALID/u);
      assert.equal(existsSync(out), false);
    });

    const executor = generateAuthorityKeyPair();
    const credentialOptions = {
      authorityBundle: legacyBundle,
      executorId: "mnde:local:prod:executor:codex:01",
      publicPem: executor.publicPem,
      environmentId: "prod",
      capabilities: ["sign_execution_receipt"],
      issuedAt: NOW,
      notBefore: NOW,
      expiresAt: LATER
    };
    const legacyCredential = await issueExecutorCredential({ ...credentialOptions, rootPrivatePem: root.privatePem });
    await test("executor credential format is byte-identical through the capability", async () => {
      const capabilityCredential = await issueExecutorCredential({ ...credentialOptions, rootSigner: external });
      assert.deepEqual(capabilityCredential, legacyCredential);
    });

    await test("externally root-signed executor credential verifies offline", async () => {
      const credential = await issueExecutorCredential({ ...credentialOptions, rootSigner: external });
      const verified = await verifyExecutorCredential(credential, {
        authorityBundle: legacyBundle,
        trustedRootFingerprint: legacyBundle.root_key.fingerprint,
        environmentId: "prod",
        expectedExecutorId: credentialOptions.executorId,
        requiredCapability: "sign_execution_receipt",
        now: NOW
      });
      assert.equal(verified.ok, true, verified.detail);
    });

    await test("executor enrollment CLI uses external-root mode without --root-key", async () => {
      const outDir = join(dir, "external-executor");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "scripts", "trust-enroll-executor.mjs"),
        "--executor-id", credentialOptions.executorId,
        "--environment", "prod",
        "--bundle", bundlePath,
        "--out-dir", outDir,
        "--issued-at", NOW,
        "--ttl-hours", "24"
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.equal(run.status, 0, run.stderr);
      const summary = JSON.parse(run.stdout);
      const credential = JSON.parse(readFileSync(summary.credential_path, "utf8"));
      const verified = await verifyExecutorCredential(credential, {
        authorityBundle: legacyBundle,
        trustedRootFingerprint: legacyBundle.root_key.fingerprint,
        environmentId: "prod",
        expectedExecutorId: credentialOptions.executorId,
        requiredCapability: "sign_execution_receipt",
        now: NOW
      });
      assert.equal(verified.ok, true, verified.detail);
    });

    await test("executor enrollment rejects mixed external-root and --root-key before output", () => {
      const outDir = join(dir, "forbidden-executor");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "scripts", "trust-enroll-executor.mjs"),
        "--executor-id", credentialOptions.executorId,
        "--environment", "prod",
        "--bundle", bundlePath,
        "--root-key", join(dir, "must-not-be-read.pem"),
        "--out-dir", outDir
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, /ERR_ROOT_PEM_FALLBACK_FORBIDDEN/u);
      assert.equal(existsSync(outDir), false);
    });

    await test("production bootstrap external-root mode never creates root.key.pem", async () => {
      const outDir = join(dir, "external-authority");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "scripts", "init-production-authority.mjs"),
        "--out", outDir,
        "--authority-id", "external-acme-prod",
        "--root-key-id", root.keyId,
        "--valid-days", "365",
        "--bundle-days", "90"
      ], { encoding: "utf8", env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath) });
      assert.equal(run.status, 0, run.stderr);
      assert.equal(existsSync(join(outDir, "root.key.pem")), false);
      assert.equal(readFileSync(join(outDir, "root.pub.pem"), "utf8"), root.publicPem);
      const bundle = JSON.parse(readFileSync(join(outDir, "authority.bundle.json"), "utf8"));
      assert.equal((await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: new Date().toISOString() })).ok, true);
    });

    await test("production bootstrap writes nothing when the external root signer fails", () => {
      const outDir = join(dir, "failed-external-authority");
      const run = spawnSync(process.execPath, [
        join(repoRoot, "scripts", "init-production-authority.mjs"),
        "--out", outDir,
        "--authority-id", "external-failure-prod",
        "--root-key-id", root.keyId
      ], {
        encoding: "utf8",
        env: processEnvWithExternalRoot(root, rootPublicPath, rootPrivatePath, { MOCK_SIGNER_MODE: "exit1" })
      });
      assert.notEqual(run.status, 0);
      assert.equal(existsSync(outDir), false);
    });

    const verifierPolicyOptions = {
      authorityId: legacyBundle.authority_id,
      rootKeyId: root.keyId,
      rootPublicPem: root.publicPem,
      policyVersion: 1,
      issuedAt: NOW,
      notAfter: null,
      verifierPolicies: [{
        issuer: "https://token.actions.githubusercontent.com",
        audience: "https://mnde.example.com",
        subject_allowlist: ["repo:acme/infra:ref:refs/heads/main"],
        trusted_jwks_hash: `sha256:${"a".repeat(64)}`
      }],
      minLevelTable: [{ environment: "production", authority_scope: "chain-1", min_level: "ASSERTION_HASH_BOUND" }]
    };
    const legacyVerifierPolicy = await signVerifierPolicy({ ...verifierPolicyOptions, rootPrivatePem: root.privatePem });
    await test("verifier-policy format is byte-identical through the capability", async () => {
      const capabilityPolicy = await signVerifierPolicy({ ...verifierPolicyOptions, rootSigner: external });
      assert.deepEqual(capabilityPolicy, legacyVerifierPolicy);
    });

    await test("externally root-signed verifier policy verifies offline", async () => {
      const policy = await signVerifierPolicy({ ...verifierPolicyOptions, rootSigner: external });
      assert.equal((await verifyPolicySignature(policy, { rootPublicKey: root.publicPem })).ok, true);
    });
  } finally {
    if (priorMode === undefined) delete process.env.MOCK_SIGNER_MODE;
    else process.env.MOCK_SIGNER_MODE = priorMode;
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL RootSigner tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS RootSigner tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
