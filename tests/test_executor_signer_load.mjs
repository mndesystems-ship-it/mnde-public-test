// Direct tests for loadExecutorSigner — the fail-closed runtime loader that
// verifies an executor credential against the authority and proves the loaded
// private key matches it, from out-of-repo material.

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import { loadExecutorSigner } from "../src/custody/executor-identity.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

const CODEX_ID = "mnde:local:prod:executor:codex:01";
const ENV_ID = "prod";
const NOW = "2026-06-15T10:00:00.000Z";

async function makeAuthority() {
  const root = { keyId: "authority-root-v1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde:local:prod",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  return { root, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

async function issueFor(authority, keypair, { expiresAt = "2026-07-01T00:00:00.000Z" } = {}) {
  return issueExecutorCredential({
    authorityBundle: authority.bundle,
    rootPrivatePem: authority.root.privatePem,
    executorId: CODEX_ID,
    publicPem: keypair.publicPem,
    environmentId: ENV_ID,
    capabilities: ["sign_execution_receipt"],
    issuedAt: "2026-06-01T00:00:00.000Z",
    notBefore: "2026-06-01T00:00:00.000Z",
    expiresAt
  });
}

const work = mkdtempSync(join(tmpdir(), "mnde-signer-"));
function writeKey(name, pem) {
  const p = join(work, name);
  writeFileSync(p, pem, { mode: 0o600 });
  return p;
}

function baseOpts(authority, extra = {}) {
  return {
    executorId: CODEX_ID,
    authorityBundle: authority.bundle,
    trustedRootFingerprint: authority.trustedRootFingerprint,
    environmentId: ENV_ID,
    repoRoot,
    now: NOW,
    ...extra
  };
}

console.log("loadExecutorSigner — fail-closed runtime loader\n");

const authority = await makeAuthority();
const codexKeys = generateAuthorityKeyPair();
const codexCred = await issueFor(authority, codexKeys);
const codexKeyPath = writeKey("codex.key", codexKeys.privatePem);

await test("1. valid key + credential load successfully", async () => {
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: codexKeyPath, credential: codexCred }));
  assert.equal(r.ok, true, r.detail ?? r.code);
  assert.equal(r.executorId, CODEX_ID);
  assert.equal(r.keyId, codexCred.key_id);
  assert.equal(r.credentialId, codexCred.credential_id);
  assert.ok(r.privatePem.includes("PRIVATE KEY"), "signer carries the loaded key for use");
});

await test("2. private key / credential mismatch fails closed", async () => {
  const otherKeys = generateAuthorityKeyPair();
  const otherKeyPath = writeKey("other.key", otherKeys.privatePem);
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: otherKeyPath, credential: codexCred }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "ERR_EXECUTOR_KEY_MISMATCH");
});

await test("3. expired credential fails closed", async () => {
  const expiredCred = await issueFor(authority, codexKeys, { expiresAt: "2026-06-10T00:00:00.000Z" });
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: codexKeyPath, credential: expiredCred, now: "2026-06-20T00:00:00.000Z" }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "ERR_EXECUTOR_CREDENTIAL_EXPIRED");
});

await test("4. wrong environment fails closed", async () => {
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: codexKeyPath, credential: codexCred, environmentId: "staging" }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "ERR_EXECUTOR_ENVIRONMENT_MISMATCH");
});

await test("5. missing / unreadable key file fails closed", async () => {
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: join(work, "does-not-exist.key"), credential: codexCred }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "ERR_EXECUTOR_KEY_MISSING");
});

await test("6. in-repository private-key path fails closed", async () => {
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"), credential: codexCred }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "ERR_EXECUTOR_KEY_PATH_UNSAFE");
});

await test("7. no private material appears in failure results", async () => {
  const otherKeys = generateAuthorityKeyPair();
  const otherKeyPath = writeKey("leak.key", otherKeys.privatePem);
  const r = await loadExecutorSigner(baseOpts(authority, { privateKeyPath: otherKeyPath, credential: codexCred }));
  assert.equal(r.ok, false);
  const serialized = JSON.stringify(r);
  assert.ok(!serialized.includes("PRIVATE KEY"), "failure result must not contain a PRIVATE KEY marker");
  assert.ok(!serialized.includes(otherKeys.privatePem.slice(40, 90)), "failure result must not contain key bytes");
  // The credential's public key is not secret, but the private PEM must be absent.
  assert.ok(!serialized.includes(codexKeys.privatePem.slice(40, 90)));
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor signer load (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
