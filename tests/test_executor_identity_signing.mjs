// Executor identity signing — the executor signs FIRST, the custody receipt-role
// key countersigns. Proves Codex and Claude are distinct signing identities, that
// one cannot sign as the other, that the authority countersignature still holds,
// and that the enrollment tool writes key material OUTSIDE the repository.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  verifyCanonical
} from "../src/custody/index.mjs";
import { issueExecutorCredential, executorKeyId } from "../src/custody/executor-credential.mjs";
import {
  buildSignedExecutionReceipt,
  verifySignedExecutionReceipt
} from "../src/execution-gate/index.mjs";

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
const CLAUDE_ID = "mnde:local:prod:executor:claude:01";
const ENV_ID = "prod";
const SIGNED_AT = "2026-06-15T10:00:00.000Z";

function minimalRequest(overrides = {}) {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-exec-001",
    requested_at: SIGNED_AT,
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: "https://token.actions.githubusercontent.com", verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: "staging" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "org/repo", commit_sha: "abc123", branch: "main" },
    ...overrides
  };
}

async function makeAuthority() {
  const root = { keyId: "authority-root-v1", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "receipt-key-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde:local:prod",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  return { root, receiptKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

async function makeExecutor(authority, executorId) {
  const keypair = generateAuthorityKeyPair();
  const credential = await issueExecutorCredential({
    authorityBundle: authority.bundle,
    rootPrivatePem: authority.root.privatePem,
    executorId,
    publicPem: keypair.publicPem,
    environmentId: ENV_ID,
    capabilities: ["sign_execution_receipt"],
    issuedAt: "2026-06-01T00:00:00.000Z",
    notBefore: "2026-06-01T00:00:00.000Z",
    expiresAt: "2026-07-01T00:00:00.000Z"
  });
  return {
    keypair,
    credential,
    signer: { executorId, keyId: credential.key_id, credentialId: credential.credential_id, privatePem: keypair.privatePem }
  };
}

async function buildExecutorReceipt(authority, executor, extra = {}) {
  return buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: authority.bundle,
    signingKeyId: authority.receiptKey.keyId,
    signingPrivateKeyPem: authority.receiptKey.privatePem,
    executor: executor.signer,
    ...extra
  });
}

function executorPayload(receipt) {
  const { verifiable_signature: _a, executor_signature: _b, ...rest } = receipt;
  return canonicalizeJson(rest);
}

console.log("Executor identity signing\n");

const authority = await makeAuthority();
const codex = await makeExecutor(authority, CODEX_ID);
const claude = await makeExecutor(authority, CLAUDE_ID);

await test("Codex and Claude identities differ (distinct key ids and credentials)", async () => {
  assert.notEqual(codex.credential.key_id, claude.credential.key_id);
  assert.notEqual(codex.credential.credential_id, claude.credential.credential_id);
  assert.equal(codex.credential.key_id, executorKeyId(codex.keypair.publicPem));
});

await test("authority-only receipt still builds and verifies (compatibility preserved)", async () => {
  const receipt = await buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: authority.bundle,
    signingKeyId: authority.receiptKey.keyId,
    signingPrivateKeyPem: authority.receiptKey.privatePem
  });
  assert.equal(receipt.executor_signature, undefined);
  assert.equal(receipt.executor_id, undefined);
  const v = await verifySignedExecutionReceipt(receipt, { authorityBundle: authority.bundle, trustedRootFingerprint: authority.trustedRootFingerprint });
  assert.equal(v.verified, true, v.reason ?? "");
});

await test("executor-signed receipt carries executor fields and a valid executor signature", async () => {
  const receipt = await buildExecutorReceipt(authority, codex);
  assert.equal(receipt.executor_id, CODEX_ID);
  assert.equal(receipt.executor_key_id, codex.credential.key_id);
  assert.equal(receipt.executor_credential_id, codex.credential.credential_id);
  assert.ok(receipt.executor_signature?.value);
  const ok = await verifyCanonical(executorPayload(receipt), receipt.executor_signature.value, codex.keypair.publicPem);
  assert.equal(ok, true);
});

await test("Codex cannot verify as Claude", async () => {
  const receipt = await buildExecutorReceipt(authority, codex);
  const ok = await verifyCanonical(executorPayload(receipt), receipt.executor_signature.value, claude.keypair.publicPem);
  assert.equal(ok, false);
});

await test("Claude cannot verify as Codex", async () => {
  const receipt = await buildExecutorReceipt(authority, claude);
  const ok = await verifyCanonical(executorPayload(receipt), receipt.executor_signature.value, codex.keypair.publicPem);
  assert.equal(ok, false);
});

await test("authority countersignature over the executor-signed receipt still verifies", async () => {
  const receipt = await buildExecutorReceipt(authority, codex);
  const v = await verifySignedExecutionReceipt(receipt, { authorityBundle: authority.bundle, trustedRootFingerprint: authority.trustedRootFingerprint });
  assert.equal(v.verified, true, v.reason ?? "");
});

await test("passport_subject_id is bound when present and absent otherwise", async () => {
  const withPassport = await buildExecutorReceipt(authority, codex, { passportSubjectId: "psub-abc" });
  assert.equal(withPassport.passport_subject_id, "psub-abc");
  // Covered by the executor signature: tampering it breaks the executor sig.
  const tampered = { ...withPassport, passport_subject_id: "psub-evil" };
  const ok = await verifyCanonical(executorPayload(tampered), tampered.executor_signature.value, codex.keypair.publicPem);
  assert.equal(ok, false);
  const without = await buildExecutorReceipt(authority, codex);
  assert.equal(without.passport_subject_id, undefined);
});

await test("enrollment tool writes key material OUTSIDE the repo and issues a verifiable credential", async () => {
  const work = mkdtempSync(join(tmpdir(), "mnde-enroll-"));
  const bundlePath = join(work, "bundle.json");
  const rootKeyPath = join(work, "root_private.pem");
  const outDir = join(work, "executors");
  writeFileSync(bundlePath, JSON.stringify(authority.bundle));
  writeFileSync(rootKeyPath, authority.root.privatePem);

  const run = spawnSync(process.execPath, [
    join(repoRoot, "scripts", "trust-enroll-executor.mjs"),
    "--executor-id", CODEX_ID,
    "--environment", ENV_ID,
    "--bundle", bundlePath,
    "--root-key", rootKeyPath,
    "--out-dir", outDir,
    "--issued-at", "2026-06-01T00:00:00.000Z",
    "--ttl-hours", "24"
  ], { encoding: "utf8" });

  assert.equal(run.status, 0, `tool failed: ${run.stderr}`);
  const summary = JSON.parse(run.stdout);
  assert.equal(summary.executor_id, CODEX_ID);
  // Private key exists in the external dir, NOT under the repo.
  assert.ok(existsSync(summary.private_key_path));
  assert.ok(!resolve(summary.private_key_path).startsWith(resolve(repoRoot) + sep), "private key must be outside the repo");
  // stdout must not leak private key material.
  assert.ok(!run.stdout.includes("PRIVATE KEY"));
  const cred = JSON.parse(readFileSync(summary.credential_path, "utf8"));
  assert.equal(cred.executor_id, CODEX_ID);
  assert.equal(cred.schema_version, "mnde.executor.credential.v1");
});

await test("enrollment tool refuses an out-dir inside the repository (fails closed)", async () => {
  const badOut = join(repoRoot, "scripts", "__should_not_be_created__");
  const work = mkdtempSync(join(tmpdir(), "mnde-enroll-neg-"));
  const bundlePath = join(work, "bundle.json");
  const rootKeyPath = join(work, "root_private.pem");
  writeFileSync(bundlePath, JSON.stringify(authority.bundle));
  writeFileSync(rootKeyPath, authority.root.privatePem);
  const run = spawnSync(process.execPath, [
    join(repoRoot, "scripts", "trust-enroll-executor.mjs"),
    "--executor-id", CODEX_ID, "--environment", ENV_ID,
    "--bundle", bundlePath, "--root-key", rootKeyPath, "--out-dir", badOut
  ], { encoding: "utf8" });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /OUTSIDE the repository/);
  assert.ok(!existsSync(badOut), "must not create key material inside the repo");
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor identity signing (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
