import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createLiveReceiptSigningContext, signLiveReceipt, verifyCustodyAttestation } from "../src/authority-signing/index.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../src/custody/index.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const verifierPath = join(repoRoot, "tools", "verify.mjs");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
const EXECUTOR_ID = "mnde:local:prod:executor:codex:01";
const ENVIRONMENT_ID = "prod";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => server.once("error", reject).listen(0, "127.0.0.1", done));
  const address = server.address();
  await new Promise((done) => server.close(done));
  return address.port;
}

async function fixture(dir) {
  const root = { keyId: "executor-test-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "executor-test-receipt", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "executor-test-ledger", ...generateAuthorityKeyPair() };
  const executor = generateAuthorityKeyPair();
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-executor-live-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  const credential = await issueExecutorCredential({
    authorityBundle: bundle,
    rootPrivatePem: root.privatePem,
    executorId: EXECUTOR_ID,
    publicPem: executor.publicPem,
    environmentId: ENVIRONMENT_ID,
    capabilities: ["sign_execution_receipt"],
    issuedAt: "2026-01-01T00:00:00.000Z",
    notBefore: "2026-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z"
  });
  const paths = {
    bundle: join(dir, "authority.bundle.json"),
    receiptKey: join(dir, "receipt.key.pem"),
    ledgerKey: join(dir, "ledger.key.pem"),
    executorKey: join(dir, "executor key.pem"),
    credential: join(dir, "executor.credential.json")
  };
  writeFileSync(paths.bundle, JSON.stringify(bundle), { mode: 0o600 });
  writeFileSync(paths.receiptKey, receipt.privatePem, { mode: 0o600 });
  writeFileSync(paths.ledgerKey, ledger.privatePem, { mode: 0o600 });
  writeFileSync(paths.executorKey, executor.privatePem, { mode: 0o600 });
  writeFileSync(paths.credential, JSON.stringify(credential), { mode: 0o600 });
  return { root, receipt, ledger, executor, bundle, credential, paths };
}

function baseEnv(F, dir, port, receiptLog) {
  return {
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY: samplePolicy,
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: F.paths.bundle,
    MNDE_RECEIPT_SIGNING_KEY: F.paths.receiptKey,
    MNDE_RECEIPT_KEY_ID: F.receipt.keyId,
    MNDE_LEDGER_SIGNING_KEY: F.paths.ledgerKey,
    MNDE_LEDGER_KEY_ID: F.ledger.keyId,
    MNDE_RECEIPT_LOG: receiptLog,
    MNDE_EXECUTION_LEDGER_PATH: join(dir, `ledger-${port}.jsonl`),
    MNDE_BIND_PORT: String(port)
  };
}

function executorEnv(F) {
  return {
    MNDE_EXECUTOR_ID: EXECUTOR_ID,
    MNDE_EXECUTOR_PRIVATE_KEY: F.paths.executorKey,
    MNDE_EXECUTOR_CREDENTIAL: F.paths.credential,
    MNDE_EXECUTOR_ENVIRONMENT: ENVIRONMENT_ID
  };
}

function decisionRequest(id) {
  return {
    schema_version: "1.0",
    request_id: id,
    timestamp: new Date().toISOString(),
    principal: { id: "executor-live-test" },
    agent: { id: "codex" },
    tool: { tool_name: "read_status" },
    parameters: {},
    environment: { name: ENVIRONMENT_ID },
    context: {}
  };
}

function runVerifier(receiptPath, F) {
  return spawnSync(process.execPath, [
    verifierPath,
    receiptPath,
    "--authority-bundle", F.paths.bundle,
    "--root-fingerprint", F.bundle.root_key.fingerprint,
    "--executor-environment", ENVIRONMENT_ID,
    "--expected-executor-id", EXECUTOR_ID
  ], { cwd: repoRoot, encoding: "utf8", windowsHide: true });
}

console.log("Executor-bound live sidecar receipts\n");
const dir = mkdtempSync(join(tmpdir(), "mnde-executor-live-"));
let sidecar;
try {
  const F = await fixture(dir);
  const port = await freePort();
  const receiptLog = join(dir, "executor-receipts.jsonl");
  sidecar = await startMndeSidecar({
    url: `http://127.0.0.1:${port}`,
    env: { ...baseEnv(F, dir, port, receiptLog), ...executorEnv(F) }
  });

  let validReceipt;
  await test("real sidecar issues an executor-and-authority receipt", async () => {
    const response = await fetch(`${sidecar.url}/v1/decisions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(decisionRequest("executor-live-1"))
    });
    const body = await response.json();
    assert.equal(body.decision, "ALLOW");
    validReceipt = body.receipt;
    assert.equal(validReceipt.signing_mode, "executor_and_authority");
    assert.equal(validReceipt.executor.identity.executor_id, EXECUTOR_ID);
    assert.equal(validReceipt.executor.credential.credential_id, F.credential.credential_id);
    assert.ok(validReceipt.executor.signature.value);
    assert.ok(validReceipt.custody_attestation.signature.value);
    assert.ok(!JSON.stringify(validReceipt).includes("PRIVATE KEY"));
    assert.match(sidecar.getStdout(), /signing_mode=executor_and_authority/);
    assert.ok(!sidecar.getStdout().includes(F.paths.executorKey), "startup log must not expose the private-key path");
  });

  await test("independent verifier reports executor_and_authority_verified", () => {
    const path = join(dir, "executor-bound-receipt.json");
    writeFileSync(path, JSON.stringify(validReceipt));
    const verified = runVerifier(path, F);
    assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
    assert.match(verified.stdout, /Verification state: executor_and_authority_verified/);
    assert.match(verified.stdout, /FINAL VERDICT: VERIFIED/);
  });

  await test("tampering signed receipt evidence becomes INVALID", () => {
    const tampered = structuredClone(validReceipt);
    const canonicalRequest = JSON.parse(tampered.receipt.canonical_request);
    canonicalRequest.context = { ...canonicalRequest.context, commit_sha: "tampered-after-signing" };
    tampered.receipt.canonical_request = JSON.stringify(canonicalRequest);
    const path = join(dir, "tampered-receipt.json");
    writeFileSync(path, JSON.stringify(tampered));
    const verified = runVerifier(path, F);
    assert.equal(verified.status, 1, `${verified.stdout}\n${verified.stderr}`);
    assert.match(verified.stdout, /Error code: ERR_RECEIPT_SIGNATURE_INVALID/);
    assert.match(verified.stdout, /FINAL VERDICT: FAILED/);
  });

  await sidecar.stop();
  sidecar = null;

  await test("missing executor key fails startup with no listener or fallback receipt", async () => {
    const removed = `${F.paths.executorKey}.removed`;
    renameSync(F.paths.executorKey, removed);
    const missingPort = await freePort();
    const missingLog = join(dir, "missing-key-receipts.jsonl");
    await assert.rejects(
      startMndeSidecar({
        url: `http://127.0.0.1:${missingPort}`,
        env: { ...baseEnv(F, dir, missingPort, missingLog), ...executorEnv(F) }
      }),
      /ERR_EXECUTOR_KEY_MISSING/
    );
    await assert.rejects(fetch(`http://127.0.0.1:${missingPort}/readyz`));
    assert.equal(existsSync(missingLog), false);
    renameSync(removed, F.paths.executorKey);
  });

  await test("runtime executor signer failure emits no authority-only receipt", async () => {
    let authorityCalls = 0;
    const provider = {
      trustedRootFingerprint: F.bundle.root_key.fingerprint,
      getPublicBundle: () => structuredClone(F.bundle),
      signReceipt: async (payload) => {
        authorityCalls += 1;
        return { key_id: F.receipt.keyId, value: await signCanonical(payload, F.receipt.privatePem) };
      }
    };
    const contextResult = createLiveReceiptSigningContext(
      { ok: true, mode: "custody", provider },
      {
        configured: true,
        executor_id: EXECUTOR_ID,
        executor_key_id: F.credential.key_id,
        credential_id: F.credential.credential_id,
        environment_id: ENVIRONMENT_ID,
        credential: F.credential,
        signer: Object.freeze({ sign: async () => { throw new Error("injected failure"); } })
      }
    );
    const result = await signLiveReceipt({ schema_version: "test.receipt.v1", evidence: { commit_sha: "abc" } }, contextResult.context);
    assert.equal(result.ok, false);
    assert.equal(result.reason_code, "ERR_EXECUTOR_BOUND_SIGNING_FAILED");
    assert.equal(authorityCalls, 0, "authority signing must not run after executor signing fails");
    assert.equal(result.receipt, undefined);
  });

  await test("authority-only compatibility remains byte-compatible and verifies", async () => {
    const authorityPort = await freePort();
    const authorityLog = join(dir, "authority-only-receipts.jsonl");
    const authoritySidecar = await startMndeSidecar({
      url: `http://127.0.0.1:${authorityPort}`,
      env: baseEnv(F, dir, authorityPort, authorityLog)
    });
    try {
      const response = await fetch(`${authoritySidecar.url}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(decisionRequest("authority-live-1"))
      });
      const body = await response.json();
      assert.equal(body.receipt.schema_version, "mnde.signed-receipt.v1");
      assert.equal(body.receipt.signing_mode, undefined);
      assert.equal(body.receipt.custody_attestation.signing_mode, undefined);
      assert.equal(body.receipt.executor, undefined);
      const path = join(dir, "authority-only-receipt.json");
      writeFileSync(path, JSON.stringify(body.receipt));
      const verified = spawnSync(process.execPath, [
        verifierPath,
        path,
        "--authority-bundle", F.paths.bundle,
        "--root-fingerprint", F.bundle.root_key.fingerprint
      ], { cwd: repoRoot, encoding: "utf8", windowsHide: true });
      assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
      assert.match(verified.stdout, /Verification state: authority_only_verified/);
      const required = await verifyCustodyAttestation(body.receipt, {
        authorityBundle: F.bundle,
        trustedRootFingerprint: F.bundle.root_key.fingerprint,
        requireExecutor: true
      });
      assert.equal(required.ok, false);
      assert.equal(required.reason_code, "ERR_EXECUTOR_REQUIRED");
    } finally {
      await authoritySidecar.stop();
    }
  });
} finally {
  await sidecar?.stop();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor live sidecar (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
