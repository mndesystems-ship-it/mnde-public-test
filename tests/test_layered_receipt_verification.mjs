// Layered receipt verification — exact state reporting and the "no hiding" rules.
//
// Proves each of the six states is reported precisely, and that a valid signature
// in one layer never masks an invalid signature in the other.

import assert from "node:assert/strict";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  fingerprintOf,
  generateAuthorityKeyPair,
  signCanonical
} from "../src/custody/index.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import {
  buildSignedExecutionReceipt,
  RECEIPT_VERIFICATION_STATES,
  verifyLayeredReceipt
} from "../src/execution-gate/index.mjs";

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

const S = RECEIPT_VERIFICATION_STATES;
const CODEX_ID = "mnde:local:prod:executor:codex:01";
const CLAUDE_ID = "mnde:local:prod:executor:claude:01";
const ENV_ID = "prod";
const SIGNED_AT = "2026-06-15T10:00:00.000Z";
const NOW = "2026-06-15T10:00:00.000Z";

function minimalRequest() {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-layered-001",
    requested_at: SIGNED_AT,
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: "https://token.actions.githubusercontent.com", verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: "staging" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "org/repo", commit_sha: "abc123", branch: "main" }
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

async function makeExecutor(authority, executorId, { expiresAt = "2026-07-01T00:00:00.000Z" } = {}) {
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
    expiresAt
  });
  return { keypair, credential, signer: { executorId, keyId: credential.key_id, credentialId: credential.credential_id, privatePem: keypair.privatePem } };
}

function baseOpts(authority, executor, extra = {}) {
  return {
    authorityBundle: authority.bundle,
    trustedRootFingerprint: authority.trustedRootFingerprint,
    environmentId: ENV_ID,
    executorCredential: executor?.credential,
    now: NOW,
    ...extra
  };
}

console.log("Layered receipt verification\n");

const authority = await makeAuthority();
const codex = await makeExecutor(authority, CODEX_ID);
const claude = await makeExecutor(authority, CLAUDE_ID);

async function authorityOnlyReceipt() {
  return buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: authority.bundle,
    signingKeyId: authority.receiptKey.keyId,
    signingPrivateKeyPem: authority.receiptKey.privatePem
  });
}
async function executorReceipt(executor, extra = {}) {
  return buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: authority.bundle,
    signingKeyId: authority.receiptKey.keyId,
    signingPrivateKeyPem: authority.receiptKey.privatePem,
    executor: executor.signer,
    ...extra
  });
}
function flip(value) {
  return (value.startsWith("0000") ? "ffff" : "0000") + value.slice(4);
}

// ── State reporting ───────────────────────────────────────────────────────────

await test("authority-only receipt returns authority_verified", async () => {
  const receipt = await authorityOnlyReceipt();
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, null));
  assert.equal(r.state, S.AUTHORITY);
});

await test("executor-only receipt returns executor_verified", async () => {
  const full = await executorReceipt(codex);
  const { verifiable_signature: _drop, ...executorOnly } = full;
  const r = await verifyLayeredReceipt(executorOnly, baseOpts(authority, codex));
  assert.equal(r.state, S.EXECUTOR);
  assert.equal(r.executor_id, CODEX_ID);
});

await test("both valid returns executor_and_authority_verified", async () => {
  const receipt = await executorReceipt(codex);
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, codex));
  assert.equal(r.state, S.EXECUTOR_AND_AUTHORITY);
});

await test("both plus passport returns executor_authority_and_passport_verified", async () => {
  const receipt = await executorReceipt(codex, { passportSubjectId: "psub-abc" });
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, codex, { expectedPassportSubjectId: "psub-abc" }));
  assert.equal(r.state, S.EXECUTOR_AUTHORITY_AND_PASSPORT);
  assert.equal(r.passport_subject_id, "psub-abc");
});

await test("shared-file legacy receipt returns legacy_verified", async () => {
  const authorityReceipt = await authorityOnlyReceipt();
  const { verifiable_signature: _drop, ...body } = authorityReceipt;
  const legacyKey = generateAuthorityKeyPair();
  const value = await signCanonical(canonicalizeJson(body), legacyKey.privatePem);
  const legacyReceipt = {
    ...body,
    verifiable_signature: { algorithm: "ED25519", authority_id: "legacy-shared-key", key_id: "legacy-shared-key", signed_at: SIGNED_AT, public_key_fingerprint: fingerprintOf(legacyKey.publicPem), value }
  };
  const r = await verifyLayeredReceipt(legacyReceipt, { legacyPublicKeyPem: legacyKey.publicPem, now: NOW });
  assert.equal(r.state, S.LEGACY);
});

// ── Failure modes ─────────────────────────────────────────────────────────────

await test("executor credential mismatch fails", async () => {
  const receipt = await executorReceipt(codex);
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, codex, { executorCredential: claude.credential }));
  assert.equal(r.state, S.FAILED);
});

await test("expired executor credential fails", async () => {
  const shortLived = await makeExecutor(authority, CODEX_ID, { expiresAt: "2026-06-10T00:00:00.000Z" });
  const receipt = await executorReceipt(shortLived);
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, shortLived, { now: "2026-06-20T00:00:00.000Z" }));
  assert.equal(r.state, S.FAILED);
  assert.equal(r.reason, "ERR_EXECUTOR_CREDENTIAL_EXPIRED");
});

await test("wrong environment fails", async () => {
  const receipt = await executorReceipt(codex);
  const r = await verifyLayeredReceipt(receipt, baseOpts(authority, codex, { environmentId: "staging" }));
  assert.equal(r.state, S.FAILED);
  assert.equal(r.reason, "ERR_EXECUTOR_ENVIRONMENT_MISMATCH");
});

await test("modified executor ID fails", async () => {
  const receipt = await executorReceipt(codex);
  const tampered = { ...receipt, executor_id: CLAUDE_ID };
  const r = await verifyLayeredReceipt(tampered, baseOpts(authority, codex));
  assert.equal(r.state, S.FAILED);
});

await test("modified passport subject fails", async () => {
  const receipt = await executorReceipt(codex, { passportSubjectId: "psub-abc" });
  const tampered = { ...receipt, passport_subject_id: "psub-evil" };
  const r = await verifyLayeredReceipt(tampered, baseOpts(authority, codex, { expectedPassportSubjectId: "psub-abc" }));
  assert.equal(r.state, S.FAILED);
});

await test("modified executor signature fails even when the authority signature is re-made valid", async () => {
  // Attacker breaks the executor signature, then re-signs the authority layer over
  // the tampered body with the receipt key. Authority is valid; executor is not.
  const receipt = await executorReceipt(codex);
  const tampered = { ...receipt, executor_signature: { ...receipt.executor_signature, value: flip(receipt.executor_signature.value) } };
  const { verifiable_signature: _drop, ...bodyWithBadExec } = tampered;
  const reSigned = await signCanonical(canonicalizeJson(bodyWithBadExec), authority.receiptKey.privatePem);
  tampered.verifiable_signature = { ...receipt.verifiable_signature, value: reSigned };
  const r = await verifyLayeredReceipt(tampered, baseOpts(authority, codex));
  assert.equal(r.state, S.FAILED, "a valid authority signature must not hide an invalid executor signature");
  assert.equal(r.layer, "executor");
});

await test("modified authority signature fails even when the executor signature is valid", async () => {
  const receipt = await executorReceipt(codex);
  const tampered = { ...receipt, verifiable_signature: { ...receipt.verifiable_signature, value: flip(receipt.verifiable_signature.value) } };
  const r = await verifyLayeredReceipt(tampered, baseOpts(authority, codex));
  assert.equal(r.state, S.FAILED, "a valid executor signature must not hide an invalid authority signature");
  assert.equal(r.layer, "authority");
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} layered receipt verification (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
