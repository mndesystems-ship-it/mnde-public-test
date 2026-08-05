// Executor-identity hostile + integration tests — EXACT failure codes, and the
// reconciliation guarantee that identity-bearing receipts coexist with main's
// signed, Merkle-anchored JSONL ledger.
//
//   npm run test:executor-identity-hostile
//
// Companion to test_executor_credential (credential-layer codes) and
// test_layered_receipt_verification (state reporting). This file adds the cases
// those assert only as a generic FAILED, pins the EXACT reason/layer, and proves
// end-to-end that an identity-bearing receipt anchors and its Merkle inclusion
// proof + the inner receipt both verify OFFLINE.
//
// Design note on "revocation": executor credentials carry no per-credential CRL.
// Executor revocation is achieved by (a) short expiry [see test_executor_credential
// EXPIRED cases] and (b) invalidating the ISSUING authority bundle. This file
// exercises path (b) with an exact code.

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalizeJson } from "../shared/json.ts";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../src/custody/bundle.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import {
  buildSignedExecutionReceipt,
  verifyLayeredReceipt,
  RECEIPT_VERIFICATION_STATES
} from "../src/execution-gate/index.mjs";
import { appendLedgerEntry } from "../src/execution-ledger/append.mjs";
import { anchorLedger, buildProofBundle } from "../src/execution-ledger/anchor.mjs";
import { verifyProofBundle } from "../src/execution-ledger/proof.mjs";
import { canonicalReceiptHash, LEDGER_ASSURANCE } from "../src/execution-ledger/index.mjs";
import { signReceiptForDelivery } from "../src/authority-signing/index.mjs";

const S = RECEIPT_VERIFICATION_STATES;
const EPOCH = "1970-01-01T00:00:00.000Z";
const FAR = "2999-01-01T00:00:00.000Z";
const AT = "2026-06-29T00:00:00.000Z";
const ENV = "prod";
const CODEX = "mnde:local:prod:executor:codex:01";
const CLAUDE = "mnde:local:prod:executor:claude:01";
const SUBJECT = "sha256:subject-abc";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  ok - ${name}`); }
  catch (e) { failed += 1; console.error(`  FAIL - ${name}\n        ${e instanceof Error ? e.message : String(e)}`); }
}
function flip(value) { return (value.startsWith("0000") ? "ffff" : "0000") + value.slice(4); }
function clone(x) { return structuredClone(x); }

// ── Authority + executor fixtures ─────────────────────────────────────────────
async function makeBundle({ notAfter = FAR } = {}) {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "ledger-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde:local:prod", issuedAt: AT, notAfter, root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: EPOCH, validUntil: FAR }],
    policyKeys: [], approvalKeys: [], resultKeys: [],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: EPOCH, validUntil: FAR }],
    activationKeys: [], revocation: []
  });
  const signLedger = async (payload) => ({ key_id: ledger.keyId, value: await signCanonical(payload, ledger.privatePem), fingerprint: bundle.keys.ledger[0].fingerprint });
  const trustedRootFingerprint = bundle.root_key.fingerprint;
  const provider = {
    trustedRootFingerprint,
    getPublicBundle: () => clone(bundle),
    signReceipt: async (payload) => ({ key_id: receipt.keyId, value: await signCanonical(payload, receipt.privatePem), fingerprint: bundle.keys.receipt[0].fingerprint })
  };
  return { root, receipt, ledger, bundle, signLedger, trustedRootFingerprint, provider };
}

async function makeExecutor(A, executorId, { expiresAt = FAR } = {}) {
  const keys = generateAuthorityKeyPair();
  const credential = await issueExecutorCredential({
    authorityBundle: A.bundle, rootPrivatePem: A.root.privatePem,
    executorId, publicPem: keys.publicPem, environmentId: ENV,
    capabilities: ["sign_execution_receipt"], issuedAt: AT, notBefore: AT, expiresAt
  });
  return { keys, credential, signer: { executorId, keyId: credential.key_id, credentialId: credential.credential_id, privatePem: keys.privatePem } };
}

function req(id) {
  return {
    schema_version: "mnde.execution_request.v1", execution_id: id, requested_at: AT,
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: "https://x", verified: true, claims: {} },
    resource: { kind: "service", id: "api", name: "API" }, environment: { name: "staging" },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} }, approval: { required: false },
    evidence: { repo: "o/r", commit_sha: "abc", branch: "main" }
  };
}
async function idReceipt(A, ex, id, extra = {}) {
  return buildSignedExecutionReceipt(req(id), "ALLOW", {
    authorityBundle: A.bundle, signingKeyId: A.receipt.keyId, signingPrivateKeyPem: A.receipt.privatePem,
    executor: ex.signer, passportSubjectId: SUBJECT, ...extra
  });
}
async function authorityOnlyReceipt(A, id) {
  return buildSignedExecutionReceipt(req(id), "ALLOW", {
    authorityBundle: A.bundle, signingKeyId: A.receipt.keyId, signingPrivateKeyPem: A.receipt.privatePem
  });
}
function baseOpts(A, ex, extra = {}) {
  return { authorityBundle: A.bundle, trustedRootFingerprint: A.trustedRootFingerprint, environmentId: ENV, executorCredential: ex?.credential, now: AT, ...extra };
}

console.log("Executor-identity hostile + integration\n");

const A = await makeBundle();
const codex = await makeExecutor(A, CODEX);
const claude = await makeExecutor(A, CLAUDE);

// ── Unit: exact codes the state-only tests don't pin ──────────────────────────

await test("passport subject substitution → ERR_PASSPORT_SUBJECT_MISMATCH", async () => {
  const r = await idReceipt(A, codex, "u1");
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex, { expectedPassportSubjectId: "sha256:someone-else" }));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_PASSPORT_SUBJECT_MISMATCH");
});

await test("executor signature tamper → ERR_RECEIPT_SIGNATURE_INVALID (layer executor)", async () => {
  const r = await idReceipt(A, codex, "u2");
  r.executor_signature.value = flip(r.executor_signature.value);
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_RECEIPT_SIGNATURE_INVALID");
  assert.equal(res.layer, "executor");
});

await test("authority signature tamper → ERR_RECEIPT_SIGNATURE_INVALID (layer authority)", async () => {
  const r = await idReceipt(A, codex, "u3");
  r.verifiable_signature.value = flip(r.verifiable_signature.value);
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_RECEIPT_SIGNATURE_INVALID");
  assert.equal(res.layer, "authority");
});

await test("valid executor must not hide tampered authority (one valid, one invalid)", async () => {
  const r = await idReceipt(A, codex, "u4");
  r.verifiable_signature.value = flip(r.verifiable_signature.value); // executor still valid
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.layer, "authority");
});

await test("valid authority must not hide tampered executor (one valid, one invalid)", async () => {
  const r = await idReceipt(A, codex, "u5");
  r.executor_signature.value = flip(r.executor_signature.value); // authority countersig also breaks, executor checked first
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.layer, "executor");
});

await test("post-sign mutation of a neutral signed field → ERR_RECEIPT_SIGNATURE_INVALID (executor)", async () => {
  const r = await idReceipt(A, codex, "u6");
  r.evidence.commit_sha = "tampered-after-signing"; // identity intact; signature must break
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_RECEIPT_SIGNATURE_INVALID");
  assert.equal(res.layer, "executor");
});

await test("identity field changed after signing → ERR_EXECUTOR_IDENTITY_MISMATCH", async () => {
  const r = await idReceipt(A, codex, "u7");
  r.executor_id = CLAUDE; // now disagrees with the (codex) credential
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_IDENTITY_MISMATCH");
});

await test("replay across executors: codex receipt presented with claude credential → ERR_EXECUTOR_IDENTITY_MISMATCH", async () => {
  const r = await idReceipt(A, codex, "u8");
  const res = await verifyLayeredReceipt(r, baseOpts(A, claude)); // wrong credential for this receipt
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_IDENTITY_MISMATCH");
});

await test("executor layer present but credential missing → ERR_EXECUTOR_CREDENTIAL_MISSING", async () => {
  const r = await idReceipt(A, codex, "u9");
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex, { executorCredential: null }));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_CREDENTIAL_MISSING");
});

await test("malformed credential (missing field) → ERR_EXECUTOR_CREDENTIAL_INVALID", async () => {
  const r = await idReceipt(A, codex, "u10");
  const badCred = clone(codex.credential);
  delete badCred.environment_id;
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex, { executorCredential: badCred }));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("unsupported credential version → ERR_EXECUTOR_CREDENTIAL_INVALID", async () => {
  const r = await idReceipt(A, codex, "u11");
  const badCred = clone(codex.credential);
  badCred.schema_version = "mnde.executor.credential.v2"; // unsupported
  const res = await verifyLayeredReceipt(r, baseOpts(A, codex, { executorCredential: badCred }));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("issuing bundle no longer valid (revocation/expiry path) → ERR_EXECUTOR_CREDENTIAL_INVALID", async () => {
  // Executor revocation semantics: invalidate the issuing authority bundle.
  const expiredAuthority = await makeBundle({ notAfter: "2026-06-01T00:00:00.000Z" }); // expired before AT
  const ex = await makeExecutor(expiredAuthority, CODEX);
  const r = await idReceipt(expiredAuthority, ex, "u12");
  const res = await verifyLayeredReceipt(r, baseOpts(expiredAuthority, ex));
  assert.equal(res.state, S.FAILED);
  assert.equal(res.reason, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

// ── Integration: identity-bearing receipts coexist with Merkle anchoring ──────

async function envelope(A, inner) {
  const r = await signReceiptForDelivery(inner, { mode: "custody", provider: A.provider }, { now: AT });
  assert.equal(r.ok, true, `envelope: ${r.reason_code ?? ""}`);
  return r.receipt; // mnde.signed-receipt.v1 wrapping `inner`
}

// Build a receipt store + signed v2 ledger from `inners`, anchor it, and return artefacts.
async function anchorChain(A, inners) {
  const dir = mkdtempSync(join(tmpdir(), "mnde-eih-"));
  const storePath = join(dir, "receipts.jsonl");
  const ledgerPath = join(dir, ".data", "ledger.jsonl");
  const checkpointPath = join(dir, ".data", "checkpoints.jsonl");
  mkdirSync(join(dir, ".data"), { recursive: true });
  const envelopes = [];
  for (const inner of inners) envelopes.push(await envelope(A, inner));
  writeFileSync(storePath, envelopes.map((e) => canonicalizeJson(e)).join("\n") + "\n");
  for (const e of envelopes) {
    const out = await appendLedgerEntry({ ledgerPath, receipt: e, receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger: A.signLedger, createdAt: AT });
    assert.equal(out.ok, true, `append: ${out.code ?? ""}`);
  }
  const checkpoint = await anchorLedger(ledgerPath, checkpointPath, { signLedger: A.signLedger, bundle: A.bundle, issuedAt: AT });
  return { dir, storePath, ledgerPath, checkpointPath, envelopes, checkpoint };
}

await test("identity-bearing receipt anchors; Merkle inclusion proof verifies OFFLINE", async () => {
  const inners = [await idReceipt(A, codex, "i1a"), await idReceipt(A, claude, "i1b"), await idReceipt(A, codex, "i1c")];
  const ch = await anchorChain(A, inners);
  assert.equal(ch.checkpoint.tree_size, 3);
  const targetHash = canonicalReceiptHash(ch.envelopes[1]);
  const proof = await buildProofBundle(ch.ledgerPath, ch.checkpoint, { receipt_hash: targetHash }, { receiptStorePath: ch.storePath, trustedBundle: A.bundle });
  // Fresh offline verifier: only the proof bundle + a fresh copy of the public bundle.
  const res = await verifyProofBundle(clone(proof), clone(A.bundle), { trustedRootFingerprint: A.trustedRootFingerprint });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.assurance, LEDGER_ASSURANCE.OPERATOR_SIGNED_INCLUSION);
  assert.equal(res.sequence, 2);
  assert.equal(res.tree_size, 3);
  rmSync(ch.dir, { recursive: true, force: true });
});

await test("inner identity receipt verifies OFFLINE → executor_authority_and_passport_verified", async () => {
  const inner = await idReceipt(A, codex, "i2");
  const res = await verifyLayeredReceipt(inner, baseOpts(A, codex, { expectedPassportSubjectId: SUBJECT }));
  assert.equal(res.ok, true);
  assert.equal(res.state, S.EXECUTOR_AUTHORITY_AND_PASSPORT);
  assert.equal(res.executor_id, CODEX);
});

await test("old (pre-identity) receipt still anchors and verifies authority_verified", async () => {
  const inner = await authorityOnlyReceipt(A, "i3");
  const ch = await anchorChain(A, [inner]);
  const targetHash = canonicalReceiptHash(ch.envelopes[0]);
  const proof = await buildProofBundle(ch.ledgerPath, ch.checkpoint, { receipt_hash: targetHash }, { receiptStorePath: ch.storePath, trustedBundle: A.bundle });
  const res = await verifyProofBundle(clone(proof), clone(A.bundle), { trustedRootFingerprint: A.trustedRootFingerprint });
  assert.equal(res.ok, true, res.reason);
  const lr = await verifyLayeredReceipt(inner, { authorityBundle: A.bundle, trustedRootFingerprint: A.trustedRootFingerprint, now: AT });
  assert.equal(lr.state, S.AUTHORITY);
  rmSync(ch.dir, { recursive: true, force: true });
});

await test("anchoring binds exact bytes: a mutated inner fails layered verify while the original proof still holds", async () => {
  const inner = await idReceipt(A, codex, "i4");
  const ch = await anchorChain(A, [inner]);
  const proof = await buildProofBundle(ch.ledgerPath, ch.checkpoint, { receipt_hash: canonicalReceiptHash(ch.envelopes[0]) }, { receiptStorePath: ch.storePath, trustedBundle: A.bundle });
  const original = await verifyProofBundle(clone(proof), clone(A.bundle), { trustedRootFingerprint: A.trustedRootFingerprint });
  assert.equal(original.ok, true, original.reason);
  // Mutate a copy of the inner receipt; its layered verification must fail closed.
  const mutated = clone(inner);
  mutated.evidence.commit_sha = "tampered";
  const lr = await verifyLayeredReceipt(mutated, baseOpts(A, codex));
  assert.equal(lr.state, S.FAILED);
  assert.equal(lr.reason, "ERR_RECEIPT_SIGNATURE_INVALID");
  rmSync(ch.dir, { recursive: true, force: true });
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
