#!/usr/bin/env node
// Hostile tests for mnde.execution_ledger_entry.v1.

import assert from "node:assert/strict";
import { canonicalizeJson } from "../shared/json.ts";
import { sha256 } from "../src/crypto/provider.mjs";
import {
  buildAuthorityBundle,
  fingerprintOf,
  generateAuthorityKeyPair,
  signCanonical
} from "../src/custody/index.mjs";
import { buildExecutionResult, computeResultHash } from "../src/execution-gate/result.mjs";
import { buildSignedExecutionReceipt } from "../src/execution-gate/signed-receipt.mjs";
import { buildSignedExecutionResult } from "../src/execution-gate/signed-result.mjs";
import { buildSignedLedgerEntry } from "../src/execution-gate/signed-ledger-entry.mjs";
import { LEDGER_SCHEMA, ledgerEntryHash } from "../src/execution-gate/ledger.mjs";
import { verifyLedgerEntry } from "../src/execution-gate/verify-ledger-entry.mjs";

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
      console.log(`  [FAIL] ${name}: ${error.stack ?? error.message}`);
    }
  });
}

const EPOCH = "1970-01-01T00:00:00.000Z";
const FAR_FUTURE = "2999-01-01T00:00:00.000Z";
const REQUESTED_AT = "2026-06-26T12:00:00.000Z";
const CREATED_AT = "2026-06-26T12:01:00.000Z";
const NOW = "2026-06-26T12:01:30.000Z";
const LEDGER_ID = "ledger-prod-deployments";
const ENVIRONMENT = "prod";

function sha256HexCanonical(value) {
  return sha256(canonicalizeJson(value));
}

function sha256Tagged(value) {
  return `sha256:${sha256HexCanonical(value)}`;
}

function sha256String(value) {
  return sha256(value);
}

function keyEntry(key, { validFrom = EPOCH, validUntil = FAR_FUTURE } = {}) {
  return {
    key_id: key.keyId,
    public_key: key.publicPem,
    fingerprint: fingerprintOf(key.publicPem),
    valid_from: validFrom,
    valid_until: validUntil
  };
}

async function rootSignBundle(body, root) {
  return {
    ...body,
    signature: {
      algorithm: "ED25519",
      value: await signCanonical(canonicalizeJson(body), root.privatePem)
    }
  };
}

async function makeBundle({
  ledgerValidUntil = FAR_FUTURE,
  revokeLedger = false,
  duplicateLedgerWithReceipt = false,
  malformedLedgerPublicKey = false
} = {}) {
  const root = { keyId: "test-root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "test-receipt-key", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "test-policy-key", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "test-approval-key", ...generateAuthorityKeyPair() };
  const resultKey = { keyId: "test-result-key", ...generateAuthorityKeyPair() };
  const ledgerKey = duplicateLedgerWithReceipt
    ? { ...receiptKey, keyId: "test-ledger-key" }
    : { keyId: "test-ledger-key", ...generateAuthorityKeyPair() };

  if (!duplicateLedgerWithReceipt && !malformedLedgerPublicKey) {
    const bundle = await buildAuthorityBundle({
      authorityId: "mnde-ledger-test-authority",
      issuedAt: "2026-01-01T00:00:00.000Z",
      notAfter: "2028-01-01T00:00:00.000Z",
      root,
      receiptKeys: [keyEntry(receiptKey)],
      policyKeys: [keyEntry(policyKey)],
      approvalKeys: [keyEntry(approvalKey)],
      resultKeys: [keyEntry(resultKey)],
      ledgerKeys: [keyEntry(ledgerKey, { validUntil: ledgerValidUntil })],
      revocation: revokeLedger ? [ledgerKey.keyId] : []
    });
    return { root, receiptKey, policyKey, approvalKey, resultKey, ledgerKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
  }

  const ledgerEntry = malformedLedgerPublicKey
    ? { key_id: ledgerKey.keyId, public_key: "not a pem", fingerprint: "f".repeat(64), valid_from: EPOCH, valid_until: FAR_FUTURE }
    : keyEntry(ledgerKey);
  const body = {
    schema_version: "mnde.authority.bundle.v1",
    authority_id: "mnde-ledger-test-authority",
    issued_at: "2026-01-01T00:00:00.000Z",
    not_after: "2028-01-01T00:00:00.000Z",
    root_key: { key_id: root.keyId, public_key: root.publicPem, fingerprint: fingerprintOf(root.publicPem) },
    keys: {
      receipt: [keyEntry(receiptKey)],
      policy: [keyEntry(policyKey)],
      approval: [keyEntry(approvalKey)],
      result: [keyEntry(resultKey)],
      ledger: [ledgerEntry]
    },
    revocation: revokeLedger ? [ledgerKey.keyId] : []
  };
  const bundle = await rootSignBundle(body, root);
  return { root, receiptKey, policyKey, approvalKey, resultKey, ledgerKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

function minimalRequest() {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-ledger-test-001",
    requested_at: REQUESTED_AT,
    action: { type: "deploy", name: "deploy-api", dry_run: false },
    principal: { id: "octocat", type: "github_actor", issuer: "https://token.actions.githubusercontent.com", verified: true, claims: {} },
    resource: { kind: "service", id: "api-service", name: "API Service" },
    environment: { name: ENVIRONMENT },
    risk: { level: "low", destructive: false, reversible: true, touches_secrets: false, touches_customer_data: false, blast_radius: "service" },
    cost: { estimated_cents: 0, dimensions: {} },
    approval: { required: false },
    evidence: { repo: "org/repo", commit_sha: "abc123", branch: "main" }
  };
}

async function makeSignedReceipt(fixtures, { request = minimalRequest(), decision = "ALLOW" } = {}) {
  return await buildSignedExecutionReceipt(request, decision, {
    authorityBundle: fixtures.bundle,
    signingKeyId: fixtures.receiptKey.keyId,
    signingPrivateKeyPem: fixtures.receiptKey.privatePem,
    policyProvenance: {
      policy_id: "policy-default",
      serial: 1,
      policy_hash: "sha256:" + "a".repeat(64),
      bundle_id: "bundle-default",
      bundle_digest: "sha256:" + "b".repeat(64)
    }
  });
}

function makeExecutionResult(signedReceipt, overrides = {}) {
  const body = {
    schema_version: "mnde.execution_result.v2",
    result_id: "result-ledger-test-001",
    execution_id: signedReceipt.execution_id,
    execution_request_hash: signedReceipt.request_hash,
    execution_receipt_hash: sha256HexCanonical(signedReceipt),
    decision: signedReceipt.decision,
    status: signedReceipt.decision === "REFUSE" ? "NOT_EXECUTED" : "SUCCEEDED",
    executor: {
      id: "test-runner-1",
      type: "github_actions",
      identity_evidence: { type: "github_oidc", subject: "repo:org/repo:ref:refs/heads/main", issuer: "https://token.actions.githubusercontent.com" },
      identity_evidence_asserted_only: true
    },
    started_at: "2026-06-26T12:00:30.000Z",
    ended_at: CREATED_AT,
    recorded_at: CREATED_AT,
    effects: signedReceipt.decision === "REFUSE"
      ? []
      : [{ type: "deployment", resource_id: "api-service", before: null, after: "sha256:" + "c".repeat(64) }],
    evidence: [{ type: "workflow_run", identifier: "run-12345" }],
    ...(signedReceipt.decision === "REFUSE" ? { non_execution_reason: "MANUAL_ABORT" } : {}),
    ...overrides
  };
  return buildExecutionResult(body);
}

async function makeSignedResult(fixtures, signedReceipt, executionResult = makeExecutionResult(signedReceipt)) {
  return await buildSignedExecutionResult(executionResult, {
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    signingKeyId: fixtures.resultKey.keyId,
    signingPrivateKeyPem: fixtures.resultKey.privatePem,
    authorityChainId: "mnde-ledger-test-chain",
    signedAt: CREATED_AT,
    now: NOW,
    signedReceipt
  });
}

function ledgerCustody(fixtures, signingKey = fixtures.ledgerKey) {
  return {
    async signLedger(payload) {
      return {
        key_id: fixtures.ledgerKey.keyId,
        value: await signCanonical(payload, signingKey.privatePem),
        fingerprint: fingerprintOf(fixtures.ledgerKey.publicPem)
      };
    }
  };
}

async function makeLedger(fixtures, signedReceipt, signedExecutionResult, overrides = {}) {
  return await buildSignedLedgerEntry({
    authorityBundle: fixtures.bundle,
    trustedRootFingerprint: fixtures.trustedRootFingerprint,
    custody: overrides.custody ?? ledgerCustody(fixtures),
    ledgerId: overrides.ledgerId ?? LEDGER_ID,
    sequenceNumber: overrides.sequenceNumber ?? 1,
    previousEntryHash: Object.hasOwn(overrides, "previousEntryHash") ? overrides.previousEntryHash : null,
    createdAt: overrides.createdAt ?? CREATED_AT,
    signedReceipt,
    signedExecutionResult,
    executorId: "test-runner-1",
    environment: overrides.environment ?? ENVIRONMENT,
    metadata: overrides.metadata ?? { workflow: { run_id: "12345" } },
    now: NOW
  });
}

async function verify(fixtures, envelope, signedReceipt, signedExecutionResult, extra = {}) {
  return await verifyLedgerEntry(envelope, {
    authorityBundle: extra.authorityBundle ?? fixtures.bundle,
    trustedRootFingerprint: extra.trustedRootFingerprint ?? fixtures.trustedRootFingerprint,
    signedReceipt,
    signedExecutionResult,
    previousLedgerEntry: extra.previousLedgerEntry,
    previousSignedReceipt: extra.previousSignedReceipt,
    previousSignedExecutionResult: extra.previousSignedExecutionResult,
    expectedLedgerId: extra.expectedLedgerId,
    expectedEnvironment: extra.expectedEnvironment,
    requirePreviousEntry: extra.requirePreviousEntry,
    now: extra.now ?? NOW,
    nowMs: extra.nowMs ?? Date.parse(NOW),
    maxClockSkewMs: extra.maxClockSkewMs
  });
}

function authorityFor(fixtures) {
  return {
    authority_id: fixtures.bundle.authority_id,
    authority_bundle_fingerprint: fixtures.bundle.root_key.fingerprint,
    signing_key_fingerprint: fingerprintOf(fixtures.ledgerKey.publicPem),
    key_id: fixtures.ledgerKey.keyId,
    key_role: "ledger",
    algorithm: "ED25519"
  };
}

function ledgerEntryFor(signedReceipt, signedExecutionResult, overrides = {}) {
  return {
    ledger_id: overrides.ledger_id ?? LEDGER_ID,
    sequence_number: overrides.sequence_number ?? 1,
    previous_entry_hash: Object.hasOwn(overrides, "previous_entry_hash") ? overrides.previous_entry_hash : null,
    entry_type: "EXECUTION_RESULT",
    execution_request_hash: overrides.execution_request_hash ?? signedReceipt.request_hash,
    receipt_hash: overrides.receipt_hash ?? sha256Tagged(signedReceipt),
    result_hash: overrides.result_hash ?? sha256Tagged(signedExecutionResult),
    policy_hash: Object.hasOwn(overrides, "policy_hash") ? overrides.policy_hash : signedReceipt.policy_provenance?.policy_hash ?? null,
    executor_id: overrides.executor_id ?? "test-runner-1",
    environment: overrides.environment ?? ENVIRONMENT,
    created_at: overrides.created_at ?? CREATED_AT,
    metadata: overrides.metadata ?? { workflow: { run_id: "12345" } }
  };
}

async function manualSignLedger(fixtures, ledgerEntry, {
  signingKey = fixtures.ledgerKey,
  authority = authorityFor(fixtures),
  signaturePayloadHash
} = {}) {
  const body = {
    schema: LEDGER_SCHEMA,
    ledger_entry: ledgerEntry,
    authority
  };
  const payloadHash = signaturePayloadHash ?? sha256String(canonicalizeJson(body));
  const signatureBody = canonicalizeJson({ ...body, signature_payload_hash: payloadHash });
  return {
    ...body,
    entry_hash: ledgerEntryHash(ledgerEntry),
    signature_payload_hash: payloadHash,
    verifiable_signature: {
      algorithm: "ED25519",
      key_id: authority.key_id,
      value: await signCanonical(signatureBody, signingKey.privatePem)
    }
  };
}

async function makeSignedResultWithWrongRequestHash(fixtures, signedReceipt) {
  const wrongHash = "f".repeat(64);
  const receiptHash = sha256HexCanonical(signedReceipt);
  const erBody = {
    schema_version: "mnde.execution_result.v2",
    result_id: "result-ledger-wrong-request",
    execution_id: signedReceipt.execution_id,
    execution_request_hash: wrongHash,
    execution_receipt_hash: receiptHash,
    decision: "ALLOW",
    status: "SUCCEEDED",
    executor: {
      id: "test-runner-1",
      type: "github_actions",
      identity_evidence: { type: "github_oidc", subject: "repo:org/repo:ref:refs/heads/main", issuer: "https://token.actions.githubusercontent.com" },
      identity_evidence_asserted_only: true
    },
    started_at: "2026-06-26T12:00:30.000Z",
    ended_at: CREATED_AT,
    recorded_at: CREATED_AT,
    effects: [{ type: "deployment", resource_id: "api-service", before: null, after: "sha256:" + "d".repeat(64) }],
    evidence: [{ type: "workflow_run", identifier: "run-999" }]
  };
  const executionResult = { ...erBody, result_hash: computeResultHash(erBody) };
  const envelopeBody = {
    schema: "mnde.signed_execution_result.v1",
    signed_at: CREATED_AT,
    trust_model: "offline-root-pinned",
    authority_chain_id: "mnde-ledger-test-chain",
    execution_result: executionResult,
    receipt_binding: {
      execution_receipt_hash: receiptHash,
      execution_request_hash: wrongHash,
      execution_id: signedReceipt.execution_id,
      receipt_schema: signedReceipt.schema_version
    },
    authority: {
      authority_id: fixtures.bundle.authority_id,
      authority_bundle_fingerprint: fixtures.bundle.root_key.fingerprint,
      signing_key_fingerprint: fingerprintOf(fixtures.resultKey.publicPem),
      key_id: fixtures.resultKey.keyId,
      key_role: "result",
      algorithm: "ED25519"
    }
  };
  const signature_payload_hash = sha256String(canonicalizeJson(envelopeBody));
  const signatureBody = canonicalizeJson({ ...envelopeBody, signature_payload_hash });
  return {
    ...envelopeBody,
    signature_payload_hash,
    verifiable_signature: {
      algorithm: "ED25519",
      key_id: fixtures.resultKey.keyId,
      value: await signCanonical(signatureBody, fixtures.resultKey.privatePem)
    }
  };
}

console.log("\nBehavioral - valid ledger entries:");

const F = await makeBundle();
const signedReceipt = await makeSignedReceipt(F);
const signedExecutionResult = await makeSignedResult(F, signedReceipt);

test("valid genesis ledger entry verifies", async () => {
  const entry = await makeLedger(F, signedReceipt, signedExecutionResult);
  const r = await verify(F, entry, signedReceipt, signedExecutionResult, {
    expectedLedgerId: LEDGER_ID,
    expectedEnvironment: ENVIRONMENT
  });
  assert.strictEqual(r.valid, true, r.message);
  assert.strictEqual(r.sequence_number, 1);
  assert.strictEqual(r.entry_hash, ledgerEntryHash(entry.ledger_entry));
});

test("valid sequence 2 verifies against previous entry", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const second = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 2,
    previousEntryHash: ledgerEntryHash(genesis.ledger_entry)
  });
  const r = await verify(F, second, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, true, r.message);
  assert.strictEqual(r.sequence_number, 2);
});

console.log("\nHostile - chain rules:");

test("genesis with non-null previous hash fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult, {
    previous_entry_hash: "sha256:" + "1".repeat(64)
  }));
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_GENESIS_PREVIOUS_HASH_INVALID");
});

test("sequence 2 without previous entry fails", async () => {
  const entry = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 2,
    previousEntryHash: "sha256:" + "2".repeat(64)
  });
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_PREVIOUS_REQUIRED");
});

test("sequence skips from 1 to 3 fails", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const third = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 3,
    previousEntryHash: ledgerEntryHash(genesis.ledger_entry)
  });
  const r = await verify(F, third, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_SEQUENCE_GAP");
});

test("wrong previous_entry_hash fails", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const second = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 2,
    previousEntryHash: "sha256:" + "3".repeat(64)
  });
  const r = await verify(F, second, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_PREVIOUS_HASH_MISMATCH");
});

test("different ledger_id from previous entry fails", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const second = await makeLedger(F, signedReceipt, signedExecutionResult, {
    ledgerId: "ledger-other",
    sequenceNumber: 2,
    previousEntryHash: ledgerEntryHash(genesis.ledger_entry)
  });
  const r = await verify(F, second, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_ID_MISMATCH");
});

test("expected environment mismatch fails", async () => {
  const entry = await makeLedger(F, signedReceipt, signedExecutionResult);
  const r = await verify(F, entry, signedReceipt, signedExecutionResult, { expectedEnvironment: "staging" });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_ENVIRONMENT_MISMATCH");
});

console.log("\nHostile - binding rules:");

test("receipt hash mismatch fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult, {
    receipt_hash: "sha256:" + "4".repeat(64)
  }));
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_RECEIPT_HASH_MISMATCH");
});

test("result hash mismatch fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult, {
    result_hash: "sha256:" + "5".repeat(64)
  }));
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_RESULT_HASH_MISMATCH");
});

test("receipt/result request hash mismatch fails", async () => {
  const hostileResult = await makeSignedResultWithWrongRequestHash(F, signedReceipt);
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, hostileResult));
  const r = await verify(F, entry, signedReceipt, hostileResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_REQUEST_HASH_MISMATCH");
});

console.log("\nHostile - ledger authority keys:");

test("ledger signed by receipt key fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult), {
    signingKey: F.receiptKey
  });
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_SIGNATURE_INVALID");
});

test("ledger signed by result key fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult), {
    signingKey: F.resultKey
  });
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_SIGNATURE_INVALID");
});

test("duplicate ledger key material across roles fails", async () => {
  const dup = await makeBundle({ duplicateLedgerWithReceipt: true });
  const entry = await manualSignLedger(dup, ledgerEntryFor(signedReceipt, signedExecutionResult));
  const r = await verify(dup, entry, signedReceipt, signedExecutionResult, { authorityBundle: dup.bundle, trustedRootFingerprint: dup.trustedRootFingerprint });
  assert.strictEqual(r.valid, false);
});

test("expired ledger key fails", async () => {
  const expired = await makeBundle({ ledgerValidUntil: "2026-01-01T00:00:00.000Z" });
  const entry = await manualSignLedger(expired, ledgerEntryFor(signedReceipt, signedExecutionResult));
  const r = await verify(expired, entry, signedReceipt, signedExecutionResult, { authorityBundle: expired.bundle, trustedRootFingerprint: expired.trustedRootFingerprint });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_KEY_EXPIRED");
});

test("revoked ledger key fails", async () => {
  const revoked = await makeBundle({ revokeLedger: true });
  const entry = await manualSignLedger(revoked, ledgerEntryFor(signedReceipt, signedExecutionResult));
  const r = await verify(revoked, entry, signedReceipt, signedExecutionResult, { authorityBundle: revoked.bundle, trustedRootFingerprint: revoked.trustedRootFingerprint });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_KEY_REVOKED");
});

test("malformed ledger public key returns structured invalid verdict", async () => {
  const malformed = await makeBundle({ malformedLedgerPublicKey: true });
  const entry = await manualSignLedger(malformed, ledgerEntryFor(signedReceipt, signedExecutionResult));
  const r = await verify(malformed, entry, signedReceipt, signedExecutionResult, { authorityBundle: malformed.bundle, trustedRootFingerprint: malformed.trustedRootFingerprint });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_KEY_MALFORMED");
});

console.log("\nHostile - tampering and metadata:");

test("tampered sequence_number fails signature payload hash", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const second = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 2,
    previousEntryHash: ledgerEntryHash(genesis.ledger_entry)
  });
  const tampered = {
    ...second,
    ledger_entry: { ...second.ledger_entry, sequence_number: 3 }
  };
  const r = await verify(F, tampered, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_SIGNATURE_PAYLOAD_HASH_INVALID");
});

test("tampered previous_entry_hash fails signature payload hash", async () => {
  const genesis = await makeLedger(F, signedReceipt, signedExecutionResult);
  const second = await makeLedger(F, signedReceipt, signedExecutionResult, {
    sequenceNumber: 2,
    previousEntryHash: ledgerEntryHash(genesis.ledger_entry)
  });
  const tampered = {
    ...second,
    ledger_entry: { ...second.ledger_entry, previous_entry_hash: "sha256:" + "6".repeat(64) }
  };
  const r = await verify(F, tampered, signedReceipt, signedExecutionResult, { previousLedgerEntry: genesis });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_SIGNATURE_PAYLOAD_HASH_INVALID");
});

test("future created_at fails", async () => {
  const entry = await makeLedger(F, signedReceipt, signedExecutionResult, {
    createdAt: "2026-06-26T12:20:00.000Z"
  });
  const r = await verify(F, entry, signedReceipt, signedExecutionResult, { nowMs: Date.parse(NOW), maxClockSkewMs: 300000 });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_CREATED_AT_FUTURE");
});

test("nested metadata token fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult, {
    metadata: { nested: { token: "secret" } }
  }));
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_METADATA_FORBIDDEN_FIELD");
});

test("case-variant Authorization fails", async () => {
  const entry = await manualSignLedger(F, ledgerEntryFor(signedReceipt, signedExecutionResult, {
    metadata: { Authorization: "Bearer abc" }
  }));
  const r = await verify(F, entry, signedReceipt, signedExecutionResult);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.code, "LEDGER_METADATA_FORBIDDEN_FIELD");
});

await testChain;
const passed = results.filter(Boolean).length;
const failed = results.filter((r) => !r).length;
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
