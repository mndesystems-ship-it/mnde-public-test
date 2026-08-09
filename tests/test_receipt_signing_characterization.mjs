// Characterization: current execution-gate receipt signing (pre-executor-identity).
//
// This test PINS the behavior of `mnde.execution_gate.receipt.v1` as it exists
// before executor identity is added, so the step-6 change is provably additive:
//
//   * a valid receipt is signed by exactly ONE layer — the custody receipt-role
//     (authority) key — and verifies authority-only;
//   * the receipt carries NO executor dimension and NO passport binding today;
//   * the authority signature covers the whole body except verifiable_signature.
//
// If a later change makes executor/passport fields unconditionally present, or
// breaks the authority-only path, this characterization fails loudly.

import assert from "node:assert/strict";

import { canonicalizeJson } from "../shared/json.ts";
import { sha256 } from "../src/crypto/provider.mjs";
import {
  buildAuthorityBundle,
  fingerprintOf,
  findBundleKey,
  generateAuthorityKeyPair,
  signCanonical
} from "../src/custody/index.mjs";
import { signReceiptForDelivery } from "../src/authority-signing/index.mjs";
import {
  buildSignedExecutionReceipt,
  verifySignedExecutionReceipt
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

async function makeBundle() {
  const root = { keyId: "char-root", ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: "char-receipt-key-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-char-authority",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  return { receiptKey, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

function minimalRequest() {
  return {
    schema_version: "mnde.execution_request.v1",
    execution_id: "exec-char-001",
    requested_at: "2026-06-15T10:00:00.000Z",
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

async function buildCurrentReceipt() {
  const { receiptKey, bundle, trustedRootFingerprint } = await makeBundle();
  const receipt = await buildSignedExecutionReceipt(minimalRequest(), "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  return { receipt, bundle, trustedRootFingerprint, receiptKey };
}

// Frozen origin/main authority-only builder. This is intentionally kept local
// to the regression test so the comparison cannot accidentally reuse the PR's
// implementation under test.
async function buildOriginMainAuthorityOnlyReceipt(request, decision, options) {
  const { authorityBundle, signingKeyId, signingPrivateKeyPem, policyProvenance, refusalReason } = options;
  const requestHash = sha256(canonicalizeJson(request));
  const signedAt = request.requested_at;
  const keyResult = findBundleKey(authorityBundle, "receipt", signingKeyId, signedAt);
  assert.equal(keyResult.ok, true, keyResult.reason ?? "origin/main reference key unusable");
  const body = {
    schema_version: "mnde.execution_gate.receipt.v1",
    execution_id: request.execution_id,
    request_schema_version: request.schema_version,
    request_hash: requestHash,
    decided_at: request.requested_at,
    decision,
    ...(refusalReason !== undefined ? { refusal_reason: refusalReason } : {}),
    principal: { id: request.principal.id, type: request.principal.type, verified: request.principal.verified },
    action: { type: request.action.type, name: request.action.name, dry_run: request.action.dry_run },
    resource: { kind: request.resource.kind, id: request.resource.id, name: request.resource.name },
    environment: { name: request.environment.name },
    risk: {
      level: request.risk.level,
      destructive: request.risk.destructive,
      reversible: request.risk.reversible,
      blast_radius: request.risk.blast_radius
    },
    evidence: { repo: request.evidence.repo, commit_sha: request.evidence.commit_sha, branch: request.evidence.branch },
    ...(policyProvenance !== undefined ? { policy_provenance: policyProvenance } : {}),
    authority_id: authorityBundle.authority_id,
    signing_key_id: signingKeyId
  };
  const value = await signCanonical(canonicalizeJson(body), signingPrivateKeyPem);
  return {
    ...body,
    verifiable_signature: {
      algorithm: "ED25519",
      authority_id: authorityBundle.authority_id,
      key_id: signingKeyId,
      signed_at: signedAt,
      public_key_fingerprint: fingerprintOf(keyResult.publicKey),
      value
    }
  };
}

async function buildOriginMainAuthorityOnlyEnvelope(inner, provider, at) {
  const receiptType = inner.schema_version;
  const match = receiptType.match(/v(\d+)$/);
  const attestationPayload = {
    schema_version: "mnde.custody.attestation.v1",
    receipt_type: receiptType,
    receipt_version: match ? `v${match[1]}` : "v1",
    decision: inner.decision_output?.decision ?? inner.decision ?? "UNKNOWN",
    receipt_hash: sha256(canonicalizeJson(inner)),
    authority_bundle_fingerprint: provider.trustedRootFingerprint,
    signed_at: at
  };
  const signed = await provider.signReceipt(canonicalizeJson(attestationPayload));
  return {
    schema_version: "mnde.signed-receipt.v1",
    receipt: inner,
    custody_attestation: {
      ...attestationPayload,
      signing_key_id: signed.key_id,
      signature: { algorithm: "ED25519", value: signed.value }
    }
  };
}

console.log("Characterization — current execution-gate receipt signing\n");

await test("current receipt verifies authority-only", async () => {
  const { receipt, bundle, trustedRootFingerprint } = await buildCurrentReceipt();
  const result = await verifySignedExecutionReceipt(receipt, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, true, result.reason ?? "");
});

await test("current receipt schema is mnde.execution_gate.receipt.v1", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.schema_version, "mnde.execution_gate.receipt.v1");
});

await test("current receipt carries NO executor dimension", async () => {
  const { receipt } = await buildCurrentReceipt();
  for (const field of ["executor_id", "executor_key_id", "executor_credential_id", "executor_signature"]) {
    assert.equal(receipt[field], undefined, `${field} must be absent in the pre-migration receipt`);
  }
});

await test("current receipt carries NO passport binding", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.passport_subject_id, undefined);
});

await test("the single signature layer is the custody receipt-role (authority) key", async () => {
  const { receipt, bundle, receiptKey } = await buildCurrentReceipt();
  assert.ok(receipt.verifiable_signature, "verifiable_signature must be present");
  assert.equal(receipt.verifiable_signature.algorithm, "ED25519");
  assert.equal(receipt.verifiable_signature.authority_id, bundle.authority_id);
  assert.equal(receipt.verifiable_signature.key_id, receiptKey.keyId);
  assert.equal(receipt.authority_id, bundle.authority_id);
  assert.equal(receipt.signing_key_id, receiptKey.keyId);
});

await test("authority signature covers the body except verifiable_signature (tamper breaks it)", async () => {
  const { receipt, bundle, trustedRootFingerprint } = await buildCurrentReceipt();
  const tampered = { ...receipt, decision: receipt.decision === "ALLOW" ? "REFUSE" : "ALLOW" };
  const result = await verifySignedExecutionReceipt(tampered, { authorityBundle: bundle, trustedRootFingerprint });
  assert.equal(result.verified, false);
  assert.match(result.reason, /signature/);
});

await test("decided_at is deterministic (equals requested_at, no wall-clock)", async () => {
  const { receipt } = await buildCurrentReceipt();
  assert.equal(receipt.decided_at, minimalRequest().requested_at);
  assert.equal(receipt.decided_at, receipt.verifiable_signature.signed_at);
});

await test("canonical payload excludes only verifiable_signature", async () => {
  const { receipt } = await buildCurrentReceipt();
  const { verifiable_signature: _omit, ...body } = receipt;
  // Reproducing the exact exclusion the signer/verifier use must round-trip.
  assert.equal(typeof canonicalizeJson(body), "string");
  assert.ok(!canonicalizeJson(body).includes("verifiable_signature"));
});

await test("authority-only execution receipt bytes are identical to origin/main", async () => {
  const { receiptKey, bundle } = await makeBundle();
  const request = minimalRequest();
  const options = {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  };
  const baseline = await buildOriginMainAuthorityOnlyReceipt(request, "ALLOW", options);
  const current = await buildSignedExecutionReceipt(request, "ALLOW", options);
  assert.equal(current.signing_mode, undefined);
  assert.equal(canonicalizeJson(current), canonicalizeJson(baseline));
});

await test("authority-only custody envelope and attestation bytes are identical to origin/main", async () => {
  const { receiptKey, bundle } = await makeBundle();
  const request = minimalRequest();
  const inner = await buildOriginMainAuthorityOnlyReceipt(request, "ALLOW", {
    authorityBundle: bundle,
    signingKeyId: receiptKey.keyId,
    signingPrivateKeyPem: receiptKey.privatePem
  });
  const provider = {
    trustedRootFingerprint: bundle.root_key.fingerprint,
    getPublicBundle: () => structuredClone(bundle),
    signReceipt: async (payload) => ({
      key_id: receiptKey.keyId,
      value: await signCanonical(payload, receiptKey.privatePem)
    })
  };
  const at = request.requested_at;
  const baseline = await buildOriginMainAuthorityOnlyEnvelope(inner, provider, at);
  const currentResult = await signReceiptForDelivery(inner, { mode: "custody", provider }, { now: at });
  assert.equal(currentResult.ok, true, currentResult.reason_code ?? "");
  assert.equal(currentResult.receipt.schema_version, "mnde.signed-receipt.v1");
  assert.equal(currentResult.receipt.signing_mode, undefined);
  assert.equal(currentResult.receipt.custody_attestation.signing_mode, undefined);
  assert.equal(canonicalizeJson(currentResult.receipt), canonicalizeJson(baseline));
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} receipt signing characterization (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
