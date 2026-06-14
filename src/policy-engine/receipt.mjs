// Policy Engine receipts.
//
// Wraps a deterministic policy-engine decision into a signed, offline-verifiable
// receipt on the SAME Ed25519 authority chain as every other MNDe receipt (same
// signing key, same authority manifest, same verification primitives). This is
// how the policy engine and the receipt/verification system are combined into a
// single trust surface: one key, one authority, one way to verify.
//
// Verification replays the decision by re-running the deterministic engine on the
// embedded request + policy + authorities, then checks the signature against the
// trusted authority manifest. A tampered request, policy, or decision fails closed.

import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson, parseStrictJson } from "../../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM, signReceiptPayload, verifyReceiptPayloadSignature } from "../../shared/index.ts";
import { findAuthorityReceiptKey, loadAuthorityBundle, loadAuthorityBundleForReceipt } from "../../shared/authority-manifest.mjs";
import { evaluatePolicyRequest } from "./index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCHEMA = "mnde.pe.receipt.v1";

function canonicalPayloadWithoutSignature(receiptLike) {
  const { verifiable_signature: _omit, ...payload } = receiptLike;
  return canonicalizeJson(payload);
}

// Build a signed receipt for a policy-engine decision.
export function buildPolicyReceipt(request, policy, options = {}) {
  const authorities = Array.isArray(options.authorities) ? options.authorities : [];
  const trustAnchors = options.trustAnchors;
  const approvalTrustAnchors = options.approvalTrustAnchors;
  const approvalEnforced = Boolean(approvalTrustAnchors);
  const approvals = Array.isArray(options.approvals) ? options.approvals : [];
  const decision = evaluatePolicyRequest(request, policy, { authorities, now: options.now, trustAnchors, approvals, approvalTrustAnchors });

  const payload = {
    schema_version: SCHEMA,
    canonical_request: canonicalizeJson(request),
    canonical_policy: canonicalizeJson(policy),
    authorities,
    trust_enforced: Boolean(trustAnchors),
    // Embedded only when approval enforcement is active, so non-enforced receipts
    // are unchanged. Approval trust anchors are NOT embedded (verifier-supplied).
    ...(approvalEnforced ? { approval_enforced: true, approvals } : {}),
    request_hash: decision.request_hash,
    policy_hash: decision.policy_hash,
    authority_chain_hash: decision.authority_chain_hash,
    decision_output: decision
  };

  const bundle = loadAuthorityBundle(repoRoot, { kind: "local" });
  if (!bundle.ok) throw new Error(`ERR_AUTHORITY_MANIFEST_INVALID: ${bundle.reason}`);
  const activeKey = bundle.manifest.active_keys?.[0];
  if (!activeKey) throw new Error("ERR_AUTHORITY_NO_ACTIVE_KEY");

  return {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: bundle.manifest.authority_id,
      key_id: activeKey.key_id,
      public_key_fingerprint: activeKey.public_key_fingerprint,
      signed_at: new Date().toISOString(),
      value: signReceiptPayload(canonicalPayloadWithoutSignature(payload))
    }
  };
}

// Verify a policy-engine receipt: replay the decision and check the signature.
export function verifyPolicyReceipt(receipt, options = {}) {
  if (!receipt || receipt.schema_version !== SCHEMA) return { verified: false, reason: "unsupported schema" };

  const parsedRequest = parseStrictJson(receipt.canonical_request);
  const parsedPolicy = parseStrictJson(receipt.canonical_policy);
  if (!parsedRequest.ok || !parsedPolicy.ok) return { verified: false, reason: "canonical request/policy parse failed" };

  // A receipt issued under a cryptographic authority chain can only be verified
  // with trust anchors the verifier supplies out of band.
  if (receipt.trust_enforced && !options.trustAnchors) {
    return { verified: false, reason: "trust anchors required to verify a trust-enforced receipt" };
  }
  if (receipt.approval_enforced && !options.approvalTrustAnchors) {
    return { verified: false, reason: "approval trust anchors required to verify an approval-enforced receipt" };
  }

  const original = receipt.decision_output ?? {};
  const replay = evaluatePolicyRequest(parsedRequest.value, parsedPolicy.value, {
    authorities: Array.isArray(receipt.authorities) ? receipt.authorities : [],
    now: original.evaluated_at,
    trustAnchors: receipt.trust_enforced ? options.trustAnchors : undefined,
    approvals: receipt.approval_enforced ? (Array.isArray(receipt.approvals) ? receipt.approvals : []) : undefined,
    approvalTrustAnchors: receipt.approval_enforced ? options.approvalTrustAnchors : undefined
  });

  for (const field of ["decision", "reason_code", "request_hash", "policy_hash", "authority_chain_hash", "decision_hash"]) {
    if (replay[field] !== original[field]) return { verified: false, reason: `decision drift: ${field}` };
  }
  if (receipt.request_hash !== original.request_hash || receipt.policy_hash !== original.policy_hash || receipt.authority_chain_hash !== original.authority_chain_hash) {
    return { verified: false, reason: "receipt header hashes do not match decision" };
  }

  const signature = receipt.verifiable_signature;
  if (!signature) return { verified: false, reason: "missing signature" };
  const bundle = loadAuthorityBundleForReceipt(repoRoot, signature.authority_id);
  if (!bundle.ok) return { verified: false, reason: bundle.reason };
  const keyResult = findAuthorityReceiptKey(bundle.manifest, { authorityId: signature.authority_id, keyId: signature.key_id, signedAt: signature.signed_at });
  if (!keyResult.ok) return { verified: false, reason: keyResult.reason };
  if (signature.public_key_fingerprint !== keyResult.key.public_key_fingerprint) return { verified: false, reason: "fingerprint mismatch" };

  const ok = verifyReceiptPayloadSignature(canonicalPayloadWithoutSignature(receipt), signature.value, keyResult.key.public_key);
  return ok
    ? { verified: true, reason: null, decision: original.decision, reason_code: original.reason_code }
    : { verified: false, reason: "signature invalid" };
}

export const POLICY_RECEIPT_SCHEMA = SCHEMA;
