// Custody-signed execution gate receipt builder.
//
// Extends the deterministic execution-gate receipt with an Ed25519 signature
// from the MNDe authority bundle. The signature covers a canonical serialisation
// of the receipt body with the `verifiable_signature` field excluded — the same
// pattern used by the policy-engine receipt and the authority-signing module.
//
// decided_at and verifiable_signature.signed_at are both taken from
// request.requested_at (NOT wall-clock) so the output is fully deterministic and
// reproducible from the original request.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { fingerprintOf, findBundleKey, signCanonical } from "../custody/index.mjs";

export const SIGNED_EXECUTION_RECEIPT_SCHEMA = "mnde.execution_gate.receipt.v1";

// Canonical payload = receipt body with verifiable_signature omitted.
function canonicalPayloadWithoutSignature(receiptBody) {
  const { verifiable_signature: _omit, ...payload } = receiptBody;
  return canonicalizeJson(payload);
}

// sha256 of canonicalizeJson(request).
function hashRequest(request) {
  return sha256(canonicalizeJson(request));
}

// Build a custody-signed execution gate receipt.
//
// options:
//   authorityBundle        — loaded mnde.authority.bundle.v1 object (public material only)
//   signingKeyId           — key_id of the receipt key in the bundle to sign with
//   signingPrivateKeyPem   — Ed25519 private key PEM (never embedded in output)
//   policyProvenance       — optional { policy_id, serial, policy_hash, bundle_id, bundle_digest }
//   decision               — "ALLOW" | "REFUSE"
//   refusalReason          — string | undefined
export async function buildSignedExecutionReceipt(request, decision, options) {
  const { authorityBundle, signingKeyId, signingPrivateKeyPem, policyProvenance, refusalReason } = options;

  if (!authorityBundle || !signingKeyId || !signingPrivateKeyPem) {
    throw new Error("buildSignedExecutionReceipt: authorityBundle, signingKeyId, and signingPrivateKeyPem are required");
  }

  const requestHash = hashRequest(request);

  // Deterministic timestamp — never wall-clock.
  const signedAt = request.requested_at;

  // Resolve the signing key from the bundle to obtain its public key for fingerprint.
  const keyResult = findBundleKey(authorityBundle, "receipt", signingKeyId, signedAt);
  if (!keyResult.ok) {
    throw new Error(`buildSignedExecutionReceipt: signing key not usable: ${keyResult.reason}`);
  }
  const publicKeyFingerprint = fingerprintOf(keyResult.publicKey);

  // Build the receipt body (without the signature field).
  const body = {
    schema_version: SIGNED_EXECUTION_RECEIPT_SCHEMA,
    execution_id: request.execution_id,
    request_schema_version: request.schema_version,
    request_hash: requestHash,
    // decided_at is deterministic — NOT wall-clock.
    decided_at: request.requested_at,
    decision,
    ...(refusalReason !== undefined ? { refusal_reason: refusalReason } : {}),
    principal: {
      id: request.principal.id,
      type: request.principal.type,
      verified: request.principal.verified
    },
    action: {
      type: request.action.type,
      name: request.action.name,
      dry_run: request.action.dry_run
    },
    resource: {
      kind: request.resource.kind,
      id: request.resource.id,
      name: request.resource.name
    },
    environment: {
      name: request.environment.name
    },
    risk: {
      level: request.risk.level,
      destructive: request.risk.destructive,
      reversible: request.risk.reversible,
      blast_radius: request.risk.blast_radius
    },
    evidence: {
      repo: request.evidence.repo,
      commit_sha: request.evidence.commit_sha,
      branch: request.evidence.branch
    },
    ...(policyProvenance !== undefined ? { policy_provenance: policyProvenance } : {}),
    authority_id: authorityBundle.authority_id,
    signing_key_id: signingKeyId
  };

  // Sign the canonical form of the body (verifiable_signature absent).
  const canonical = canonicalPayloadWithoutSignature(body);
  const signatureValue = await signCanonical(canonical, signingPrivateKeyPem);

  return {
    ...body,
    verifiable_signature: {
      algorithm: "ED25519",
      authority_id: authorityBundle.authority_id,
      key_id: signingKeyId,
      signed_at: signedAt,
      public_key_fingerprint: publicKeyFingerprint,
      value: signatureValue
    }
  };
}
