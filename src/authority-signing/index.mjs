// Live receipt signing — the integration layer between a deterministic receipt
// builder and a key-custody provider.
//
//   Decision Engine -> Receipt Builder -> [Signing Adapter] -> Custody Provider
//                                              (this module)
//
// Signing is a separate authority concern: decision engines never import custody
// and never sign. A built receipt is handed here; in legacy mode it passes
// through byte-for-byte, in custody mode it is wrapped in an additive envelope
// that carries a production custody attestation. The inner receipt is never
// mutated, so the existing verifier keeps its byte-for-byte guarantees.
//
//   mnde.signed-receipt.v1 = { schema_version, receipt: <inner, untouched>,
//                              custody_attestation: { ... , signature } }
//
// Verification is fully offline against a published authority bundle: the inner
// receipt verifies through the existing unified verifier, AND the custody
// attestation verifies against the bundle (root trust, bundle signature, key
// validity window, revocation, attestation signature).

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import {
  createCustody,
  findBundleKey,
  verifyAgainstBundle,
  verifyAuthorityBundle,
  createExternalSignerCustody
} from "../custody/index.mjs";

export const SIGNED_RECEIPT_SCHEMA = "mnde.signed-receipt.v1";
export const ATTESTATION_SCHEMA = "mnde.custody.attestation.v1";

function sha256Hex(text) {
  return sha256(text);
}
function decisionOf(receipt) {
  if (typeof receipt?.decision_output?.decision === "string") return receipt.decision_output.decision;
  if (typeof receipt?.decision === "string") return receipt.decision;
  return "UNKNOWN";
}
function versionOf(schema) {
  const match = typeof schema === "string" ? schema.match(/v(\d+)$/) : null;
  return match ? `v${match[1]}` : "v1";
}

// Map low-level custody/bundle/key reasons onto distinct, stable wire codes.
function custodyConfigCode(reason) {
  const text = String(reason ?? "");
  if (/cannot read MNDE_AUTHORITY_BUNDLE|MNDE_AUTHORITY_BUNDLE not configured/.test(text)) return "ERR_CUSTODY_BUNDLE_MISSING";
  if (/not valid JSON|not an mnde\.authority\.bundle/.test(text)) return "ERR_CUSTODY_BUNDLE_INVALID";
  if (/revoked|KEY_REVOKED/.test(text)) return "ERR_CUSTODY_KEY_REVOKED";
  if (/KEY_EXPIRED|not usable/.test(text)) return "ERR_CUSTODY_KEY_EXPIRED";
  if (/fingerprint mismatch|does not match the bundle key/.test(text)) return "ERR_CUSTODY_KEY_MISMATCH";
  if (/EXTERNAL_SIGNER_CMD|external signer/.test(text)) return "ERR_CUSTODY_SIGNER_UNAVAILABLE";
  if (/SIGNING_KEY|EXTERNAL_SIGNER_PUBLIC_KEY|no published .* key|not configured|not a valid public key/.test(text)) return "ERR_CUSTODY_KEY_MISSING";
  if (/unknown MNDE_KEY_CUSTODY/.test(text)) return "ERR_CUSTODY_MISCONFIGURED";
  return "ERR_CUSTODY_MISCONFIGURED";
}
function bundleCode(reason) {
  return reason === "BUNDLE_STALE" ? "ERR_CUSTODY_BUNDLE_STALE" : "ERR_CUSTODY_BUNDLE_INVALID";
}
function keyCode(reason) {
  if (reason === "KEY_EXPIRED") return "ERR_CUSTODY_KEY_EXPIRED";
  if (reason === "KEY_REVOKED") return "ERR_CUSTODY_KEY_REVOKED";
  return "ERR_CUSTODY_KEY_MISSING";
}

// Resolve signing configuration. Default legacy; custody is opt-in and fails
// closed — a misconfiguration never silently downgrades to legacy.
export async function loadSigningConfig(env = process.env) {
  const requested = env.MNDE_RECEIPT_SIGNING_MODE;
  // Both "custody" (local-demo / file-backed-production) and "external-signer"
  // engage custody signing. Anything else is legacy pass-through.
  if (requested !== "custody" && requested !== "external-signer") return { ok: true, mode: "legacy" };

  let provider;
  if (requested === "external-signer") {
    try {
      provider = createExternalSignerCustody(env);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, mode: "custody", reason_code: custodyConfigCode(detail), detail };
    }
  } else {
    const custody = await createCustody(env);
    if (!custody.ok) return { ok: false, mode: "custody", reason_code: custodyConfigCode(custody.reason), detail: custody.reason };
    provider = custody.provider;
  }

  const bundle = provider.getPublicBundle();
  const check = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint });
  if (!check.ok) return { ok: false, mode: "custody", reason_code: bundleCode(check.reason), detail: check.reason };

  // mode is normalized to "custody" so signReceiptForDelivery engages; signer_mode
  // records which provider (custody | external-signer) is in use.
  return { ok: true, mode: "custody", signer_mode: provider.mode, provider, fingerprint: provider.trustedRootFingerprint };
}

// Sign a built receipt for delivery. Legacy mode is a pass-through. Custody mode
// returns an mnde.signed-receipt.v1 envelope, or fails closed with a distinct
// reason code. Never logs or returns key material.
export async function signReceiptForDelivery(receipt, signingConfig, options = {}) {
  if (!signingConfig || signingConfig.mode !== "custody") return { ok: true, receipt };
  const provider = signingConfig.provider;
  if (!provider) return { ok: false, reason_code: "ERR_CUSTODY_UNAVAILABLE", detail: "no custody provider" };

  const at = options.now ?? new Date().toISOString();
  const bundle = provider.getPublicBundle();

  // Re-validate the bundle at signing time (catches a bundle gone stale).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint, now: at });
  if (!bundleCheck.ok) return { ok: false, reason_code: bundleCode(bundleCheck.reason), detail: bundleCheck.reason };

  const receiptType = typeof receipt?.schema_version === "string" ? receipt.schema_version : "unknown";
  const attestationPayload = {
    schema_version: ATTESTATION_SCHEMA,
    receipt_type: receiptType,
    receipt_version: versionOf(receiptType),
    decision: decisionOf(receipt),
    receipt_hash: sha256Hex(canonicalizeJson(receipt)),
    authority_bundle_fingerprint: provider.trustedRootFingerprint,
    // Activation binding (mnde.activation.v1): the preflight-verified id of the
    // active authority transition this decision was produced under. Part of the
    // signed attestation payload — tampering breaks the attestation signature.
    // The inner receipt stays byte-for-byte untouched.
    ...(typeof signingConfig.activation_id === "string" && signingConfig.activation_id.length > 0
      ? { activation_id: signingConfig.activation_id }
      : {}),
    signed_at: at
  };

  let signed;
  try {
    signed = await provider.signReceipt(canonicalizeJson(attestationPayload));
  } catch (error) {
    // error.message comes from custody — paths/reasons only, never key bytes.
    return { ok: false, reason_code: "ERR_CUSTODY_SIGNING_FAILED", detail: error?.message ?? String(error) };
  }

  // The key that actually signed must be valid in the published bundle.
  const keyCheck = findBundleKey(bundle, "receipt", signed.key_id, at);
  if (!keyCheck.ok) return { ok: false, reason_code: keyCode(keyCheck.reason), detail: keyCheck.reason };

  return {
    ok: true,
    receipt: {
      schema_version: SIGNED_RECEIPT_SCHEMA,
      receipt,
      custody_attestation: {
        ...attestationPayload,
        signing_key_id: signed.key_id,
        signature: { algorithm: "ED25519", value: signed.value }
      }
    }
  };
}

// Verify ONLY the custody attestation of an envelope against a published bundle.
// Offline; no network. The inner receipt is verified separately by the caller
// (the unified verifier) so this stays a focused production-trust interface.
export async function verifyCustodyAttestation(envelope, options = {}) {
  if (!envelope || envelope.schema_version !== SIGNED_RECEIPT_SCHEMA) {
    return { ok: false, reason: "not a custody-signed receipt" };
  }
  const attestation = envelope.custody_attestation;
  const inner = envelope.receipt;
  if (!attestation || !inner) return { ok: false, reason: "malformed signed receipt" };

  const bundle = options.authorityBundle;
  if (!bundle) return { ok: false, reason: "authority bundle required to verify a custody-signed receipt" };

  const now = options.now ?? new Date().toISOString();

  // 1) Trust the bundle (root anchor out of band, bundle signature, staleness).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: options.trustedRootFingerprint, now, maxAgeMs: options.maxAgeMs });
  if (!bundleCheck.ok) return { ok: false, reason: `bundle: ${bundleCheck.reason}` };

  // 2) The receipt must be bound to THIS bundle.
  if (attestation.authority_bundle_fingerprint !== bundle.root_key?.fingerprint) {
    return { ok: false, reason: "authority fingerprint mismatch" };
  }

  // 3) The inner receipt must be byte-identical to what was attested.
  if (sha256Hex(canonicalizeJson(inner)) !== attestation.receipt_hash) {
    return { ok: false, reason: "receipt hash mismatch" };
  }

  // 4) Verify the attestation signature against the bundle's receipt key
  //    (key lookup honors validity window + revocation).
  const { signing_key_id, signature, ...signedFields } = attestation;
  const sigValue = signature?.value;
  if (typeof sigValue !== "string") return { ok: false, reason: "missing attestation signature" };
  const check = await verifyAgainstBundle(canonicalizeJson(signedFields), sigValue, "receipt", signing_key_id, signedFields.signed_at, bundle);
  if (!check.ok) return { ok: false, reason: check.reason };

  return {
    ok: true,
    decision: attestation.decision,
    signing_key_id,
    authority_fingerprint: attestation.authority_bundle_fingerprint,
    trust_source: "ROOT_PINNED_AUTHORITY_BUNDLE",
    signed_at: attestation.signed_at,
    receipt_hash: attestation.receipt_hash,
    // Activation binding, when the producing runtime was activation-bound.
    // Covered by the attestation signature verified above.
    activation_id: typeof attestation.activation_id === "string" ? attestation.activation_id : null
  };
}
