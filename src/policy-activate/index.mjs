// Policy activation orchestration (milestone B).
//
// Turns a reviewed compiled policy into the ACTIVE authority by REUSING the
// existing signing (signPolicyBundle) and activation (activateSignedPolicyBundle)
// modules — it adds no second crypto or trust implementation. It determines the
// next serial from authoritative state, signs the exact compiled policy hash,
// activates only after every trust check succeeds, re-reads authoritative state,
// and proves the requested hash is ACTIVE with the lifecycle classifier from A.
//
// No partial activation: state is mutated only inside activateSignedPolicyBundle,
// which commits atomically. If signing succeeds but any later step fails, the
// previous ACTIVE authority remains authoritative. Activation happens ONLY here
// (and its CLI) — never from an editor autosave, import, compile, or review edit.

import { existsSync, readFileSync } from "node:fs";

import { signPolicyBundle, activateSignedPolicyBundle, policyHash, POLICY_BUNDLE_SCHEMA, POLICY_BUNDLE_STATE_SCHEMA } from "../policy-bundles/index.mjs";
import { evaluatePolicyPhase, currentActivation, reviewReady, fingerprint, PHASE } from "../policy-lifecycle/index.mjs";

function isObject(v) { return typeof v === "object" && v !== null && !Array.isArray(v); }
function fail(reason, detail) { return { ok: false, reason, detail: detail ?? null }; }

// Read authoritative activation state read-only. Missing file => a fresh default
// (serial 0). A present-but-malformed file fails closed BEFORE any signing.
function readActivationState(statePath) {
  if (typeof statePath !== "string" || statePath.length === 0) return { ok: false, reason: "STATE_PATH_REQUIRED" };
  if (!existsSync(statePath)) return { ok: true, state: { schema_version: POLICY_BUNDLE_STATE_SCHEMA, mode: "enforce", serial_floors: {}, serial_digests: {}, consumed_rollback_authorizations: [], activation_events: [] } };
  let raw;
  try { raw = readFileSync(statePath, "utf8"); } catch (e) { return { ok: false, reason: "STATE_UNREADABLE", detail: e?.message ?? String(e) }; }
  let state;
  try { state = JSON.parse(raw); } catch { return { ok: false, reason: "MALFORMED_STATE" }; }
  if (!isObject(state) || state.schema_version !== POLICY_BUNDLE_STATE_SCHEMA || state.mode !== "enforce" || !isObject(state.serial_floors) || !isObject(state.serial_digests) || !Array.isArray(state.activation_events)) {
    return { ok: false, reason: "MALFORMED_STATE" };
  }
  return { ok: true, state };
}

function nextSerial(state, policyId) {
  let high = state.serial_floors?.[policyId] ?? 0;
  for (const e of state.activation_events || []) if (e && e.policy_id === policyId && Number.isSafeInteger(e.serial)) high = Math.max(high, e.serial);
  for (const s of Object.keys(state.serial_digests?.[policyId] ?? {})) { const n = Number(s); if (Number.isSafeInteger(n)) high = Math.max(high, n); }
  return high + 1;
}

function signerFingerprint(authorityBundle, keyId) {
  const entry = authorityBundle?.keys?.policy?.find?.((k) => k && k.key_id === keyId);
  return entry?.fingerprint ?? null;
}

// input: { policyDocument, keyId, privateKeyPem, authorityBundle, trustedRootFingerprint,
//          statePath, now, issuedAt?, bundleId?, serial?(override), profile? }
// deps (for tests): { signPolicyBundle, activateSignedPolicyBundle, evaluatePolicyPhase,
//                     policyHash, readActivationState }
export async function activatePolicy(input, deps = {}) {
  const D = {
    signPolicyBundle,
    activateSignedPolicyBundle,
    evaluatePolicyPhase,
    policyHash,
    readActivationState,
    ...deps
  };
  const { policyDocument, keyId, privateKeyPem, authorityBundle, trustedRootFingerprint, statePath, now, issuedAt, bundleId, profile } = input || {};

  // 1. The policy must be a reviewed, compiled policy (READY), never a raw draft.
  const ready = reviewReady(policyDocument);
  if (!ready.ok) return fail("POLICY_NOT_READY", ready.issues.join("; "));

  // 2. Required signing + activation inputs (fail closed on anything missing).
  if (typeof keyId !== "string" || keyId.length === 0) return fail("MISSING_SIGNER", "no signing key id");
  if (typeof privateKeyPem !== "string" || privateKeyPem.length === 0) return fail("MISSING_SIGNER", "no signing private key");
  if (!isObject(authorityBundle)) return fail("MISSING_AUTHORITY_BUNDLE");
  if (typeof trustedRootFingerprint !== "string" || trustedRootFingerprint.length === 0) return fail("MISSING_TRUSTED_ROOT");
  if (typeof statePath !== "string" || statePath.length === 0) return fail("STATE_PATH_REQUIRED");
  if (typeof now !== "string" || now.length === 0) return fail("MISSING_NOW");

  // 3. Trust initialization: the out-of-band root fingerprint must bind to the
  // authority bundle's own root. In production this is mandatory (fail closed).
  const rootFp = authorityBundle?.root_key?.fingerprint;
  if (profile === "production" && (typeof rootFp !== "string" || rootFp.length === 0)) return fail("PRODUCTION_TRUST_ROOT_REQUIRED");
  if (rootFp && rootFp !== trustedRootFingerprint) return fail("TRUST_ROOT_MISMATCH");

  // 4. Determine the next serial from authoritative state.
  const pre = D.readActivationState(statePath);
  if (!pre.ok) return fail(pre.reason === "STATE_PATH_REQUIRED" ? "STATE_PATH_REQUIRED" : "MALFORMED_STATE", pre.detail);
  const previous = currentActivation(pre.state, policyDocument.policy_id);
  const serial = Number.isSafeInteger(input.serial) ? input.serial : nextSerial(pre.state, policyDocument.policy_id);

  const expectedHash = D.policyHash(policyDocument);

  // 5. Sign the exact compiled policy hash (signPolicyBundle hashes the document).
  let bundle;
  try {
    bundle = await D.signPolicyBundle({
      bundle_id: bundleId ?? `${policyDocument.policy_id}-${serial}`,
      policy_id: policyDocument.policy_id,
      serial,
      issued_at: issuedAt ?? now,
      policy_document: policyDocument
    }, { keyId, privateKeyPem });
  } catch (e) {
    // Covers an unreadable/encrypted/invalid signing key, etc. No state touched.
    return fail("SIGNING_FAILED", e?.message ?? String(e));
  }

  // 6. Verify the freshly signed bundle BEFORE activation: it must be well-formed
  // and bind to the exact compiled policy we intended.
  if (!isObject(bundle) || bundle.schema_version !== POLICY_BUNDLE_SCHEMA) return fail("BUNDLE_MALFORMED");
  if (bundle.policy_id !== policyDocument.policy_id || bundle.serial !== serial) return fail("BUNDLE_IDENTITY_MISMATCH");
  if (bundle.policy_hash !== expectedHash) return fail("POLICY_HASH_MISMATCH", `expected ${expectedHash}, bundle carries ${bundle.policy_hash}`);
  if (D.policyHash(bundle.policy_document) !== expectedHash) return fail("POLICY_HASH_MISMATCH", "bundle document does not hash to the compiled policy");

  // 7. Activate. This re-verifies the signature against the trusted authority,
  // enforces the serial floor, and writes state atomically — only on full success.
  let activation;
  try {
    activation = await D.activateSignedPolicyBundle({ bundle, authorityBundle, trustedRootFingerprint, statePath, now });
  } catch (e) {
    return fail("ACTIVATION_ERROR", e?.message ?? String(e));
  }
  if (!activation || activation.ok !== true) return fail("ACTIVATION_REFUSED", activation?.reason ?? "unknown");

  // 8. Re-read authoritative state after activation.
  const post = D.readActivationState(statePath);
  if (!post.ok) return fail("STATE_REREAD_FAILED", post.reason);

  // 9. Prove the requested hash is now ACTIVE using the lifecycle classifier (A).
  const phase = D.evaluatePolicyPhase({ policyDocument, activeBundle: bundle, state: post.state });
  if (phase.phase !== PHASE.ACTIVE) return fail("ACTIVE_CONFIRMATION_FAILED", `classifier reports ${phase.phase}`);

  // 10. Success — the caller reports previous/new authority, hash, serial, signer.
  return {
    ok: true,
    result: "ACTIVATED",
    previous: previous ? { policy_id: previous.policy_id, serial: previous.serial } : null,
    current: { policy_id: policyDocument.policy_id, serial, policy_hash: bundle.policy_hash, fingerprint: fingerprint(bundle.policy_hash) },
    policy_hash: bundle.policy_hash,
    serial,
    signer_key_id: keyId,
    signer_fingerprint: signerFingerprint(authorityBundle, keyId),
    bundle,
    provenance: activation.policyBundleProvenance
  };
}
