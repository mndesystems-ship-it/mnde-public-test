// Independently verify an mnde.execution-grant.v1 against a published authority
// bundle — fully offline, no network, no issuer involvement. This proves the
// CAP-1 statement: MNDe has a cryptographically signed, independently verifiable
// capability representing permission for one bounded execution.
//
// CAP-1 does NOT enforce single-use / redemption (CAP-3) — verifying a grant twice
// legitimately succeeds twice here. Whether POSSESSION of a valid grant is
// REQUIRED at an execution boundary, and whether it can be spent only once, is
// exactly what later rungs add.

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyAgainstBundle, verifyAuthorityBundle } from "../custody/index.mjs";
import {
  GRANT_ERR,
  canonicalGrantPayload,
  isPlainObject,
  receiptFacts,
  ttlState,
  validateGrantStructure,
  validateLimits,
  validateScope
} from "./grant.mjs";

function fail(reason_code, detail) {
  return detail ? { ok: false, verified: false, reason_code, detail } : { ok: false, verified: false, reason_code };
}

// verifyExecutionGrant(grant, { authorityBundle, trustedRootFingerprint, now?, receipt? })
//
//   authorityBundle          — REQUIRED published bundle to verify against.
//   trustedRootFingerprint   — out-of-band root anchor (bundle must chain to it).
//   now                      — verification instant (defaults to real time).
//   receipt                  — OPTIONAL. When supplied, the grant's four binding
//                              hashes must match this receipt exactly, and the
//                              receipt's decision must be ALLOW.
//
// Returns { ok: true, verified: true, grant_id, execution_id, scope, limits,
// issuer_key_id } or { ok: false, verified: false, reason_code, detail? }.
export async function verifyExecutionGrant(grant, options = {}) {
  const now = options.now ?? new Date().toISOString();

  // 1) Structure + static field validation (cheap, no crypto).
  const structErr = validateGrantStructure(grant);
  if (structErr) return fail(structErr);
  const scopeErr = validateScope(grant.scope);
  if (scopeErr) return fail(scopeErr);
  const limitsErr = validateLimits(grant.limits);
  if (limitsErr) return fail(limitsErr);

  // 2) Validity window.
  const ttlErr = ttlState(grant.limits, now);
  if (ttlErr) return fail(ttlErr);

  // 3) Bundle trust (root anchor, bundle signature, staleness).
  const bundle = options.authorityBundle;
  if (!bundle) return fail(GRANT_ERR.BUNDLE_REQUIRED);
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: options.trustedRootFingerprint, now });
  if (!bundleCheck.ok) return fail(GRANT_ERR.BUNDLE_UNTRUSTED, bundleCheck.reason);

  // 4) Signature over the canonical grant payload, against the bundle's receipt
  //    key (lookup honors validity window + revocation at issue time).
  const sig = grant.signature;
  if (!isPlainObject(sig) || sig.algorithm !== "ED25519" || typeof sig.value !== "string" || sig.key_id !== grant.issuer_key_id) {
    return fail(GRANT_ERR.INVALID_SIGNATURE);
  }
  const canonical = canonicalizeJson(canonicalGrantPayload(grant));
  const sigCheck = await verifyAgainstBundle(canonical, sig.value, "receipt", grant.issuer_key_id, grant.issued_at, bundle);
  if (!sigCheck.ok) return fail(GRANT_ERR.INVALID_SIGNATURE, sigCheck.reason);

  // 5) Optional receipt binding: the grant must pin THIS exact ALLOW decision.
  if (options.receipt !== undefined) {
    const f = receiptFacts(options.receipt);
    if (
      f.decision !== "ALLOW" ||
      f.execution_id !== grant.execution_id ||
      f.decision_hash !== grant.decision_hash ||
      f.request_hash !== grant.request_hash ||
      f.policy_hash !== grant.policy_hash
    ) {
      return fail(GRANT_ERR.REQUEST_MISMATCH);
    }
  }

  return {
    ok: true,
    verified: true,
    grant_id: grant.grant_id,
    execution_id: grant.execution_id,
    scope: grant.scope,
    limits: grant.limits,
    issuer_key_id: grant.issuer_key_id
  };
}
