// Issue an mnde.execution-grant.v1 — a custody-signed capability for ONE bounded
// execution, cryptographically bound to a specific ALLOW decision receipt.
//
// CAP-1 does NOT decide *who* is allowed to request a grant (that is CAP-2). This
// function only mints one from an already-produced ALLOW receipt plus a request
// describing the scope + limits, signing it with the same custody Ed25519
// authority infrastructure that signs receipts. No new trust path, no new PKI.

import { canonicalizeJson } from "../../shared/json.ts";
import { randomBytes } from "../crypto/provider.mjs";
import { findBundleKey } from "../custody/index.mjs";
import {
  EXECUTION_GRANT_SCHEMA,
  GRANT_ERR,
  canonicalGrantPayload,
  receiptFacts,
  validateLimits,
  validateScope
} from "./grant.mjs";

// issueExecutionGrant({ receipt, request, signer, bundle, now? })
//
//   receipt  — a signed/verifiable ALLOW decision receipt (legacy, PE, or custody
//              envelope). Its four binding hashes are pinned into the grant.
//   request  — { scope, limits: { max_cost_cents, max_calls?, not_before?, not_after },
//               grant_id? }. grant_id is generated when absent.
//   signer   — async (canonicalString) => { key_id, value }: the custody receipt
//              signer (e.g. provider.signReceipt from loadSigningConfig).
//   bundle   — the published authority bundle (provider.getPublicBundle()).
//
// Returns { ok: true, grant } or { ok: false, reason_code, detail? }.
export async function issueExecutionGrant({ receipt, request, signer, bundle, now } = {}) {
  const at = now ?? new Date().toISOString();

  const facts = receiptFacts(receipt);
  if (facts.decision !== "ALLOW") return { ok: false, reason_code: GRANT_ERR.RECEIPT_NOT_ALLOW };
  if (!facts.execution_id || !facts.decision_hash || !facts.request_hash || !facts.policy_hash) {
    return { ok: false, reason_code: GRANT_ERR.RECEIPT_UNBINDABLE };
  }

  if (!request || typeof request !== "object") return { ok: false, reason_code: GRANT_ERR.SCOPE_INVALID };
  const scopeErr = validateScope(request.scope);
  if (scopeErr) return { ok: false, reason_code: scopeErr };

  const requested = request.limits && typeof request.limits === "object" ? request.limits : {};
  const limits = {
    max_cost_cents: requested.max_cost_cents,
    max_calls: Number.isInteger(requested.max_calls) ? requested.max_calls : 1,
    not_before: typeof requested.not_before === "string" ? requested.not_before : at,
    not_after: requested.not_after
  };
  const limitsErr = validateLimits(limits);
  if (limitsErr) return { ok: false, reason_code: limitsErr };

  const payload = {
    schema_version: EXECUTION_GRANT_SCHEMA,
    grant_id: typeof request.grant_id === "string" && request.grant_id.length > 0 ? request.grant_id : `grn-${randomBytes(16).toString("hex")}`,
    execution_id: facts.execution_id,
    decision_hash: facts.decision_hash,
    request_hash: facts.request_hash,
    policy_hash: facts.policy_hash,
    scope: request.scope,
    limits,
    issued_at: at
  };

  if (typeof signer !== "function") return { ok: false, reason_code: GRANT_ERR.SIGNING_FAILED, detail: "no signer" };
  let signed;
  try {
    signed = await signer(canonicalizeJson(canonicalGrantPayload(payload)));
  } catch (error) {
    return { ok: false, reason_code: GRANT_ERR.SIGNING_FAILED, detail: error?.message ?? String(error) };
  }
  if (!signed || typeof signed.value !== "string" || signed.value.length === 0 || typeof signed.key_id !== "string") {
    return { ok: false, reason_code: GRANT_ERR.SIGNING_FAILED, detail: "signer returned no signature" };
  }

  // The key that actually signed must be a valid receipt key in the published
  // bundle at issue time (validity window + revocation) — same rule receipts use.
  const keyCheck = findBundleKey(bundle, "receipt", signed.key_id, at);
  if (!keyCheck.ok) return { ok: false, reason_code: GRANT_ERR.SIGNING_KEY_INVALID, detail: keyCheck.reason };

  const grant = {
    ...payload,
    issuer_key_id: signed.key_id,
    signature: {
      algorithm: "ED25519",
      authority_id: bundle?.authority_id ?? null,
      key_id: signed.key_id,
      value: signed.value
    }
  };
  return { ok: true, grant };
}
