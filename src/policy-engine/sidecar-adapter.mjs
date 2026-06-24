// Sidecar adapter for the policy engine (opt-in decision path).
//
// Loaded by the sidecar ONLY when MNDE_DECISION_ENGINE=policy-engine. Maps an
// incoming decision request to a policy-engine request, evaluates it against the
// sidecar-configured policy, and returns a signed policy-engine receipt.
//
// Trust anchors come ONLY from sidecar configuration (env/flag/file) — NEVER from
// the request body. Signed artifacts (authority grants, approvals) may be attached
// to the request; the keys that vouch for them come from config.

import { readFileSync } from "node:fs";

import { buildPolicyReceipt } from "./receipt.mjs";
import { loadSignedPolicyBundleConfig } from "../policy-bundles/index.mjs";

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

// Load decision-engine config. Fails closed (ok:false) on any malformed/missing
// configured file, so the sidecar can refuse rather than silently run unprotected.
export function loadPolicyEngineConfig(env) {
  // Signed bundles are opt-in. The legacy MNDE_PE_POLICY path stays unchanged
  // unless an operator explicitly supplies a bundle path.
  if (env.MNDE_PE_POLICY_BUNDLE) {
    const signed = loadSignedPolicyBundleConfig(env);
    if (!signed.ok) return signed;
    return {
      ok: true,
      policy: signed.policy,
      signedPolicyBundle: signed.signedPolicyBundle,
      policyBundleProvenance: signed.policyBundleProvenance
    };
  }
  const policyPath = env.MNDE_PE_POLICY;
  if (!policyPath) return { ok: false, reason: "MNDE_PE_POLICY is required when MNDE_DECISION_ENGINE=policy-engine" };
  let policy;
  try {
    policy = loadJson(policyPath);
  } catch (error) {
    return { ok: false, reason: `policy load failed: ${error?.message ?? String(error)}` };
  }
  let trustAnchors;
  if (env.MNDE_PE_TRUST_ANCHORS) {
    try {
      trustAnchors = loadJson(env.MNDE_PE_TRUST_ANCHORS);
    } catch (error) {
      return { ok: false, reason: `trust anchors load failed: ${error?.message ?? String(error)}` };
    }
  }
  let approvalTrustAnchors;
  if (env.MNDE_PE_APPROVAL_TRUST_ANCHORS) {
    try {
      approvalTrustAnchors = loadJson(env.MNDE_PE_APPROVAL_TRUST_ANCHORS);
    } catch (error) {
      return { ok: false, reason: `approval trust anchors load failed: ${error?.message ?? String(error)}` };
    }
  }
  return { ok: true, policy, trustAnchors, approvalTrustAnchors };
}

// Accept either a native policy-engine request or the legacy decision envelope.
export function toPolicyEngineRequest(body, now) {
  if (body && body.schema_version === "1.0" && body.tool && typeof body.tool.tool_name === "string") {
    return { ...body, timestamp: typeof body.timestamp === "string" ? body.timestamp : now };
  }
  const er = body?.execution_request ?? {};
  const toolCall = Array.isArray(er.tool_calls) ? er.tool_calls[0] : undefined;
  return {
    schema_version: "1.0",
    request_id: typeof er.request_id === "string" ? er.request_id : (typeof body?.request_id === "string" ? body.request_id : "request"),
    timestamp: now,
    principal: { id: typeof er?.actor?.user_id === "string" ? er.actor.user_id : "unknown" },
    agent: { id: typeof er?.orbit_intent?.boundary === "string" ? er.orbit_intent.boundary : (typeof er?.actor?.user_id === "string" ? er.actor.user_id : "agent") },
    tool: { tool_name: typeof toolCall?.tool === "string" ? toolCall.tool : "unknown" },
    parameters: toolCall && typeof toolCall.parameters === "object" && toolCall.parameters !== null ? toolCall.parameters : {},
    environment: { region: typeof er?.submitted_region === "string" ? er.submitted_region : "unknown" },
    context: {}
  };
}

export function decidePolicyEngine(body, config, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const request = toPolicyEngineRequest(body, now);
  // When the caller is authenticated, the principal comes from the verified
  // token identity — never from the request body.
  if (options.caller && typeof options.caller.id === "string") {
    request.principal = { ...(request.principal ?? {}), id: options.caller.id };
  }
  // Signed artifacts attached to the request. Anchors are config-only (above).
  const authorities = Array.isArray(body?.mnde_authorities) ? body.mnde_authorities : (Array.isArray(body?.authorities) ? body.authorities : []);
  const approvals = Array.isArray(body?.mnde_approvals) ? body.mnde_approvals : (Array.isArray(body?.approvals) ? body.approvals : []);
  const receipt = buildPolicyReceipt(request, config.policy, {
    authorities,
    trustAnchors: config.trustAnchors,
    approvals,
    approvalTrustAnchors: config.approvalTrustAnchors,
    policyBundleProvenance: config.policyBundleProvenance,
    now
  });
  return {
    decision: receipt.decision_output.decision,
    reason_code: receipt.decision_output.reason_code,
    receipt
  };
}
