import path from "node:path";

import { sha256 as hashHex } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyPolicyTrust, verifyAuthorityGrant } from "./trust.mjs";
import { evaluateApprovals } from "./authenticated-approvals.mjs";

const REQUIRED_REQUEST_FIELDS = [
  "schema_version",
  "request_id",
  "timestamp",
  "principal",
  "agent",
  "tool",
  "parameters",
  "environment",
  "context"
];

const VALID_EFFECTS = new Set(["ALLOW", "REFUSE"]);
const VALID_POLICY_STATES = new Set(["ACTIVE"]);
const VALID_OPERATORS = new Set(["eq", "neq", "contains", "prefix", "path_prefix", "exists", "missing"]);
const VALID_ATTRIBUTE_ROOTS = new Set(["principal", "agent", "tool", "parameters", "environment", "context"]);
const FIXED_FAIL_CLOSED_TIME = "1970-01-01T00:00:00.000Z";

function sha256(value) {
  return `sha256:${hashHex(value)}`;
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// MNDe canonical JSON is integer-only (see docs/number-model.md): decimals must be
// represented as scaled integers or strings. Detect any non-safe-integer number
// anywhere in a value so a request/policy that contains one is refused with a
// DISTINCT reason rather than failing opaquely inside canonicalization. This
// matches the HTTP boundary, where parseStrictJson already rejects non-integers
// with ERR_INVALID_JSON_NUMBER; this guards the direct library/SDK call path.
function hasNonIntegerNumber(value) {
  if (typeof value === "number") return !Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.some(hasNonIntegerNumber);
  if (isPlainObject(value)) return Object.values(value).some(hasNonIntegerNumber);
  return false;
}

function canonicalHash(value) {
  return sha256(canonicalizeJson(value));
}

function refuse(reasonCode, context = {}) {
  return buildDecision("REFUSE", reasonCode, context);
}

function buildDecision(decision, reasonCode, context = {}) {
  const request = isPlainObject(context.request) ? context.request : {};
  const policy = isPlainObject(context.policy) ? context.policy : {};
  const authorities = Array.isArray(context.authorities) ? context.authorities : [];
  const evaluatedAt = context.now ?? evaluationTime(request);
  const requestHash = context.requestHash ?? safeHash(request);
  const policyHash = context.policyHash ?? safeHash(policy);
  const authorityChainHash = context.authorityChainHash ?? safeHash({ authorities });
  const decisionMaterial = {
    request_hash: requestHash,
    policy_hash: policyHash,
    authority_chain_hash: authorityChainHash,
    decision,
    reason_code: reasonCode,
    evaluated_at: evaluatedAt
  };

  return {
    schema_version: "1.0",
    decision,
    reason_code: reasonCode,
    request_id: typeof request.request_id === "string" ? request.request_id : "unknown",
    policy_id: typeof policy.policy_id === "string" ? policy.policy_id : "unknown",
    policy_version: typeof policy.version === "string" ? policy.version : "unknown",
    policy_hash: policyHash,
    authority_chain_hash: authorityChainHash,
    decision_hash: canonicalHash(decisionMaterial),
    request_hash: requestHash,
    evaluated_at: evaluatedAt,
    // Approval summary is metadata only; not part of decisionMaterial, so it does
    // not affect decision_hash. Present only when approval enforcement is active.
    ...(context.approval ? { approval: context.approval } : {})
  };
}

function isValidTimestamp(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && !Number.isNaN(Date.parse(value));
}

function evaluationTime(request) {
  return isValidTimestamp(request?.timestamp) ? request.timestamp : FIXED_FAIL_CLOSED_TIME;
}

function safeHash(value) {
  try {
    return canonicalHash(value);
  } catch {
    return sha256("invalid");
  }
}

function validateRequest(request) {
  if (!isPlainObject(request)) return "INVALID_REQUEST";
  for (const field of REQUIRED_REQUEST_FIELDS) {
    if (!(field in request)) return "INVALID_REQUEST";
  }
  if (request.schema_version !== "1.0") return "INVALID_REQUEST";
  if (typeof request.request_id !== "string" || request.request_id.length === 0) return "INVALID_REQUEST";
  if (!isValidTimestamp(request.timestamp)) return "INVALID_REQUEST";
  if (!isPlainObject(request.principal) || !isPlainObject(request.agent) || !isPlainObject(request.tool)) return "INVALID_REQUEST";
  if (!isPlainObject(request.parameters) || !isPlainObject(request.environment) || !isPlainObject(request.context)) return "INVALID_REQUEST";
  if (typeof request.tool.tool_name !== "string" || request.tool.tool_name.length === 0) return "INVALID_REQUEST";
  return null;
}

function validatePolicy(policy) {
  if (!isPlainObject(policy)) return "INVALID_POLICY";
  if (policy.schema_version !== "1.0") return "INVALID_POLICY";
  if (typeof policy.policy_id !== "string" || typeof policy.version !== "string") return "INVALID_POLICY";
  if (!VALID_POLICY_STATES.has(policy.state)) return "INVALID_POLICY";
  if (!Array.isArray(policy.rules)) return "INVALID_POLICY";
  const ruleIds = new Set();
  for (const rule of policy.rules) {
    if (!isPlainObject(rule)) return "INVALID_POLICY";
    if (typeof rule.rule_id !== "string" || rule.rule_id.length === 0) return "INVALID_POLICY";
    if (ruleIds.has(rule.rule_id)) return "INVALID_POLICY";
    ruleIds.add(rule.rule_id);
    if (!VALID_EFFECTS.has(rule.effect)) return "INVALID_POLICY";
    if (!isPlainObject(rule.match)) return "INVALID_POLICY";
    const expressionError = validateExpression(rule.match);
    if (expressionError) return expressionError;
    if (rule.authority_required !== undefined && (!Array.isArray(rule.authority_required) || rule.authority_required.some((id) => typeof id !== "string"))) {
      return "INVALID_POLICY";
    }
  }
  return null;
}

function validateExpression(expr, depth = 0, maxDepth = 8) {
  if (depth > maxDepth) return "POLICY_LIMIT_EXCEEDED";
  if (!isPlainObject(expr)) return "INVALID_POLICY";

  const logicalKeys = Object.keys(expr).filter((key) => ["all", "any", "not"].includes(key));
  if (logicalKeys.length > 1) return "INVALID_POLICY";
  if ("all" in expr || "any" in expr) {
    const items = "all" in expr ? expr.all : expr.any;
    if (!Array.isArray(items) || items.length === 0) return "INVALID_POLICY";
    for (const item of items) {
      const childError = validateExpression(item, depth + 1, maxDepth);
      if (childError) return childError;
    }
    return null;
  }
  if ("not" in expr) {
    return validateExpression(expr.not, depth + 1, maxDepth);
  }

  if (typeof expr.field !== "string" || typeof expr.op !== "string") return "INVALID_POLICY";
  if (!VALID_OPERATORS.has(expr.op)) return "INVALID_POLICY";
  const root = expr.field.split(".")[0];
  if (!VALID_ATTRIBUTE_ROOTS.has(root)) return "INVALID_POLICY";
  return null;
}

function getPath(root, dottedPath) {
  if (typeof dottedPath !== "string" || dottedPath.length === 0) return { exists: false };
  const parts = dottedPath.split(".");
  let current = root;
  for (const part of parts) {
    if (!isPlainObject(current) && !Array.isArray(current)) return { exists: false };
    if (!(part in current)) return { exists: false };
    current = current[part];
  }
  return { exists: true, value: current };
}

function normalizePath(value) {
  const normalizedSlashes = String(value).replaceAll("\\", "/");
  return path.posix.normalize(normalizedSlashes);
}

function containsWildcardLikePath(value) {
  return typeof value === "string" && /[*?[\]{}]/.test(value);
}

function pathHasPrefix(candidate, prefix) {
  if (containsWildcardLikePath(candidate) || containsWildcardLikePath(prefix)) return false;
  const normalizedCandidate = normalizePath(candidate);
  const normalizedPrefix = normalizePath(prefix);
  if (normalizedCandidate === normalizedPrefix) return true;
  const prefixWithSlash = normalizedPrefix.endsWith("/") ? normalizedPrefix : `${normalizedPrefix}/`;
  return normalizedCandidate.startsWith(prefixWithSlash);
}

function evaluateLeaf(expr, request) {
  if (!isPlainObject(expr)) throw new Error("INVALID_POLICY");
  const { field, op, value } = expr;
  if (typeof op !== "string" || !VALID_OPERATORS.has(op)) throw new Error("INVALID_POLICY");
  if (typeof field !== "string") throw new Error("INVALID_POLICY");

  const found = getPath(request, field);
  if (op === "exists") return found.exists;
  if (op === "missing") return !found.exists;
  if (!found.exists) throw new Error("ATTRIBUTE_MISSING");

  switch (op) {
    case "eq":
      return found.value === value;
    case "neq":
      return found.value !== value;
    case "contains":
      return Array.isArray(found.value) && found.value.includes(value);
    case "prefix":
      return typeof found.value === "string" && typeof value === "string" && found.value.startsWith(value);
    case "path_prefix":
      return typeof found.value === "string" && typeof value === "string" && pathHasPrefix(found.value, value);
    default:
      throw new Error("INVALID_POLICY");
  }
}

function evaluateExpression(expr, request, depth = 0, maxDepth = 8) {
  if (depth > maxDepth) throw new Error("POLICY_LIMIT_EXCEEDED");
  if (!isPlainObject(expr)) throw new Error("INVALID_POLICY");

  const keys = Object.keys(expr);
  const logicalKeys = keys.filter((key) => ["all", "any", "not"].includes(key));
  if (logicalKeys.length > 1) throw new Error("INVALID_POLICY");

  if ("all" in expr) {
    if (!Array.isArray(expr.all)) throw new Error("INVALID_POLICY");
    return expr.all.every((item) => evaluateExpression(item, request, depth + 1, maxDepth));
  }
  if ("any" in expr) {
    if (!Array.isArray(expr.any)) throw new Error("INVALID_POLICY");
    return expr.any.some((item) => evaluateExpression(item, request, depth + 1, maxDepth));
  }
  if ("not" in expr) {
    return !evaluateExpression(expr.not, request, depth + 1, maxDepth);
  }
  return evaluateLeaf(expr, request);
}

function authorityStatus(requiredIds, authorities, now, rejectedById = {}) {
  if (!Array.isArray(requiredIds) || requiredIds.length === 0) return { ok: true };
  for (const id of requiredIds) {
    const authority = authorities.find((candidate) => candidate?.authority_id === id);
    if (!authority) return { ok: false, reason: rejectedById[id] ?? "AUTHORITY_REQUIRED" };
    if (!isValidTimestamp(authority.valid_from) || !isValidTimestamp(authority.valid_until) || !isValidTimestamp(now)) {
      return { ok: false, reason: "AUTHORITY_EXPIRED" };
    }
    if (Date.parse(authority.valid_until) <= Date.parse(now)) {
      return { ok: false, reason: "AUTHORITY_EXPIRED" };
    }
    if (Date.parse(authority.valid_from) > Date.parse(now)) {
      return { ok: false, reason: "AUTHORITY_EXPIRED" };
    }
  }
  return { ok: true };
}

export function evaluatePolicyRequest(request, policy, options = {}) {
  const now = options.now ?? evaluationTime(request);
  const authorities = Array.isArray(options.authorities) ? options.authorities : [];
  const context = { request, policy, authorities, now };

  try {
    const requestError = validateRequest(request);
    if (requestError) return refuse(requestError, context);

    const policyError = validatePolicy(policy);
    if (policyError) return refuse(policyError, context);

    // Integer-only canonical number model (frozen). A non-integer number cannot be
    // represented in canonical form; refuse with a distinct reason instead of
    // letting canonicalization fail opaquely (which would surface as INVALID_POLICY).
    if (hasNonIntegerNumber(request) || hasNonIntegerNumber(policy)) {
      return refuse("NON_INTEGER_NUMBER", context);
    }

    const requestHash = canonicalHash(request);
    const policyHash = canonicalHash(policy);
    const authorityChainHash = canonicalHash({ authorities });
    const decisionContext = { ...context, requestHash, policyHash, authorityChainHash };
    const maxDepth = Number.isSafeInteger(policy?.limits?.max_depth) ? policy.limits.max_depth : 8;

    // Optional cryptographic authority chain. When trust anchors are supplied,
    // the policy must be signed by a trusted policy key, and only grants with a
    // valid signature from a trusted authority key count toward authority_required.
    // Trust anchors are provided by the verifier out of band, never read from the
    // policy or request. With no trust anchors this block is inert.
    const trustAnchors = options.trustAnchors;
    let effectiveAuthorities = authorities;
    const rejectedById = {};
    if (options.rejectLegacyAuthorities && authorities.length > 0 && !trustAnchors) {
      return buildDecision("REFUSE", "ERR_PE_LEGACY_AUTHORITY_REFUSED", decisionContext);
    }
    if (trustAnchors) {
      const policyTrust = verifyPolicyTrust(policy, trustAnchors);
      if (!policyTrust.ok) return buildDecision("REFUSE", policyTrust.reason, decisionContext);
      effectiveAuthorities = [];
      for (const grant of authorities) {
        const grantTrust = verifyAuthorityGrant(grant, trustAnchors, now);
        if (grantTrust.ok) effectiveAuthorities.push(grant);
        else if (typeof grant?.authority_id === "string") rejectedById[grant.authority_id] = grantTrust.reason;
      }
    }

    // Optional authenticated approvals. When approval trust anchors are supplied,
    // each provided approval is verified, and rules that declare `approval_required`
    // are gated on enough valid approvals for this action. With no approval trust
    // anchors this block is inert and `approval_required` has no effect.
    const approvalTrustAnchors = options.approvalTrustAnchors;
    const approvalEnforced = Boolean(approvalTrustAnchors);
    const approvalEval = approvalEnforced ? evaluateApprovals(options.approvals ?? [], approvalTrustAnchors, now, request) : null;
    if (approvalEnforced) decisionContext.approval = { enforced: true, verifications: approvalEval.verifications };

    function approvalStatusForRule(rule) {
      if (!approvalEnforced) return { ok: true };
      const required = rule.approval_required;
      if (required === undefined) return { ok: true };
      const needed = required === true ? 1 : Number.isSafeInteger(required) && required > 0 ? required : null;
      if (needed === null) return { ok: false, reason: "APPROVAL_MALFORMED" };
      if (approvalEval.validCount >= needed) return { ok: true };
      if (approvalEval.present === 0) return { ok: false, reason: "APPROVAL_REQUIRED" };
      const firstBad = approvalEval.verifications.find((v) => v.result !== "VALID");
      return { ok: false, reason: firstBad ? firstBad.result : "APPROVAL_MISSING" };
    }

    const matchingRules = [];
    for (const rule of policy.rules) {
      if (evaluateExpression(rule.match, request, 0, maxDepth)) matchingRules.push(rule);
    }

    if (matchingRules.some((rule) => rule.effect === "REFUSE")) {
      return buildDecision("REFUSE", "RULE_REFUSE", decisionContext);
    }

    const allowRules = matchingRules.filter((rule) => rule.effect === "ALLOW");
    if (allowRules.length === 0) {
      return buildDecision("REFUSE", "NO_MATCHING_RULE", decisionContext);
    }

    let lastFailure = null;
    for (const rule of allowRules) {
      const authority = authorityStatus(rule.authority_required, effectiveAuthorities, now, rejectedById);
      if (!authority.ok) { lastFailure = authority.reason; continue; }
      const approval = approvalStatusForRule(rule);
      if (!approval.ok) { lastFailure = approval.reason; continue; }
      return buildDecision("ALLOW", "OK_ALLOW", decisionContext);
    }

    return buildDecision("REFUSE", lastFailure ?? "AUTHORITY_REQUIRED", decisionContext);
  } catch (error) {
    const reason = error?.message === "POLICY_LIMIT_EXCEEDED" || error?.message === "ATTRIBUTE_MISSING" ? error.message : "INVALID_POLICY";
    return refuse(reason, context);
  }
}
