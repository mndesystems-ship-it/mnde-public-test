// Normalized, protocol-independent execution envelope — `mnde.execution.request.v1`.
//
// M1 of the agentic-execution expansion (see docs/agentic-execution-expansion.md,
// Section F). This is PURE SUPERSTRUCTURE over the existing policy engine: adapters
// translate any protocol's request into this one envelope, and `normalizeExecutionEnvelope`
// maps the envelope into the EXISTING policy-engine request shape (schema_version "1.0").
//
// Deliberate non-goals for M1 (do NOT add here without a milestone bump):
//   - No change to the frozen decision-hash material or any cryptographic behavior.
//     This module never hashes, signs, or verifies anything; it only reshapes a request.
//   - `nonce` / `expires_at` are validated-if-present but NOT enforced as decision
//     inputs. Replay/expiry enforcement is M4.
//   - `authority[]` entries are passed through to the engine's existing authority
//     verification unchanged; multi-hop delegation is M2 and is not started here.
//
// Fail-closed contract: `normalizeExecutionEnvelope` NEVER returns a partial request.
// It returns `{ ok: true, request, authorities, meta }` or `{ ok: false, reason }`.
// A caller MUST treat `ok: false` as REFUSE. `decideFromEnvelope` enforces this by
// producing a genuine engine REFUSE for a rejected envelope WITHOUT ever handing the
// rejected (possibly native-request-shaped) envelope to the engine — see
// REJECTED_ENVELOPE_SENTINEL.

import { evaluatePolicyRequest } from "../policy-engine/index.mjs";

// The envelope schema id. Note this is DISTINCT from the deploy-pipeline
// `mnde.execution_request.v1` (underscore) in docs/execution-request-v1.md — that
// schema is unchanged and unaffected by this module.
export const EXECUTION_ENVELOPE_SCHEMA = "mnde.execution.request.v1";

// Stable, machine-readable reasons for envelope-layer fail-closed refusals. These
// are envelope-boundary reasons; once an envelope normalizes, all further reason
// codes come from the policy engine unchanged.
export const ENVELOPE_REASONS = Object.freeze({
  SCHEMA_UNSUPPORTED: "ERR_ENVELOPE_SCHEMA_UNSUPPORTED",
  MALFORMED: "ERR_ENVELOPE_MALFORMED"
});

// The complete, fixed set of top-level envelope keys. The envelope FRAME is strict:
// an unknown top-level key fails closed, so no caller-supplied field can be silently
// dropped during normalization. (The payload — `parameters` and `context` — is
// free-form and carried through losslessly.)
const KNOWN_TOP_LEVEL_KEYS = new Set([
  "schema",
  "request_id",
  "timestamp",
  "principal",
  "action",
  "resource",
  "parameters",
  "authority",
  "environment",
  "context",
  "nonce",
  "expires_at"
]);

// `action.namespace` and `action.operation` are joined into the engine's
// `tool.tool_name` as `namespace + "." + operation`. Forbidding "." (and any other
// separator/whitespace) in each token keeps that join INJECTIVE: two different
// (namespace, operation) pairs can never collide onto the same tool_name and thus
// can never receive the same policy treatment by accident.
const ACTION_TOKEN_RE = /^[A-Za-z0-9_-]+$/;

// Same timestamp shape the policy engine accepts (UTC ISO-8601, optional millis).
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

// A deliberately-invalid request used ONLY for the fail-closed branch of
// decideFromEnvelope. It can never satisfy the policy engine's validateRequest
// (missing every required field), so the engine can only ever return an
// INVALID_REQUEST REFUSE for it. The rejected envelope itself is NEVER handed to
// the engine: a malformed envelope can also happen to be a well-formed NATIVE
// policy-engine request (it shares request_id/timestamp/principal/parameters/
// environment/context field names), and evaluating it directly would let a rejected
// envelope reach ALLOW — a fail-open. Frozen so it cannot be mutated between calls.
const REJECTED_ENVELOPE_SENTINEL = Object.freeze({ schema_version: "mnde.execution.request.rejected" });

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
function isValidTimestamp(value) {
  return typeof value === "string" && TIMESTAMP_RE.test(value) && !Number.isNaN(Date.parse(value));
}

// Prototype-pollution defense. `parameters`/`context` are free-form UNTRUSTED input,
// and `principal`/`environment` are caller-controlled and copied into the request.
// These keys are dangerous in a copy step: `__proto__` has an accessor on
// Object.prototype (so `out["__proto__"] = obj` would set a prototype, not a
// property), and `constructor`/`prototype` are the usual pollution pivots. We reject
// them fail-closed rather than trying to preserve them.
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// Internal marker used by sanitizeUntrusted as a backstop; validateExecutionEnvelope
// already rejects forbidden keys before normalization copies anything, so this is
// belt-and-suspenders for an authorization boundary.
class ForbiddenKeyError extends Error {}

// Non-throwing predicate: does `value` contain a forbidden OWN key at any depth?
// Used by the public validator so a dangerous payload is reported as MALFORMED.
// Only own enumerable keys are inspected (Object.keys), which is exactly what a
// JSON-parsed payload exposes (JSON.parse creates `__proto__` as an own data key).
function hasForbiddenKeyDeep(value) {
  if (Array.isArray(value)) return value.some(hasForbiddenKeyDeep);
  if (isPlainObject(value)) {
    for (const key of Object.keys(value)) {
      if (FORBIDDEN_KEYS.has(key)) return true;
      if (hasForbiddenKeyDeep(value[key])) return true;
    }
  }
  return false;
}

// Deep, prototype-SAFE copy of untrusted input. Every object is rebuilt with a
// null prototype (`Object.create(null)`), so:
//   - a literal "__proto__" key can never invoke the Object.prototype setter
//     (a null-prototype object has no such accessor);
//   - no inherited property (hasOwnProperty, toString, or anything from a polluted
//     prototype) can ever be observed by the policy engine's `in`-based attribute
//     lookups — only own keys exist.
// Forbidden keys still throw (backstop). `undefined` values are dropped: `undefined`
// cannot be represented in canonical JSON, so carrying it forward would turn a
// well-formed decision into an opaque failure. Own keys/values are otherwise
// preserved faithfully, so canonicalization (which reads only own keys) is byte-for
// -byte identical to the pre-hardening output for any ordinary payload.
function sanitizeUntrusted(value) {
  if (Array.isArray(value)) return value.map(sanitizeUntrusted);
  if (isPlainObject(value)) {
    const out = Object.create(null);
    for (const key of Object.keys(value)) {
      if (FORBIDDEN_KEYS.has(key)) throw new ForbiddenKeyError(key);
      const child = value[key];
      if (child !== undefined) out[key] = sanitizeUntrusted(child);
    }
    return out;
  }
  return value;
}

// Build a null-prototype object from a small set of DERIVED (already-validated,
// non-attacker-controlled) fields, dropping undefined. Used for agent/tool/resource
// so every object under a policy attribute root is prototype-safe and uniform.
function nullProtoObject(source) {
  const out = Object.create(null);
  for (const key of Object.keys(source)) {
    if (source[key] !== undefined) out[key] = source[key];
  }
  return out;
}

// Structural validation of an `mnde.execution.request.v1` envelope. Returns `null`
// when valid, or a stable ENVELOPE_REASONS code. Distinguishes an unsupported
// schema from a structural defect so callers can tell "wrong kind of object" from
// "right kind, malformed."
export function validateExecutionEnvelope(envelope) {
  if (!isPlainObject(envelope)) return ENVELOPE_REASONS.MALFORMED;
  if (envelope.schema !== EXECUTION_ENVELOPE_SCHEMA) return ENVELOPE_REASONS.SCHEMA_UNSUPPORTED;

  for (const key of Object.keys(envelope)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) return ENVELOPE_REASONS.MALFORMED;
  }

  if (!isNonEmptyString(envelope.request_id)) return ENVELOPE_REASONS.MALFORMED;
  if (!isValidTimestamp(envelope.timestamp)) return ENVELOPE_REASONS.MALFORMED;

  if (!isPlainObject(envelope.principal)) return ENVELOPE_REASONS.MALFORMED;
  if (!isNonEmptyString(envelope.principal.id)) return ENVELOPE_REASONS.MALFORMED;
  if (envelope.principal.type !== undefined && !isNonEmptyString(envelope.principal.type)) {
    return ENVELOPE_REASONS.MALFORMED;
  }

  if (!isPlainObject(envelope.action)) return ENVELOPE_REASONS.MALFORMED;
  if (!isNonEmptyString(envelope.action.namespace) || !ACTION_TOKEN_RE.test(envelope.action.namespace)) {
    return ENVELOPE_REASONS.MALFORMED;
  }
  if (!isNonEmptyString(envelope.action.operation) || !ACTION_TOKEN_RE.test(envelope.action.operation)) {
    return ENVELOPE_REASONS.MALFORMED;
  }

  if (!isPlainObject(envelope.parameters)) return ENVELOPE_REASONS.MALFORMED;
  if (!isPlainObject(envelope.context)) return ENVELOPE_REASONS.MALFORMED;

  // Optional fields: absent is fine; present must be well-formed (fail closed).
  if (envelope.resource !== undefined) {
    if (!isPlainObject(envelope.resource)) return ENVELOPE_REASONS.MALFORMED;
    if (!isNonEmptyString(envelope.resource.type)) return ENVELOPE_REASONS.MALFORMED;
    if (!isNonEmptyString(envelope.resource.id)) return ENVELOPE_REASONS.MALFORMED;
  }
  if (envelope.authority !== undefined && !Array.isArray(envelope.authority)) {
    return ENVELOPE_REASONS.MALFORMED;
  }
  if (envelope.environment !== undefined && !isPlainObject(envelope.environment)) {
    return ENVELOPE_REASONS.MALFORMED;
  }
  if (envelope.nonce !== undefined && !isNonEmptyString(envelope.nonce)) {
    return ENVELOPE_REASONS.MALFORMED;
  }
  if (envelope.expires_at !== undefined && !isValidTimestamp(envelope.expires_at)) {
    return ENVELOPE_REASONS.MALFORMED;
  }

  // Dangerous-key defense (fail closed). Any caller-controlled object whose contents
  // are copied into the normalized request is scanned, at any depth, for a forbidden
  // own key (`__proto__`/`constructor`/`prototype`). A top-level forbidden key is
  // already rejected above by the strict unknown-top-level-key check; this closes the
  // NESTED case (e.g. `parameters.__proto__`, `context.a.__proto__`). Signed
  // `authority[]` grants are intentionally NOT scanned or copied — they are passed
  // through untouched to preserve their signatures.
  for (const field of ["principal", "action", "resource", "parameters", "environment", "context"]) {
    if (envelope[field] !== undefined && hasForbiddenKeyDeep(envelope[field])) {
      return ENVELOPE_REASONS.MALFORMED;
    }
  }

  return null;
}

// Map a validated envelope into the existing policy-engine request (schema_version
// "1.0"). The mapping is deterministic and canonical: two adapters that emit
// envelopes with equal field values produce byte-identical normalized requests
// (canonicalizeJson sorts keys), and therefore identical policy treatment.
export function normalizeExecutionEnvelope(envelope) {
  const reason = validateExecutionEnvelope(envelope);
  if (reason) return { ok: false, reason };

  // Deep, prototype-safe copies of the caller-controlled objects. validate() already
  // rejected forbidden keys; the try/catch is a backstop so a forbidden key can never
  // reach the engine even if the two ever drift.
  let principal;
  let parameters;
  let environment;
  let context;
  try {
    principal = sanitizeUntrusted(envelope.principal);
    parameters = sanitizeUntrusted(envelope.parameters);
    environment = envelope.environment !== undefined ? sanitizeUntrusted(envelope.environment) : Object.create(null);
    context = sanitizeUntrusted(envelope.context);
  } catch (error) {
    if (error instanceof ForbiddenKeyError) return { ok: false, reason: ENVELOPE_REASONS.MALFORMED };
    throw error;
  }

  const agent = nullProtoObject(
    principal.type !== undefined ? { id: principal.id, type: principal.type } : { id: principal.id }
  );
  const toolName = `${envelope.action.namespace}.${envelope.action.operation}`;

  if (envelope.resource !== undefined) {
    // A top-level `resource` is authoritative over any `context.resource` a caller
    // may also have set, so resource identity always comes from the dedicated field.
    context.resource = nullProtoObject({ type: envelope.resource.type, id: envelope.resource.id });
  }

  const request = {
    schema_version: "1.0",
    request_id: envelope.request_id,
    timestamp: envelope.timestamp,
    principal,
    agent,
    tool: nullProtoObject({
      tool_name: toolName,
      namespace: envelope.action.namespace,
      operation: envelope.action.operation
    }),
    parameters,
    environment,
    context
  };

  return {
    ok: true,
    request,
    // Passed straight to the engine's existing authority verification. Not
    // interpreted here (M1). Absent → empty array (no authorities), never a wildcard.
    authorities: Array.isArray(envelope.authority) ? envelope.authority : [],
    // Envelope-level metadata carried for audit/forward-compat. NOT enforced as a
    // decision input in M1 (see module header); replay/expiry is M4.
    meta: {
      nonce: envelope.nonce ?? null,
      expires_at: envelope.expires_at ?? null
    }
  };
}

// Convenience: decide directly from an envelope. Always returns a genuine
// policy-engine decision object, plus `envelope_ok` / `envelope_reason` metadata
// (never part of decision material). An invalid envelope is routed through the
// engine as an INVALID_REQUEST REFUSE — fail closed, no execution, no partial
// request ever produced.
export function decideFromEnvelope(envelope, policy, options = {}) {
  const normalized = normalizeExecutionEnvelope(envelope);
  if (!normalized.ok) {
    // Fail closed: evaluate a guaranteed-invalid sentinel, NOT the rejected envelope.
    // Feeding the raw envelope here would be a fail-open — see REJECTED_ENVELOPE_SENTINEL.
    // `options` is intentionally dropped: nothing from the caller can influence a
    // fail-closed refusal.
    const decision = evaluatePolicyRequest(REJECTED_ENVELOPE_SENTINEL, policy, {});
    return { ...decision, envelope_ok: false, envelope_reason: normalized.reason };
  }
  const decision = evaluatePolicyRequest(normalized.request, policy, {
    ...options,
    authorities: normalized.authorities
  });
  return { ...decision, envelope_ok: true, envelope_reason: null };
}
