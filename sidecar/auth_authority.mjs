import { createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const ROLE_CAPABILITIES = {
  ADMIN: new Set(["activate_policy", "manage_runtime", "export_audit", "manage_integrations", "manage_users", "view_runtime", "replay_decisions", "inspect_receipts", "verify_receipts", "view_dashboard"]),
  OPERATOR: new Set(["view_runtime", "replay_decisions", "inspect_receipts", "verify_receipts", "view_dashboard"]),
  AUDITOR: new Set(["inspect_receipts", "verify_receipts", "replay_decisions", "export_audit", "view_dashboard"]),
  VIEWER: new Set(["view_dashboard"])
};

const SENSITIVE_PATHS = new Map([
  ["/policy/activate", "activate_policy"],
  ["/audit/bundle", "export_audit"],
  ["/replay/recent", "replay_decisions"],
  ["/receipts/verify", "verify_receipts"],
  ["/verify", "verify_receipts"]
]);

const ASSERTION_ISSUER = "mnde-desktop";
const ASSERTION_AUDIENCE = "mnde-sidecar";
const ASSERTION_MAX_LIFETIME_MS = 120_000;
const ASSERTION_CLOCK_SKEW_MS = 30_000;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{24,128}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const seenNonces = new Map();

export function requiredCapabilityForPath(pathname) {
  return SENSITIVE_PATHS.get(pathname) ?? null;
}

export function parseAuthorityAssertion(headers) {
  const raw = headers?.["x-mnde-authority-assertion"];
  if (Array.isArray(raw)) return raw.length === 1 && typeof raw[0] === "string" ? raw[0] : null;
  return typeof raw === "string" && raw.trim() !== "" ? raw.trim() : null;
}

export function validateAuthorityAssertion(assertion, now = Date.now()) {
  if (typeof assertion !== "string" || assertion.trim() === "") return { ok: false, reason: "ERR_AUTH_REQUIRED" };
  const publicKeyB64 = process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64;
  if (typeof publicKeyB64 !== "string" || publicKeyB64.trim() === "") return { ok: false, reason: "ERR_AUTH_ASSERTION_KEY_MISSING" };

  const parts = assertion.split(".");
  if (parts.length !== 2 || parts.some((part) => part.length === 0)) return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  const [payloadPart, signaturePart] = parts;
  let payload;
  let signature;
  try {
    payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    signature = Buffer.from(signaturePart, "base64url");
  } catch {
    return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  if (!verifyAuthoritySignature(publicKeyB64, payloadPart, signature)) return { ok: false, reason: "ERR_AUTH_SIGNATURE_INVALID" };

  const claims = validateAssertionClaims(payload, now);
  if (!claims.ok) return claims;
  return { ok: true, actor: sanitizeActor(claims.actor), capabilities: claims.capabilities, nonce: payload.nonce };
}

export function authorizeAuthorityAction(pathname, assertion, now = Date.now()) {
  const capability = requiredCapabilityForPath(pathname);
  if (!capability) return { ok: true, actor: null, capability: null };
  const context = validateAuthorityAssertion(assertion, now);
  if (!context.ok) return { ...context, capability };
  if (!context.capabilities.has(capability)) return { ok: false, reason: "ERR_AUTHZ_REFUSED", actor: context.actor, capability };
  if (!reserveNonce(context.nonce, now)) return { ok: false, reason: "ERR_AUTH_REPLAY", actor: context.actor, capability };
  return { ok: true, actor: context.actor, capability };
}

export function refusalBody(reason, actor = null, target = null) {
  return {
    status: "REFUSED",
    decision: "REFUSE",
    reason_code: reason,
    reason,
    actor: actor ? sanitizeActor(actor) : null,
    target
  };
}

export function appendAuthAuditEvent(path, event) {
  mkdirSync(dirname(path), { recursive: true });
  const actor = event.actor ? sanitizeActor(event.actor) : {};
  const record = {
    timestamp: new Date().toISOString(),
    user_id: actor.user_id ?? null,
    display_name: actor.display_name ?? null,
    role: actor.role ?? null,
    tenant_id: actor.tenant_id ?? null,
    provider: actor.provider ?? null,
    action: event.action,
    target: event.target ?? null,
    result: event.result,
    decision_hash: event.decision_hash ?? null,
    reason: event.reason ?? null
  };
  appendFileSync(path, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
  return record;
}

export function sanitizeActor(input) {
  return {
    user_id: String(input.user_id ?? input.subject),
    display_name: String(input.display_name ?? input.subject),
    email: String(input.email ?? ""),
    tenant_id: String(input.tenant_id ?? ""),
    provider: String(input.provider ?? "enterprise_oidc"),
    role: String(input.role ?? input.roles?.[0]),
    login_time: String(input.login_time ?? new Date(Number(input.issued_at)).toISOString()),
    session_expiry: String(input.session_expiry ?? new Date(Number(input.expires_at)).toISOString()),
    session_id: String(input.session_id ?? "")
  };
}

function verifyAuthoritySignature(publicKeyB64, payloadPart, signature) {
  try {
    const rawPublicKey = Buffer.from(publicKeyB64, "base64url");
    if (rawPublicKey.length !== 32 || signature.length !== 64) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]), format: "der", type: "spki" });
    return verify(null, Buffer.from(payloadPart, "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

function validateAssertionClaims(payload, now) {
  const stringClaims = ["issuer", "audience", "subject", "nonce", "session_id"];
  const missing = stringClaims.filter((key) => typeof payload[key] !== "string" || payload[key].trim() === "");
  if (missing.length > 0) return { ok: false, reason: "ERR_AUTH_CLAIMS_MISSING", missing };
  if (!constantStringEqual(payload.issuer, ASSERTION_ISSUER)) return { ok: false, reason: "ERR_AUTH_ISSUER_INVALID" };
  if (!constantStringEqual(payload.audience, ASSERTION_AUDIENCE)) return { ok: false, reason: "ERR_AUTH_AUDIENCE_INVALID" };
  if (!NONCE_PATTERN.test(payload.nonce)) return { ok: false, reason: "ERR_AUTH_NONCE_INVALID" };
  if (!Number.isFinite(payload.issued_at) || !Number.isFinite(payload.expires_at)) return { ok: false, reason: "ERR_AUTH_TIME_INVALID" };
  if (payload.expires_at <= now) return { ok: false, reason: "ERR_AUTH_EXPIRED" };
  if (payload.issued_at > now + ASSERTION_CLOCK_SKEW_MS) return { ok: false, reason: "ERR_AUTH_CLOCK_SKEW" };
  if (payload.issued_at < now - ASSERTION_MAX_LIFETIME_MS - ASSERTION_CLOCK_SKEW_MS) return { ok: false, reason: "ERR_AUTH_CLOCK_SKEW" };
  if (payload.expires_at - payload.issued_at > ASSERTION_MAX_LIFETIME_MS) return { ok: false, reason: "ERR_AUTH_ASSERTION_TOO_LONG" };
  if (!Array.isArray(payload.roles) || payload.roles.length === 0) return { ok: false, reason: "ERR_AUTH_ROLE_INVALID" };
  if (!Array.isArray(payload.capabilities) || payload.capabilities.length === 0) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  const roles = [...new Set(payload.roles.map((role) => typeof role === "string" ? role.trim() : ""))].filter(Boolean);
  if (roles.length !== payload.roles.length || roles.some((role) => !ROLE_CAPABILITIES[role])) return { ok: false, reason: "ERR_AUTH_ROLE_INVALID" };
  const allowedCapabilities = new Set(roles.flatMap((role) => [...ROLE_CAPABILITIES[role]]));
  const assertedCapabilities = new Set(payload.capabilities.map((capability) => typeof capability === "string" ? capability.trim() : "").filter(Boolean));
  if (assertedCapabilities.size !== payload.capabilities.length) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  if ([...assertedCapabilities].some((capability) => !allowedCapabilities.has(capability))) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  return { ok: true, actor: { ...payload, role: roles[0] }, capabilities: assertedCapabilities };
}

function reserveNonce(nonce, now) {
  loadPersistentNonces(now);
  cleanupNonces(now);
  if (seenNonces.has(nonce)) return false;
  seenNonces.set(nonce, now + ASSERTION_MAX_LIFETIME_MS + ASSERTION_CLOCK_SKEW_MS);
  if (!persistNonces(now)) {
    seenNonces.delete(nonce);
    return false;
  }
  return true;
}

function cleanupNonces(now) {
  let changed = false;
  for (const [nonce, expiresAt] of seenNonces) {
    if (expiresAt <= now) {
      seenNonces.delete(nonce);
      changed = true;
    }
  }
  if (changed) persistNonces(now);
}

function nonceCachePath() {
  return process.env.MNDE_AUTH_NONCE_CACHE ?? join(process.cwd(), "auth-nonce-cache.json");
}

function loadPersistentNonces(now) {
  try {
    const parsed = JSON.parse(readFileSync(nonceCachePath(), "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    for (const [nonce, expiresAt] of Object.entries(parsed)) {
      if (NONCE_PATTERN.test(nonce) && Number.isFinite(expiresAt) && expiresAt > now) {
        seenNonces.set(nonce, expiresAt);
      }
    }
  } catch {
    return;
  }
}

function persistNonces(now) {
  try {
    const entries = {};
    for (const [nonce, expiresAt] of seenNonces) {
      if (expiresAt > now) entries[nonce] = expiresAt;
    }
    writeFileSync(nonceCachePath(), JSON.stringify(entries), { encoding: "utf8" });
    return true;
  } catch {
    return false;
  }
}

function constantStringEqual(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf8");
  const rightBuffer = Buffer.from(String(right), "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
