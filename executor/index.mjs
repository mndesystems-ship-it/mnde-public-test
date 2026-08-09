// @mnde/executor — authorize a function call through MNDe before running it.
//
// A developer wraps a risky action. MNDe is asked first. ALLOW runs it once;
// REFUSE (or anything ambiguous) never runs it.
//
// ─────────────────────────────────────────────────────────────────────────────
// SAFETY INVARIANT (this is the product claim):
//
//   There is exactly ONE call site for the wrapped function in this file, and it
//   is reachable ONLY after the sidecar returned a decision that clears the
//   strict execution gate. A bare `ALLOW` string is NOT sufficient. Execution
//   requires a receipt that:
//     1. is present,
//     2. verifies offline (signature + authority),
//     3. carries an `ALLOW` decision in its OWN signed body,
//     4. is bound to THIS exact request — the execution id we generated and the
//        exact action + parameters we sent, and
//     5. matches the expected policy hash/version when the caller declares one.
//   Any gap fails closed. Every other path — REFUSE, unreachable sidecar,
//   malformed decision, timeout, missing/unverifiable/mismatched receipt —
//   returns without calling `run()`.
//
//   If a tool is wrapped with MNDe, there is no code path where a REFUSE, or an
//   ALLOW not backed by a verified request-bound receipt, executes.
// ─────────────────────────────────────────────────────────────────────────────

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";
import { canonicalizeJson, parseStrictJson } from "../shared/json.ts";
import { resolveBearerToken, bearerAuthHeader } from "./bearer.mjs";

const DEFAULT_SIDECAR_URL = "http://127.0.0.1:8787";
const DEFAULT_RECEIPTS_DIR = "./mnde-receipts";
const DEFAULT_TIMEOUT_MS = 5000;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepMerge(base, override) {
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = isPlainObject(value) && isPlainObject(base[key]) ? deepMerge(base[key], value) : value;
  }
  return out;
}

function loadVerifyBundle(pathOrUndefined) {
  if (!pathOrUndefined) return undefined;
  try {
    return JSON.parse(readFileSync(pathOrUndefined, "utf8"));
  } catch {
    return undefined;
  }
}

let sequence = 0;
function nextExecutionId(action) {
  sequence += 1;
  return `${action || "action"}-${Date.now()}-${process.pid}-${sequence}`;
}

// Pull an action name out of the several shapes it takes across engines: a bare
// string (legacy tool_calls[].tool), or an object { tool_name } / { tool }
// (policy-engine canonical_request.tool).
function extractActionName(value) {
  if (typeof value === "string") return value;
  if (isPlainObject(value)) {
    if (typeof value.tool_name === "string") return value.tool_name;
    if (typeof value.tool === "string") return value.tool;
  }
  return null;
}

// Exact, order-insensitive JSON comparison (both sides canonicalized the same
// way). Returns false rather than throwing on any non-canonicalizable value, so
// an unexpected shape fails closed.
function jsonEqual(a, b) {
  try { return canonicalizeJson(a) === canonicalizeJson(b); } catch { return false; }
}

// Normalize the request-binding identity out of a receipt, tolerant of BOTH
// supported engines — the legacy pipeline (nested `execution_request` with
// `tool_calls`) and the policy engine (flat `canonical_request` with `tool` +
// `parameters`). Once a receipt has verified offline, its `canonical_request` is
// authenticated (its hash is the signed request_hash), so comparing this to the
// exact action/input we sent is a trustworthy binding across both paths.
function receiptBinding(receipt) {
  const dout = isPlainObject(receipt.decision_output) ? receipt.decision_output : {};
  let cr = null;
  if (typeof receipt.canonical_request === "string") {
    // parseStrictJson returns a wrapped { ok, value } result — unwrap it.
    try {
      const parsed = parseStrictJson(receipt.canonical_request);
      cr = parsed && parsed.ok ? parsed.value : null;
    } catch { cr = null; }
  }
  cr = isPlainObject(cr) ? cr : {};
  const er = isPlainObject(cr.execution_request) ? cr.execution_request : null;

  // Every execution-id-like field present in the receipt. All must equal the id
  // we generated for this call (anti-replay); at least one must be present.
  const requestIds = [];
  const pushId = (v) => { if (typeof v === "string" && v.length > 0) requestIds.push(v); };
  if (er) {
    pushId(er.request_id);
    if (isPlainObject(er.release_request)) pushId(er.release_request.execution_id);
  } else {
    pushId(cr.request_id);
  }
  pushId(dout.execution_id);

  // The decided action + parameters, per shape. The executor always submits
  // exactly one tool call, so a legacy receipt with anything other than one is
  // treated as unbindable (action stays null -> fail closed).
  let action = null;
  let params = null;
  if (er && Array.isArray(er.tool_calls)) {
    if (er.tool_calls.length === 1) {
      action = extractActionName(er.tool_calls[0] ? er.tool_calls[0].tool : null);
      params = isPlainObject(er.tool_calls[0].parameters) ? er.tool_calls[0].parameters : {};
    }
  } else if (!er) {
    action = extractActionName(cr.tool);
    params = isPlainObject(cr.parameters) ? cr.parameters : {};
  }

  return {
    decision: typeof dout.decision === "string" ? dout.decision : null,
    requestIds,
    action,
    params,
    policyHash: dout.policy_hash ?? receipt.policy_hash ?? null,
    policyVersion: dout.policy_version ?? receipt.policy_version ?? null
  };
}

function buildResult(parts) {
  return {
    decision: parts.decision,
    allowed: parts.decision === "ALLOW",
    refused: parts.decision === "REFUSE",
    executed: Boolean(parts.executed),
    reason: parts.reason ?? null,
    result: parts.result,
    error: parts.error,
    receipt: parts.receipt ?? null,
    receiptPath: parts.receiptPath ?? null,
    verified: parts.verified ?? null,
    failClosed: Boolean(parts.failClosed)
  };
}

export function createMndeExecutor(config = {}) {
  const sidecarUrl = String(config.sidecarUrl ?? DEFAULT_SIDECAR_URL).replace(/\/+$/, "");
  const receiptsDir = resolve(config.receiptsDir ?? DEFAULT_RECEIPTS_DIR);
  const testerId = config.testerId ?? process.env.MNDE_TESTER_ID ?? "TESTER-UNASSIGNED";
  const installationId = config.installationId ?? process.env.MNDE_INSTALLATION_ID ?? "INSTALLATION-UNASSIGNED";
  const timeoutMs = Number.isFinite(config.timeoutMs) ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
  // Offline verification is MANDATORY for execution and can no longer be disabled
  // — an unverified receipt never executes. (The old `verify:false` bypass was
  // exactly the fail-open hole this gate closes.)
  // Optional expected-policy binding: when the caller declares the policy it
  // expects to be enforced, a receipt decided under any other policy is refused.
  const expectedPolicyHash = config.expectedPolicyHash ?? process.env.MNDE_EXECUTOR_EXPECTED_POLICY_HASH ?? null;
  const expectedPolicyVersion = config.expectedPolicyVersion ?? process.env.MNDE_EXECUTOR_EXPECTED_POLICY_VERSION ?? null;
  // Sent only when configured (env MNDE_SIDECAR_BEARER_TOKEN or config.bearerToken).
  const bearerToken = resolveBearerToken(config.bearerToken);
  // Optional published authority bundle for offline verification of custody-signed
  // receipts. Unset by default; legacy/PE receipts verify without it.
  const verifyAuthorityBundle = loadVerifyBundle(config.verifyAuthorityBundle ?? process.env.MNDE_VERIFY_AUTHORITY_BUNDLE);

  mkdirSync(receiptsDir, { recursive: true });

  function persist(name, value) {
    const filePath = join(receiptsDir, name);
    writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    return filePath;
  }

  async function offlineVerify(receiptPath) {
    try {
      // Unified verifier handles legacy pipeline, policy-engine, and custody-signed
      // receipts; legacy/PE receipts verify identically to before. A custody
      // envelope additionally needs the published authority bundle.
      return (await verifyAnyReceiptFile(receiptPath, { authorityBundle: verifyAuthorityBundle })).verified === true;
    } catch {
      return false;
    }
  }

  // The strict execution gate. Runs ONLY when the sidecar's HTTP decision was
  // ALLOW; returns { ok, reason } and never has a side effect. `ok:true` is the
  // sole condition under which the wrapped function may run.
  function authorizeExecution({ receipt, action, input, executionId, verified }) {
    if (!isPlainObject(receipt)) return { ok: false, reason: "ERR_NO_RECEIPT" };
    if (verified !== true) return { ok: false, reason: "ERR_RECEIPT_UNVERIFIED" };
    const b = receiptBinding(receipt);
    // The receipt's OWN signed decision must be ALLOW (not just the HTTP body).
    if (b.decision !== "ALLOW") return { ok: false, reason: "ERR_RECEIPT_DECISION_MISMATCH" };
    // Request-instance binding (anti-replay): the signed receipt must name the
    // exact execution id we generated for THIS call — every id it carries, and at
    // least one.
    if (b.requestIds.length === 0 || !b.requestIds.every((rid) => rid === executionId)) {
      return { ok: false, reason: "ERR_RECEIPT_REQUEST_MISMATCH" };
    }
    // Action + parameter binding: the receipt must have decided the exact action
    // and parameters we submitted.
    if (b.action == null || b.action !== action) return { ok: false, reason: "ERR_RECEIPT_ACTION_MISMATCH" };
    if (!jsonEqual(b.params ?? {}, isPlainObject(input) ? input : {})) return { ok: false, reason: "ERR_RECEIPT_ACTION_MISMATCH" };
    // Expected-policy binding (only when the caller declares one).
    if (expectedPolicyHash && b.policyHash !== expectedPolicyHash) return { ok: false, reason: "ERR_POLICY_MISMATCH" };
    if (expectedPolicyVersion && b.policyVersion !== expectedPolicyVersion) return { ok: false, reason: "ERR_POLICY_MISMATCH" };
    return { ok: true, reason: null };
  }

  function buildRequest({ action, input, executionId, requestOverrides }) {
    const base = reviewerRequest({
      requestId: executionId,
      tool: action,
      testerId,
      installationId,
      parameters: isPlainObject(input) ? input : {}
    });
    return isPlainObject(requestOverrides) ? deepMerge(base, requestOverrides) : base;
  }

  // Ask MNDe. Fails closed: any transport/parse/shape problem returns { error }.
  async function askMnde({ action, input, executionId, requestOverrides }) {
    const request = buildRequest({ action, input, executionId, requestOverrides });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetch(`${sidecarUrl}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json", ...bearerAuthHeader(bearerToken) },
        body: JSON.stringify(request),
        signal: controller.signal
      });
    } catch (error) {
      return { error: "ERR_SIDECAR_UNREACHABLE", detail: String(error?.message ?? error) };
    } finally {
      clearTimeout(timer);
    }

    let body;
    try {
      body = await response.json();
    } catch {
      return { error: "ERR_MALFORMED_DECISION", detail: "decision response was not JSON" };
    }
    if (!isPlainObject(body) || (body.decision !== "ALLOW" && body.decision !== "REFUSE")) {
      return { error: "ERR_MALFORMED_DECISION", detail: `decision field was ${JSON.stringify(body?.decision)}` };
    }
    return {
      decision: body.decision,
      reason: typeof body.reason_code === "string" ? body.reason_code : null,
      receipt: isPlainObject(body.receipt) ? body.receipt : null,
      request
    };
  }

  async function execute({ action, input, run, executionId, requestOverrides } = {}) {
    if (typeof run !== "function") {
      throw new TypeError("mnde.execute({ run }) requires run to be a function");
    }
    const id = executionId ?? nextExecutionId(action);
    const decision = await askMnde({ action, input, executionId: id, requestOverrides });

    // FAIL CLOSED — the sidecar gave us nothing we can trust. run() is unreachable here.
    if (decision.error) {
      const receiptPath = persist(`failclosed-${id}.json`, {
        mnde_failclosed: true,
        decision: "REFUSE",
        action: action ?? null,
        execution_id: id,
        reason: decision.error,
        detail: decision.detail ?? null,
        note: "Client-side fail-closed record. This is NOT a signed receipt — MNDe returned no usable decision, so the action was refused locally.",
        recorded_at: new Date().toISOString()
      });
      return buildResult({ decision: "REFUSE", executed: false, reason: decision.error, receipt: null, receiptPath, verified: false, failClosed: true });
    }

    // Persist the receipt BEFORE running, so a throwing run() can never erase it.
    let receiptPath = null;
    let verified = null;
    if (decision.receipt) {
      receiptPath = persist(`receipt-${id}.json`, decision.receipt);
      verified = await offlineVerify(receiptPath);
    }

    // Sidecar authorization was REFUSE (or anything not ALLOW). Normal denial —
    // not a client fault. run() is unreachable here.
    if (decision.decision !== "ALLOW") {
      return buildResult({ decision: "REFUSE", executed: false, reason: decision.reason, receipt: decision.receipt, receiptPath, verified, failClosed: false });
    }

    // STRICT GATE — an ALLOW string is not enough. Execution requires a present,
    // offline-verified receipt whose OWN signed decision is ALLOW and which is
    // bound to this exact request (and expected policy, when declared). Fail closed
    // on any gap. This is the execution-firewall claim.
    const authz = authorizeExecution({ receipt: decision.receipt, action, input, executionId: id, verified });
    if (!authz.ok) {
      const failPath = receiptPath ?? persist(`failclosed-${id}.json`, {
        mnde_failclosed: true,
        decision: "REFUSE",
        action: action ?? null,
        execution_id: id,
        reason: authz.reason,
        note: "Client-side fail-closed record: MNDe returned ALLOW but the receipt did not satisfy the strict execution gate (missing, unverifiable, or not bound to this request/policy), so the action was refused locally.",
        recorded_at: new Date().toISOString()
      });
      return buildResult({ decision: "REFUSE", executed: false, reason: authz.reason, receipt: decision.receipt ?? null, receiptPath: failPath, verified: verified ?? false, failClosed: true });
    }

    // ALLOW + verified, request-bound receipt — the one and only place run() runs.
    let runResult;
    let runError;
    let executed = false;
    try {
      executed = true;
      runResult = await run();
    } catch (error) {
      runError = String(error?.message ?? error);
    }
    return buildResult({
      decision: "ALLOW",
      executed,
      reason: decision.reason,
      result: runResult,
      error: runError,
      receipt: decision.receipt,
      receiptPath,
      verified,
      failClosed: false
    });
  }

  // Turn a raw function into an MNDe-guarded tool. Callers must not retain or
  // invoke separate raw-function references for actions they intend MNDe to protect.
  function wrapTool(toolName, fn, defaults = {}) {
    if (typeof fn !== "function") throw new TypeError("mnde.wrapTool(name, fn) requires fn to be a function");
    const wrapped = (input, options = {}) =>
      execute({ action: toolName, input, run: () => fn(input), ...defaults, ...options });
    wrapped.mndeProtected = true;
    wrapped.toolName = toolName;
    return wrapped;
  }

  function verifyReceipt(receiptPath) {
    const report = verifyReceiptFile(receiptPath);
    return { verified: verificationPassed(report), report };
  }

  return { execute, wrapTool, verifyReceipt, config: { sidecarUrl, receiptsDir, testerId, installationId, timeoutMs, expectedPolicyHash, expectedPolicyVersion } };
}

export default createMndeExecutor;
