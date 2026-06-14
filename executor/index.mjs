// @mnde/executor — authorize a function call through MNDe before running it.
//
// A developer wraps a risky action. MNDe is asked first. ALLOW runs it once;
// REFUSE (or anything ambiguous) never runs it.
//
// ─────────────────────────────────────────────────────────────────────────────
// SAFETY INVARIANT (this is the product claim):
//
//   There is exactly ONE call site for the wrapped function in this file, and it
//   is reachable only after the sidecar returned a well-formed `ALLOW`. Every
//   other path — REFUSE, unreachable sidecar, malformed decision, timeout,
//   thrown error before the decision — returns without calling `run()`.
//
//   If a tool is wrapped with MNDe, there is no code path where REFUSE executes.
// ─────────────────────────────────────────────────────────────────────────────

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";

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

let sequence = 0;
function nextExecutionId(action) {
  sequence += 1;
  return `${action || "action"}-${Date.now()}-${process.pid}-${sequence}`;
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
  const verify = config.verify !== false;

  mkdirSync(receiptsDir, { recursive: true });

  function persist(name, value) {
    const filePath = join(receiptsDir, name);
    writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    return filePath;
  }

  function offlineVerify(receiptPath) {
    if (!verify) return null;
    try {
      // Unified verifier handles both legacy pipeline receipts and policy-engine
      // receipts; legacy receipts verify identically to before.
      return verifyAnyReceiptFile(receiptPath).verified;
    } catch {
      return false;
    }
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
        headers: { "content-type": "application/json" },
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
      receipt: isPlainObject(body.receipt) ? body.receipt : null
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
      verified = offlineVerify(receiptPath);
    }

    // REFUSE — single source of truth. run() is unreachable here.
    if (decision.decision !== "ALLOW") {
      return buildResult({ decision: "REFUSE", executed: false, reason: decision.reason, receipt: decision.receipt, receiptPath, verified, failClosed: false });
    }

    // ALLOW — the one and only place run() is ever invoked.
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

  // Turn a raw function into an MNDe-guarded tool. The raw function is captured
  // in the closure and is never exposed — the only way to call it is through MNDe.
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

  return { execute, wrapTool, verifyReceipt, config: { sidecarUrl, receiptsDir, testerId, installationId, timeoutMs, verify } };
}

export default createMndeExecutor;
