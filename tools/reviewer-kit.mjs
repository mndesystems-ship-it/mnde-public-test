#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { verifyReceiptFile, verificationPassed } from "./verify-receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactsRoot = join(repoRoot, "reviewer-kit", "artifacts");
const logsRoot = join(artifactsRoot, "logs");
const receiptsRoot = join(artifactsRoot, "receipts");
const proofsRoot = join(artifactsRoot, "proofs");
const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";
const testerId = process.env.MNDE_TESTER_ID ?? readTesterIdentity().tester_id ?? "TESTER-UNASSIGNED";
const installationId = process.env.MNDE_INSTALLATION_ID ?? readTesterIdentity().installation_id ?? "INSTALLATION-UNASSIGNED";
let sidecarProcess = null;

function readTesterIdentity() {
  try {
    return JSON.parse(readFileSync(join(repoRoot, ".mnde-test", "identity.json"), "utf8").replace(/^\uFEFF/, ""));
  } catch {
    return {};
  }
}

function ensureDirs() {
  for (const dir of [
    logsRoot,
    receiptsRoot,
    join(proofsRoot, "determinism"),
    join(proofsRoot, "replay"),
    join(proofsRoot, "security")
  ]) {
    mkdirSync(dir, { recursive: true });
  }
}

function cleanArtifacts() {
  rmSync(artifactsRoot, { recursive: true, force: true });
  ensureDirs();
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function httpJson(path, { method = "GET", body, headers = {} } = {}) {
  const response = await fetch(`${sidecarUrl}${path}`, {
    method,
    headers: body === undefined ? headers : { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body)
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`non-JSON response from ${path}: ${text.slice(0, 120)}`);
  }
  return { status: response.status, body: parsed };
}

async function waitReady() {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const ready = await httpJson("/readyz");
      if (ready.body?.ok === true) return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error("sidecar readiness timed out");
}

async function assertPortFree() {
  try {
    await httpJson("/healthz");
    throw new Error("sidecar port 8787 is already in use");
  } catch (error) {
    if (String(error.message).includes("already in use")) throw error;
  }
}

function startSidecar() {
  const stdoutPath = join(logsRoot, "sidecar.stdout.log");
  const stderrPath = join(logsRoot, "sidecar.stderr.log");
  const stdout = "ignore";
  const stderr = "pipe";
  const env = {
    ...process.env,
    MNDE_RECEIPT_LOG: join(logsRoot, "sidecar-receipts.jsonl"),
    MNDE_AUTH_AUDIT_LOG: join(logsRoot, "auth-audit.jsonl"),
    MNDE_RECEIPT_HMAC_SECRET: "demo-legacy-signature-key-000000000001",
    MNDE_RECEIPT_HMAC_KEY_ID: "demo-legacy-signature-key",
    MNDE_INLINE_REFUSAL_RECEIPTS: "1",
    MNDE_RECEIPT_DURABILITY_MODE: "strict_audit",
    MNDE_WORKER_POOL_SIZE: "1",
    MNDE_WORKER_QUEUE_MAX_DEPTH: "16",
    MNDE_TESTER_ID: testerId,
    MNDE_INSTALLATION_ID: installationId,
    // v1 makes policy-engine the sidecar default; the reviewer kit demonstrates the
    // legacy GPU pipeline, so pin the legacy compatibility engine explicitly unless
    // an ambient value selects a different engine.
    MNDE_DECISION_ENGINE: process.env.MNDE_DECISION_ENGINE ?? "legacy"
  };
  sidecarProcess = spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
    cwd: repoRoot,
    env,
    stdio: ["ignore", stdout, stderr],
    windowsHide: true
  });
  sidecarProcess.stderr?.on("data", (chunk) => {
    writeFileSync(stderrPath, chunk, { flag: "a" });
  });
  writeFileSync(stdoutPath, "", "utf8");
  writeFileSync(join(logsRoot, "sidecar.pid"), String(sidecarProcess.pid), "utf8");
}

async function stopSidecar() {
  if (!sidecarProcess || sidecarProcess.exitCode !== null) return;
  sidecarProcess.kill();
  const exited = await new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 3000);
    sidecarProcess.once("exit", () => {
      clearTimeout(timeout);
      resolve(true);
    });
  });
  if (!exited && sidecarProcess.exitCode === null) {
    sidecarProcess.kill("SIGKILL");
    await new Promise((resolve) => {
      const timeout = setTimeout(resolve, 3000);
      sidecarProcess.once("exit", () => {
        clearTimeout(timeout);
        resolve();
      });
    });
  }
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      await httpJson("/healthz");
      await new Promise((resolve) => setTimeout(resolve, 250));
    } catch {
      return;
    }
  }
  throw new Error("sidecar still reachable after shutdown");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runDecision({ requestId, tool, parameters, expected, receiptName, proofPath }) {
  const request = reviewerRequest({ requestId, tool, parameters, testerId, installationId });
  const response = await httpJson("/v1/decisions", { method: "POST", body: request });
  assert(response.body?.decision === expected, `expected ${expected}, got ${response.body?.decision}`);
  assert(response.body?.receipt, `${expected} receipt missing`);
  const receiptPath = join(receiptsRoot, receiptName);
  writeJson(receiptPath, response.body.receipt);
  writeJson(proofPath, response.body);
  return { response: response.body, receiptPath };
}

function verifyOffline(receiptPath, proofName) {
  const report = verifyReceiptFile(receiptPath);
  writeJson(join(proofsRoot, "replay", proofName), report);
  assert(verificationPassed(report), `offline verification failed: ${receiptPath}`);
  return report;
}

async function verifyReplay(receipt) {
  const replay = await httpJson("/replay", { method: "POST", body: { receipt } });
  assert(replay.body?.drift === false, "replay verification failed");
  return replay.body;
}

async function runHostileInputs() {
  const cases = [
    { name: "malformed-json", body: "{\"execution_request\":" },
    { name: "empty-object", body: "{}" },
    { name: "unexpected-fields", body: JSON.stringify({ unexpected: true, execution_request: {} }) },
    { name: "invalid-schema", body: JSON.stringify({ schema_version: "invalid" }) },
    { name: "oversized-request", body: JSON.stringify({ padding: "x".repeat(1_100_000) }) }
  ];
  const results = [];
  for (const testCase of cases) {
    const result = await httpJson("/v1/decisions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: testCase.body
    });
    const receipt = result.body?.receipt ?? null;
    const receiptPath = join(receiptsRoot, `hostile-${testCase.name}-receipt.json`);
    if (receipt) writeJson(receiptPath, receipt);
    const verified = receipt ? verificationPassed(verifyReceiptFile(receiptPath)) : false;
    results.push({
      case: testCase.name,
      http_status: result.status,
      decision: result.body?.decision ?? null,
      reason_code: result.body?.reason_code ?? null,
      receipt_persisted: result.body?.receipt_persisted ?? null,
      receipt_path: receipt ? `reviewer-kit/artifacts/receipts/hostile-${testCase.name}-receipt.json` : null,
      offline_verified: verified,
      pass: result.body?.decision === "REFUSE" && result.body?.receipt_persisted === true && Boolean(receipt) && verified
    });
  }
  const proof = { checked_at: new Date().toISOString(), cases: results, verdict: results.every((item) => item.pass) ? "PASS" : "FAIL" };
  writeJson(join(proofsRoot, "security", "hostile-inputs.json"), proof);
  assert(proof.verdict === "PASS", "hostile input proof failed");
}

async function runExecutorBlocked() {
  const decision = await runDecision({
    requestId: "reviewer-kit-executor-blocked",
    tool: "recursive_delete",
    parameters: { target: "backups/", script: "rm -rf /tmp/workspace" },
    expected: "REFUSE",
    receiptName: "executor-blocked-receipt.json",
    proofPath: join(proofsRoot, "security", "executor-blocked-response.json")
  });
  const offline = verificationPassed(verifyReceiptFile(decision.receiptPath));
  const replay = await verifyReplay(decision.response.receipt);
  const proof = {
    checked_at: new Date().toISOString(),
    action: "recursive_delete backups/",
    mnde_decision: decision.response.decision,
    reason_code: decision.response.reason_code,
    blocked_before_execution: decision.response.decision === "REFUSE",
    executor_ran_action: false,
    receipt_path: "reviewer-kit/artifacts/receipts/executor-blocked-receipt.json",
    receipt_verifies_offline: offline,
    replay_passes: replay.drift === false,
    verdict: decision.response.decision === "REFUSE" && offline && replay.drift === false ? "PASS" : "FAIL"
  };
  writeJson(join(proofsRoot, "security", "executor-blocked-before-execution.json"), proof);
  assert(proof.verdict === "PASS", "executor blocked demo failed");
}

async function ensureMissingAuthorityFails() {
  const manifestPath = join(repoRoot, ".mnde-test", "authority", "authority-manifest.json");
  const backupPath = `${manifestPath}.reviewer-kit-backup`;
  const sampleReceipt = join(receiptsRoot, "allow-receipt.json");
  try {
    rmSync(backupPath, { force: true });
    await import("node:fs").then(({ renameSync }) => renameSync(manifestPath, backupPath));
    const report = verifyReceiptFile(sampleReceipt);
    assert(!verificationPassed(report), "missing authority bundle unexpectedly verified");
    writeJson(join(proofsRoot, "security", "missing-authority-bundle.json"), report);
  } finally {
    const { existsSync, renameSync } = await import("node:fs");
    if (!existsSync(manifestPath) && existsSync(backupPath)) renameSync(backupPath, manifestPath);
  }
}

async function main() {
  cleanArtifacts();
  await assertPortFree();
  startSidecar();
  try {
    await waitReady();
    console.log("MNDe Reviewer Session Ready");
    const health = await httpJson("/healthz");
    assert(health.body?.ok === true, "healthz failed");
    console.log("[PASS] healthz");
    const ready = await httpJson("/readyz");
    assert(ready.body?.ok === true, "readyz failed");
    console.log("[PASS] readyz");

    const allow = await runDecision({
      requestId: "reviewer-kit-allow-read-status",
      tool: "read_status",
      expected: "ALLOW",
      receiptName: "allow-receipt.json",
      proofPath: join(proofsRoot, "determinism", "allow-response.json")
    });
    console.log("[ALLOW]\nReceipt Stored");

    const refuse = await runDecision({
      requestId: "reviewer-kit-refuse-recursive-delete",
      tool: "recursive_delete",
      parameters: { script: "rm -rf /tmp/workspace" },
      expected: "REFUSE",
      receiptName: "refuse-receipt.json",
      proofPath: join(proofsRoot, "security", "refuse-response.json")
    });
    console.log("[REFUSE]\nReceipt Stored");

    verifyOffline(allow.receiptPath, "allow-receipt-verification.json");
    verifyOffline(refuse.receiptPath, "refuse-receipt-verification.json");
    await verifyReplay(allow.response.receipt);
    await verifyReplay(refuse.response.receipt);
    console.log("[PASS] receipt verification");
    console.log("[PASS] replay verification");

    await runHostileInputs();
    console.log("[PASS] hostile inputs");
    await runExecutorBlocked();
    console.log("[PASS] executor blocked before execution");
    await ensureMissingAuthorityFails();
    console.log("[PASS] missing authority bundle fails clearly");
  } finally {
    await stopSidecar();
  }

  console.log("========================================");
  console.log("MNDe External Review Complete");
  console.log("========================================");
  console.log("");
  console.log("Environment: PASS");
  console.log("ALLOW: PASS");
  console.log("REFUSE: PASS");
  console.log("Receipt Verification: PASS");
  console.log("Replay Verification: PASS");
  console.log("Hostile Inputs: PASS");
  console.log("Executor Blocked: PASS");
  console.log("");
  console.log("FINAL VERDICT: PASS");
}

main().catch(async (error) => {
  await stopSidecar();
  console.error(`[FAIL] ${error instanceof Error ? error.message : String(error)}`);
  console.error("");
  console.error("FINAL VERDICT: FAIL");
  process.exit(1);
});
