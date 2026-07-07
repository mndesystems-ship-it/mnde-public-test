#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAnyReceiptFile } from "../tools/verify.mjs";
import { reviewerRequest } from "./reviewer-request.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactsRoot = join(repoRoot, "reviewer-kit", "artifacts");
const receiptPath = join(artifactsRoot, "receipts", "executor-blocked-receipt.json");
const proofPath = join(artifactsRoot, "proofs", "security", "executor-blocked-before-execution.json");
const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";
const markerPath = join(artifactsRoot, "proofs", "security", "executor-destruction-marker.txt");
const testerId = process.env.MNDE_TESTER_ID ?? "TESTER-UNASSIGNED";
const installationId = process.env.MNDE_INSTALLATION_ID ?? "INSTALLATION-UNASSIGNED";

mkdirSync(dirname(receiptPath), { recursive: true });
mkdirSync(dirname(proofPath), { recursive: true });

async function askMndeBeforeExecuting(action) {
  const request = reviewerRequest({
    requestId: "reviewer-kit-executor-blocked",
    tool: action,
    testerId,
    installationId,
    parameters: { target: "backups/", script: "rm -rf /tmp/workspace" }
  });
  const response = await fetch(`${sidecarUrl}/v1/decisions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  });
  return response.json();
}

const decision = await askMndeBeforeExecuting("recursive_delete");
let actionExecuted = false;
if (decision.decision === "ALLOW") {
  writeFileSync(markerPath, "destructive action executed\n", "utf8");
  actionExecuted = true;
}

const receipt = decision.receipt ?? null;
if (receipt) {
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
}

const offlineVerified = receipt ? verifyAnyReceiptFile(receiptPath).verified : false;
let replayPass = false;
if (receipt && receipt.schema_version === "mnde.pe.receipt.v1") {
  // Policy-engine receipts replay deterministically OFFLINE: the unified
  // verifier re-evaluates the engine and fails on any decision drift.
  replayPass = offlineVerified;
} else if (receipt) {
  const replay = await fetch(`${sidecarUrl}/replay`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt })
  }).then((response) => response.json());
  replayPass = replay.drift === false;
}

const proof = {
  checked_at: new Date().toISOString(),
  action: "recursive_delete backups/",
  mnde_decision: decision.decision ?? null,
  reason_code: decision.reason_code ?? null,
  blocked_before_execution: decision.decision === "REFUSE" && !actionExecuted && !existsSync(markerPath),
  executor_ran_action: actionExecuted,
  receipt_path: receipt ? "reviewer-kit/artifacts/receipts/executor-blocked-receipt.json" : null,
  receipt_verifies_offline: offlineVerified,
  replay_passes: replayPass,
  verdict: "FAIL"
};
proof.verdict = proof.blocked_before_execution && proof.receipt_verifies_offline && proof.replay_passes ? "PASS" : "FAIL";

writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");

if (proof.verdict !== "PASS") {
  console.error(JSON.stringify(proof, null, 2));
  process.exit(1);
}

console.log("[PASS] executor blocked before execution");
