#!/usr/bin/env node
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { executeDeterministicPipeline, resetRuntimeState, verifySignedReceipt } from "../audit/node_runtime.ts";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { replayReceiptDeterministically } from "../sidecar/replay_engine.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { boundaryReplayEndpointResponse } from "../shared/receipt-replay.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function loadPolicy() {
  return JSON.parse(readFileSync(join(repoRoot, "mnde-release-package", "sidecar-local", "policy.v1.signed.json"), "utf8"));
}

function runLikeWorker(input) {
  resetRuntimeState();
  return executeDeterministicPipeline(JSON.stringify(input));
}

function receiptDecision(result) {
  assert("receipt" in result, `expected receipt, got ${JSON.stringify(result)}`);
  return {
    decision: result.receipt.decision_output.decision,
    reason: result.receipt.decision_output.reason_code,
    projected: result.receipt.pipeline_trace.arm.projected_total_cost_cents,
    receipt: result.receipt
  };
}

function writeTempReceipt(receipt, name) {
  const receiptPath = join(mkdtempSync(join(tmpdir(), "mnde-correctness-")), name);
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return receiptPath;
}

function forgeHmacOnlyReceipt() {
  process.env.MNDE_RECEIPT_HMAC_SECRET = "demo-legacy-signature-key-000000000001";
  process.env.MNDE_RECEIPT_HMAC_KEY_ID = "reviewer-kit-hmac-key";
  const receipt = JSON.parse(readFileSync(join(repoRoot, "examples", "receipts", "valid-receipt.json"), "utf8"));
  delete receipt.verifiable_signature;
  const { signature: _legacySignature, verifiable_signature: _verifiableSignature, ...payload } = receipt;
  receipt.signature = {
    algorithm: "HMAC-SHA256",
    key_id: "reviewer-kit-hmac-key",
    value: createHmac("sha256", process.env.MNDE_RECEIPT_HMAC_SECRET).update(canonicalizeJson(payload)).digest("hex")
  };
  const receiptPath = join(mkdtempSync(join(tmpdir(), "mnde-correctness-")), "hmac-only.json");
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return { receipt, receiptPath };
}

{
  const forged = forgeHmacOnlyReceipt();
  const runtimeVerified = verifySignedReceipt(forged.receipt);
  const offlineVerified = verificationPassed(verifyReceiptFile(forged.receiptPath));
  assert(runtimeVerified === false, "runtime verifier accepted forged HMAC-only receipt");
  assert(offlineVerified === false, "offline verifier accepted forged HMAC-only receipt");
  assert(runtimeVerified === offlineVerified, "runtime and offline verifiers disagreed");
}

{
  const request = reviewerRequest({ requestId: "duplicate-execution-id-proof", tool: "read_status" });
  request.policy_document = loadPolicy();
  const first = receiptDecision(runLikeWorker(request));
  const second = receiptDecision(runLikeWorker(request));
  assert(first.decision === "ALLOW", `first duplicate proof request should allow, got ${first.decision}`);
  assert(second.decision === "REFUSE", `second duplicate execution_id should refuse, got ${second.decision}`);
  assert(verificationPassed(verifyReceiptFile(writeTempReceipt(second.receipt, "duplicate-refuse.json"))), "duplicate execution_id REFUSE receipt should verify offline");
  const endpointReplay = boundaryReplayEndpointResponse(second.receipt);
  assert(endpointReplay?.drift === false, "sidecar /replay boundary response should not drift for duplicate execution_id REFUSE receipt");
  const replayEngine = replayReceiptDeterministically(second.receipt);
  assert(replayEngine.status === "PASS", `replay engine should pass duplicate execution_id REFUSE receipt, got ${replayEngine.status}`);
}

{
  const request = reviewerRequest({ requestId: "manual-approval-proof", tool: "read_status" });
  request.policy_document = loadPolicy();
  request.pricing_data.gpu_hour_cents = 6000;
  request.execution_request.runtime_observation.actual_total_cost_cents = 6000;
  request.execution_request.release_request.hold_state = "NONE";
  const result = receiptDecision(runLikeWorker(request));
  assert(result.projected > request.policy_document.rules.require_manual_approval_above_cents, "test request did not exceed approval threshold");
  assert(result.decision !== "ALLOW", "cost above manual approval threshold without approval was allowed");
}

console.log("PASS correctness fixes tests");
