#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAnyReceiptFile } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactsRoot = join(repoRoot, "reviewer-kit", "artifacts");
const receiptDir = join(artifactsRoot, "receipts");
const proofPath = join(artifactsRoot, "proofs", "security", "hostile-inputs.json");
const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";

mkdirSync(receiptDir, { recursive: true });
mkdirSync(dirname(proofPath), { recursive: true });

const cases = [
  { name: "malformed-json", body: "{\"execution_request\":" },
  { name: "empty-object", body: "{}" },
  { name: "unexpected-fields", body: JSON.stringify({ unexpected: true, execution_request: {} }) },
  { name: "invalid-schema", body: JSON.stringify({ schema_version: "invalid" }) },
  { name: "oversized-request", body: JSON.stringify({ padding: "x".repeat(1_100_000) }) }
];

async function postRaw(body) {
  const response = await fetch(`${sidecarUrl}/v1/decisions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed, raw: text };
}

const results = [];
for (const testCase of cases) {
  const result = await postRaw(testCase.body);
  const receipt = result.body?.receipt ?? null;
  const receiptPath = join(receiptDir, `hostile-${testCase.name}-receipt.json`);
  let verified = false;
  if (receipt) {
    writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    verified = verifyAnyReceiptFile(receiptPath).verified;
  }
  const pass = result.body?.decision === "REFUSE" &&
    result.body?.receipt_persisted === true &&
    Boolean(receipt) &&
    verified;
  results.push({
    case: testCase.name,
    http_status: result.status,
    decision: result.body?.decision ?? null,
    reason_code: result.body?.reason_code ?? null,
    receipt_persisted: result.body?.receipt_persisted ?? null,
    receipt_path: receipt ? `reviewer-kit/artifacts/receipts/hostile-${testCase.name}-receipt.json` : null,
    offline_verified: verified,
    pass
  });
}

const proof = {
  checked_at: new Date().toISOString(),
  cases: results,
  verdict: results.every((result) => result.pass) ? "PASS" : "FAIL"
};
writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");

if (proof.verdict !== "PASS") {
  console.error(JSON.stringify(proof, null, 2));
  process.exit(1);
}

console.log("[PASS] hostile inputs fail closed with signed receipts");
