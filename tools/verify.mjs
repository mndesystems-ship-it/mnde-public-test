#!/usr/bin/env node
// Unified MNDe receipt verifier.
//
//   node tools/verify.mjs <receipt.json>
//
// One command verifies any MNDe receipt, regardless of which engine produced it:
//   - mnde.pe.receipt.v1  -> policy-engine replay + signature (verifyPolicyReceipt)
//   - everything else     -> the existing pipeline verifier (verifyReceiptFile)
//
// Both receipt types share one Ed25519 authority chain. This file only dispatches;
// it does not change how existing receipts are verified — the legacy path is
// imported unchanged, preserving its byte-for-byte verification guarantees.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { verifyReceiptFile, verificationPassed } from "./verify-receipt.mjs";
import { verifyPolicyReceipt, POLICY_RECEIPT_SCHEMA } from "../src/policy-engine/receipt.mjs";

export function verifyAnyReceiptFile(filePath, options = {}) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(filePath, "utf8").replace(/^﻿/, ""));
  } catch (error) {
    return { kind: "error", verified: false, reason: `unreadable receipt: ${error?.message ?? String(error)}` };
  }

  if (receipt?.schema_version === POLICY_RECEIPT_SCHEMA) {
    const result = verifyPolicyReceipt(receipt, { trustAnchors: options.trustAnchors, approvalTrustAnchors: options.approvalTrustAnchors });
    return { kind: "policy-engine", verified: result.verified, reason: result.reason, decision: result.decision };
  }

  const report = verifyReceiptFile(filePath);
  return { kind: "pipeline", verified: verificationPassed(report), report };
}

function main() {
  const args = process.argv.slice(2);
  const valueOf = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const trustAnchorsPath = valueOf("--trust-anchors");
  const approvalAnchorsPath = valueOf("--approval-trust-anchors");
  const flagValues = new Set([trustAnchorsPath, approvalAnchorsPath].filter(Boolean));
  const filePath = args.find((a) => !a.startsWith("--") && !flagValues.has(a));
  if (!filePath) {
    process.stderr.write("Usage: node tools/verify.mjs <receipt.json> [--trust-anchors <f>] [--approval-trust-anchors <f>]\n");
    process.exit(2);
  }
  const trustAnchors = trustAnchorsPath ? JSON.parse(readFileSync(trustAnchorsPath, "utf8")) : undefined;
  const approvalTrustAnchors = approvalAnchorsPath ? JSON.parse(readFileSync(approvalAnchorsPath, "utf8")) : undefined;
  const result = verifyAnyReceiptFile(filePath, { trustAnchors, approvalTrustAnchors });
  process.stdout.write("========================================\n");
  process.stdout.write("MNDe Receipt Verification (unified)\n");
  process.stdout.write("========================================\n");
  process.stdout.write(`Receipt:  ${filePath}\n`);
  process.stdout.write(`Type:     ${result.kind}\n`);
  if (result.decision) process.stdout.write(`Decision: ${result.decision}\n`);
  process.stdout.write(`FINAL VERDICT: ${result.verified ? "VERIFIED" : "FAILED"}${result.reason ? ` (${result.reason})` : ""}\n`);
  process.exit(result.verified ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
