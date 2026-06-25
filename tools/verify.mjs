#!/usr/bin/env node
// Unified MNDe receipt verifier.
//
//   node tools/verify.mjs <receipt.json> [--authority-bundle <bundle.json>]
//     [--policy-bundle <bundle.json> --policy-authority-bundle <bundle.json>
//      --policy-root-fingerprint <hex>]
//
// One command verifies any MNDe receipt, regardless of which engine produced it
// or whether it carries a production custody attestation:
//   - mnde.signed-receipt.v1 -> custody attestation (offline, against a published
//                               authority bundle) AND the inner receipt
//   - mnde.pe.receipt.v1      -> policy-engine replay + signature (verifyPolicyReceipt)
//   - everything else         -> the existing pipeline verifier (verifyReceiptFile)
//
// Receipt type is auto-detected. The legacy and policy-engine paths are imported
// unchanged, preserving their byte-for-byte verification guarantees. Custody
// verification is additive and depends only on the published bundle (no network).

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { verifyReceiptFile, verificationPassed } from "./verify-receipt.mjs";
import { verifyPolicyReceipt, POLICY_RECEIPT_SCHEMA } from "../src/policy-engine/receipt.mjs";
import { verifyCustodyAttestation, SIGNED_RECEIPT_SCHEMA } from "../src/authority-signing/index.mjs";

// Verify a receipt object (legacy / policy-engine / custody-signed envelope).
export function verifyAnyReceiptObject(receipt, options = {}) {
  try {
    if (receipt?.schema_version === SIGNED_RECEIPT_SCHEMA) {
      return verifySignedEnvelope(receipt, options);
    }
    if (receipt?.schema_version === POLICY_RECEIPT_SCHEMA) {
      const result = verifyPolicyReceipt(receipt, {
        trustAnchors: options.trustAnchors,
        approvalTrustAnchors: options.approvalTrustAnchors,
        historicalPolicyBundle: options.historicalPolicyBundle,
        policyAuthorityBundle: options.policyAuthorityBundle,
        policyTrustedRootFingerprint: options.policyTrustedRootFingerprint,
        authorityBundle: options.authorityBundle,
        trustedRootFingerprint: options.trustedRootFingerprint,
        now: options.now
      });
      return { kind: "policy-engine", verified: result.verified, reason: result.reason, decision: result.decision };
    }
    // Legacy pipeline verifier is file-based; round-trip the object through a temp file.
    const dir = mkdtempSync(join(tmpdir(), "mnde-verify-"));
    try {
      const file = join(dir, "receipt.json");
      writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
      const report = verifyReceiptFile(file);
      return { kind: "pipeline", verified: verificationPassed(report), report };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } catch {
    const kind = receipt?.schema_version === SIGNED_RECEIPT_SCHEMA
      ? "custody-signed"
      : receipt?.schema_version === POLICY_RECEIPT_SCHEMA
        ? "policy-engine"
        : "pipeline";
    return { kind, verified: false, reason: "verification error" };
  }
}

// Verify a custody-signed envelope: BOTH the inner receipt and the production
// custody attestation must verify. Fails closed if the authority bundle is absent.
export function verifySignedEnvelope(envelope, options = {}) {
  const attest = verifyCustodyAttestation(envelope, options);
  const inner = attest.ok || envelope?.receipt ? verifyAnyReceiptObject(envelope?.receipt, options) : { verified: false, reason: "no inner receipt" };
  const verified = Boolean(attest.ok) && Boolean(inner.verified);
  const reason = !attest.ok ? `attestation: ${attest.reason}` : (!inner.verified ? `inner receipt: ${inner.reason ?? "failed"}` : null);
  return {
    kind: "custody-signed",
    verified,
    reason,
    decision: attest.decision,
    custody: attest.ok
      ? { key_id: attest.signing_key_id, authority_fingerprint: attest.authority_fingerprint, trust_chain: "VALID", revocation: "NOT_REVOKED", signed_at: attest.signed_at }
      : { trust_chain: "INVALID" },
    inner,
    verified_at: new Date().toISOString()
  };
}

export function verifyAnyReceiptFile(filePath, options = {}) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(filePath, "utf8").replace(/^﻿/, ""));
  } catch (error) {
    return { kind: "error", verified: false, reason: `unreadable receipt: ${error?.message ?? String(error)}` };
  }
  return verifyAnyReceiptObject(receipt, options);
}

function main() {
  const args = process.argv.slice(2);
  const valueOf = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const trustAnchorsPath = valueOf("--trust-anchors");
  const approvalAnchorsPath = valueOf("--approval-trust-anchors");
  const authorityBundlePath = valueOf("--authority-bundle");
  const rootFingerprint = valueOf("--root-fingerprint");
  const historicalPolicyBundlePath = valueOf("--policy-bundle");
  const policyAuthorityBundlePath = valueOf("--policy-authority-bundle");
  const policyRootFingerprint = valueOf("--policy-root-fingerprint");
  const flagValues = new Set([trustAnchorsPath, approvalAnchorsPath, authorityBundlePath, rootFingerprint, historicalPolicyBundlePath, policyAuthorityBundlePath, policyRootFingerprint].filter(Boolean));
  const filePath = args.find((a) => !a.startsWith("--") && !flagValues.has(a));
  if (!filePath) {
    process.stderr.write("Usage: node tools/verify.mjs <receipt.json> [--authority-bundle <f>] [--root-fingerprint <hex>] [--policy-bundle <f> --policy-authority-bundle <f> --policy-root-fingerprint <hex>] [--trust-anchors <f>] [--approval-trust-anchors <f>]\n");
    process.exit(2);
  }
  const trustAnchors = trustAnchorsPath ? JSON.parse(readFileSync(trustAnchorsPath, "utf8")) : undefined;
  const approvalTrustAnchors = approvalAnchorsPath ? JSON.parse(readFileSync(approvalAnchorsPath, "utf8")) : undefined;
  const authorityBundle = authorityBundlePath ? JSON.parse(readFileSync(authorityBundlePath, "utf8")) : undefined;
  const historicalPolicyBundle = historicalPolicyBundlePath ? JSON.parse(readFileSync(historicalPolicyBundlePath, "utf8")) : undefined;
  const policyAuthorityBundle = policyAuthorityBundlePath ? JSON.parse(readFileSync(policyAuthorityBundlePath, "utf8")) : undefined;
  const result = verifyAnyReceiptFile(filePath, {
    trustAnchors,
    approvalTrustAnchors,
    authorityBundle,
    trustedRootFingerprint: rootFingerprint,
    historicalPolicyBundle,
    policyAuthorityBundle,
    policyTrustedRootFingerprint: policyRootFingerprint
  });
  process.stdout.write("========================================\n");
  process.stdout.write("MNDe Receipt Verification (unified)\n");
  process.stdout.write("========================================\n");
  process.stdout.write(`Receipt:  ${filePath}\n`);
  process.stdout.write(`Type:     ${result.kind}\n`);
  if (result.decision) process.stdout.write(`Decision: ${result.decision}\n`);
  if (result.custody) {
    process.stdout.write(`Key id:      ${result.custody.key_id ?? "-"}\n`);
    process.stdout.write(`Authority:   ${result.custody.authority_fingerprint ?? "-"}\n`);
    process.stdout.write(`Trust chain: ${result.custody.trust_chain}\n`);
    process.stdout.write(`Revocation:  ${result.custody.revocation ?? "-"}\n`);
  }
  if (result.verified_at) process.stdout.write(`Verified at: ${result.verified_at}\n`);
  process.stdout.write(`FINAL VERDICT: ${result.verified ? "VERIFIED" : "FAILED"}${result.reason ? ` (${result.reason})` : ""}\n`);
  process.exit(result.verified ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
