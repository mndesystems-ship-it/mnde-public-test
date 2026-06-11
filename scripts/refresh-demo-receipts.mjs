#!/usr/bin/env node
import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runStrictArm, resetArmStores } from "../arm/engine.ts";
import { runStrictOrbit } from "../orbit/engine.ts";
import { runStrictPreflight } from "../preflight/engine.ts";
import { runStrictRamona } from "../ram0na/engine.ts";
import { DEMO_AUTHORITY_ID, DEMO_AUTHORITY_NAME, RECEIPT_KEY_ID, publicKeyFingerprint, writeSignedAuthorityManifest } from "../shared/authority-manifest.mjs";
import { REASON_CODES } from "../shared/contracts.ts";
import { canonicalizeJson } from "../shared/json.ts";
import { createRuntimeInput } from "../sidecar/runtime_request.mjs";
import { reviewerRequest } from "./reviewer-request.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const policy = JSON.parse(readFileSync(join(repoRoot, "mnde-release-package", "sidecar-local", "policy.v1.signed.json"), "utf8"));
const demoHmacSecret = "demo-legacy-signature-key";
const demoHmacKeyId = "demo-legacy-signature-key";
const signedAt = new Date().toISOString();

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function formatUsdFromCents(cents) {
  return `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}

function signReceiptPayload(payload, privateKey, publicKeyPem) {
  const canonicalPayload = canonicalizeJson(payload);
  return {
    ...payload,
    signature: {
      algorithm: "HMAC-SHA256",
      key_id: demoHmacKeyId,
      value: createHmac("sha256", demoHmacSecret).update(canonicalPayload).digest("hex")
    },
    verifiable_signature: {
      algorithm: "ED25519",
      authority_id: DEMO_AUTHORITY_ID,
      key_id: RECEIPT_KEY_ID,
      public_key_fingerprint: publicKeyFingerprint(publicKeyPem),
      signed_at: signedAt,
      value: sign(null, Buffer.from(canonicalPayload, "utf8"), privateKey).toString("hex")
    }
  };
}

function buildDemoReceipt({ requestId, tool, parameters = {}, receiptPrivateKey, receiptPublicKeyPem }) {
  resetArmStores();
  const request = reviewerRequest({
    requestId,
    tool,
    parameters,
    testerId: "TESTER-001",
    installationId: "INSTALLATION-DEMO"
  });
  const runtimeInput = createRuntimeInput(request, policy);
  const rawInput = canonicalizeJson(runtimeInput);
  const preflight = runStrictPreflight(rawInput);
  if ("parse_boundary" in preflight) throw new Error(`preflight refused demo receipt: ${preflight.reason_code}`);
  const preflightTrace = {
    layer: "preflight",
    request_hash: preflight.request_hash,
    policy_hash: preflight.policy_hash,
    policy_version: preflight.parsed_input.policy_document.policy_version
  };
  const orbit = runStrictOrbit(preflight.parsed_input);
  const arm = runStrictArm(preflight.parsed_input, orbit, preflight.request_hash);
  const ramona = runStrictRamona(preflight.parsed_input, arm);
  const pipelineAllows = orbit.decision === "ALLOW" && arm.decision === "ALLOW" && ramona.decision === "ALLOW";
  const decision = pipelineAllows ? "ALLOW" : "REFUSE";
  const reasonCode = decision === "ALLOW" ? REASON_CODES.OkAllow : ramona.reason_code;
  const decisionHash = sha256(canonicalizeJson({
    request_hash: preflight.request_hash,
    policy_hash: preflight.policy_hash,
    decision,
    reason_code: reasonCode,
    policy_version: preflight.parsed_input.policy_document.policy_version,
    execution_id: arm.execution_id,
    projected_total_cost_cents: arm.projected_total_cost_cents,
    allowed_cost_cents: arm.allowed_cost_cents,
    prevented_cost_cents: arm.prevented_cost_cents
  }));
  const payload = {
    schema_version: "ecs.receipt.v2",
    canonical_request: preflight.canonical_input,
    request_hash: preflight.request_hash,
    decision_output: {
      decision,
      decision_hash: decisionHash,
      request_hash: preflight.request_hash,
      reason_code: reasonCode,
      total_cost_usd: formatUsdFromCents(arm.projected_total_cost_cents),
      allowed_cost_usd: formatUsdFromCents(arm.allowed_cost_cents),
      prevented_cost_usd: formatUsdFromCents(arm.prevented_cost_cents),
      policy_version: preflight.parsed_input.policy_document.policy_version,
      policy_hash: preflight.policy_hash,
      execution_id: arm.execution_id,
      key_set_version: "receipt-key-set-v1"
    },
    pipeline_trace: {
      preflight: preflightTrace,
      orbit,
      arm,
      ramona
    }
  };
  return signReceiptPayload(payload, receiptPrivateKey, receiptPublicKeyPem);
}

function corrupt(receipt, mutate) {
  const copy = structuredClone(receipt);
  mutate(copy);
  return copy;
}

function verifyOrThrow(path) {
  const report = verifyReceiptFile(path);
  if (!verificationPassed(report)) {
    throw new Error(`generated receipt did not verify: ${path}`);
  }
}

const rootKeys = generateKeyPairSync("ed25519");
const receiptKeys = generateKeyPairSync("ed25519");
const rootPrivateKeyPem = rootKeys.privateKey.export({ type: "pkcs8", format: "pem" });
const rootPublicKeyPem = rootKeys.publicKey.export({ type: "spki", format: "pem" });
const receiptPrivateKey = receiptKeys.privateKey;
const receiptPublicKeyPem = receiptKeys.publicKey.export({ type: "spki", format: "pem" });

writeSignedAuthorityManifest({
  repoRoot,
  kind: "demo",
  authorityId: DEMO_AUTHORITY_ID,
  authorityName: DEMO_AUTHORITY_NAME,
  rootPrivateKeyPem,
  rootPublicKeyPem,
  receiptPublicKeyPem
});

const valid = buildDemoReceipt({
  requestId: "demo-valid-read-status",
  tool: "read_status",
  receiptPrivateKey,
  receiptPublicKeyPem
});
const refuse = buildDemoReceipt({
  requestId: "demo-refuse-recursive-delete",
  tool: "recursive_delete",
  parameters: { script: "rm -rf /tmp/workspace" },
  receiptPrivateKey,
  receiptPublicKeyPem
});

const exampleValidPath = join(repoRoot, "examples", "receipts", "valid-receipt.json");
const exampleRefusePath = join(repoRoot, "examples", "receipts", "refuse-receipt.json");
const testValidPath = join(repoRoot, "tests", "receipts", "valid-receipt.json");
writeJson(exampleValidPath, valid);
writeJson(exampleRefusePath, refuse);
writeJson(testValidPath, valid);
writeJson(join(repoRoot, "tests", "receipts", "invalid-signature.json"), corrupt(valid, (receipt) => {
  receipt.verifiable_signature.value = "00".repeat(64);
}));
writeJson(join(repoRoot, "tests", "receipts", "invalid-request-hash.json"), corrupt(valid, (receipt) => {
  receipt.request_hash = "0".repeat(64);
}));
writeJson(join(repoRoot, "tests", "receipts", "invalid-decision-hash.json"), corrupt(valid, (receipt) => {
  receipt.decision_output.decision_hash = "1".repeat(64);
}));
writeJson(join(repoRoot, "tests", "receipts", "invalid-policy-hash.json"), corrupt(valid, (receipt) => {
  receipt.decision_output.policy_hash = "2".repeat(64);
}));
writeJson(join(repoRoot, "tests", "receipts", "missing-field.json"), corrupt(valid, (receipt) => {
  delete receipt.canonical_request;
}));
writeFileSync(join(repoRoot, "tests", "receipts", "corrupted-json.json"), "{ not valid json\n", "utf8");

verifyOrThrow(exampleValidPath);
verifyOrThrow(exampleRefusePath);
verifyOrThrow(testValidPath);

console.log("PASS demo receipts refreshed and verified");
