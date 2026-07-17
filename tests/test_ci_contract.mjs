#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const workflowPath = join(repoRoot, ".github", "workflows", "ci.yml");
const expectedTestScriptsPath = join(repoRoot, "tests", "expected-test-scripts.json");

assert.equal(packageJson.scripts.test, "node ./scripts/run-all-tests.mjs");
assert.equal(packageJson.scripts.ci, "node ./scripts/run-ci.mjs");
assert.equal(packageJson.scripts["check:whitespace"], "node ./scripts/check-whitespace.mjs");
assert.equal(packageJson.scripts["test:replay"], "node ./scripts/test-replay-verification.mjs");
assert.equal(packageJson.scripts["test:conformance"], "node ./tests/test_conformance_vectors.mjs");

for (const file of [
  workflowPath,
  join(repoRoot, "scripts", "run-all-tests.mjs"),
  join(repoRoot, "scripts", "run-ci.mjs"),
  join(repoRoot, "scripts", "check-whitespace.mjs"),
  join(repoRoot, "scripts", "test-replay-verification.mjs"),
  expectedTestScriptsPath
]) {
  assert.equal(existsSync(file), true, `${file} is missing`);
}

const expectedTestScripts = JSON.parse(readFileSync(expectedTestScriptsPath, "utf8"));
assert.ok(Array.isArray(expectedTestScripts), "expected test script list must be an array");
assert.deepEqual([...expectedTestScripts].sort(), expectedTestScripts, "expected test script list must be sorted");
assert.equal(new Set(expectedTestScripts).size, expectedTestScripts.length, "expected test script list must not contain duplicates");
assert.deepEqual(
  Object.keys(packageJson.scripts).filter((name) => name.startsWith("test:")).sort(),
  expectedTestScripts,
  "package.json test:* scripts must match tests/expected-test-scripts.json"
);

const workflow = readFileSync(workflowPath, "utf8");
assert.match(workflow, /uses:\s+actions\/checkout@[a-f0-9]{40}/);
assert.match(workflow, /uses:\s+actions\/setup-node@[a-f0-9]{40}/);
assert.doesNotMatch(workflow, /uses:\s+actions\/checkout@v\d/);
assert.doesNotMatch(workflow, /uses:\s+actions\/setup-node@v\d/);
for (const snippet of [
  "npm ci",
  "npm test",
  "npm run reviewer-kit",
  "npm run check:whitespace",
  "npm run test:replay",
  "npm run test:conformance"
]) {
  assert.match(workflow, new RegExp(snippet.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

function walkFiles(entry) {
  const full = join(repoRoot, entry);
  if (!existsSync(full)) return [];
  if (statSync(full).isFile()) return /\.(?:mjs|ts)$/.test(full) ? [full] : [];
  const out = [];
  for (const child of readdirSync(full)) {
    if (child === "node_modules" || child === ".git") continue;
    out.push(...walkFiles(join(entry, child)));
  }
  return out;
}

const allowedCryptoImports = new Map([
  ["scripts/bootstrap_dev_receipt_keys.mjs", "key authoring"],
  ["scripts/refresh-demo-receipts.mjs", "demo key/HMAC receipt authoring"],
  ["shared/authority-manifest.mjs", "A.2b shared crypto layer"],
  ["shared/hash.ts", "A.2b shared crypto layer"],
  ["shared/policy-trust.ts", "A.2b shared crypto layer"],
  ["shared/receipt-signing.ts", "A.2b shared crypto layer"],
  ["shared/receipt-replay.mjs", "A.2b shared crypto layer"],
  ["sidecar/auth_authority.mjs", "deferred raw Ed25519 authority verifier"],
  ["sidecar/refusal_receipt.mjs", "deferred legacy HMAC refusal receipts"],
  ["src/crypto/node-provider.mjs", "crypto provider implementation"],
  ["src/custody/lifecycle.mjs", "Node-only lifecycle root-key validation"],
  ["src/identity/adapters/github-actions.mjs", "deferred RS256 OIDC adapter support"],
  ["src/policy-engine/authenticated-approvals.mjs", "deferred raw Ed25519 approval helper"],
  ["src/policy-engine/authority-grants.mjs", "deferred raw Ed25519 grant helper"],
  ["src/policy-engine/trust.mjs", "deferred raw Ed25519 policy helper"]
]);

const productionFiles = [
  ...walkFiles("bin"),
  ...walkFiles("executor"),
  ...walkFiles("mcp"),
  ...walkFiles("scripts"),
  ...walkFiles("sidecar"),
  ...walkFiles("src"),
  ...walkFiles("tools"),
  ...walkFiles("shared"),
  ...walkFiles("mnde-local-sidecar.mjs")
];

const directCryptoImport = /\b(?:from\s+["'](?:node:)?crypto["']|import\s*\(["'](?:node:)?crypto["']\)|require\s*\(\s*["'](?:node:)?crypto["']\s*\))/;
const cryptoImportViolations = productionFiles
  .filter((file) => directCryptoImport.test(readFileSync(file, "utf8")))
  .map((file) => file.slice(repoRoot.length + 1).replace(/\\/g, "/"))
  .filter((file) => !allowedCryptoImports.has(file));

assert.deepEqual(cryptoImportViolations, [], "direct crypto imports must stay inside src/crypto or documented deferred/key-authoring files");

const asyncCustodyExports = new Set([
  "buildAuthorityBundle",
  "verifyAuthorityBundle",
  "verifyAgainstBundle",
  "signCanonical",
  "verifyCanonical",
  "createCustody",
  "createLocalDemoCustody",
  "rotateSigningKey",
  "revokeKey",
  "buildSignedExecutionReceipt",
  "verifySignedExecutionReceipt",
  "verifyExecutionResult",
  "buildSignedExecutionResult",
  "verifySignedExecutionResult",
  "loadSigningConfig",
  "signReceiptForDelivery",
  "verifyCustodyAttestation",
  "verifyAnyReceiptFile",
  "verifyAnyReceiptObject",
  "verifyPolicyReceipt",
  "verifyHistoricalPolicyBundleProvenance",
  "signPolicyBundle",
  "signRollbackAuthorization",
  "activateSignedPolicyBundle",
  "loadSignedPolicyBundleConfig"
]);

const callPattern = new RegExp(`\\b(${[...asyncCustodyExports].join("|")})\\s*\\(`);
const missedAwaitViolations = [];
for (const file of productionFiles) {
  const rel = file.slice(repoRoot.length + 1).replace(/\\/g, "/");
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!callPattern.test(line)) return;
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
    if (/^(export\s+)?async\s+function\s+/.test(trimmed)) return;
    if (/^(export\s+)?function\s+/.test(trimmed)) return;
    if (trimmed.includes("await ") || trimmed.startsWith("return ") || trimmed.includes("=>")) return;
    if (/^\w+:\s/.test(trimmed)) return;
    missedAwaitViolations.push(`${rel}:${index + 1}: ${trimmed}`);
  });
}

assert.deepEqual(missedAwaitViolations, [], "async custody/provider callers must await or return the Promise explicitly");

console.log("PASS CI contract");
