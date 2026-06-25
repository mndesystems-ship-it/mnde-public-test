#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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

console.log("PASS CI contract");
