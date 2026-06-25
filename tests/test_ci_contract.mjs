#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const workflowPath = join(repoRoot, ".github", "workflows", "ci.yml");

assert.equal(packageJson.scripts.test, "node ./scripts/run-all-tests.mjs");
assert.equal(packageJson.scripts.ci, "node ./scripts/run-ci.mjs");
assert.equal(packageJson.scripts["check:whitespace"], "node ./scripts/check-whitespace.mjs");
assert.equal(packageJson.scripts["test:replay"], "node ./scripts/test-replay-verification.mjs");

for (const file of [
  workflowPath,
  join(repoRoot, "scripts", "run-all-tests.mjs"),
  join(repoRoot, "scripts", "run-ci.mjs"),
  join(repoRoot, "scripts", "check-whitespace.mjs"),
  join(repoRoot, "scripts", "test-replay-verification.mjs")
]) {
  assert.equal(existsSync(file), true, `${file} is missing`);
}

const workflow = readFileSync(workflowPath, "utf8");
for (const snippet of [
  "npm ci",
  "npm test",
  "npm run reviewer-kit",
  "npm run check:whitespace",
  "npm run test:replay"
]) {
  assert.match(workflow, new RegExp(snippet.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

console.log("PASS CI contract");
