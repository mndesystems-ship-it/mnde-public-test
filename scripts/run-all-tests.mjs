#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const expectedTestScripts = JSON.parse(readFileSync(join(repoRoot, "tests", "expected-test-scripts.json"), "utf8"));
const packageTestScripts = Object.keys(packageJson.scripts)
  .filter((name) => name.startsWith("test:"))
  .sort();

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!Array.isArray(expectedTestScripts) || expectedTestScripts.some((name) => typeof name !== "string")) {
  fail("tests/expected-test-scripts.json must be an array of script names.");
}
if (JSON.stringify([...expectedTestScripts].sort()) !== JSON.stringify(expectedTestScripts)) {
  fail("tests/expected-test-scripts.json must be sorted.");
}
if (new Set(expectedTestScripts).size !== expectedTestScripts.length) {
  fail("tests/expected-test-scripts.json must not contain duplicate scripts.");
}
if (JSON.stringify(packageTestScripts) !== JSON.stringify(expectedTestScripts)) {
  const expected = new Set(expectedTestScripts);
  const actual = new Set(packageTestScripts);
  const missing = expectedTestScripts.filter((name) => !actual.has(name));
  const unexpected = packageTestScripts.filter((name) => !expected.has(name));
  if (missing.length > 0) console.error(`Missing package scripts: ${missing.join(", ")}`);
  if (unexpected.length > 0) console.error(`Unexpected package scripts: ${unexpected.join(", ")}`);
  fail("package.json test:* scripts must match tests/expected-test-scripts.json.");
}

// Run every suite even after a failure: a single broken suite must not hide
// the status of everything after it. Failures are collected and summarized.
const failures = [];
for (const scriptName of expectedTestScripts) {
  console.log(`\n=== npm run ${scriptName} ===`);
  const result = process.platform === "win32"
    ? spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", "npm", "run", scriptName], { cwd: repoRoot, stdio: "inherit" })
    : spawnSync("npm", ["run", scriptName], { cwd: repoRoot, stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
    failures.push(scriptName);
  } else if (result.status !== 0) {
    failures.push(scriptName);
  }
}

if (failures.length > 0) {
  console.error(`\nFAIL test scripts (${expectedTestScripts.length - failures.length}/${expectedTestScripts.length} passed)`);
  console.error(`Failing suites: ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nPASS all test scripts (${expectedTestScripts.length}/${expectedTestScripts.length})`);
