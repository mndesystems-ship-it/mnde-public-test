#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const testScripts = Object.keys(packageJson.scripts)
  .filter((name) => name.startsWith("test:"))
  .sort();

if (testScripts.length === 0) {
  console.error("No test:* scripts found.");
  process.exit(1);
}

for (const scriptName of testScripts) {
  console.log(`\n=== npm run ${scriptName} ===`);
  const result = process.platform === "win32"
    ? spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", "npm", "run", scriptName], { cwd: repoRoot, stdio: "inherit" })
    : spawnSync("npm", ["run", scriptName], { cwd: repoRoot, stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

console.log(`\nPASS all test scripts (${testScripts.length}/${testScripts.length})`);
