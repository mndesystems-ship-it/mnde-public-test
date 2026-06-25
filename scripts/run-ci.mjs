#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const steps = [
  ["test"],
  ["run", "reviewer-kit"],
  ["run", "check:whitespace"],
  ["run", "test:replay"]
];

for (const args of steps) {
  console.log(`\n=== npm ${args.join(" ")} ===`);
  const result = process.platform === "win32"
    ? spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", "npm", ...args], { cwd: repoRoot, stdio: "inherit" })
    : spawnSync("npm", args, { cwd: repoRoot, stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

console.log("\nPASS CI guardrails");
