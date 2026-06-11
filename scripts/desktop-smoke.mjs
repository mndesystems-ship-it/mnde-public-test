#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const exePath = process.env.MNDE_DESKTOP_EXE ? resolve(process.env.MNDE_DESKTOP_EXE) : null;

if (!exePath) {
  console.log("DESKTOP SMOKE: SKIPPED");
  console.log("Set MNDE_DESKTOP_EXE to a release-downloaded desktop executable to run this optional smoke test.");
  process.exit(0);
}

if (!existsSync(exePath)) {
  console.error(`DESKTOP SMOKE: FAIL`);
  console.error(`Executable not found: ${exePath}`);
  process.exit(1);
}

const child = spawn(exePath, [], {
  stdio: "ignore",
  windowsHide: true,
  detached: process.platform !== "win32"
});

await new Promise((resolveDone) => setTimeout(resolveDone, 3000));

if (child.exitCode !== null) {
  console.error("DESKTOP SMOKE: FAIL");
  console.error(`Desktop process exited early with code ${child.exitCode}`);
  process.exit(1);
}

child.kill();
console.log("DESKTOP SMOKE: PASS");
