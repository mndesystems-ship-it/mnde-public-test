#!/usr/bin/env node
// Standalone MNDe sidecar launcher — one command, zero manual setup.
//
//   npm run sidecar
//
// Clone the repo, run this, and you have a working MNDe authority service ready
// for executor, MCP server, or MCP proxy requests. It bootstraps any missing
// local authority assets, validates the environment (failing loudly if anything
// is wrong), starts the existing sidecar runtime in the foreground while
// streaming its logs, and shuts down cleanly on Ctrl+C.
//
// Node APIs only — works the same on Windows, macOS, and Linux.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./bootstrap_dev_receipt_keys.mjs";
import { authorityPaths, loadAuthorityBundle } from "../shared/authority-manifest.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HOST = "127.0.0.1";
const PORT_RAW = process.env.MNDE_BIND_PORT ?? "8787";
const PORT = Number.parseInt(PORT_RAW, 10);
const URL_BASE = `http://${HOST}:${PORT}`;
const receiptsDir = resolve(process.env.MNDE_RECEIPTS_DIR ?? join(repoRoot, "mnde-receipts"));
const logsDir = join(receiptsDir, "_sidecar-logs");
const READY_TIMEOUT_MS = Number.parseInt(process.env.MNDE_SIDECAR_READY_TIMEOUT_MS ?? "20000", 10);

function out(line = "") {
  process.stdout.write(`${line}\n`);
}
function failClosed(problems) {
  for (const problem of problems) process.stderr.write(`ERROR: ${problem}\n`);
  process.exit(1);
}
function displayPath(absPath) {
  const rel = relative(process.cwd(), absPath);
  return rel && !rel.startsWith("..") && !rel.includes(`:${sep}`) ? `./${rel.split(sep).join("/")}` : absPath;
}

// 1. Startup banner
out("MNDe Sidecar");
out("");
out("Starting authority service...");
out("");

// 2. Bootstrap local authority assets (existing repo logic; no new trust path).
try {
  bootstrapReceiptKeys({ repoRoot });
} catch (error) {
  failClosed([`Authority setup failed: ${error?.message ?? String(error)}`]);
}

// 3. Receipt directory — create if missing, then prove it is writable (fail closed).
try {
  mkdirSync(receiptsDir, { recursive: true });
  mkdirSync(logsDir, { recursive: true });
  const probe = join(receiptsDir, `.write-probe-${process.pid}`);
  writeFileSync(probe, "ok");
  rmSync(probe, { force: true });
} catch {
  failClosed(["Receipt directory not writable."]);
}

// 4. Validation — fail loudly, exit non-zero.
const problems = [];
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) problems.push(`Invalid bind port: ${PORT_RAW}`);
if (!existsSync(join(repoRoot, "mnde-local-sidecar.mjs"))) problems.push("Sidecar runtime mnde-local-sidecar.mjs missing.");
const localAuthority = authorityPaths(repoRoot, { kind: "local" });
if (!existsSync(localAuthority.manifestPath)) problems.push("Authority manifest missing.");
if (!existsSync(join(repoRoot, "shared", "receipt_keys", "receipt_signing_private.pem"))) problems.push("Receipt signing key missing.");
const bundle = loadAuthorityBundle(repoRoot, { kind: "local" });
if (!bundle.ok) problems.push(`Authority manifest invalid: ${bundle.reason}`);
if (problems.length > 0) failClosed(problems);

// 5. Start the existing sidecar runtime in the foreground, streaming its logs.
const env = {
  ...process.env,
  MNDE_BIND_PORT: String(PORT),
  MNDE_RECEIPT_LOG: process.env.MNDE_RECEIPT_LOG ?? join(logsDir, "sidecar-receipts.jsonl"),
  MNDE_AUTH_AUDIT_LOG: process.env.MNDE_AUTH_AUDIT_LOG ?? join(logsDir, "auth-audit.jsonl"),
  MNDE_RECEIPT_HMAC_SECRET: process.env.MNDE_RECEIPT_HMAC_SECRET ?? "demo-legacy-signature-key-000000000001",
  MNDE_RECEIPT_HMAC_KEY_ID: process.env.MNDE_RECEIPT_HMAC_KEY_ID ?? "demo-legacy-signature-key",
  MNDE_INLINE_REFUSAL_RECEIPTS: process.env.MNDE_INLINE_REFUSAL_RECEIPTS ?? "1",
  MNDE_RECEIPT_DURABILITY_MODE: process.env.MNDE_RECEIPT_DURABILITY_MODE ?? "strict_audit",
  MNDE_WORKER_POOL_SIZE: process.env.MNDE_WORKER_POOL_SIZE ?? "1",
  MNDE_WORKER_QUEUE_MAX_DEPTH: process.env.MNDE_WORKER_QUEUE_MAX_DEPTH ?? "16",
  MNDE_TESTER_ID: process.env.MNDE_TESTER_ID ?? "MNDE-LOCAL",
  MNDE_INSTALLATION_ID: process.env.MNDE_INSTALLATION_ID ?? "MNDE-LOCAL-INSTALL"
};

const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], { cwd: repoRoot, env, stdio: ["ignore", "inherit", "inherit"] });

let childExited = false;
let childExitCode = null;
let started = false;
let shuttingDown = false;

child.on("exit", (code) => {
  childExited = true;
  childExitCode = code;
  if (started && !shuttingDown) {
    process.stderr.write(`\nERROR: Sidecar process exited unexpectedly (code ${code}).\n`);
    process.exit(code ?? 1);
  }
});

// 6. Clean shutdown on Ctrl+C (and, cross-platform, on a "stop" line via stdin).
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  out("");
  out("Stopping MNDe Sidecar...");
  const finalize = () => {
    out("Stopped.");
    process.exit(0);
  };
  if (childExited) {
    finalize();
    return;
  }
  const killTimer = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }, 4000);
  child.once("exit", () => {
    clearTimeout(killTimer);
    finalize();
  });
  try {
    child.kill();
  } catch {
    /* already gone */
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
try {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    if (/^\s*(stop|quit|exit)\s*$/im.test(chunk.toString())) shutdown();
  });
  process.stdin.on("error", () => {});
} catch {
  /* stdin may be unavailable in some environments */
}

const ready = await waitReady();
if (!ready) {
  if (childExited) failClosed([`Sidecar exited during startup (code ${childExitCode}).`]);
  try {
    child.kill();
  } catch {
    /* ignore */
  }
  failClosed(["Sidecar did not become ready in time."]);
}

// 5. Status output
started = true;
out("");
out("MNDe Sidecar");
out("");
out("Status: READY");
out(`URL: ${URL_BASE}`);
out("Authority: LOCAL READY");
out(`Receipts: ${displayPath(receiptsDir)}`);
out("");
out("Press Ctrl+C to stop");

async function waitReady() {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (childExited) return false;
    try {
      const response = await fetch(`${URL_BASE}/readyz`);
      const body = await response.json();
      if (body?.ok === true) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  return false;
}
