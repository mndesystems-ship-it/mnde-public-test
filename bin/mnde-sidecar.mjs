#!/usr/bin/env node
// @mnde/sidecar — zero-to-first-receipt bootstrap CLI.
//
//   npx @mnde/sidecar init      # generate local keys + authority + starter policy
//   npx @mnde/sidecar doctor    # fail-closed readiness check (exit 1 on any FAIL)
//   npx @mnde/sidecar start     # run the sidecar (foreground)
//   npx @mnde/sidecar smoke     # prove it: one decision -> signed receipt -> verified
//
// Goal: `init -> doctor -> start` (or `smoke`) yields a first verifiable receipt
// in under two minutes. Everything here reuses the repo's audited modules; this
// file only wires them into a friendly command surface. No new trust path.
//
// packageRoot = wherever this package is installed (runtime code, read-only).
// home = MNDE_HOME, or ./.mnde under the caller's CWD by default — the ONLY
// place this CLI ever writes. Never the package install directory: writing
// signing keys/policy into node_modules would be wrong (fragile across
// reinstalls, frequently not even writable) and is exactly the mistake this
// slice fixes relative to earlier packaging attempts.

import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { getReleaseIdentity, formatReleaseIdentity } from "../src/release/identity.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = resolve(process.env.MNDE_HOME ?? join(process.cwd(), ".mnde"));
// Publish HOME back onto the real env var (not just this local const) so any
// audited module loaded in-process — e.g. verifyAnyReceiptObject's in-process
// call into src/policy-engine/receipt.mjs, which reads process.env.MNDE_HOME
// itself rather than taking a repoRoot parameter — resolves the same local
// authority bundle doctor/init/start/smoke all agree on. Spawned children
// already receive MNDE_HOME explicitly via their own env object below; this
// line is what makes THIS process consistent with those children.
process.env.MNDE_HOME = HOME;
const STARTER_POLICY = join(HOME, "starter-policy.json");
const TEMPLATE_POLICY = join(packageRoot, "templates", "starter-policy.json");
const RECEIPTS_DIR = process.env.MNDE_RECEIPTS_DIR ?? join(HOME, "receipts");
const LOGS_DIR = join(RECEIPTS_DIR, "_sidecar-logs");
const KEY_DIR = join(HOME, "shared", "receipt_keys");
const PRIVATE_KEY = join(KEY_DIR, "receipt_signing_private.pem");
const RUNTIME = join(packageRoot, "mnde-local-sidecar.mjs");
const START_SIDECAR = join(packageRoot, "scripts", "start-sidecar.mjs");
const PORT = Number.parseInt(process.env.MNDE_BIND_PORT ?? "8787", 10);
const SMOKE_PORT = Number.parseInt(process.env.MNDE_SMOKE_PORT ?? "8788", 10);
const MIN_NODE_MAJOR = 20;

const say = (s = "") => process.stdout.write(s + "\n");
const err = (s = "") => process.stderr.write(s + "\n");
const ok = (s) => `  \x1b[32m✓\x1b[0m ${s}`;
const bad = (s) => `  \x1b[31m✗\x1b[0m ${s}`;
const warn = (s) => `  \x1b[33m!\x1b[0m ${s}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function materializeStarterPolicy() {
  mkdirSync(HOME, { recursive: true });
  if (!existsSync(STARTER_POLICY)) copyFileSync(TEMPLATE_POLICY, STARTER_POLICY);
}

async function health(port) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1200) });
    return r.ok;
  } catch { return false; }
}

// `child` is optional but important: without checking it, a child that
// crashes almost immediately (corrupt key, bad config) still burns the full
// timeoutMs polling a port that will never answer — found via a hostile
// corrupt-key test where smoke took 25s to report a failure that was actually
// decided within the first second.
async function waitReady(port, child, timeoutMs = 25000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child && child.exitCode !== null) return false;
    if (await health(port)) return true;
    await sleep(400);
  }
  return false;
}

// start-sidecar spawns a grandchild runtime; kill the whole tree cross-platform.
function stopTree(child) {
  if (!child) return;
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/F", "/T", "/PID", String(child.pid)], { stdio: "ignore" });
    else child.kill("SIGTERM");
  } catch { /* already gone */ }
}

// Resolve a module that is a .ts file in a source checkout but a compiled .js
// file once packaged (build-package.mjs mirrors shared/foo.ts -> dist/shared/foo.js).
// A dynamic import (rather than a static one) is required here regardless: it
// must run AFTER this file's own process.env.MNDE_HOME assignment above, since
// shared/receipt-signing.ts computes its key paths once at module-load time
// from that same env var — a static top-level import would be hoisted ahead
// of that assignment by ESM ordering and silently see the wrong value.
function resolveTsOrJs(relPath) {
  const tsPath = join(packageRoot, `${relPath}.ts`);
  return existsSync(tsPath) ? tsPath : join(packageRoot, `${relPath}.js`);
}

function buildRequest(reviewerRequest, tool, parameters) {
  return reviewerRequest({ requestId: `mnde-sidecar-${tool}-${Date.now()}`, tool, testerId: "mnde-sidecar", installationId: "local", parameters });
}

// ---- commands ---------------------------------------------------------------

// Report the identity of the installed artifact from embedded metadata only —
// never Git. `version --json` emits the machine-readable release identity.
function cmdVersion() {
  const identity = getReleaseIdentity();
  if (process.argv.includes("--json")) say(JSON.stringify(identity, null, 2));
  else say(formatReleaseIdentity(identity));
  return 0;
}

function cmdInit() {
  say("MNDe Sidecar — init\n");
  say(`  home: ${HOME}`);
  return import(pathToFileURL(join(packageRoot, "scripts", "bootstrap_dev_receipt_keys.mjs")).href).then(({ bootstrapReceiptKeys }) => {
    // bootstrapReceiptKeys is itself idempotent (skips regeneration when a
    // valid, matching key pair already exists) and fails closed — throws,
    // touches nothing — rather than silently regenerating whenever an
    // existing keypair is incomplete, corrupt, or mismatched. See
    // scripts/bootstrap_dev_receipt_keys.mjs. It is the same audited helper
    // every test in this repo uses; nothing new here.
    let res;
    try {
      res = bootstrapReceiptKeys({ repoRoot: HOME });
    } catch (error) {
      // Caught here (rather than falling through to the top-level catch)
      // specifically so this prints a clean, actionable message instead of a
      // raw stack trace — this same catch also covers unrelated fs failures
      // from this same call, e.g. an unwritable or invalid MNDE_HOME.
      err(`Init failed: ${error?.message ?? String(error)}`);
      return 1;
    }
    mkdirSync(RECEIPTS_DIR, { recursive: true });
    mkdirSync(LOGS_DIR, { recursive: true });
    materializeStarterPolicy();
    say(ok(`receipt signing keys + authority manifest (${res.status})`));
    say(ok(`receipt directory  ${RECEIPTS_DIR}`));
    say(ok(`starter policy     ${STARTER_POLICY}`));
    say("\nNext:  npx @mnde/sidecar doctor   then   npx @mnde/sidecar start");
    return 0;
  });
}

async function cmdDoctor() {
  const identity = getReleaseIdentity();
  say(`MNDe Sidecar — doctor  (${identity.product} ${identity.version ?? "unknown"}, ${identity.commit_short ?? identity.source})\n`);
  const checks = [];
  const push = (label, pass, detail = "", soft = false) => checks.push({ label, pass, detail, soft });

  const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
  push(`Node >= ${MIN_NODE_MAJOR}`, nodeMajor >= MIN_NODE_MAJOR, `found v${process.versions.node}`);
  push("Sidecar runtime present", existsSync(RUNTIME), RUNTIME);

  const { receiptSigningKeyStatus } = await import(pathToFileURL(resolveTsOrJs("shared/receipt-signing")).href);
  const keyStatus = receiptSigningKeyStatus();
  push("Receipt signing key present + valid", keyStatus.ok, keyStatus.ok ? PRIVATE_KEY : keyStatus.reason);

  const localAuthority = (await import(pathToFileURL(join(packageRoot, "shared", "authority-manifest.mjs")).href));
  const manifestPath = localAuthority.authorityPaths(HOME, { kind: "local" }).manifestPath;
  push("Authority manifest present", existsSync(manifestPath), manifestPath);
  let bundle = { ok: false, reason: "not checked" };
  try { bundle = localAuthority.loadAuthorityBundle(HOME, { kind: "local" }); } catch (e) { bundle = { ok: false, reason: e?.message ?? String(e) }; }
  push("Authority manifest valid", Boolean(bundle.ok), bundle.ok ? "" : bundle.reason);

  let policyOk = false, policyDetail = STARTER_POLICY;
  try {
    const p = JSON.parse(readFileSync(STARTER_POLICY, "utf8"));
    policyOk = Array.isArray(p.rules) && p.rules.length > 0;
    if (!policyOk) policyDetail = "policy has no rules";
  } catch (e) { policyDetail = `missing/unparseable (${e?.code ?? "run init"})`; }
  push("Starter policy present + valid", policyOk, policyDetail);

  let writable = false;
  try {
    mkdirSync(RECEIPTS_DIR, { recursive: true });
    const probe = join(RECEIPTS_DIR, `.doctor-probe-${process.pid}`);
    writeFileSync(probe, "ok"); rmSync(probe, { force: true }); writable = true;
  } catch { writable = false; }
  push("Receipt directory writable", writable, RECEIPTS_DIR);

  const portBusy = await health(PORT);
  push(`Port ${PORT} available`, !portBusy, portBusy ? "a sidecar already answers here" : "", true);

  for (const c of checks) {
    const line = c.pass ? ok(c.label) : (c.soft ? warn(c.label) : bad(c.label));
    say(c.detail ? `${line} — \x1b[2m${c.detail}\x1b[0m` : line);
  }
  const hardFails = checks.filter((c) => !c.pass && !c.soft);
  say("");
  if (hardFails.length === 0) { say("\x1b[32mAll checks passed.\x1b[0m  Run: npx @mnde/sidecar start"); return 0; }
  err(`\x1b[31m${hardFails.length} check(s) failed.\x1b[0m  Run: npx @mnde/sidecar init`);
  return 1;
}

async function cmdStart() {
  // Fast precheck so we fail with a clear message instead of a stack trace.
  const missing = [];
  if (!existsSync(RUNTIME)) missing.push("sidecar runtime");
  if (!existsSync(PRIVATE_KEY)) missing.push("receipt signing key");
  if (missing.length) { err(`Not initialized (${missing.join(", ")}). Run: npx @mnde/sidecar init`); return 1; }
  const { receiptSigningKeyStatus } = await import(pathToFileURL(resolveTsOrJs("shared/receipt-signing")).href);
  const keyStatus = receiptSigningKeyStatus();
  if (!keyStatus.ok) {
    err(`Not ready: ${keyStatus.reason}`);
    return 1;
  }
  materializeStarterPolicy();
  say(`MNDe Sidecar — starting on http://127.0.0.1:${PORT}  (Ctrl+C to stop)\n`);
  say(`  home: ${HOME}`);
  const child = spawn(process.execPath, [START_SIDECAR], {
    cwd: packageRoot,
    env: { ...process.env, MNDE_HOME: HOME, MNDE_BIND_PORT: String(PORT), MNDE_PE_POLICY: STARTER_POLICY, MNDE_RECEIPTS_DIR: RECEIPTS_DIR },
    stdio: "inherit"
  });
  return new Promise((res) => child.on("exit", (code) => res(code ?? 0)));
}

async function cmdSmoke() {
  const t0 = Date.now();
  say("MNDe Sidecar — smoke (first receipt)\n");
  const { reviewerRequest } = await import(pathToFileURL(join(packageRoot, "scripts", "reviewer-request.mjs")).href);
  const { verifyAnyReceiptObject } = await import(pathToFileURL(join(packageRoot, "tools", "verify.mjs")).href);

  // Always boot our OWN transient sidecar with the starter policy on SMOKE_PORT.
  // Reusing whatever happens to be running on PORT is non-deterministic — a
  // foreign policy would REFUSE read_status and give a false failure.
  materializeStarterPolicy();
  if (!existsSync(PRIVATE_KEY)) { err("Not initialized. Run: npx @mnde/sidecar init"); return 1; }
  const targetPort = SMOKE_PORT;
  if (await health(SMOKE_PORT)) { err(`Smoke port ${SMOKE_PORT} is busy. Set MNDE_SMOKE_PORT to a free port.`); return 1; }
  say(`  booting a transient sidecar on ${targetPort} (starter policy)...`);
  const child = spawn(process.execPath, [START_SIDECAR], {
    cwd: packageRoot,
    env: {
      ...process.env,
      MNDE_HOME: HOME,
      MNDE_BIND_PORT: String(SMOKE_PORT),
      MNDE_PE_POLICY: STARTER_POLICY,
      MNDE_RECEIPTS_DIR: join(HOME, "smoke-receipts")
    },
    stdio: "ignore"
  });
  if (!(await waitReady(SMOKE_PORT, child))) { stopTree(child); err("sidecar did not become ready"); return 1; }

  try {
    const body = buildRequest(reviewerRequest, "read_status", { resource: "deployment/checkout-api" });
    const j = await (await fetch(`http://127.0.0.1:${targetPort}/v1/decisions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body)
    })).json();
    const receipt = j.receipt;
    const v = receipt ? await verifyAnyReceiptObject(receipt) : { verified: false, reason: "no receipt" };
    const hash = (receipt?.decision_output?.decision_hash ?? "").slice(0, 30);
    say("");
    say(`  decision      : ${j.decision} / ${j.reason_code}`);
    say(`  decision_hash : ${hash}…`);
    say(`  offline verify: ${v.verified ? "\x1b[32mVERIFIED ✓\x1b[0m" : "\x1b[31mFAILED ✗\x1b[0m"}${v.reason ? ` (${v.reason})` : ""}`);
    if (receipt) { mkdirSync(HOME, { recursive: true }); writeFileSync(join(HOME, "first-receipt.json"), JSON.stringify(receipt, null, 2) + "\n"); }
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    say("");
    const pass = j.decision === "ALLOW" && v.verified;
    say(pass
      ? `\x1b[32mFirst verifiable receipt in ${secs}s.\x1b[0m  Saved to ${join(HOME, "first-receipt.json")}`
      : `\x1b[31mSmoke failed\x1b[0m (decision=${j.decision}, verified=${v.verified}).`);
    return pass ? 0 : 1;
  } finally {
    stopTree(child);
  }
}

function cmdHelp() {
  say(`@mnde/sidecar — verifiable authorization receipts for AI actions

Usage:
  npx @mnde/sidecar <command>

Commands:
  version   show installed release identity (add --json for machine output)
  init      generate local receipt keys + authority + starter policy (idempotent)
  doctor    fail-closed readiness check (exit 1 on any hard failure)
  start     run the sidecar in the foreground on port ${PORT}
  smoke     one decision -> signed receipt -> offline-verified (proves the install)
  help      this message

State lives in MNDE_HOME (default ./.mnde in your current directory) — never
inside this package's own install location. Delete that directory to fully
uninstall local state; it is the only thing this CLI ever writes.

Env:  MNDE_HOME (default ./.mnde)   MNDE_BIND_PORT (default 8787)   MNDE_SMOKE_PORT (default 8788)`);
  return 0;
}

const command = process.argv[2] ?? "help";
const table = { version: cmdVersion, "--version": cmdVersion, "-v": cmdVersion, init: cmdInit, doctor: cmdDoctor, start: cmdStart, smoke: cmdSmoke, help: cmdHelp, "--help": cmdHelp, "-h": cmdHelp };
const fn = table[command];
if (!fn) { err(`Unknown command: ${command}\n`); cmdHelp(); process.exit(2); }

try {
  const code = await fn();
  process.exitCode = code ?? 0;
} catch (e) {
  err(`\x1b[31merror:\x1b[0m ${e?.stack ?? e?.message ?? e}`);
  process.exitCode = 1;
}
