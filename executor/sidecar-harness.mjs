// Test/demo harness: start and stop a real MNDe sidecar.
//
// This is NOT part of the @mnde/executor public API. In real usage the sidecar
// runs as its own long-lived process and your code just points the executor at
// its URL. The harness exists so `npm run executor-demo`, `npm run test:executor`,
// and the examples are one-command runnable against a genuine sidecar + real
// signed receipts.

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { resolveDecisionEngine } from "../shared/decision-engine.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export async function startMndeSidecar({
  url = "http://127.0.0.1:8787",
  testerId = "EXEC-DEMO-001",
  installationId = "EXEC-INSTALL-001",
  env: extraEnv = {}
} = {}) {
  // Fresh-clone safe: generate local receipt signing keys + signed local authority
  // if they don't exist yet (idempotent). Without this the sidecar refuses to boot.
  bootstrapReceiptKeys({ repoRoot });

  const logsRoot = join(repoRoot, "mnde-receipts", "_sidecar-logs");
  mkdirSync(logsRoot, { recursive: true });

  const env = {
    ...process.env,
    MNDE_RECEIPT_LOG: join(logsRoot, "sidecar-receipts.jsonl"),
    MNDE_AUTH_AUDIT_LOG: join(logsRoot, "auth-audit.jsonl"),
    MNDE_RECEIPT_HMAC_SECRET: "demo-legacy-signature-key-000000000001",
    MNDE_RECEIPT_HMAC_KEY_ID: "demo-legacy-signature-key",
    MNDE_INLINE_REFUSAL_RECEIPTS: "1", // return REFUSE receipts inline so the wrapper can store + verify them
    MNDE_RECEIPT_DURABILITY_MODE: "strict_audit",
    MNDE_WORKER_POOL_SIZE: "1",
    MNDE_WORKER_QUEUE_MAX_DEPTH: "16",
    MNDE_TESTER_ID: testerId,
    MNDE_INSTALLATION_ID: installationId,
    // v1 default: the policy engine is the canonical decision path. The legacy
    // compatibility pipeline is an explicit opt-in (MNDE_DECISION_ENGINE=legacy).
    MNDE_DECISION_ENGINE: process.env.MNDE_DECISION_ENGINE ?? "policy-engine",
    // Caller overrides last (e.g. MNDE_DECISION_ENGINE, MNDE_PE_POLICY, MNDE_BIND_PORT).
    ...extraEnv
  };
  // Under policy-engine with no policy selected, the sidecar runs the built-in
  // default-deny and every decision REFUSES. Harness runs are demos/tests, so
  // supply the repo demo policy instead; any caller/ambient policy or bundle
  // selection wins.
  if (resolveDecisionEngine(env) === "policy-engine" && !env.MNDE_PE_POLICY && !env.MNDE_PE_POLICY_BUNDLE) {
    env.MNDE_PE_POLICY = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
  }

  const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
    cwd: repoRoot,
    env,
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true
  });

  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  await waitReady(url, child, () => stderr);

  return {
    url,
    getStderr() {
      return stderr;
    },
    async stop() {
      if (child.exitCode !== null) return;
      child.kill();
      await new Promise((done) => {
        const timeout = setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
          done();
        }, 3000);
        child.once("exit", () => {
          clearTimeout(timeout);
          done();
        });
      });
    }
  };
}

async function waitReady(url, child, getStderr) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`MNDe sidecar exited early (code ${child.exitCode}):\n${getStderr()}`);
    }
    try {
      const response = await fetch(`${url}/readyz`);
      const body = await response.json();
      if (body?.ok === true) return;
    } catch {
      /* not up yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`MNDe sidecar readiness timed out:\n${getStderr()}`);
}
