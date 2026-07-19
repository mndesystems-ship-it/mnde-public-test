#!/usr/bin/env node
// Startup authentication readiness — race test.
//
// Security invariant under test: a production sidecar must NEVER answer an
// unauthenticated request to a protected endpoint with HTTP 200 — not during
// startup, not after readiness, not under concurrent load. Acceptable responses
// are: connection refused (not yet listening), 503 (startup unavailable), or 403
// (authenticated enforcement active). A single 200 to an unauthenticated caller
// is a hard failure.
//
// The test spawns the real sidecar directly (NOT via the readiness-gated harness)
// and floods it with unauthenticated + forged requests from t=0 — before it binds,
// through the readiness transition, and after it is serving — across many restarts
// and under concurrency. No sleeps or arbitrary delays; it races the process.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let passed = 0;
function check(name, cond) { assert.equal(cond, true, name); console.log(`  [PASS] ${name}`); passed += 1; }

async function productionEnv(dir) {
  // Custody signing + production profile.
  const custRoot = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const custReceipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const custodyBundle = await buildAuthorityBundle({
    authorityId: "race-prod", issuedAt: "2026-06-14T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z",
    root: custRoot,
    receiptKeys: [{ keyId: custReceipt.keyId, publicPem: custReceipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const custodyBundlePath = join(dir, "authority.bundle.json");
  const custodyKeyPath = join(dir, "receipt.key.pem");
  writeFileSync(custodyBundlePath, JSON.stringify(custodyBundle));
  writeFileSync(custodyKeyPath, custReceipt.privatePem);

  // Enforced signed policy bundle + bearer caller auth for production posture.
  const peRoot = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const peAuthority = await buildAuthorityBundle({
    authorityId: "race-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root: peRoot,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const policyBundle = await signPolicyBundle({
    bundle_id: "race-policy-1-1.0.0", policy_id: "race-policy", serial: 1, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "race-policy", version: "1.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const peAuthorityPath = join(dir, "pe-authority.json");
  writeFileSync(policyBundlePath, JSON.stringify(policyBundle));
  writeFileSync(peAuthorityPath, JSON.stringify(peAuthority));

  // Read-side authority assertion signing key (verifier holds the public half).
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });

  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: custodyBundlePath,
    MNDE_RECEIPT_SIGNING_KEY: custodyKeyPath,
    MNDE_RECEIPT_KEY_ID: custReceipt.keyId,
    MNDE_SIDECAR_AUTH: "bearer",
    MNDE_SIDECAR_AUTH_TOKENS: JSON.stringify({ "race-token": "race-caller" }),
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: peAuthorityPath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: peAuthority.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z",
    MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64: Buffer.from(publicDer).subarray(-32).toString("base64url"),
    MNDE_AUTH_AUDIT_LOG: join(dir, "auth-audit.jsonl"),
    MNDE_AUTH_NONCE_CACHE: join(dir, "auth-nonces.json")
  };
}

// One protected-endpoint probe. Never supplies valid auth. Returns the numeric
// status, or a synthetic marker for a connection that never reached a listener.
async function probe(port, headers = {}) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/identity`, { headers });
    return res.status;
  } catch {
    return "conn-refused"; // not listening yet / socket torn down — acceptable
  }
}

// Forge an assertion whose signature is structurally present but cryptographically
// invalid (bit-flipped decoded bytes). Must always be refused.
function forgedAssertion() {
  const { privateKey } = generateKeyPairSync("ed25519"); // wrong key vs the sidecar's configured public key
  const payload = { issuer: "x", audience: "mnde-sidecar", subject: "attacker", nonce: `nonce-${Math.random().toString(36).slice(2).padEnd(20, "x")}`, issued_at: Date.now() - 1000, expires_at: Date.now() + 60000, roles: ["ADMIN"], capabilities: ["view_runtime", "inspect_receipts", "view_dashboard"] };
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const s = sign(null, Buffer.from(p), privateKey);
  s[0] ^= 0x01;
  return `${p}.${s.toString("base64url")}`;
}

function spawnSidecar(port, env) {
  return spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
    cwd: repoRoot,
    env: { ...process.env, MNDE_BIND_PORT: String(port), MNDE_HARNESS_INSTANCE_ID: `race-${port}-${Math.random()}`, ...env },
    stdio: ["ignore", "ignore", "pipe"], windowsHide: true
  });
}

async function main() {
  console.log("MNDe sidecar startup authentication readiness — race test\n");
  bootstrapReceiptKeys({ repoRoot });
  mkdirSync(join(repoRoot, "mnde-receipts", "_sidecar-logs"), { recursive: true });

  const RESTARTS = Number.parseInt(process.env.MNDE_RACE_RESTARTS ?? "12", 10);
  const CONCURRENCY = 40;
  const statusTally = new Map();
  let two_hundreds = 0;
  let totalRequests = 0;
  let sawServing = 0;

  for (let r = 0; r < RESTARTS; r += 1) {
    const dir = mkdtempSync(join(tmpdir(), "mnde-race-"));
    const env = await productionEnv(dir);
    const port = 8830 + r; // distinct port per restart — no cross-iteration collisions
    const child = spawnSidecar(port, env);
    let childErr = "";
    child.stderr?.on("data", (c) => { childErr += c.toString(); });

    // Flood the protected endpoint from t=0 (before bind) until we have observed
    // a serving process (a 403) and pushed well past it. Unauthenticated + forged.
    const deadline = Date.now() + 6000;
    let serving = false;
    try {
      while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`sidecar exited early (code ${child.exitCode}): ${childErr}`);
        const headerVariants = [ {}, { "x-mnde-authority-assertion": "not-a-real-assertion" }, { "x-mnde-authority-assertion": forgedAssertion() } ];
        const batch = Array.from({ length: CONCURRENCY }, (_v, i) => probe(port, headerVariants[i % headerVariants.length]));
        const statuses = await Promise.all(batch);
        for (const s of statuses) {
          totalRequests += 1;
          statusTally.set(s, (statusTally.get(s) ?? 0) + 1);
          if (s === 200) two_hundreds += 1;
          if (s === 403) serving = true;
        }
        if (serving) {
          // Serving confirmed: one more full concurrent burst past readiness, then stop.
          const burst = await Promise.all(Array.from({ length: CONCURRENCY * 2 }, (_v, i) => probe(port, headerVariants[i % headerVariants.length])));
          for (const s of burst) { totalRequests += 1; statusTally.set(s, (statusTally.get(s) ?? 0) + 1); if (s === 200) two_hundreds += 1; }
          break;
        }
      }
      if (serving) sawServing += 1;
    } finally {
      child.kill();
      await new Promise((done) => { const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } done(); }, 3000); child.once("exit", () => { clearTimeout(t); done(); }); });
      rmSync(dir, { recursive: true, force: true });
    }
  }

  console.log(`  restarts: ${RESTARTS}, total unauthenticated/forged requests: ${totalRequests}`);
  console.log(`  status distribution: ${JSON.stringify(Object.fromEntries(statusTally))}`);
  check("every restart reached a serving (enforcing) state", sawServing === RESTARTS);
  check("no unauthenticated/forged request EVER received HTTP 200", two_hundreds === 0);
  check("all observed statuses are conn-refused | 503 | 403 (never authenticated success)",
    [...statusTally.keys()].every((s) => s === "conn-refused" || s === 503 || s === 403));

  console.log(`\nPASS sidecar-startup-race tests (${passed}/${passed})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
