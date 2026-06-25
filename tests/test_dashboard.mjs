// Operational dashboard (no-login) tests.
//
//   npm run test:dashboard
//
// Proves the infrastructure-first repositioning: a fresh user launches MNDe and
// the sidecar serves a local operational dashboard at "/" with NO login, signup,
// account creation, or cloud dependency. The dashboard answers one question —
// "Is MNDe protecting execution right now?" — and reads only local status
// endpoints. The decision/receipt/replay/authority/policy paths are untouched.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "acme-prod-dashboard",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId
  };
}

function authorityAssertion(privateKey, overrides = {}) {
  const now = Date.now();
  const nonce = `nonce-${now}-${Math.random().toString(36).slice(2).padEnd(24, "x")}`;
  const payload = {
    issuer: "mnde-desktop",
    audience: "mnde-sidecar",
    subject: "auditor-1",
    nonce,
    session_id: `session-${nonce}`,
    issued_at: now - 1000,
    expires_at: now + 60_000,
    roles: ["AUDITOR"],
    capabilities: ["inspect_receipts", "replay_decisions", "export_audit", "view_dashboard"],
    display_name: "Auditor",
    provider: "test",
    ...overrides
  };
  const payloadPart = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signaturePart = sign(null, Buffer.from(payloadPart, "utf8"), privateKey).toString("base64url");
  return `${payloadPart}.${signaturePart}`;
}

async function main() {
  console.log("MNDe operational dashboard (no login)\n");

  const sc = await startMndeSidecar({ url: "http://127.0.0.1:8794", env: { MNDE_BIND_PORT: "8794" } });
  let html = "";
  let contentType = "";
  try {
    await test("GET / serves the operational dashboard as HTML (200, no auth)", async () => {
      const res = await fetch(`${sc.url}/`);
      assert.equal(res.status, 200);
      contentType = res.headers.get("content-type") || "";
      assert.match(contentType, /text\/html/);
      html = await res.text();
      assert.ok(html.includes("Is MNDe protecting execution right now?"), "headline question must be present");
    });

    await test("GET /dashboard also serves the dashboard", async () => {
      const res = await fetch(`${sc.url}/dashboard`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/html/);
    });

    await test("status screen shows all seven operational panels", () => {
      for (const panel of ["Protection Status", "Sidecar Status", "Active Policy", "Trust Status", "Last Decision", "Receipt Count", "Protected Sources"]) {
        assert.ok(html.includes(panel), `missing panel: ${panel}`);
      }
    });

    await test("navigation is reduced to Status / Decisions / Policy / Audit / Settings", () => {
      for (const nav of [">Status<", ">Decisions<", ">Policy<", ">Audit<", ">Settings<"]) {
        assert.ok(html.includes(nav), `missing nav item: ${nav}`);
      }
      // No SaaS / marketing nav.
      for (const banned of [">Welcome<", ">Get Started<", ">Sign In<", ">Login<"]) {
        assert.ok(!html.includes(banned), `forbidden nav item: ${banned}`);
      }
    });

    await test("no login / signup / account / marketing CTAs anywhere", () => {
      // The forbidden items are interactive CTAs / screens — checked as their
      // canonical title-case labels. (Repositioning prose like "no login" is fine.)
      for (const banned of ["Login", "Log In", "Sign In", "Sign Up", "Create Account", "Get Started", "Welcome"]) {
        assert.ok(!html.includes(banned), `forbidden CTA present: ${banned}`);
      }
      assert.ok(!/type=["']password["']/.test(html), "no password field allowed");
    });

    await test("no forced cloud dependency (no external origins, no email collection)", () => {
      assert.ok(!html.includes("https://"), "dashboard must not load external resources");
      assert.ok(!/type=["']email["']/.test(html), "no email collection field");
      assert.ok(!/<form\b/.test(html), "no sign-in/sign-up form");
    });

    await test("dashboard reads local status endpoints only (relative URLs)", () => {
      for (const ep of ["/readyz", "/healthz", "/receipts/recent", "/policy/current", "/capabilities", "/identity"]) {
        assert.ok(html.includes(ep), `dashboard should read ${ep}`);
      }
    });

    await test("decision path is unchanged — sidecar still decides and signs", async () => {
      const res = await fetch(`${sc.url}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_version: "1.0", request_id: "dash-1", timestamp: new Date().toISOString(), principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
      });
      const body = await res.json();
      assert.ok(body.decision === "ALLOW" || body.decision === "REFUSE", "sidecar still returns a decision");
    });
  } finally {
    await sc.stop();
  }

  const prodDir = mkdtempSync(join(tmpdir(), "mnde-dashboard-prod-"));
  let prod = null;
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const auditLog = join(prodDir, "auth-audit.jsonl");
    prod = await startMndeSidecar({
      url: "http://127.0.0.1:8796",
      env: {
        ...writeProductionCustody(prodDir),
        MNDE_BIND_PORT: "8796",
        MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64: Buffer.from(publicDer).subarray(-32).toString("base64url"),
        MNDE_AUTH_AUDIT_LOG: auditLog,
        MNDE_AUTH_NONCE_CACHE: join(prodDir, "auth-nonces.json")
      }
    });

    await test("production keeps health and readiness open", async () => {
      for (const ep of ["/healthz", "/readyz"]) {
        const res = await fetch(`${prod.url}${ep}`);
        assert.equal(res.status, 200, `${ep} should stay open`);
      }
    });

    await test("production read endpoints require authority assertion and create audit evidence", async () => {
      const sensitiveReads = ["/", "/dashboard", "/identity", "/metrics", "/receipts/recent", "/policy/current", "/capabilities"];
      for (const ep of sensitiveReads) {
        const res = await fetch(`${prod.url}${ep}`);
        assert.equal(res.status, 403, `${ep} must reject unauthenticated production reads`);
      }
      const lines = readFileSync(auditLog, "utf8").trim().split(/\n/).filter(Boolean).map((line) => JSON.parse(line));
      assert.ok(lines.length >= sensitiveReads.length, "unauthorized production reads must be audited");
      for (const record of lines.slice(-sensitiveReads.length)) {
        assert.equal(record.result, "REFUSE");
        assert.equal(record.reason, "ERR_AUTH_REQUIRED");
      }
    });

    await test("production read endpoint accepts valid authority assertion", async () => {
      const assertion = authorityAssertion(privateKey, { capabilities: ["view_runtime"], roles: ["OPERATOR"] });
      const res = await fetch(`${prod.url}/identity`, { headers: { "x-mnde-authority-assertion": assertion } });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.schema_version, "mnde.sidecar_identity.v1");
    });
  } finally {
    if (prod) await prod.stop();
    rmSync(prodDir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL dashboard tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS dashboard tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
