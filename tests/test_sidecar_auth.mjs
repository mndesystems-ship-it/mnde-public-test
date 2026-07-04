// Sidecar caller authentication tests (opt-in bearer mode).
//
//   npm run test:auth
//
// Default (auth off) is unchanged. In bearer mode, /v1/decisions rejects missing,
// malformed, and wrong tokens, accepts a valid token, maps the authenticated
// caller into the PE principal, never creates an ALLOW receipt for a rejected
// caller, and the MCP proxy does not forward an unauthenticated call.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
const TOKEN = "good-token-123";
const TOKENS_JSON = JSON.stringify({ [TOKEN]: "svc-caller" });

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
async function post(url, body, headers = {}) {
  const r = await fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
function peReq(tool, extra = {}) {
  return { schema_version: "1.0", request_id: `req-${tool}`, timestamp: new Date().toISOString(), principal: { id: "from-body" }, agent: { id: "a" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {}, ...extra };
}
async function postReplay(url, headers = {}) {
  const r = await fetch(`${url}/replay`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ receipt: { schema_version: "test-unverifiable" } })
  });
  return { status: r.status, body: await r.json() };
}

// Production custody + posture env so a production-profile sidecar can boot
// (mirrors tests/test_dashboard.mjs).
function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const bundle = buildAuthorityBundle({
    authorityId: "acme-prod-replay-auth",
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

function productionEnforcementExtras(dir) {
  const root = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = buildAuthorityBundle({
    authorityId: "mnde-replay-auth-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundle = signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "pe-authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    MNDE_SIDECAR_AUTH: "bearer",
    MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON,
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z"
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
  console.log("MNDe sidecar — caller authentication\n");

  // ── auth off (default): existing behavior ──────────────────────────────────
  const off = await startMndeSidecar({ url: "http://127.0.0.1:8787", env: {} });
  try {
    await test("default auth off: request without Authorization works", async () => {
      const { body } = await post(off.url, reviewerRequest({ requestId: "r1", tool: "read_status" }));
      assert.notEqual(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.decision, "ALLOW");
    });
    await test("local profile: POST /replay stays open (reviewer-kit compatibility)", async () => {
      const { status, body } = await postReplay(off.url);
      assert.equal(status, 200);
      assert.equal(body.schema_version, "mnde.receipt_replay.v1");
    });
    await test("local profile: /readyz keeps the detailed readiness payload", async () => {
      const res = await fetch(`${off.url}/readyz`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(typeof body.ok, "boolean");
      assert.equal(typeof body.degraded, "boolean");
      for (const field of ["active_policy_version", "policy_hash", "receipt_queue", "worker_pool", "watchdog", "sockets", "max_inflight", "shed_inflight", "durability_mode"]) {
        assert.ok(field in body, `local /readyz must keep detailed field: ${field}`);
      }
    });
  } finally {
    await off.stop();
  }

  // ── bearer + legacy ────────────────────────────────────────────────────────
  const legacy = await startMndeSidecar({ url: "http://127.0.0.1:8797", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_BIND_PORT: "8797" } });
  try {
    await test("bearer: missing token rejected (no ALLOW receipt)", async () => {
      const { status, body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }));
      assert.equal(status, 401);
      assert.equal(body.decision, "REFUSE");
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    });
    await test("bearer: malformed Authorization header rejected", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: "Token abc" });
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
    });
    await test("bearer: wrong token rejected", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: "Bearer nope" });
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
    });
    await test("bearer: valid token accepted (legacy mode still works)", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: `Bearer ${TOKEN}` });
      assert.equal(body.decision, "ALLOW");
      assert.equal(body.authenticated_caller, "svc-caller");
    });
  } finally {
    await legacy.stop();
  }

  // ── bearer + policy-engine ─────────────────────────────────────────────────
  const pe = await startMndeSidecar({ url: "http://127.0.0.1:8798", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: "8798" } });
  try {
    await test("bearer + PE: valid token accepted and caller maps into principal", async () => {
      const { body } = await post(pe.url, peReq("read_status"), { authorization: `Bearer ${TOKEN}` });
      assert.equal(body.decision, "ALLOW");
      assert.equal(body.authenticated_caller, "svc-caller");
      // body principal "from-body" must be overridden by the token identity
      const principal = JSON.parse(body.receipt.canonical_request).principal.id;
      assert.equal(principal, "svc-caller");
    });
    await test("bearer + PE: missing token rejected with no receipt", async () => {
      const { status, body } = await post(pe.url, peReq("read_status"));
      assert.equal(status, 401);
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    });
    await test("bearer + PE: unauthenticated call is not forwarded through the MCP proxy", async () => {
      const marker = join(repoRoot, "mnde-receipts", "auth-proxy-marker.txt");
      rmSync(marker, { force: true });
      // The proxy/executor send no Authorization header -> sidecar rejects -> REFUSE.
      const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
        MNDE_SIDECAR_URL: pe.url,
        MNDE_MCP_MARKER: marker,
        MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/auth-proxy",
        MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
      });
      try {
        await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
        client.notify("notifications/initialized", {});
        const call = await client.request("tools/call", { name: "read_status", arguments: {} });
        const env = JSON.parse(call.content.find((c) => { try { return JSON.parse(c.text).mnde; } catch { return false; } }).text).mnde;
        assert.equal(env.decision, "REFUSE");
        assert.equal(env.forwarded, false);
        assert.equal(existsSync(marker), false, "an unauthenticated call must not be forwarded");
      } finally {
        await client.stop();
      }
    });
  } finally {
    await pe.stop();
  }

  // ── production: POST /replay requires an authority assertion ───────────────
  const prodDir = mkdtempSync(join(tmpdir(), "mnde-replay-auth-prod-"));
  let prod = null;
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const auditLog = join(prodDir, "auth-audit.jsonl");
    prod = await startMndeSidecar({
      url: "http://127.0.0.1:8799",
      env: {
        ...writeProductionCustody(prodDir),
        ...productionEnforcementExtras(prodDir),
        MNDE_BIND_PORT: "8799",
        MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64: Buffer.from(publicDer).subarray(-32).toString("base64url"),
        MNDE_AUTH_AUDIT_LOG: auditLog,
        MNDE_AUTH_NONCE_CACHE: join(prodDir, "auth-nonces.json")
      }
    });

    await test("production: unauthenticated POST /replay is refused and audited", async () => {
      const { status, body } = await postReplay(prod.url);
      assert.equal(status, 403);
      assert.equal(body.reason_code, "ERR_AUTH_REQUIRED");
      const lines = readFileSync(auditLog, "utf8").trim().split(/\n/).filter(Boolean).map((line) => JSON.parse(line));
      const record = lines.at(-1);
      assert.equal(record.action, "replay.decision");
      assert.equal(record.result, "REFUSE");
      assert.equal(record.reason, "ERR_AUTH_REQUIRED");
    });

    await test("production: assertion without replay_decisions capability is refused", async () => {
      const viewer = authorityAssertion(privateKey, { roles: ["VIEWER"], capabilities: ["view_dashboard"] });
      const { status, body } = await postReplay(prod.url, { "x-mnde-authority-assertion": viewer });
      assert.equal(status, 403);
      assert.equal(body.reason_code, "ERR_AUTHZ_REFUSED");
    });

    await test("production: /readyz reports readiness without operational metadata", async () => {
      const res = await fetch(`${prod.url}/readyz`);
      assert.equal(res.status, 200, "/readyz must stay open for readiness probes");
      const body = await res.json();
      // Readiness still reported correctly on a healthy production boot...
      assert.equal(body.ok, true);
      assert.equal(body.degraded, false);
      // ...and NOTHING else: the payload is exactly the readiness signal.
      assert.deepEqual(Object.keys(body).sort(), ["degraded", "ok"]);
    });

    await test("production: valid replay_decisions assertion reaches the replay handler", async () => {
      const assertion = authorityAssertion(privateKey);
      const { status, body } = await postReplay(prod.url, { "x-mnde-authority-assertion": assertion });
      assert.equal(status, 200);
      assert.equal(body.schema_version, "mnde.receipt_replay.v1");
      // Reusing the SAME assertion must fail: the nonce is single-use.
      const replayed = await postReplay(prod.url, { "x-mnde-authority-assertion": assertion });
      assert.equal(replayed.status, 403);
      assert.equal(replayed.body.reason_code, "ERR_AUTH_REPLAY");
    });
  } finally {
    if (prod) await prod.stop();
    rmSync(prodDir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL sidecar auth tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS sidecar auth tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
