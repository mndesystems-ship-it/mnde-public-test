// Sidecar caller authentication tests (opt-in bearer mode).
//
//   npm run test:auth
//
// Default (auth off) is unchanged. In bearer mode, /v1/decisions rejects missing,
// malformed, and wrong tokens, accepts a valid token, maps the authenticated
// caller into the PE principal, never creates an ALLOW receipt for a rejected
// caller, and the MCP proxy does not forward an unauthenticated call.

import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";

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
