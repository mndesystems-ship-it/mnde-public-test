// Authenticated proxy/executor tests.
//
//   npm run test:proxy-auth
//
// With MNDE_SIDECAR_AUTH=bearer on the sidecar and MNDE_SIDECAR_BEARER_TOKEN on
// the proxy/executor, authenticated proxy traffic works end-to-end. Missing or
// wrong outbound tokens fail closed and are not forwarded. The token never
// appears in the receipt, the proxy logs, or the result.

import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";

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
function envelopeOf(call) {
  return JSON.parse(call.content.find((c) => { try { return JSON.parse(c.text).mnde; } catch { return false; } }).text).mnde;
}
async function withProxy(sidecarUrl, proxyEnv, fn) {
  const marker = join(repoRoot, "mnde-receipts", "proxy-auth-marker.txt");
  rmSync(marker, { force: true });
  const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
    MNDE_SIDECAR_URL: sidecarUrl,
    MNDE_MCP_MARKER: marker,
    MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/proxy-auth",
    MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"]),
    ...proxyEnv
  });
  try {
    await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    client.notify("notifications/initialized", {});
    await fn(client, marker);
  } finally {
    await client.stop();
  }
}

async function main() {
  console.log("MNDe authenticated proxy/executor\n");

  // ── default: no auth anywhere (unchanged) ──────────────────────────────────
  // Dedicated port: 8787 is the sidecar's real default, so a developer's live
  // sidecar may legitimately own it while tests run.
  const open = await startMndeSidecar({ url: "http://127.0.0.1:8808", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy } });
  try {
    await test("default proxy path unchanged (no auth, no token)", async () => {
      await withProxy(open.url, {}, async (client) => {
        const call = await client.request("tools/call", { name: "read_status", arguments: {} });
        const env = envelopeOf(call);
        assert.equal(env.decision, "ALLOW");
        assert.equal(env.forwarded, true);
      });
    });
  } finally {
    await open.stop();
  }

  // ── bearer + PE sidecar ────────────────────────────────────────────────────
  const pe = await startMndeSidecar({ url: "http://127.0.0.1:8798", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: "8798" } });
  try {
    await test("auth enabled + no outbound token: REFUSE, not forwarded", async () => {
      await withProxy(pe.url, {}, async (client, marker) => {
        const call = await client.request("tools/call", { name: "delete_backups", arguments: { path: "x", script: "rm -rf x" } });
        const env = envelopeOf(call);
        assert.equal(env.decision, "REFUSE");
        assert.equal(env.forwarded, false);
        assert.equal(existsSync(marker), false);
      });
    });
    await test("auth enabled + wrong outbound token: REFUSE, not forwarded", async () => {
      await withProxy(pe.url, { MNDE_SIDECAR_BEARER_TOKEN: "wrong-token" }, async (client, marker) => {
        const call = await client.request("tools/call", { name: "delete_backups", arguments: { path: "x", script: "rm -rf x" } });
        const env = envelopeOf(call);
        assert.equal(env.decision, "REFUSE");
        assert.equal(existsSync(marker), false);
      });
    });
    await test("auth enabled + valid token: PE evaluates, caller maps into principal, token not leaked", async () => {
      await withProxy(pe.url, { MNDE_SIDECAR_BEARER_TOKEN: TOKEN }, async (client) => {
        const call = await client.request("tools/call", { name: "read_status", arguments: {} });
        const env = envelopeOf(call);
        assert.equal(env.decision, "ALLOW");
        assert.equal(env.forwarded, true);
        const receipt = readFileSync(env.receiptPath, "utf8");
        assert.equal(JSON.parse(JSON.parse(receipt).canonical_request).principal.id, "svc-caller");
        assert.ok(!receipt.includes(TOKEN), "token must not appear in the receipt");
        assert.ok(!client.getStderr().includes(TOKEN), "token must not appear in proxy logs");
      });
    });
  } finally {
    await pe.stop();
  }

  // ── bearer + legacy sidecar ────────────────────────────────────────────────
  const legacy = await startMndeSidecar({ url: "http://127.0.0.1:8797", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_BIND_PORT: "8797" } });
  try {
    await test("legacy mode + auth + valid token still works through the proxy", async () => {
      await withProxy(legacy.url, { MNDE_SIDECAR_BEARER_TOKEN: TOKEN }, async (client) => {
        const call = await client.request("tools/call", { name: "read_status", arguments: {} });
        const env = envelopeOf(call);
        assert.equal(env.decision, "ALLOW");
        assert.equal(env.forwarded, true);
      });
    });
  } finally {
    await legacy.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL proxy-auth tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS proxy-auth tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
