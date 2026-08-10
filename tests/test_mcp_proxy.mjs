// MNDe MCP Proxy — proves MNDe protects tools you did not write.
//
//   npm run test:mcp-proxy
//
// Covers all nine acceptance criteria for proxy mode against a plain upstream
// MCP server, including upstream crash and malformed-response fail-closed.

import assert from "node:assert/strict";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

// Dedicated port: 8787 is the sidecar's real default, so a developer's live
// sidecar may legitimately own it while tests run.
const SIDECAR_URL = "http://127.0.0.1:8807";
const RECEIPTS_DIR = "./mnde-receipts/mcp-proxy-tests";
const MARKER = join(process.cwd(), "mnde-receipts", "mcp-proxy-test-marker.txt");

rmSync(RECEIPTS_DIR, { recursive: true, force: true });
rmSync(MARKER, { force: true });

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

function blocks(call) {
  return (call.content ?? [])
    .map((part) => {
      try {
        return JSON.parse(part.text);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}
const mndeOf = (call) => blocks(call).find((block) => block.mnde)?.mnde;
const upstreamRan = (call) => blocks(call).some((block) => block.source === "upstream");

function makeProxy(mode) {
  return createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
    MNDE_SIDECAR_URL: SIDECAR_URL,
    MNDE_MCP_MARKER: MARKER,
    MNDE_MCP_RECEIPTS_DIR: RECEIPTS_DIR,
    MNDE_UPSTREAM_MODE: mode,
    MNDE_PROXY_UPSTREAM_TIMEOUT_MS: "4000",
    MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
  });
}
async function handshake(client) {
  await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
  client.notify("notifications/initialized", {});
}

async function main() {
  console.log("MNDe MCP Proxy — protecting a server you did not write\n");
  const sidecar = await startMndeSidecar({ url: SIDECAR_URL });

  const proxy = makeProxy("normal");
  try {
    await handshake(proxy);

    await test("1-2. upstream tools are visible through the proxy", async () => {
      const list = await proxy.request("tools/list", {});
      const names = list.tools.map((tool) => tool.name);
      assert.deepEqual(names.sort(), ["delete_backups", "read_status", "restart_service"]);
    });

    let allowEnv;
    await test("3. ALLOW forwards the call to upstream", async () => {
      const call = await proxy.request("tools/call", { name: "read_status", arguments: { service: "billing" } });
      allowEnv = mndeOf(call);
      
      // Instrument full diagnostic state for transient failure diagnosis
      if (call.isError !== false) {
        const errorDetails = {
          call_isError: call.isError,
          mnde_decision: allowEnv?.decision,
          mnde_forwarded: allowEnv?.forwarded,
          mnde_upstreamError: allowEnv?.upstreamError,
          mnde_reason: allowEnv?.reason,
          mnde_failClosed: allowEnv?.failClosed,
          upstream_ran: upstreamRan(call),
          proxy_stderr: proxy.getStderr(),
          call_content: JSON.stringify(call.content, null, 2)
        };
        throw new Error(
          `call.isError was ${call.isError} (expected false). Diagnostics: ${JSON.stringify(errorDetails, null, 2)}`
        );
      }
      
      assert.equal(call.isError, false);
      assert.equal(allowEnv.decision, "ALLOW");
      assert.equal(allowEnv.forwarded, true);
      assert.equal(upstreamRan(call), true, "the call must have reached the upstream server");
    });

    await test("4-5. REFUSE is not forwarded; upstream marker stays absent", async () => {
      const call = await proxy.request("tools/call", { name: "delete_backups", arguments: { path: "backups/", script: "rm -rf backups/" } });
      const env = mndeOf(call);
      assert.equal(call.isError, true);
      assert.equal(env.decision, "REFUSE");
      assert.equal(env.forwarded, false, "a refused call must NOT be forwarded upstream");
      assert.equal(upstreamRan(call), false);
      assert.equal(existsSync(MARKER), false, "the upstream destructive tool must not have run");
    });

    await test("6. receipt verifies offline", async () => {
      assert.ok(allowEnv?.receiptPath, "need a receipt from the ALLOW call");
      assert.equal(verificationPassed(verifyReceiptFile(allowEnv.receiptPath)), true);
    });
  } finally {
    await proxy.stop();
  }

  const crashProxy = makeProxy("crash-on-call");
  try {
    await handshake(crashProxy);
    await test("7. upstream crash fails closed", async () => {
      const call = await crashProxy.request("tools/call", { name: "read_status", arguments: {} });
      const env = mndeOf(call);
      assert.equal(call.isError, true, "a crashed upstream must not produce a success result");
      assert.equal(env.upstreamError, "ERR_UPSTREAM_UNAVAILABLE");
      assert.equal(existsSync(MARKER), false);
    });
  } finally {
    await crashProxy.stop();
  }

  const malformedProxy = makeProxy("malformed-on-call");
  try {
    await handshake(malformedProxy);
    await test("8. malformed upstream response fails closed", async () => {
      const call = await malformedProxy.request("tools/call", { name: "read_status", arguments: {} });
      const env = mndeOf(call);
      assert.equal(call.isError, true, "a malformed upstream response must not be passed off as success");
      assert.equal(env.upstreamError, "ERR_UPSTREAM_BAD_RESPONSE");
    });
  } finally {
    await malformedProxy.stop();
    await sidecar.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL MCP proxy tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS MCP proxy tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
