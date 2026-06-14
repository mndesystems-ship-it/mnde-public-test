// MNDe MCP Proxy Demo — put MNDe in front of a server you did not write.
//
//   npm run mcp-proxy-demo
//
// Starts a sidecar, launches the MNDe proxy (which spawns a plain upstream MCP
// server), and drives the proxy as an agent would. ALLOW is forwarded to the
// upstream and runs there; REFUSE is never forwarded and the upstream's
// destruction marker stays absent. Both produce receipts that verify offline.

import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const SIDECAR_URL = "http://127.0.0.1:8787";
const MARKER = join(process.cwd(), "mnde-receipts", "mcp-proxy-demo-marker.txt");

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
function mndeOf(call) {
  return blocks(call).find((block) => block.mnde)?.mnde;
}
function upstreamRan(call) {
  return blocks(call).some((block) => block.source === "upstream");
}
function receiptVerifies(envelope) {
  if (!envelope?.receiptPath) return false;
  try {
    return verificationPassed(verifyReceiptFile(envelope.receiptPath));
  } catch {
    return false;
  }
}

async function main() {
  console.log("MNDe MCP Proxy Demo\n");
  rmSync(MARKER, { force: true });
  let pass = true;

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL });
  const agent = createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
    MNDE_SIDECAR_URL: SIDECAR_URL,
    MNDE_MCP_MARKER: MARKER,
    MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/mcp-proxy-demo",
    MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
  });

  try {
    const init = await agent.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "demo", version: "0" } });
    agent.notify("notifications/initialized", {});
    console.log(`Upstream MCP server: ${init?.serverInfo?.name} (tools you did not write)`);
    console.log("Proxy initialized: OK");

    const list = await agent.request("tools/list", {});
    console.log(`Tools via proxy: ${list.tools.map((tool) => tool.name).join(", ")}\n`);
    pass = pass && init?.serverInfo?.name === "example-upstream" && list.tools.length === 3;

    const allow = await agent.request("tools/call", { name: "read_status", arguments: { service: "billing" } });
    const allowEnv = mndeOf(allow);
    console.log("Agent calls read_status (through proxy):");
    console.log(`Decision: ${allowEnv.decision}`);
    console.log(`Forwarded: ${allowEnv.forwarded ? "YES" : "NO"}`);
    console.log(`Upstream ran: ${upstreamRan(allow) ? "YES" : "NO"}`);
    console.log(`Receipt: ${receiptVerifies(allowEnv) ? "VERIFIED" : "NOT VERIFIED"}\n`);
    pass = pass && allowEnv.decision === "ALLOW" && allowEnv.forwarded === true && upstreamRan(allow) && allow.isError === false && receiptVerifies(allowEnv);

    const refuse = await agent.request("tools/call", { name: "delete_backups", arguments: { path: "backups/", script: "rm -rf backups/" } });
    const refuseEnv = mndeOf(refuse);
    const markerAbsent = !existsSync(MARKER);
    console.log("Agent calls delete_backups (rm -rf) (through proxy):");
    console.log(`Decision: ${refuseEnv.decision}`);
    console.log(`Forwarded: ${refuseEnv.forwarded ? "YES" : "NO"}`);
    console.log(`Upstream marker absent: ${markerAbsent ? "YES" : "NO"}`);
    console.log(`Receipt: ${receiptVerifies(refuseEnv) ? "VERIFIED" : "NOT VERIFIED"}\n`);
    pass = pass && refuseEnv.decision === "REFUSE" && refuseEnv.forwarded === false && !upstreamRan(refuse) && refuse.isError === true && markerAbsent && receiptVerifies(refuseEnv);
  } finally {
    await agent.stop();
    await sidecar.stop();
  }

  console.log(`FINAL VERDICT: ${pass ? "PASS" : "FAIL"}`);
  if (!pass) process.exit(1);
}

main().catch((error) => {
  console.error(error);
  console.log("\nFINAL VERDICT: FAIL");
  process.exit(1);
});
