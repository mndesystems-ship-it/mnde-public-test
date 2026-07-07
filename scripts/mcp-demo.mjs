// MNDe MCP Server Demo — end to end over a real MCP stdio transport.
//
//   npm run mcp-demo
//
// Spins up a real sidecar, launches the MNDe MCP server, and drives it as an MCP
// client would: initialize, list tools, call a safe tool (ALLOW) and a
// destructive tool (REFUSE). Proves the destructive tool never ran by checking a
// cross-process destruction marker, and verifies both receipts offline.

import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";

const SIDECAR_URL = "http://127.0.0.1:8787";
const MARKER = join(process.cwd(), "mnde-receipts", "mcp-demo-destruction-marker.txt");

function envelopeOf(call) {
  const block = call.content.find((part) => {
    try {
      return Boolean(JSON.parse(part.text).mnde);
    } catch {
      return false;
    }
  });
  return JSON.parse(block.text).mnde;
}

function receiptVerifies(envelope) {
  if (!envelope.receiptPath) return false;
  try {
    return verifyAnyReceiptFile(envelope.receiptPath).verified;
  } catch {
    return false;
  }
}

async function main() {
  console.log("MNDe MCP Server Demo\n");
  rmSync(MARKER, { force: true });
  let pass = true;

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL });
  const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-server.mjs"], {
    MNDE_SIDECAR_URL: SIDECAR_URL,
    MNDE_MCP_MARKER: MARKER,
    MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/mcp-demo"
  });

  try {
    const init = await client.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "mnde-demo-client", version: "0.1.0" }
    });
    client.notify("notifications/initialized", {});
    console.log(`Client initializes MNDe MCP server: ${init?.serverInfo?.name ? "OK" : "FAIL"}`);

    const list = await client.request("tools/list", {});
    console.log(`Tools exposed: ${list.tools.map((tool) => tool.name).join(", ")}\n`);
    pass = pass && Boolean(init?.serverInfo?.name) && list.tools.length === 3;

    const allow = await client.request("tools/call", { name: "read_status", arguments: { service: "billing" } });
    const allowEnv = envelopeOf(allow);
    console.log("Agent calls read_status:");
    console.log(`Decision: ${allowEnv.decision}`);
    console.log(`Executed: ${allowEnv.executed ? "YES" : "NO"}`);
    console.log(`Receipt: ${receiptVerifies(allowEnv) ? "VERIFIED" : "NOT VERIFIED"}\n`);
    pass = pass && allowEnv.decision === "ALLOW" && allowEnv.executed === true && allow.isError === false && receiptVerifies(allowEnv);

    const refuse = await client.request("tools/call", {
      name: "delete_backups",
      arguments: { path: "backups/", script: "rm -rf backups/" }
    });
    const refuseEnv = envelopeOf(refuse);
    const markerAbsent = !existsSync(MARKER);
    console.log("Agent calls delete_backups (rm -rf):");
    console.log(`Decision: ${refuseEnv.decision}`);
    console.log(`Executed: ${refuseEnv.executed ? "YES" : "NO"}${markerAbsent ? "          (destruction marker absent)" : "   (MARKER PRESENT — LEAK!)"}`);
    console.log(`Receipt: ${receiptVerifies(refuseEnv) ? "VERIFIED" : "NOT VERIFIED"}\n`);
    pass = pass && refuseEnv.decision === "REFUSE" && refuseEnv.executed === false && refuse.isError === true && markerAbsent && receiptVerifies(refuseEnv);
  } finally {
    await client.stop();
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
