#!/usr/bin/env node
// MNDe MCP Server.
//
// A Model Context Protocol server (newline-delimited JSON-RPC over stdio, no
// third-party dependencies) that exposes tools gated by MNDe. Every `tools/call`
// is routed through MNDe first: ALLOW runs the tool, REFUSE does not, and the
// response carries a signed receipt. Works with MCP clients such as Claude
// Desktop, Cursor, and MCP Inspector.
//
// Run standalone:   MNDE_SIDECAR_URL=http://127.0.0.1:8787 node mcp/mnde-mcp-server.mjs
// (stdout is protocol traffic only; logs go to stderr.)

import { createMndeExecutor } from "../executor/index.mjs";
import { defaultGuardedTools } from "./guarded-tools.mjs";

const SERVER_NAME = "mnde-mcp";
const SERVER_VERSION = "0.1.0";
const PROTOCOL_VERSION = "2025-06-18";

const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";
const receiptsDir = process.env.MNDE_MCP_RECEIPTS_DIR ?? "./mnde-receipts/mcp";

const mnde = createMndeExecutor({ sidecarUrl, receiptsDir });
const tools = defaultGuardedTools();
const toolMap = new Map(tools.map((tool) => [tool.name, tool]));

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
function sendResult(id, result) {
  send({ jsonrpc: "2.0", id, result });
}
function sendError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}
function log(...parts) {
  process.stderr.write(`[mnde-mcp] ${parts.join(" ")}\n`);
}

async function handleToolCall(id, params) {
  const name = params?.name;
  const args = params?.arguments ?? {};
  const tool = toolMap.get(name);
  if (!tool) {
    sendError(id, -32602, `unknown tool: ${name}`);
    return;
  }

  // The guard. run() is reached only on ALLOW (enforced inside the executor).
  const outcome = await mnde.execute({ action: name, input: args, run: () => tool.run(args) });

  const envelope = {
    decision: outcome.decision,
    reason: outcome.reason,
    executed: outcome.executed,
    receiptPath: outcome.receiptPath,
    verified: outcome.verified,
    failClosed: outcome.failClosed
  };
  const human = outcome.allowed
    ? `ALLOW — ran ${name}. Result: ${JSON.stringify(outcome.result)}`
    : `${outcome.failClosed ? "FAIL-CLOSED" : "REFUSE"} — MNDe blocked ${name} (${outcome.reason}). The tool did not run.`;

  sendResult(id, {
    content: [
      { type: "text", text: human },
      { type: "text", text: JSON.stringify({ mnde: envelope }) }
    ],
    isError: !outcome.allowed
  });
}

async function handle(message) {
  const { id, method, params } = message;
  const isRequest = id !== undefined && id !== null;
  switch (method) {
    case "initialize":
      sendResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
      });
      return;
    case "notifications/initialized":
      return; // notification — no response
    case "ping":
      sendResult(id, {});
      return;
    case "tools/list":
      sendResult(id, {
        tools: tools.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema }))
      });
      return;
    case "tools/call":
      await handleToolCall(id, params);
      return;
    default:
      if (isRequest) sendError(id, -32601, `method not found: ${method}`);
      return;
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      sendError(null, -32700, "parse error");
      continue;
    }
    Promise.resolve(handle(message)).catch((error) => log("handler error:", error?.message ?? String(error)));
  }
});
process.stdin.on("end", () => process.exit(0));

log(`ready; sidecar=${sidecarUrl}`);
