#!/usr/bin/env node
// A plain, third-party MCP server with NO MNDe. It represents "a tool you did
// not write" — the thing the MNDe proxy is put in front of.
//
// Modes (env MNDE_UPSTREAM_MODE), used to prove the proxy fails closed:
//   normal             - behaves normally
//   crash-on-call      - exits the process on any tools/call (simulated crash)
//   malformed-on-call  - returns a structurally invalid tools/call result

import { writeFileSync } from "node:fs";

const MODE = process.env.MNDE_UPSTREAM_MODE ?? "normal";
const PROTOCOL_VERSION = "2025-06-18";

const tools = [
  {
    name: "read_status",
    description: "Read service health status (upstream).",
    inputSchema: { type: "object", properties: { service: { type: "string" } } },
    run: (args) => ({ service: args?.service ?? "billing", state: "healthy", source: "upstream" })
  },
  {
    name: "restart_service",
    description: "Restart a service (upstream).",
    inputSchema: { type: "object", properties: { service: { type: "string" } }, required: ["service"] },
    run: (args) => ({ restarted: args?.service ?? "unknown", source: "upstream" })
  },
  {
    name: "delete_backups",
    description: "Delete backups (upstream, destructive).",
    inputSchema: { type: "object", properties: { path: { type: "string" }, script: { type: "string" } } },
    run: (args) => {
      const marker = process.env.MNDE_MCP_MARKER;
      if (marker) writeFileSync(marker, `upstream deleted ${args?.path ?? ""}\n`, "utf8");
      return { deleted: true, source: "upstream" };
    }
  }
];
const toolMap = new Map(tools.map((tool) => [tool.name, tool]));

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function handle(message) {
  const { id, method, params } = message;
  switch (method) {
    case "initialize":
      send({ jsonrpc: "2.0", id, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: "example-upstream", version: "0.1.0" } } });
      return;
    case "notifications/initialized":
      return;
    case "ping":
      send({ jsonrpc: "2.0", id, result: {} });
      return;
    case "tools/list":
      send({ jsonrpc: "2.0", id, result: { tools: tools.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema })) } });
      return;
    case "tools/call": {
      if (MODE === "crash-on-call") process.exit(1);
      if (MODE === "malformed-on-call") {
        send({ jsonrpc: "2.0", id, result: { not_a_tool_result: true } }); // no content array -> invalid
        return;
      }
      const tool = toolMap.get(params?.name);
      if (!tool) {
        send({ jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${params?.name}` } });
        return;
      }
      const output = tool.run(params?.arguments ?? {});
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(output) }], isError: false } });
      return;
    }
    default:
      if (id !== undefined && id !== null) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
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
      continue;
    }
    try {
      handle(message);
    } catch (error) {
      process.stderr.write(`[example-upstream] ${error?.message ?? String(error)}\n`);
    }
  }
});
process.stdin.on("end", () => process.exit(0));
process.stderr.write(`[example-upstream] ready mode=${MODE}\n`);
