#!/usr/bin/env node
// MNDe Shell MCP Server — a run_command tool that is authorized deny-by-default
// before execution, with a signed receipt per call.
//
// Speaks newline-delimited JSON-RPC over stdio (zero dependencies). On each
// tools/call the shell policy decides ALLOW / APPROVAL_REQUIRED / REFUSE; the
// command is "run" (simulated — it never executes a real shell) ONLY on ALLOW.
//
//   MNDE_SHELL_RECEIPTS_DIR   where receipts are written (default ./mnde-receipts/shell)
//   MNDE_SHELL_EXEC_LOG       file the simulated executor appends to when it runs (proof hook)

import { appendFileSync } from "node:fs";
import { resolve } from "node:path";

import { buildShellReceipt, verifyShellReceipt, writeShellReceipt } from "../shell/receipt.mjs";

const PROTOCOL_VERSION = "2025-06-18";
const receiptsDir = resolve(process.env.MNDE_SHELL_RECEIPTS_DIR ?? "./mnde-receipts/shell");
const execLog = process.env.MNDE_SHELL_EXEC_LOG ?? null;

const TOOLS = [
  {
    name: "run_command",
    description: "Run a shell command. Authorized by MNDe (deny-by-default); unknown commands are refused.",
    inputSchema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] }
  }
];

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
  process.stderr.write(`[shell-mcp] ${parts.join(" ")}\n`);
}

// SIMULATED execution — never runs a real shell. Records that it ran so tests
// and demos can prove, across process boundaries, that a refused command did not.
function runCommand(command) {
  if (execLog) appendFileSync(execLog, `${command}\n`, "utf8");
  return { stdout: `[simulated output of: ${command}]`, exit_code: 0 };
}

function handleToolCall(id, params) {
  const command = params?.arguments?.command;
  if (typeof command !== "string") {
    sendError(id, -32602, "run_command requires a string 'command' argument");
    return;
  }

  const receipt = buildShellReceipt(command);
  const decision = receipt.decision_output.decision;
  const reason = receipt.decision_output.reason_code;
  const receiptPath = writeShellReceipt(receipt, receiptsDir, `shell-${receipt.request_hash.slice(0, 16)}-${Date.now()}.json`);
  const verified = verifyShellReceipt(receipt).verified;

  let executed = false;
  let result = null;
  if (decision === "ALLOW") {
    result = runCommand(command);
    executed = true;
  }

  const envelope = { decision, reason, executed, receiptPath, verified, policy_id: receipt.decision_output.policy_id };
  const human =
    decision === "ALLOW"
      ? `ALLOW — ran: ${command}`
      : decision === "APPROVAL_REQUIRED"
        ? `APPROVAL_REQUIRED — '${command}' needs human approval. Not run.`
        : `REFUSE (${reason}) — '${command}' not run.`;

  sendResult(id, {
    content: [
      { type: "text", text: human },
      ...(result ? [{ type: "text", text: JSON.stringify(result) }] : []),
      { type: "text", text: JSON.stringify({ mnde: envelope }) }
    ],
    isError: decision !== "ALLOW"
  });
}

function handle(message) {
  const { id, method, params } = message;
  switch (method) {
    case "initialize":
      sendResult(id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: "mnde-shell-mcp", version: "0.1.0" } });
      return;
    case "notifications/initialized":
      return;
    case "ping":
      sendResult(id, {});
      return;
    case "tools/list":
      sendResult(id, { tools: TOOLS });
      return;
    case "tools/call":
      handleToolCall(id, params);
      return;
    default:
      if (id !== undefined && id !== null) sendError(id, -32601, `method not found: ${method}`);
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
    try {
      handle(message);
    } catch (error) {
      log("handler error:", error?.message ?? String(error));
      if (message?.id !== undefined && message?.id !== null) sendError(message.id, -32603, `internal error: ${error?.message ?? String(error)}`);
    }
  }
});
process.stdin.on("end", () => process.exit(0));

log(`ready; receipts=${receiptsDir}`);
