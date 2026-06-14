// MNDe Shell Demo — deny-by-default authorization for a run_command tool.
//
//   npm run shell-demo
//
// Drives the MNDe shell MCP server as an agent would. The headline is the LAST
// case: a command MNDe has never seen does not run. Not "did we catch rm -rf" —
// "what happens when we don't know?" Answer: it doesn't run.

import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./bootstrap_dev_receipt_keys.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { verifyShellReceipt } from "../shell/receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXEC_LOG = join(repoRoot, "mnde-receipts", "shell-demo-exec.log");

function envelopeOf(call) {
  for (const part of call.content ?? []) {
    try {
      const parsed = JSON.parse(part.text);
      if (parsed.mnde) return parsed.mnde;
    } catch {
      /* not the mnde block */
    }
  }
  return null;
}
function receiptVerifies(envelope) {
  if (!envelope?.receiptPath || !existsSync(envelope.receiptPath)) return false;
  try {
    return verifyShellReceipt(JSON.parse(readFileSync(envelope.receiptPath, "utf8"))).verified;
  } catch {
    return false;
  }
}
function executed(command) {
  if (!existsSync(EXEC_LOG)) return false;
  return readFileSync(EXEC_LOG, "utf8").split(/\r?\n/).includes(command);
}

async function main() {
  console.log("MNDe Shell Demo\n");
  bootstrapReceiptKeys({ repoRoot });
  rmSync(EXEC_LOG, { force: true });
  let pass = true;

  const client = createStdioClient(process.execPath, ["mcp/shell-mcp-server.mjs"], {
    MNDE_SHELL_EXEC_LOG: EXEC_LOG,
    MNDE_SHELL_RECEIPTS_DIR: "./mnde-receipts/shell-demo"
  });

  try {
    await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "shell-demo", version: "0" } });
    client.notify("notifications/initialized", {});

    const cases = [
      { command: "ls", expect: "ALLOW", showReason: false },
      { command: "restart_service nginx", expect: "APPROVAL_REQUIRED", showReason: false },
      { command: "rm -rf /", expect: "REFUSE", showReason: false },
      { command: "some-weird-command-never-seen-before", expect: "REFUSE", showReason: true }
    ];

    for (const testCase of cases) {
      const call = await client.request("tools/call", { name: "run_command", arguments: { command: testCase.command } });
      const env = envelopeOf(call);
      const verified = receiptVerifies(env);
      const didExecute = executed(testCase.command);

      console.log("tool: run_command");
      console.log(`command: ${testCase.command}`);
      console.log(`Decision: ${env.decision}`);
      if (testCase.showReason) console.log(`Reason: ${String(env.reason).replace(/^ERR_/, "")}`);
      console.log(`Executed: ${env.executed ? "YES" : "NO"}`);
      console.log(`Receipt: ${verified ? "VERIFIED" : "NOT VERIFIED"}`);
      console.log("");

      const expectExecuted = testCase.expect === "ALLOW";
      pass = pass && env.decision === testCase.expect && env.executed === expectExecuted && didExecute === expectExecuted && verified;
    }
  } finally {
    await client.stop();
  }

  console.log(`FINAL VERDICT: ${pass ? "PASS" : "FAIL"}`);
  if (!pass) process.exit(1);
}

main().catch((error) => {
  console.error(error);
  console.log("\nFINAL VERDICT: FAIL");
  process.exit(1);
});
