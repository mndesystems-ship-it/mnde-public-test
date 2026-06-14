// Demo tool definitions exposed by the MNDe MCP server.
//
// Each tool is an ordinary function. The server wraps every call through MNDe,
// so the "run" here only executes on ALLOW. delete_backups writes a real marker
// file when it runs, which lets tests/demos prove — across process boundaries —
// that a REFUSE never executed it.

import { writeFileSync } from "node:fs";

export function defaultGuardedTools() {
  return [
    {
      name: "read_status",
      description: "Read service health status. Safe, read-only.",
      inputSchema: {
        type: "object",
        properties: { service: { type: "string", description: "service name" } }
      },
      run: async (input) => ({ service: input?.service ?? "billing", state: "healthy" })
    },
    {
      name: "restart_service",
      description: "Restart a named service.",
      inputSchema: {
        type: "object",
        properties: { service: { type: "string" } },
        required: ["service"]
      },
      run: async (input) => ({ restarted: input?.service ?? "unknown" })
    },
    {
      name: "delete_backups",
      description: "Delete backups at a path. Destructive.",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" }, script: { type: "string" } }
      },
      run: async (input) => {
        // Real, observable side effect. If MNDe ever lets this run, the marker
        // file appears and the test fails loudly.
        const marker = process.env.MNDE_MCP_MARKER;
        if (marker) writeFileSync(marker, `deleted ${input?.path ?? ""}\n`, "utf8");
        return { deleted: true, path: input?.path ?? null };
      }
    }
  ];
}
