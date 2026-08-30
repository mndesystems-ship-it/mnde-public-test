// Policy drafting layer.
//
// Enumerates tools, inspects schemas, categorizes capabilities, and produces a
// RECOMMENDATION. It never approves tools, never modifies an active policy, and
// never enables permissions. Output is a draft for explicit human review.
//
// This is not the authority policy engine. MNDe does not enforce policy.draft.json.

const DESTRUCTIVE = /\b(delete|destroy|drop|wipe|format|shutdown|reboot|kill|terminate|rm|rmdir|unlink|truncate)\b/;
const MUTATING = /\b(write|update|create|modify|patch|put|post|exec|execute|run|spawn|shell|command|deploy|install|publish|transfer|pay|refund|charge|send|move|rename|chmod|chown)\b/;
const READ_ONLY = /\b(read|list|get|status|search|fetch|query|describe|show|view|inspect|count|head|stat|ls|cat)\b/;

// Finer, deterministic reason detectors. These NARROW the reason code within a
// bucket; they never change the `recommended` decision (which stays governed by
// the bucket precedence above), so an unrecognized tool still fails closed.
const EXECUTES = /\b(exec|execute|run|spawn|shell|command)\b/;
const CREDENTIALS = /\b(credential|password|secret|token|api key|apikey|key)\b/;
const PERMISSIONS = /\b(permission|privilege|grant|role|chmod|chown|sudo|iam|acl)\b/;
const FINANCIAL = /\b(pay|payment|charge|refund|transfer|invoice|billing|withdraw|deposit)\b/;
const MESSAGING = /\b(send|publish|email|notify|message|post|broadcast|dispatch)\b/;

// Reason code within the destructive bucket (recommended: deny, risk: destructive).
function destructiveReason(text) {
  if (CREDENTIALS.test(text)) return "MODIFIES_CREDENTIALS";
  if (PERMISSIONS.test(text)) return "CHANGES_PERMISSIONS";
  return "DESTRUCTIVE_OPERATION";
}
// Reason code within the mutating bucket (recommended: approval, risk: mutation).
function mutationReason(text) {
  if (EXECUTES.test(text)) return "EXECUTES_CODE";
  if (CREDENTIALS.test(text)) return "MODIFIES_CREDENTIALS";
  if (PERMISSIONS.test(text)) return "CHANGES_PERMISSIONS";
  if (FINANCIAL.test(text)) return "FINANCIAL_SIDE_EFFECT";
  if (MESSAGING.test(text)) return "SENDS_EXTERNAL_MESSAGE";
  return "MODIFIES_DATA";
}

// Deterministic capability classification of a single tool. Returns the
// human-facing `recommended` decision plus a `risk_class` and a stable
// `reason_code` the UI can translate into an explanation (never generated prose).
export function categorizeTool(tool) {
  const text = `${tool?.name ?? ""} ${tool?.description ?? ""} ${JSON.stringify(tool?.inputSchema ?? {})}`
    .toLowerCase()
    .replace(/[_-]+/g, " ");
  if (DESTRUCTIVE.test(text)) return { capability: "destructive", recommended: "deny", risk_class: "destructive", reason_code: destructiveReason(text) };
  if (MUTATING.test(text)) return { capability: "mutating", recommended: "approval", risk_class: "mutation", reason_code: mutationReason(text) };
  if (READ_ONLY.test(text)) return { capability: "read-only", recommended: "allow", risk_class: "read", reason_code: "READ_ONLY_OPERATION" };
  return { capability: "unclassified", recommended: "deny", risk_class: "unknown", reason_code: "UNCLASSIFIED_OPERATION" };
}

// servers: [{ name, client?, tools?: [{ name, description, inputSchema }] }]
// `tools` is present only when a caller enumerated them (e.g. via an MCP probe).
// Pure and deterministic given identical input.
export function draftPolicy(servers, options = {}) {
  const generatedAt = options.now ?? new Date().toISOString();
  const entries = (servers ?? []).map((server) => {
    const toolsEnumerated = Array.isArray(server.tools);
    const tools = toolsEnumerated
      ? server.tools.map((tool) => ({ tool: tool.name, ...categorizeTool(tool) }))
      : [];
    return {
      server: server.name,
      client: server.client ?? null,
      tools_enumerated: toolsEnumerated,
      tools,
      note: toolsEnumerated ? null : "Tools not enumerated. Run with --probe, or fill in tool rules before activation."
    };
  });
  return {
    schema_version: "mnde.policy.draft.v1",
    generated_at: generatedAt,
    default_decision: "REFUSE",
    review_required: true,
    note: "DRAFT ONLY — NOT ACTIVE. MNDe does not enforce this file. Review every recommendation and convert it into an explicit, versioned policy before enabling enforcement.",
    servers: entries,
    summary: {
      servers: entries.length,
      tools_recommended_allow: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "allow").length, 0),
      tools_recommended_approval: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "approval").length, 0),
      tools_recommended_deny: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "deny").length, 0)
    }
  };
}
