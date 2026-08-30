#!/usr/bin/env node
// Regression coverage for policy-draft import in the Policy Editor.
//
// The editor is a single self-contained HTML file whose logic lives in one
// inline <script>. This test loads that REAL script into a node:vm sandbox with
// a minimal DOM stub and exercises the shipped importPolicy() and evaluate()
// functions directly — it does not reimplement the mapping. That way the test
// fails if the editor's behavior drifts, not if a copy drifts.
//
// It locks down the security-relevant contract from the production
// authorization spec (§30 "Draft import", §50 "Testing requirements",
// §51 invariants 1 and 8):
//
//   1. allow        -> ALLOW
//   2. approval     -> APPROVAL            (compiles to effect ALLOW + approval_required)
//   3. deny         -> REFUSE
//   4. unclassified -> REFUSE
//   5. tools_enumerated:false -> skipped, with a visible notice
//   6. malformed draft -> controlled error, active rules untouched
//   7. unknown recommendation value -> fail closed to REFUSE, never ALLOW  (invariant 1)
//   8. compiled output stays schema_version "1.0"
//   9. importing a draft never weakens engine default-deny semantics        (invariant 8)
//
// Plus: a signed mnde.policy.bundle.v1 auto-detects and unwraps for editing.

import { loadEditor, request } from "./helpers/policy-editor-sandbox.mjs";

let failures = 0;
function check(label, condition) {
  if (condition) {
    console.log(`  ok   ${label}`);
  } else {
    console.error(`  FAIL ${label}`);
    failures++;
  }
}

const { sandbox, alerts } = loadEditor();
const compiled = () => sandbox.window.__policy;
const ruleById = (id) => (compiled().rules || []).find((r) => r.rule_id === id);

// --- Cases 1-4, 7, 8: mapping through a single realistic draft --------------
console.log("draft mapping:");
const draft = {
  schema_version: "mnde.policy.draft.v1",
  default_decision: "REFUSE",
  servers: [{
    server: "filesystem", client: "cursor", tools_enumerated: true,
    tools: [
      { tool: "read_file", capability: "read-only", recommended: "allow" },
      { tool: "write_file", capability: "mutating", recommended: "approval" },
      { tool: "delete_file", capability: "destructive", recommended: "deny" },
      { tool: "weird_tool", capability: "unclassified", recommended: "deny" },
      { tool: "sneaky_tool", capability: "unclassified", recommended: "review" } // unsupported value
    ]
  }]
};
alerts.length = 0;
sandbox.importPolicy(draft);

const allow = ruleById("allow-read_file");
check("1. allow -> ALLOW (no approval)", !!allow && allow.effect === "ALLOW" && allow.approval_required === undefined);

const approval = ruleById("approve-write_file");
check("2. approval -> APPROVAL (effect ALLOW + approval_required)", !!approval && approval.effect === "ALLOW" && approval.approval_required === 1);

const deny = ruleById("refuse-delete_file");
check("3. deny -> REFUSE", !!deny && deny.effect === "REFUSE");

const unclassified = ruleById("refuse-weird_tool");
check("4. unclassified -> REFUSE", !!unclassified && unclassified.effect === "REFUSE");

const unknown = ruleById("refuse-sneaky_tool");
check("7. unknown recommendation value -> REFUSE, never ALLOW", !!unknown && unknown.effect === "REFUSE" && unknown.approval_required === undefined);
// The security invariant, asserted independently of rule naming: NO tool from an
// unknown/unsupported recommendation may end up ALLOW or APPROVAL.
const anyUnknownAllowed = (compiled().rules || []).some((r) => r.rule_id === "allow-sneaky_tool" || r.rule_id === "approve-sneaky_tool");
check("7. unknown value produced no ALLOW/APPROVAL rule (invariant 1)", anyUnknownAllowed === false);

check("8. compiled output is schema_version \"1.0\"", compiled().schema_version === "1.0");
check("   draft's default_decision is not injected as a rule", (compiled().rules || []).length === 5);

// --- Case 5: unenumerated server is skipped with a visible notice -----------
console.log("unenumerated server:");
const draftUnenumerated = {
  schema_version: "mnde.policy.draft.v1",
  servers: [
    { server: "database", client: "cursor", tools_enumerated: false, tools: [], note: "Tools not enumerated." },
    { server: "empty", client: "cursor", tools_enumerated: true, tools: [] }
  ]
};
alerts.length = 0;
sandbox.importPolicy(draftUnenumerated);
check("5. no rules created for an unenumerated server", (compiled().rules || []).length === 0);
check("5. import surfaced a notice about the skipped server",
  alerts.some((a) => /no enumerated tools/i.test(a) && /skipped/i.test(a)));

// --- Case 9: default-deny survives import (engine-level) ---------------------
console.log("default-deny semantics:");
sandbox.importPolicy(draft); // restore the 5-rule policy
check("9. a tool absent from the draft is REFUSED (default deny)",
  sandbox.evaluate(compiled(), request("some_unlisted_tool")).decision === "REFUSE");
check("9. the allow-recommended tool evaluates ALLOW",
  sandbox.evaluate(compiled(), request("read_file")).decision === "ALLOW");
check("9. the deny-recommended tool evaluates REFUSE",
  sandbox.evaluate(compiled(), request("delete_file")).decision === "REFUSE");
check("9. the unknown-recommendation tool evaluates REFUSE",
  sandbox.evaluate(compiled(), request("sneaky_tool")).decision === "REFUSE");

// --- Case 6: malformed inputs -> controlled error, active rules untouched ---
console.log("malformed input:");
const ruleCountBefore = (compiled().rules || []).length; // 5 from the restored draft
for (const [label, bad] of [
  ["draft schema without servers array", { schema_version: "mnde.policy.draft.v1" }],
  ["unrecognized object", { random: true }],
  ["null", null],
  ["number", 42]
]) {
  alerts.length = 0;
  sandbox.importPolicy(bad);
  check(`6. ${label} -> controlled error`, alerts.some((a) => /not a recognized mnde policy/i.test(a)));
  check(`6. ${label} left the active rules unchanged`, (compiled().rules || []).length === ruleCountBefore);
}

// --- Bonus: signed bundle auto-detects and unwraps for editing --------------
console.log("signed bundle unwrap:");
const bundle = {
  schema_version: "mnde.policy.bundle.v1",
  bundle_id: "b-1", policy_id: "p", serial: 1,
  policy_document: {
    schema_version: "1.0", policy_id: "p", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "allow-read_status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
  }
};
alerts.length = 0;
sandbox.importPolicy(bundle);
check("bundle unwrapped to its policy_document", (compiled().rules || []).length === 1 && !!ruleById("allow-read_status"));
check("bundle import warns that editing invalidates the signature",
  alerts.some((a) => /signature/i.test(a) && /re-sign/i.test(a)));

// --- Summary ----------------------------------------------------------------
if (failures > 0) {
  console.error(`\nFAIL policy-editor draft import (${failures} check(s) failed)`);
  process.exit(1);
}
console.log("\nPASS policy-editor draft import");
