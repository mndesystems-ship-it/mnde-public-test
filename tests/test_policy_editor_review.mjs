#!/usr/bin/env node
// P0 human-authorization surface: the Allow / Ask me first / Block review model,
// its recommendation-vs-selection state, "Restore recommendation", and — the
// security core — the round-trip and default-deny invariants.
//
// Drives the SHIPPED review functions in the real editor script (via the shared
// vm harness), so it fails on editor drift rather than on a copy.
//
// Hard invariants exercised (see the authorization-ux-invariants project note):
//   - Unknown never becomes ALLOW.
//   - Recommendation never equals authorization (selection is separate state).
//   - Default deny survives import, compilation, and round trip.
//   - The simplified UI never hides authority present in the compiled policy.
//   - The compiled policy, not UI state, defines effective authority.

import { loadEditor, request } from "./helpers/policy-editor-sandbox.mjs";

let failures = 0;
function check(label, condition) {
  if (condition) { console.log(`  ok   ${label}`); }
  else { console.error(`  FAIL ${label}`); failures++; }
}

const { sandbox } = loadEditor();
const compiled = () => sandbox.compilePolicy();
const rowFor = (tool) => sandbox.reviewRows().find((r) => r.tool === tool);
const MODE_OF = { Allow: "ALLOW", ask: "APPROVAL", block: "REFUSE" };

const draft = {
  schema_version: "mnde.policy.draft.v1",
  default_decision: "REFUSE",
  servers: [{
    server: "filesystem", client: "cursor", tools_enumerated: true,
    tools: [
      { tool: "read_file", recommended: "allow", risk_class: "read", reason_code: "READ_ONLY_OPERATION" },
      { tool: "write_file", recommended: "approval", risk_class: "mutation", reason_code: "MODIFIES_DATA" },
      { tool: "delete_file", recommended: "deny", risk_class: "destructive", reason_code: "DESTRUCTIVE_OPERATION" },
      { tool: "spooky_tool", recommended: "conditional" } // unsupported value -> fail closed
    ]
  }]
};
sandbox.importPolicy(draft);

// --- Review model: recommendation vs selection are SEPARATE state -----------
console.log("review model (recommendation != selection):");
check("read_file recommended Allow and selected Allow", rowFor("read_file").recommendedMode === "ALLOW" && rowFor("read_file").selectedMode === "ALLOW");
check("write_file recommended APPROVAL", rowFor("write_file").recommendedMode === "APPROVAL");
check("delete_file recommended REFUSE", rowFor("delete_file").recommendedMode === "REFUSE");
check("row carries a deterministic reason_code, not prose", rowFor("delete_file").reason_code === "DESTRUCTIVE_OPERATION");
check("unsupported recommendation flagged and held at Block", rowFor("spooky_tool").unsupported === true && rowFor("spooky_tool").selectedMode === "REFUSE");
check("nothing is marked changed on a fresh import", sandbox.reviewRows().every((r) => r.changed === false));

// --- Recommendation never equals authorization ------------------------------
// A human selection different from the recommendation is tracked as a change and
// changes the compiled policy — but only the compiled policy is authority.
console.log("selection changes authority, recommendation does not:");
sandbox.setDecision(rowFor("delete_file").key, "ALLOW");
check("selecting Allow marks delete_file changed", rowFor("delete_file").changed === true && rowFor("delete_file").selectedMode === "ALLOW");
check("recommendation is unchanged by the selection", rowFor("delete_file").recommendedMode === "REFUSE");
check("compiled policy now reflects the human selection", sandbox.evaluate(compiled(), request("delete_file")).decision === "ALLOW");

// --- Restore recommendation -------------------------------------------------
console.log("restore recommendation:");
sandbox.restoreRecommendation(rowFor("delete_file").key);
check("restore returns delete_file to REFUSE", rowFor("delete_file").selectedMode === "REFUSE" && rowFor("delete_file").changed === false);
check("compiled policy blocks delete_file again", sandbox.evaluate(compiled(), request("delete_file")).decision === "REFUSE");

// --- Round trip: human state -> compiled -> parsed effective authority ------
// For every tool, its selected decision must land in the matching bucket of the
// effective authority parsed back out of the compiled policy.
console.log("round trip (human state -> compiled -> effective authority):");
sandbox.setDecision(rowFor("write_file").key, "ALLOW");   // Ask me first -> Allow
sandbox.setDecision(rowFor("read_file").key, "REFUSE");   // Allow -> Block
const state = sandbox.reviewState();                       // human selections
const eff = sandbox.effectiveAuthority(compiled());        // parsed from compiled policy
const bucketOf = (tool) => eff.allow.includes(tool) ? "ALLOW" : eff.ask.includes(tool) ? "APPROVAL" : eff.block.includes(tool) ? "REFUSE" : null;
let roundTripOk = true;
for (const tool of Object.keys(state)) {
  if (bucketOf(tool) !== state[tool]) { roundTripOk = false; console.error(`     mismatch: ${tool} selected ${state[tool]} but effective ${bucketOf(tool)}`); }
}
check("every human selection round-trips to the same effective decision", roundTripOk);

// --- Invariant: the summary hides no authority present in the compiled policy
console.log("no hidden authority (invariant 5):");
const totalListed = eff.allow.length + eff.ask.length + eff.block.length;
check("effective authority accounts for every compiled rule", totalListed === (compiled().rules || []).length);
check("no authority-granting rule is missing from the summary",
  (compiled().rules || []).every((r) => {
    const label = r.match && r.match.op === "eq" ? r.match.value : r.rule_id;
    return eff.allow.includes(label) || eff.ask.includes(label) || eff.block.includes(label);
  }));

// --- Invariant: unspecified and newly-unknown capabilities remain REFUSE -----
console.log("unspecified / newly-unknown -> REFUSE (invariants 1 & default-deny):");
check("a capability absent from the policy is REFUSED (default deny)",
  sandbox.evaluate(compiled(), request("capability_never_seen")).decision === "REFUSE");
check("a 'newly discovered' tool not in the active policy is REFUSED",
  sandbox.evaluate(compiled(), request("newly_added_after_activation")).decision === "REFUSE");
check("the unsupported-recommendation tool remains REFUSED",
  sandbox.evaluate(compiled(), request("spooky_tool")).decision === "REFUSE");
// And it never became authority under any selection default.
check("unsupported tool is not in Allow or Ask buckets", !eff.allow.includes("spooky_tool") && !eff.ask.includes("spooky_tool"));

// --- Compiled policy, not UI state, defines authority -----------------------
console.log("compiled policy is the authority (invariant 6):");
check("effective summary derives from compiled rules", sandbox.effectiveAuthority(compiled()).block.includes("read_file"));

if (failures > 0) {
  console.error(`\nFAIL policy-editor review (${failures} check(s) failed)`);
  process.exit(1);
}
console.log("\nPASS policy-editor review");
