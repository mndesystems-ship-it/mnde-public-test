import { DECISIONS } from "./canonical.mjs";
import { EVENT_IMPORT_ERRORS, EventImportError } from "./errors.mjs";
import { deterministicUuid, isoTimestamp, isPlainObject } from "./util.mjs";

const MODES = new Set(["historical", "current", "proposed", "partial", "synthetic", "comparison"]);

export function replayEvents(options) {
  const { store, tenantId, policy, mode = "current", filters = {}, now = new Date() } = options;
  if (!MODES.has(mode)) throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, `Unknown replay mode ${mode}`);
  if (!isPlainObject(policy) || typeof policy.name !== "string" || typeof policy.version !== "string" || typeof policy.evaluate !== "function") {
    throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, "Replay policy must expose name, version, and evaluate(event)");
  }
  const startedAt = isoTimestamp(now);
  if (startedAt === null) throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, "Replay timestamp is invalid");
  const events = store.queryEvents({ ...filters, tenant: tenantId }, { limit: options.limit ?? 1000 });
  const policyReference = { name: policy.name, version: policy.version, hash: policy.hash ?? null };
  const results = events.map((event) => {
    let evaluated;
    try {
      evaluated = policy.evaluate(event);
    } catch (cause) {
      throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, `Policy evaluation failed for ${event.event_id}`, { cause, evidence: { event_id: event.event_id } });
    }
    if (evaluated && typeof evaluated.then === "function") throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, "Replay policies must be synchronous and deterministic");
    const decision = typeof evaluated === "string" ? evaluated : evaluated?.decision;
    if (!DECISIONS.includes(decision)) throw new EventImportError(EVENT_IMPORT_ERRORS.REPLAY_POLICY_INVALID, `Policy returned invalid decision ${JSON.stringify(decision)}`);
    return {
      event_id: event.event_id,
      historical_decision: event.decision,
      simulated_decision: decision,
      would_allow: decision === "allow",
      would_deny: decision === "deny",
      would_review: decision === "review",
      would_escalate: evaluated?.escalate === true,
      changed_decision: decision !== event.decision,
      reason: typeof evaluated === "object" && typeof evaluated.reason === "string" ? evaluated.reason : null
    };
  });
  const run = {
    run_id: deterministicUuid(`${tenantId}:${mode}:${policy.name}:${policy.version}:${startedAt}:${events.map((event) => event.event_id).join(",")}`),
    tenant: tenantId,
    mode,
    policy_reference: policyReference,
    started_at: startedAt,
    completed_at: startedAt,
    status: "COMPLETED"
  };
  store.recordSimulation(run, results);
  return { ...run, results };
}
