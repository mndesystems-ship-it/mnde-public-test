function sortedEvents(events) {
  return [...events].sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.event_id.localeCompare(right.event_id));
}

export function buildTimeline(events, options = {}) {
  const { type = "execution", subjectId = null } = options;
  const filtered = sortedEvents(events).filter((event) => {
    if (subjectId === null) return true;
    if (type === "actor") return event.actor.id === subjectId;
    if (type === "resource") return event.resource.id === subjectId;
    if (["workflow", "session", "ticket", "deployment", "receipt"].includes(type)) return event.relationships[type] === subjectId;
    if (type === "decision") return event.decision === subjectId;
    return true;
  });
  return { timeline_version: "mnde.execution_timeline.v1", type, subject_id: subjectId, events: filtered };
}

function resolveRecords(events, field, aliases = []) {
  const aliasMap = new Map();
  for (const record of aliases) for (const alias of record.aliases ?? []) aliasMap.set(alias, record.identity_id ?? record.resource_id);
  const records = new Map();
  for (const event of sortedEvents(events)) {
    const value = event[field];
    if (!value?.id) continue;
    const canonicalId = aliasMap.get(value.id) ?? value.id;
    const existing = records.get(canonicalId) ?? { id: canonicalId, aliases: new Set(), evidence: [], first_seen: event.timestamp, last_seen: event.timestamp, explicitly_resolved: false };
    existing.explicitly_resolved ||= aliasMap.has(value.id);
    existing.aliases.add(value.id);
    if (value.email) existing.aliases.add(value.email);
    if (value.display_name) existing.aliases.add(value.display_name);
    existing.evidence.push(event.evidence);
    existing.first_seen = existing.first_seen < event.timestamp ? existing.first_seen : event.timestamp;
    existing.last_seen = existing.last_seen > event.timestamp ? existing.last_seen : event.timestamp;
    records.set(canonicalId, existing);
  }
  return [...records.values()].map((record) => {
    const { explicitly_resolved, ...publicRecord } = record;
    return { ...publicRecord, aliases: [...record.aliases].sort(), confidence: explicitly_resolved ? 1 : 0.5 };
  });
}

export function resolveIdentities(events, aliases = []) { return resolveRecords(events, "actor", aliases); }
export function resolveResources(events, aliases = []) { return resolveRecords(events, "resource", aliases); }

export function executionSummary(events) {
  const sorted = sortedEvents(events);
  const countBy = (field) => Object.fromEntries([...new Set(sorted.map((event) => event[field]))].sort().map((value) => [value, sorted.filter((event) => event[field] === value).length]));
  return {
    report_version: "mnde.execution_summary.v1",
    event_count: sorted.length,
    first_event_at: sorted[0]?.timestamp ?? null,
    last_event_at: sorted.at(-1)?.timestamp ?? null,
    decisions: countBy("decision"),
    actions: countBy("action"),
    risk_levels: countBy("risk_level")
  };
}
