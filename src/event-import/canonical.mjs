import { EVENT_IMPORT_ERRORS, EventImportError } from "./errors.mjs";
import { isPlainObject, isUuid, isoTimestamp } from "./util.mjs";

export const CANONICAL_EVENT_VERSION = "mnde.canonical_execution_event.v1";
export const DECISIONS = Object.freeze(["allow", "deny", "review", "unknown"]);
export const RISK_LEVELS = Object.freeze(["low", "medium", "high", "critical", "unknown"]);

const REQUIRED_STRINGS = ["event_id", "tenant", "source", "action", "action_category", "status"];

function canonicalFailure(message, eventId = null, code = EVENT_IMPORT_ERRORS.CANONICAL_INVALID) {
  throw new EventImportError(code, message, { evidence: { event_id: eventId } });
}

function validateRelationshipIds(event) {
  const relationships = event.relationships;
  if (!isPlainObject(relationships)) canonicalFailure("relationships must be an object", event.event_id);
  for (const field of ["parent_event", "previous_event"]) {
    const value = relationships[field];
    if (value !== null && !isUuid(value)) canonicalFailure(`${field} must be a UUID or null`, event.event_id, EVENT_IMPORT_ERRORS.REFERENCE_INVALID);
  }
  if (!Array.isArray(relationships.child_events) || relationships.child_events.some((value) => !isUuid(value))) {
    canonicalFailure("child_events must contain only UUIDs", event.event_id, EVENT_IMPORT_ERRORS.REFERENCE_INVALID);
  }
}

export function validateCanonicalEvent(event, options = {}) {
  if (!isPlainObject(event)) canonicalFailure("Canonical event must be an object");
  if (event.event_version !== CANONICAL_EVENT_VERSION) canonicalFailure(`Unsupported event_version ${JSON.stringify(event.event_version)}`, event.event_id);
  for (const field of REQUIRED_STRINGS) {
    if (typeof event[field] !== "string" || event[field].length === 0) canonicalFailure(`${field} must be a non-empty string`, event.event_id);
  }
  if (!isUuid(event.event_id)) canonicalFailure("event_id must be a UUID", event.event_id);
  if (options.tenantId && event.tenant !== options.tenantId) canonicalFailure(`Event tenant ${event.tenant} does not match import tenant ${options.tenantId}`, event.event_id, EVENT_IMPORT_ERRORS.TENANT_MISMATCH);
  if (!DECISIONS.includes(event.decision)) canonicalFailure(`Invalid decision ${JSON.stringify(event.decision)}`, event.event_id);
  if (!RISK_LEVELS.includes(event.risk_level)) canonicalFailure(`Invalid risk_level ${JSON.stringify(event.risk_level)}`, event.event_id);
  const timestamp = isoTimestamp(event.timestamp);
  if (timestamp === null || timestamp !== event.timestamp) canonicalFailure("timestamp must be a canonical ISO-8601 timestamp", event.event_id);
  const nowMs = options.nowMs ?? Date.now();
  const maxFutureMs = options.maxFutureMs ?? 300_000;
  if (Date.parse(timestamp) > nowMs + maxFutureMs) canonicalFailure("timestamp is too far in the future", event.event_id);
  if (event.duration !== null && (!Number.isSafeInteger(event.duration) || event.duration < 0)) canonicalFailure("duration must be a non-negative integer or null", event.event_id);
  if (!isPlainObject(event.actor) || !isPlainObject(event.resource) || !isPlainObject(event.evidence) || !isPlainObject(event.attributes)) {
    canonicalFailure("actor, resource, evidence, and attributes must be objects", event.event_id);
  }
  if (!Array.isArray(event.tags) || event.tags.some((tag) => typeof tag !== "string" || tag.length === 0)) canonicalFailure("tags must contain non-empty strings", event.event_id);
  validateRelationshipIds(event);
  return event;
}

export function validateCanonicalBatch(events, options = {}) {
  if (!Array.isArray(events) || events.length === 0) canonicalFailure("An import must normalize to at least one canonical event");
  const byId = new Map();
  for (const event of events) {
    validateCanonicalEvent(event, options);
    if (byId.has(event.event_id)) canonicalFailure(`Duplicate event_id ${event.event_id}`, event.event_id);
    byId.set(event.event_id, event);
  }
  const known = (id) => byId.has(id) || options.isKnownReference?.(id) === true;
  for (const event of events) {
    for (const reference of [event.relationships.parent_event, event.relationships.previous_event, ...event.relationships.child_events]) {
      if (reference !== null && !known(reference)) canonicalFailure(`Unknown event reference ${reference}`, event.event_id, EVENT_IMPORT_ERRORS.REFERENCE_INVALID);
    }
  }
  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) canonicalFailure(`Parent cycle includes ${id}`, id, EVENT_IMPORT_ERRORS.PARENT_CYCLE);
    if (visited.has(id) || !byId.has(id)) return;
    visiting.add(id);
    const parent = byId.get(id).relationships.parent_event;
    if (parent !== null) visit(parent);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of byId.keys()) visit(id);
  return events;
}
