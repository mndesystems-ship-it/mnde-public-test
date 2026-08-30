import { CANONICAL_EVENT_VERSION } from "./canonical.mjs";
import { EVENT_IMPORT_ERRORS, EventImportError } from "./errors.mjs";
import { deterministicUuid, isPlainObject, isoTimestamp } from "./util.mjs";

function nullableString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function objectOrEmpty(value) {
  return isPlainObject(value) ? value : {};
}

function relationObject(value) {
  const relationships = objectOrEmpty(value);
  return {
    parent_event: nullableString(relationships.parent_event),
    previous_event: nullableString(relationships.previous_event),
    child_events: Array.isArray(relationships.child_events) ? relationships.child_events.map(String) : [],
    session: nullableString(relationships.session),
    workflow: nullableString(relationships.workflow),
    ticket: nullableString(relationships.ticket),
    deployment: nullableString(relationships.deployment),
    receipt: nullableString(relationships.receipt)
  };
}

export function createPassthroughAdapter(options = {}) {
  return {
    name: options.name ?? "mnde-generic-canonical-adapter",
    version: options.version ?? "1.0.0",
    capabilities: ["normalize"],
    normalize(rawEvent, context) {
      const payload = objectOrEmpty(rawEvent.payload);
      const timestamp = isoTimestamp(payload.timestamp ?? rawEvent.raw_timestamp);
      const seed = `${context.importId}:${rawEvent.offset ?? rawEvent.line_number ?? context.position}:${rawEvent.hash}`;
      return {
        event_version: CANONICAL_EVENT_VERSION,
        event_id: nullableString(payload.event_id) ?? deterministicUuid(seed),
        tenant: nullableString(payload.tenant ?? payload.tenant_id) ?? context.tenantId,
        source: nullableString(payload.source) ?? context.source,
        actor: {
          id: nullableString(payload.actor?.id ?? payload.actor_id ?? payload.actor),
          display_name: nullableString(payload.actor?.display_name ?? payload.actor_name),
          email: nullableString(payload.actor?.email ?? payload.actor_email),
          credential: nullableString(payload.actor?.credential),
          service_account: nullableString(payload.actor?.service_account),
          robot: nullableString(payload.actor?.robot),
          agent: nullableString(payload.actor?.agent),
          executor: nullableString(payload.actor?.executor ?? payload.executor_id)
        },
        actor_type: nullableString(payload.actor_type) ?? "unknown",
        resource: {
          id: nullableString(payload.resource?.id ?? payload.resource_id ?? payload.resource),
          type: nullableString(payload.resource?.type ?? payload.resource_type),
          display_name: nullableString(payload.resource?.display_name ?? payload.resource_name),
          repository: nullableString(payload.resource?.repository ?? payload.repository),
          cluster: nullableString(payload.resource?.cluster ?? payload.cluster),
          database: nullableString(payload.resource?.database ?? payload.database),
          ticket: nullableString(payload.resource?.ticket ?? payload.ticket),
          host: nullableString(payload.resource?.host ?? payload.host),
          file: nullableString(payload.resource?.file ?? payload.file),
          deployment: nullableString(payload.resource?.deployment ?? payload.deployment)
        },
        resource_type: nullableString(payload.resource_type ?? payload.resource?.type) ?? "unknown",
        action: nullableString(payload.action) ?? "unknown",
        action_category: nullableString(payload.action_category) ?? "unknown",
        decision: nullableString(payload.decision)?.toLowerCase() ?? "unknown",
        timestamp,
        duration: payload.duration === null || payload.duration === undefined || payload.duration === "" ? null : Number(payload.duration),
        status: nullableString(payload.status) ?? "unknown",
        result: payload.result ?? null,
        reason: payload.reason ?? null,
        risk_level: nullableString(payload.risk_level)?.toLowerCase() ?? "unknown",
        policy_reference: isPlainObject(payload.policy_reference) ? payload.policy_reference : null,
        evidence: {
          raw_hash: rawEvent.hash,
          raw_file: rawEvent.filename,
          line: rawEvent.line_number,
          offset: rawEvent.offset,
          signature: context.signatureStatus,
          manifest: context.manifestPath,
          receipt: payload.receipt ?? null
        },
        relationships: relationObject(payload.relationships),
        attributes: objectOrEmpty(payload.attributes),
        tags: Array.isArray(payload.tags) ? payload.tags.map(String) : []
      };
    }
  };
}

export function validateAdapter(adapter) {
  if (!isPlainObject(adapter) || typeof adapter.name !== "string" || typeof adapter.version !== "string" || typeof adapter.normalize !== "function") {
    throw new EventImportError(EVENT_IMPORT_ERRORS.NORMALIZATION, "Adapter must expose name, version, and normalize(rawEvent, context)");
  }
  return adapter;
}

export function normalizeEvents(rawEvents, options) {
  const adapter = validateAdapter(options.adapter);
  return rawEvents.map((rawEvent, position) => {
    try {
      const event = adapter.normalize(rawEvent, { ...options, position });
      if (event && typeof event.then === "function") throw new Error("Async adapters are not supported by the synchronous import transaction");
      return event;
    } catch (cause) {
      if (cause instanceof EventImportError) throw cause;
      throw new EventImportError(EVENT_IMPORT_ERRORS.NORMALIZATION, `Adapter ${adapter.name}@${adapter.version} failed at raw event ${position}`, {
        cause,
        evidence: { raw_event_position: position }
      });
    }
  });
}
