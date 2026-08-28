// Example adapter: a REST/AP2-style JSON request -> `mnde.execution.request.v1`.
//
// A DIFFERENTLY-SHAPED source than the MCP adapter, on purpose: it proves the
// core's protocol-independence. The same semantic execution expressed in this shape
// must normalize to the same policy-engine request the MCP adapter produces, and
// therefore receive the same decision. Like every adapter this is a pure
// translation; validation lives in the envelope module (fail closed).
//
// Source shape (illustrative REST/AP2 request body):
//   {
//     request_id, requested_at,            // request id + timestamp
//     actor: { id, kind },                 // -> principal { id, type }
//     operation: { domain, name },         // -> action { namespace, operation }
//     target: { type, id },                // optional -> resource
//     payload: { ... },                    // -> parameters
//     ctx: { ... },                        // optional -> context
//     mandates: [ ... ]                    // optional attached authority (e.g. AP2 mandates)
//   }

import { EXECUTION_ENVELOPE_SCHEMA } from "../index.mjs";

export function httpJsonToEnvelope(request) {
  const actor = request?.actor;
  let principal;
  if (actor && typeof actor === "object") {
    // Build without an `undefined` type key so absent `kind` maps to "no type",
    // not to a key that would break canonicalization.
    principal = actor.kind !== undefined ? { id: actor.id, type: actor.kind } : { id: actor.id };
  }

  const envelope = {
    schema: EXECUTION_ENVELOPE_SCHEMA,
    request_id: request?.request_id,
    timestamp: request?.requested_at,
    principal,
    action: {
      namespace: request?.operation?.domain,
      operation: request?.operation?.name
    },
    parameters: request?.payload ?? {},
    context: request?.ctx ?? {}
  };
  if (request?.target !== undefined) envelope.resource = request.target;
  if (request?.mandates !== undefined) envelope.authority = request.mandates;
  return envelope;
}
