// Example adapter: an MCP-style tool call -> `mnde.execution.request.v1` envelope.
//
// This is a pure TRANSLATION. It reshapes fields; it does not validate, coerce, or
// "fix up" bad input. A malformed source produces a malformed envelope, which
// `normalizeExecutionEnvelope` then rejects (fail closed). Keeping validation in one
// place (the envelope module) is what makes adapter equivalence testable: any two
// adapters that emit the same envelope field values are treated identically.
//
// Source shape (illustrative MCP `tools/call` plus carried metadata):
//   {
//     id, ts,                              // request id + timestamp
//     name: "payments.purchase",           // dotted tool name -> action namespace/operation
//     arguments: { ... },                  // -> parameters
//     principal: { id, type },             // caller identity (from the transport, not the tool)
//     resource: { type, id },              // optional
//     context: { ... },                    // optional
//     authority: [ ... ]                   // optional attached grants
//   }

import { EXECUTION_ENVELOPE_SCHEMA } from "../index.mjs";

export function mcpToolCallToEnvelope(call) {
  const name = typeof call?.name === "string" ? call.name : "";
  // Split on the LAST dot: everything before is the namespace, the final segment is
  // the operation. A name with no dot yields an empty namespace, which the envelope
  // validator rejects — so an un-namespaced tool name fails closed rather than
  // silently mapping to a bare operation.
  const lastDot = name.lastIndexOf(".");
  const namespace = lastDot > 0 ? name.slice(0, lastDot) : "";
  const operation = lastDot > 0 ? name.slice(lastDot + 1) : name;

  const envelope = {
    schema: EXECUTION_ENVELOPE_SCHEMA,
    request_id: call?.id,
    timestamp: call?.ts,
    principal: call?.principal,
    action: { namespace, operation },
    parameters: call?.arguments ?? {},
    context: call?.context ?? {}
  };
  if (call?.resource !== undefined) envelope.resource = call.resource;
  if (call?.authority !== undefined) envelope.authority = call.authority;
  return envelope;
}
