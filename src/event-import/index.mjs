import { EXECUTION_REQUEST_SCHEMA } from "../execution-gate/schema.mjs";

export function normalizeImportedEvent(source) {
return {
schema_version: EXECUTION_REQUEST_SCHEMA,
execution_id: source.source_type + ":" + source.source_event_id,
requested_at: source.occurred_at,

action: {
  type: source.action.type,
  name: source.action.name,
  dry_run: false
},

principal: {
  id: source.actor.id,
  type: source.actor.type,
  issuer: source.actor.issuer,
  verified: false,
  claims: {}
},

resource: {
  kind: source.resource.kind,
  id: source.resource.id,
  name: source.resource.name
},

environment: {
  name: source.environment
},

risk: {
  level: "low",
  destructive: false,
  reversible: true,
  touches_secrets: false,
  touches_customer_data: false,
  blast_radius: "service"
},

cost: {
  estimated_cents: 0,
  dimensions: {}
},

approval: {
  required: false
},

evidence: {
  repo: source.evidence.repo,
  commit_sha: source.evidence.commit_sha,
  branch: source.evidence.branch
}

};
}
