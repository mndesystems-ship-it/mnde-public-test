import { EVENT_IMPORT_ERRORS, EventImportError } from "./errors.mjs";
import { importEvidence } from "./engine.mjs";
import { isPlainObject } from "./util.mjs";

export const CONNECTOR_METHODS = Object.freeze(["discover", "health", "import", "validate", "normalize", "version", "shutdown"]);

export function validateConnector(connector) {
  if (!isPlainObject(connector)) throw new EventImportError(EVENT_IMPORT_ERRORS.CONNECTOR_CONTRACT, "Connector must be an object");
  const missing = CONNECTOR_METHODS.filter((method) => typeof connector[method] !== "function");
  if (missing.length > 0) throw new EventImportError(EVENT_IMPORT_ERRORS.CONNECTOR_CONTRACT, `Connector is missing methods: ${missing.join(", ")}`);
  return connector;
}

export async function runConnectorImport(connector, context) {
  validateConnector(connector);
  const health = await connector.health();
  if (health?.ok !== true) throw new EventImportError(EVENT_IMPORT_ERRORS.CONNECTOR_CONTRACT, "Connector health check failed", { evidence: health ?? null });
  const packageInput = await connector.import(context.request ?? {});
  const validation = await connector.validate(packageInput);
  if (validation?.ok !== true) throw new EventImportError(EVENT_IMPORT_ERRORS.CONNECTOR_CONTRACT, "Connector rejected its import package", { evidence: validation ?? null });
  const adapter = {
    name: context.name ?? connector.name ?? "external-connector",
    version: String(await connector.version()),
    capabilities: ["normalize"],
    normalize: (rawEvent, adapterContext) => connector.normalize(rawEvent, adapterContext)
  };
  return importEvidence({ ...context, ...packageInput, adapter });
}
