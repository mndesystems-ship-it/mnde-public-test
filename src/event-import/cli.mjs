#!/usr/bin/env node
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

import { importEvidence } from "./engine.mjs";
import { openEventStore } from "./storage.mjs";

function usage() {
  console.error("Usage: events import --db <file> --raw-root <dir> --tenant <id> --source <id> --file <file> --format <format> --operator <id>");
  console.error("       events find --db <file> --tenant <id> [--source <id>] [--actor <id>] [--resource <id>] [--action <name>] [--decision <value>]");
}

export function main(argv = process.argv.slice(2)) {
  const command = argv[0];
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      db: { type: "string" }, "raw-root": { type: "string" }, tenant: { type: "string" }, source: { type: "string" },
      file: { type: "string" }, format: { type: "string" }, operator: { type: "string" }, actor: { type: "string" },
      resource: { type: "string" }, action: { type: "string" }, decision: { type: "string" }, since: { type: "string" }, until: { type: "string" }
    },
    strict: true
  });
  if (!values.db || !values.tenant) { usage(); return 2; }
  const store = openEventStore(resolve(values.db));
  try {
    if (command === "import") {
      for (const required of ["raw-root", "source", "file", "format", "operator"]) if (!values[required]) { usage(); return 2; }
      const result = importEvidence({
        store, rawRoot: resolve(values["raw-root"]), tenantId: values.tenant, source: values.source,
        filePath: resolve(values.file), filename: values.file, format: values.format, operator: values.operator
      });
      console.log(JSON.stringify({ ok: true, import: result.import, event_count: result.events.length }, null, 2));
      return 0;
    }
    if (command === "find") {
      const filters = Object.fromEntries(["tenant", "source", "actor", "resource", "action", "decision", "since", "until"].flatMap((key) => values[key] ? [[key, values[key]]] : []));
      console.log(JSON.stringify({ ok: true, events: store.queryEvents(filters) }, null, 2));
      return 0;
    }
    usage();
    return 2;
  } finally {
    store.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exit(main());
