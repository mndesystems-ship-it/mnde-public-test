import { EVENT_IMPORT_ERRORS, failImport } from "./errors.mjs";
import { isPlainObject, isoTimestamp } from "./util.mjs";

export const PARSER_FORMATS = Object.freeze([
  "json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "sqlite-export",
  "text-log", "apache-log", "syslog", "cloudtrail-json", "github-export", "gitlab-export", "evtx-export"
]);

function rawEvent(payload, context, position = {}) {
  return {
    source: context.source,
    raw_timestamp: position.rawTimestamp ?? null,
    payload,
    metadata: { format: context.format, media_type: context.mediaType ?? null },
    offset: position.offset ?? null,
    line_number: position.lineNumber ?? null,
    filename: context.filename,
    import_id: context.importId,
    hash: context.evidenceHash
  };
}

function parseJson(text, context) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    failImport(EVENT_IMPORT_ERRORS.PARSE, "JSON evidence is malformed", { cause });
  }
  const values = Array.isArray(value) ? value : (isPlainObject(value) && Array.isArray(value.events) ? value.events : [value]);
  return values.map((payload, index) => rawEvent(payload, context, { offset: index }));
}

function parseJsonLines(text, context) {
  const events = [];
  let offset = 0;
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const byteOffset = offset;
    offset += Buffer.byteLength(line, "utf8") + 1;
    if (line.trim() === "") continue;
    try {
      events.push(rawEvent(JSON.parse(line), context, { lineNumber: index + 1, offset: byteOffset }));
    } catch (cause) {
      failImport(EVENT_IMPORT_ERRORS.PARSE, `JSON line ${index + 1} is malformed`, {
        cause,
        evidence: { line_number: index + 1, offset: byteOffset }
      });
    }
  }
  return events;
}

function parseDelimitedRow(line, delimiter) {
  const cells = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (quoted && line[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (char === delimiter && !quoted) {
      cells.push(cell);
      cell = "";
    } else {
      cell += char;
    }
  }
  if (quoted) failImport(EVENT_IMPORT_ERRORS.PARSE, "Delimited evidence contains an unterminated quoted field");
  cells.push(cell);
  return cells;
}

function parseDelimited(text, context, delimiter) {
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length < 2) failImport(EVENT_IMPORT_ERRORS.PARSE, "Delimited evidence requires a header and at least one row");
  const headers = parseDelimitedRow(lines[0], delimiter);
  if (headers.some((header) => header.length === 0) || new Set(headers).size !== headers.length) {
    failImport(EVENT_IMPORT_ERRORS.PARSE, "Delimited evidence headers must be non-empty and unique");
  }
  return lines.slice(1).map((line, index) => {
    const values = parseDelimitedRow(line, delimiter);
    if (values.length !== headers.length) failImport(EVENT_IMPORT_ERRORS.PARSE, `Delimited row ${index + 2} has ${values.length} fields; expected ${headers.length}`);
    return rawEvent(Object.fromEntries(headers.map((header, position) => [header, values[position]])), context, { lineNumber: index + 2 });
  });
}

function parseTextLines(text, context) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    if (line.length === 0) return [];
    const isoPrefix = line.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/);
    return [rawEvent({ message: line }, context, { lineNumber: index + 1, rawTimestamp: isoTimestamp(isoPrefix?.[0]) })];
  });
}

function parseDocument(text, context) {
  return [rawEvent({ document: text, document_format: context.format }, context)];
}

function parseSqliteExport(text, context) {
  const trimmed = text.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return parseJson(text, context);
  return parseDelimited(text, context, trimmed.includes("\t") ? "\t" : ",");
}

const PARSERS = new Map([
  ["json", parseJson], ["cloudtrail-json", parseJson], ["github-export", parseJson], ["gitlab-export", parseJson],
  ["jsonl", parseJsonLines], ["ndjson", parseJsonLines],
  ["csv", (text, context) => parseDelimited(text, context, ",")],
  ["tsv", (text, context) => parseDelimited(text, context, "\t")],
  ["xml", parseDocument], ["yaml", parseDocument], ["evtx-export", parseDocument],
  ["sqlite-export", parseSqliteExport],
  ["text-log", parseTextLines], ["apache-log", parseTextLines], ["syslog", parseTextLines]
]);

export function registerParser(format, parser) {
  if (typeof format !== "string" || typeof parser !== "function") failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "Parser registration requires a format and function");
  PARSERS.set(format, parser);
}

export function parseEvidence(text, context) {
  const parser = PARSERS.get(context.format);
  if (!parser) failImport(EVENT_IMPORT_ERRORS.FORMAT_UNSUPPORTED, `No parser is registered for ${context.format}`);
  const events = parser(text, context);
  if (!Array.isArray(events)) failImport(EVENT_IMPORT_ERRORS.PARSE, `Parser ${context.format} did not return an event array`);
  return events;
}
