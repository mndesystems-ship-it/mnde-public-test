// Shared harness: loads the REAL inline <script> from the Policy Editor HTML into
// a node:vm sandbox with a minimal DOM stub, so tests drive the shipped
// importPolicy() / evaluate() / review functions directly (no reimplementation).

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const editorPath = join(repoRoot, "policy-editor", "mnde-policy-editor.html");

// Proxy-backed fake element: predefined no-op methods, chainable querySelector
// returning fresh fakes, and arbitrary property get/set so the real
// render/compile code runs without a browser.
function makeEl() {
  const store = { value: "", textContent: "", innerHTML: "", className: "", id: "" };
  const noop = () => {};
  const base = {
    appendChild: (x) => x, append: noop, before: noop, after: noop, remove: noop,
    focus: noop, blur: noop, click: noop, select: noop,
    setAttribute: noop, removeAttribute: noop, getAttribute: () => null, hasAttribute: () => false,
    addEventListener: noop, removeEventListener: noop, insertBefore: (x) => x,
    cloneNode: () => makeEl(), contains: () => false,
    querySelector: () => makeEl(), querySelectorAll: () => [],
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: new Proxy({}, { get: () => "", set: () => true }),
    dataset: {}, children: []
  };
  return new Proxy(base, {
    get(t, p) { if (p in t) return t[p]; if (p in store) return store[p]; return undefined; },
    set(t, p, v) { store[p] = v; return true; }
  });
}

export function loadEditor() {
  const html = readFileSync(editorPath, "utf8");
  const open = html.indexOf("<script>");
  const close = html.lastIndexOf("</script>");
  if (open === -1 || close === -1 || close < open) throw new Error("could not locate the editor <script> block");
  const source = html.slice(open + "<script>".length, close);

  const elById = new Map();
  const document = {
    getElementById: (id) => { if (!elById.has(id)) elById.set(id, makeEl()); return elById.get(id); },
    createElement: () => makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    body: makeEl(),
    documentElement: makeEl(),
    addEventListener: () => {},
    removeEventListener: () => {}
  };

  const alerts = [];
  const sandbox = {
    document,
    alert: (m) => { alerts.push(String(m)); },
    console,
    setTimeout: () => 0,
    clearTimeout: () => {},
    matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }),
    navigator: { clipboard: { writeText: async () => {} } },
    URL: { createObjectURL: () => "blob:", revokeObjectURL: () => {} },
    Blob: function Blob() {},
    FileReader: function FileReader() {},
    structuredClone: (x) => JSON.parse(JSON.stringify(x))
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "mnde-policy-editor.html" });

  for (const fn of ["importPolicy", "evaluate", "compilePolicy", "effectiveAuthority", "reviewRows", "reviewState", "setDecision", "restoreRecommendation"]) {
    if (typeof sandbox[fn] !== "function") throw new Error(`${fn} not defined after load`);
  }
  return { sandbox, alerts };
}

export function request(toolName) {
  return {
    schema_version: "1.0", request_id: "t", timestamp: "1970-01-01T00:00:00.000Z",
    principal: {}, agent: {}, tool: { tool_name: toolName },
    parameters: {}, environment: {}, context: {}
  };
}
