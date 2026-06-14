#!/usr/bin/env node
// MNDe outreach discovery — find MCP-related projects that may need
// pre-execution authorization, receipts, auditability, or execution controls.
//
//   node scripts/find-mcp-targets.mjs
//   node scripts/find-mcp-targets.mjs --quality --min-stars 1 --limit 50   (recommended daily batch)
//
// Automates discovery, scoring, categorization, draft generation, and tracking.
// It does NOT send anything. Output: outreach/mcp-targets.csv (ranked) and
// outreach/mcp-targets.json (full collected fields).
//
// Flags:
//   --min-stars N      minimum stars (default 0; keeps fresh zero-star repos)
//   --max-stars N      maximum stars (default 100)
//   --updated-days N   pushed within N days (default 30; alias: --days)
//   --limit N          max rows written (default 100)
//   --quality          re-rank by quality signals and enrich a shortlist with
//                      README / package-file detection (1 extra API call per
//                      shortlisted repo; set GITHUB_TOKEN to raise the limit)
//
// Set GITHUB_TOKEN (or GH_TOKEN) to raise the GitHub rate limit.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(repoRoot, "outreach");
const templatesDir = join(outDir, "templates");
const outCsv = join(outDir, "mcp-targets.csv");
const outJson = join(outDir, "mcp-targets.json");

function flag(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function intArg(names, def) {
  for (const name of [].concat(names)) {
    const raw = flag(name);
    if (raw !== undefined) {
      const n = Number.parseInt(raw, 10);
      if (Number.isFinite(n)) return n;
    }
  }
  return def;
}
function boolArg(name) {
  return process.argv.includes(name);
}

const MIN_STARS = intArg("--min-stars", 0);
const MAX_STARS = intArg("--max-stars", 100);
const DAYS = intArg(["--updated-days", "--days"], 30);
const LIMIT = intArg("--limit", 100);
const PER_TERM = intArg("--per-term", 30);
const QUALITY = boolArg("--quality");
const TOKEN = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? null;
const SINCE = new Date(Date.now() - DAYS * 86_400_000).toISOString().slice(0, 10);

const SEARCH_TERMS = [
  "Model Context Protocol", "MCP server", "Anthropic MCP", "tools/call", "tools/list",
  "tool calling", "agent tools", "agent framework", "SSH MCP", "filesystem MCP",
  "Docker MCP", "database MCP"
];

const SCORE = {
  shell: 5, ssh: 5, docker: 5, filesystem: 5, database: 5, payments: 5, deployment: 5,
  "agent-platform": 4,
  audit: 3, replay: 3, observability: 3, signing: 3,
  memory: 2,
  productivity: 1, other: 2
};
const HIGH = new Set(["shell", "ssh", "docker", "filesystem", "database", "payments", "deployment"]);
const MEDIUM = new Set(["agent-platform", "audit", "replay", "observability", "signing"]);

const CATEGORY_RULES = [
  ["payments", /\b(payment|stripe|billing|invoice|treasury|bank|wallet|transfer|refund)\b/],
  ["ssh", /\bssh\b|\bsftp\b/],
  ["docker", /\b(docker|container|kubernetes|k8s|helm|podman)\b/],
  ["database", /\b(sql|postgres|mysql|mongo|mongodb|database|redis|sqlite|bigquery|snowflake)\b/],
  ["deployment", /\b(deploy|deployment|ci\/cd|terraform|ansible|pulumi|provision|infrastructure)\b/],
  ["filesystem", /\b(filesystem|file system|files?|directory|fs)\b/],
  ["shell", /\b(shell|bash|zsh|command line|cli|terminal|exec|execute commands?)\b/],
  ["signing", /\b(sign|signature|signing|notary|attest|provenance|verifiable|verification)\b/],
  ["audit", /\b(audit|compliance|governance|policy)\b/],
  ["replay", /\breplay\b/],
  ["observability", /\b(observ|trace|tracing|monitor|telemetry|inspect|logfire|langfuse|eval)\b/],
  ["agent-platform", /\b(agent|agentic|orchestrat|framework|workflow|autonom|crew|langgraph|tool[- ]?platform|tool[- ]?calling)\b/],
  ["memory", /\b(memory|recall|knowledge|retrieval|rag|vector|embedding|second brain)\b/],
  ["productivity", /\b(word|docs|document|email|gmail|telegram|slack|calendar|notes?|content|post|linkedin|tweet)\b/]
];

const WHY = {
  shell: "Exposes shell command execution through MCP. Potential need for authorization before execution.",
  ssh: "Exposes SSH or remote access through MCP. Potential need for authorization and an audit record before execution.",
  docker: "Exposes container or Docker control through MCP. Commands can modify running infrastructure.",
  filesystem: "Exposes filesystem operations through MCP. Read/write/delete actions may need pre-execution checks.",
  database: "Exposes database access through MCP. Queries and writes may need authorization and an audit record.",
  payments: "Touches payments or financial operations. Actions have monetary consequences and may need approval and non-repudiation.",
  deployment: "Automates deployment or infrastructure changes through MCP. Actions change live systems.",
  "agent-platform": "Orchestrates agent tool calls. A central authorization and receipt point may apply.",
  audit: "Focused on audit or governance. Pre-execution decisions and signed receipts are adjacent.",
  replay: "Focused on replay of agent activity. Signed, replayable decision receipts are adjacent.",
  observability: "Focused on inspection after execution. Authorization before execution is complementary.",
  signing: "Focused on signing or verification. Receipt signing and authority verification are adjacent.",
  memory: "Memory or retrieval system. Lower execution risk today; write access may create future authorization needs.",
  productivity: "Productivity or content integration. Limited execution authority.",
  other: "MCP-related project. Relevance to pre-execution authorization to be confirmed."
};

const FOCUS = {
  shell: "exposes shell command execution through MCP",
  ssh: "exposes SSH access through MCP",
  docker: "exposes Docker or container control through MCP",
  filesystem: "exposes filesystem operations through MCP",
  database: "exposes database access through MCP",
  payments: "handles payment or financial operations",
  deployment: "automates deployment or infrastructure changes",
  "agent-platform": "orchestrates agent tool calls",
  audit: "works on audit or governance for agent activity",
  replay: "works on replay of agent activity",
  observability: "works on observability of agent activity",
  signing: "works on signing or verification",
  memory: "works on memory or retrieval",
  productivity: "is a productivity or content integration",
  other: "is an MCP-related project"
};

const QUALITY_TOPICS = new Set([
  "mcp", "model-context-protocol", "modelcontextprotocol", "agent", "agents", "ai-agent",
  "agentic", "claude", "openai", "anthropic", "langchain", "cursor", "llm", "tool-calling"
]);
const PACKAGE_FILES = new Set([
  "package.json", "pyproject.toml", "cargo.toml", "go.mod", "requirements.txt",
  "setup.py", "gemfile", "pom.xml", "build.gradle", "composer.json"
]);

function templateNameFor(category) {
  if (["shell", "ssh", "docker", "filesystem", "database", "deployment", "payments"].includes(category)) return "shell-maintainer";
  if (category === "agent-platform") return "production-template";
  if (["observability", "replay", "audit"].includes(category)) return "observability-partner";
  if (category === "signing") return "security-partner";
  return "shell-maintainer";
}

const templateCache = new Map();
function loadTemplate(name) {
  if (templateCache.has(name)) return templateCache.get(name);
  const path = join(templatesDir, `${name}.txt`);
  const text = existsSync(path) ? readFileSync(path, "utf8").trim() : "Interesting project — {{repo}}.\n\nI saw it {{focus}}.\n\nHow are you handling authorization before a tool call executes today?";
  templateCache.set(name, text);
  return text;
}

function categorize(haystack) {
  for (const [category, rule] of CATEGORY_RULES) if (rule.test(haystack)) return category;
  return "other";
}
function isListOrEducational(name, description) {
  const text = `${name} ${description}`.toLowerCase();
  return /awesome|(^|[-_ /])list($|[-_ ])|curated|tutorial|course|handbook|cheat[- ]?sheet|learning|study notes|exercises?$|examples?$/.test(text);
}
function genericOwner(login) {
  return /\d{2,}$/.test(login) || (login.length >= 20 && !/[-_]/.test(login));
}
function genericName(name) {
  const n = name.toLowerCase();
  return /model[-_]context[-_]protocol/.test(n) || /[0-9a-f]{8,}/.test(n) || /\d{4,}/.test(n) || /(^|[-_])(poc|demo|copy|old|backup|untitled)([-_]|$)/.test(n);
}
function rankWeight(category) {
  if (HIGH.has(category)) return 3;
  if (MEDIUM.has(category)) return 2;
  return 1;
}
function sleep(ms) {
  return new Promise((done) => setTimeout(done, ms));
}
function warn(message) {
  process.stderr.write(`WARN: ${message}\n`);
}

let coreRateLimited = false;
async function ghFetch(url) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "mnde-outreach-discovery" };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  return fetch(url, { headers });
}

async function searchTerm(term) {
  const phrase = term.includes(" ") || term.includes("/") ? `"${term}"` : term;
  const q = `${phrase} pushed:>=${SINCE} stars:${MIN_STARS}..${Math.max(MIN_STARS, MAX_STARS - 1)} archived:false`;
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=updated&order=desc&per_page=${PER_TERM}`;
  let res;
  try {
    res = await ghFetch(url);
  } catch (error) {
    warn(`request failed for "${term}": ${error?.message ?? error}`);
    return [];
  }
  if (res.status === 403 || res.status === 429) {
    warn(`rate limited on "${term}" (status ${res.status}). Set GITHUB_TOKEN to raise the limit.`);
    return [];
  }
  if (!res.ok) {
    warn(`unexpected status ${res.status} for "${term}".`);
    return [];
  }
  const body = await res.json().catch(() => ({}));
  return Array.isArray(body.items) ? body.items : [];
}

// One trees call per repo: detect a real README and package files at the root.
async function enrichRepo(item) {
  if (coreRateLimited) return { ok: false };
  const branch = item.default_branch || "main";
  const url = `https://api.github.com/repos/${item.full_name}/git/trees/${encodeURIComponent(branch)}`;
  let res;
  try {
    res = await ghFetch(url);
  } catch {
    return { ok: false };
  }
  if (res.status === 403 || res.status === 429) {
    coreRateLimited = true;
    warn("core API rate limited during quality enrichment; remaining repos left unverified. Set GITHUB_TOKEN for full checks.");
    return { ok: false };
  }
  if (!res.ok) return { ok: false };
  const body = await res.json().catch(() => ({}));
  const paths = Array.isArray(body.tree) ? body.tree.filter((e) => e.type === "blob").map((e) => String(e.path).toLowerCase()) : [];
  return {
    ok: true,
    hasReadme: paths.some((p) => /^readme(\.|$)/.test(p)),
    hasPackageFile: paths.some((p) => PACKAGE_FILES.has(p))
  };
}

function qualityScore(record) {
  let q = 0;
  if (record.topicsMatch) q += 2;
  if (record.hasReadme === true) q += 2;
  if (record.hasPackageFile === true) q += 1;
  if (record.descLen > 40) q += 1; else q -= 1;
  if (record.stars >= 1) q += 1;
  if (record.genericOwner) q -= 2;
  if (record.genericName) q -= 1;
  if (record.genericOwner && record.stars === 0 && record.descLen <= 40) q -= 2; // clearest junk: sinks below the cut
  return q;
}

function csvCell(value) {
  const s = String(value ?? "");
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

function baseCompare(a, b) {
  return b._weight - a._weight || b.score - a.score || a.stars - b.stars ||
    (b.lastUpdated < a.lastUpdated ? -1 : b.lastUpdated > a.lastUpdated ? 1 : 0);
}
function qualityCompare(a, b) {
  return b._weight - a._weight || b.score - a.score || b.qualityScore - a.qualityScore ||
    a.stars - b.stars || (b.lastUpdated < a.lastUpdated ? -1 : b.lastUpdated > a.lastUpdated ? 1 : 0);
}

async function main() {
  mkdirSync(outDir, { recursive: true });
  mkdirSync(templatesDir, { recursive: true });

  console.log("MNDe outreach discovery");
  console.log(`Window: pushed >= ${SINCE} | stars ${MIN_STARS}..${MAX_STARS - 1} | limit ${LIMIT} | quality ${QUALITY ? "on" : "off"} | token ${TOKEN ? "yes" : "no"}\n`);

  const byRepo = new Map();
  for (const term of SEARCH_TERMS) {
    const items = await searchTerm(term);
    for (const item of items) if (item?.full_name && !byRepo.has(item.full_name)) byRepo.set(item.full_name, item);
    process.stdout.write(`  searched ${JSON.stringify(term).padEnd(26)} -> ${items.length} results (unique so far: ${byRepo.size})\n`);
    await sleep(TOKEN ? 1200 : 7000);
  }

  const records = [];
  for (const item of byRepo.values()) {
    const description = item.description ?? "";
    const stars = item.stargazers_count ?? 0;
    if (item.archived) continue;
    if (stars < MIN_STARS || stars >= MAX_STARS) continue;
    if (isListOrEducational(item.name ?? "", description)) continue;
    if (!description) continue;

    const topics = (item.topics ?? []).map((t) => String(t).toLowerCase());
    const haystack = `${item.name ?? ""} ${description} ${topics.join(" ")}`.toLowerCase();
    const category = categorize(haystack);
    records.push({
      _item: item,
      repo: item.full_name,
      owner: item.owner?.login ?? "",
      url: item.html_url,
      description,
      stars,
      language: item.language ?? "",
      lastUpdated: (item.pushed_at ?? "").slice(0, 10),
      contactMethod: `${item.html_url}/issues`,
      category,
      score: SCORE[category] ?? 2,
      whyMndeFits: WHY[category] ?? WHY.other,
      suggestedMessage: loadTemplate(templateNameFor(category)).replaceAll("{{repo}}", item.full_name).replaceAll("{{focus}}", FOCUS[category] ?? FOCUS.other),
      status: "new",
      notes: "",
      _weight: rankWeight(category),
      descLen: description.length,
      topicsMatch: topics.some((t) => QUALITY_TOPICS.has(t)),
      genericOwner: genericOwner(item.owner?.login ?? ""),
      genericName: genericName(item.name ?? ""),
      hasReadme: null,
      hasPackageFile: null,
      qualityScore: 0
    });
  }

  if (QUALITY) {
    records.sort(baseCompare); // shortlist the most promising before spending API calls
    const budget = TOKEN ? Math.min(records.length, 150) : 20;
    const shortlist = records.slice(0, Math.min(records.length, Math.max(LIMIT * 2, budget)));
    let enriched = 0;
    for (const record of shortlist) {
      if (enriched >= budget || coreRateLimited) break;
      const info = await enrichRepo(record._item);
      if (info.ok) {
        record.hasReadme = info.hasReadme;
        record.hasPackageFile = info.hasPackageFile;
      }
      enriched += 1;
      await sleep(TOKEN ? 700 : 1500);
    }
    for (const record of records) record.qualityScore = qualityScore(record);
    records.sort(qualityCompare);
    console.log(`\nQuality enrichment: checked ${enriched} repo(s) for README and package files.`);
  } else {
    records.sort(baseCompare);
  }

  const limited = records.slice(0, LIMIT);
  limited.forEach((record, index) => { record.rank = index + 1; });

  const columns = ["rank", "score", "repo", "owner", "url", "description", "category", "whyMndeFits", "suggestedMessage", "status", "notes"];
  const csv = [columns.join(",")].concat(limited.map((r) => columns.map((c) => csvCell(r[c])).join(","))).join("\n") + "\n";
  writeFileSync(outCsv, csv, "utf8");
  writeFileSync(outJson, `${JSON.stringify(limited.map(({ _item, _weight, ...rest }) => rest), null, 2)}\n`, "utf8");

  console.log(`\nWrote ${limited.length} candidates (of ${records.length} found) to:`);
  console.log(`  ${outCsv}`);
  console.log(`  ${outJson}`);

  if (limited.length === 0) {
    warn("no candidates. Check network access or set GITHUB_TOKEN, then re-run.");
    return;
  }

  console.log("\nTop targets:");
  for (const r of limited.slice(0, 20)) {
    const q = QUALITY ? ` q${r.qualityScore >= 0 ? "+" : ""}${r.qualityScore}${r.hasReadme === true ? " readme" : ""}${r.hasPackageFile === true ? " pkg" : ""}` : "";
    console.log(`  #${String(r.rank).padStart(2)} [${r.score}] ${r.category.padEnd(14)} ${r.repo}${q}`);
  }
  console.log("\nReview the top results manually before contacting anyone. See docs/outreach-process.md.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
