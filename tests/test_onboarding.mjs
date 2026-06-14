// Onboarding subsystem tests — fixture-based, no external services.
//
//   npm run test:onboarding
//
// Covers discovery, wiring-plan determinism, backup creation, restore,
// policy-draft generation, cross-platform path handling, malformed configs,
// and missing configs. Nothing here touches the real system: every context is
// pointed at temp/fixture directories.

import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildContext } from "../src/onboarding/context.mjs";
import { runDiscovery, KNOWN_CLIENTS } from "../src/discovery/index.mjs";
import { buildWiringPlan, applyPlan, uninstall, readManifest } from "../src/wiring/index.mjs";
import { draftPolicy, categorizeTool } from "../src/policy-drafting/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const fixtures = join(here, "fixtures", "onboarding");

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function tmp(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

// Fresh, isolated context: copy the valid fixture home into a temp dir so apply/
// restore can mutate it safely. platform "linux" -> ~/.config/Claude/...
function freshLinuxCtx() {
  const home = tmp("mnde-onb-home-");
  cpSync(join(fixtures, "claude"), home, { recursive: true });
  const stateDir = tmp("mnde-onb-state-");
  const cwd = tmp("mnde-onb-cwd-");
  return buildContext({ platform: "linux", homedir: home, cwd, stateDir, repoRoot, env: {}, now: () => "2026-01-01T00:00:00.000Z" });
}

test("discovery finds clients, servers, and the already-wrapped one", () => {
  const ctx = freshLinuxCtx();
  const d = runDiscovery(ctx);
  const claude = d.clients.find((c) => c.id === "claude-desktop");
  assert.ok(claude.exists, "claude config should be found");
  assert.equal(claude.servers.length, 3);
  assert.equal(claude.servers.find((s) => s.name === "filesystem").wrapped, false);
  assert.equal(claude.servers.find((s) => s.name === "already-protected").wrapped, true);
  assert.equal(d.environment.os, "linux");
});

test("cross-platform client path resolution", () => {
  const claude = KNOWN_CLIENTS.find((c) => c.id === "claude-desktop");
  const win = claude.resolvePath(buildContext({ platform: "win32", homedir: "C:\\Users\\x", env: { APPDATA: "C:\\Users\\x\\AppData\\Roaming" } }));
  const mac = claude.resolvePath(buildContext({ platform: "darwin", homedir: "/Users/x", env: {} }));
  const lin = claude.resolvePath(buildContext({ platform: "linux", homedir: "/home/x", env: {} }));
  assert.match(win, /AppData[\\/]Roaming[\\/]Claude[\\/]claude_desktop_config\.json$/);
  assert.match(mac, /Library\/Application Support\/Claude\/claude_desktop_config\.json$/);
  assert.match(lin, /\.config\/Claude\/claude_desktop_config\.json$/);
});

test("wiring plan is deterministic and skips already-wrapped servers", () => {
  const a = buildWiringPlan(runDiscovery(freshLinuxCtx()), freshLinuxCtx());
  const b = buildWiringPlan(runDiscovery(freshLinuxCtx()), freshLinuxCtx());
  // Two unwrapped servers (filesystem, shell); already-protected is skipped.
  assert.equal(a.changeCount, 2);
  const mod = a.modifications.find((m) => m.clientId === "claude-desktop");
  assert.ok(mod.backupPath.endsWith(".bak"));
  assert.ok(mod.backupMetadataPath.endsWith(".bak.metadata.json"));
  assert.equal(mod.restoreCommand, "mnde uninstall");
  const names = mod.servers.map((s) => s.server).sort();
  assert.deepEqual(names, ["filesystem", "shell"]);
  // identical inputs -> identical plan
  const norm = (p) => JSON.stringify(p.modifications.map((m) => ({ c: m.clientId, s: m.servers.map((x) => [x.server, x.after.env.MNDE_PROXY_UPSTREAM_COMMAND, x.after.env.MNDE_PROXY_UPSTREAM_ARGS]) })));
  assert.equal(norm(a), norm(b));
  // upstream is preserved in the wrapped result
  const fs = mod.servers.find((s) => s.server === "filesystem");
  assert.equal(fs.after.env.MNDE_PROXY_UPSTREAM_COMMAND, "npx");
  assert.equal(fs.after.command, "node");
});

test("apply creates a backup, wraps servers, and records a manifest", () => {
  const ctx = freshLinuxCtx();
  const plan = buildWiringPlan(runDiscovery(ctx), ctx);
  const before = readFileSync(join(ctx.homedir, ".config", "Claude", "claude_desktop_config.json"), "utf8");
  const { applied } = applyPlan(plan, ctx);
  assert.equal(applied.length, 1);
  assert.ok(existsSync(applied[0].backupPath), "backup file must exist");
  assert.equal(readFileSync(applied[0].backupPath, "utf8"), before, "backup must equal original bytes");

  const config = JSON.parse(readFileSync(applied[0].configPath, "utf8"));
  assert.equal(config.mcpServers.filesystem.env._mnde_wrapped, "1");
  assert.equal(config.mcpServers.filesystem.env.MNDE_PROXY_UPSTREAM_COMMAND, "npx");
  assert.equal(config.mcpServers["already-protected"].env._mnde_wrapped, "1"); // untouched
  assert.ok(existsSync(applied[0].backupMetadataPath), "backup metadata must exist");
  const metadata = JSON.parse(readFileSync(applied[0].backupMetadataPath, "utf8"));
  assert.equal(metadata.schema_version, "mnde.onboarding.backup.v1");
  assert.equal(metadata.config_path, applied[0].configPath);
  assert.equal(metadata.restore_command, "mnde uninstall");
  assert.equal(metadata.sha256_before, applied[0].sha256Before);

  const manifest = readManifest(ctx);
  assert.equal(manifest.entries.length, 1);
  assert.deepEqual(manifest.entries[0].servers.sort(), ["filesystem", "shell"]);
});

test("apply is idempotent (second run wraps nothing new)", () => {
  const ctx = freshLinuxCtx();
  applyPlan(buildWiringPlan(runDiscovery(ctx), ctx), ctx);
  const second = applyPlan(buildWiringPlan(runDiscovery(ctx), ctx), ctx); // re-discover after wrapping
  assert.equal(second.applied.length, 0, "nothing new to wrap on a second apply");
});

test("uninstall restores the original config byte-for-byte", () => {
  const ctx = freshLinuxCtx();
  const configPath = join(ctx.homedir, ".config", "Claude", "claude_desktop_config.json");
  const original = readFileSync(configPath, "utf8");
  applyPlan(buildWiringPlan(runDiscovery(ctx), ctx), ctx);
  assert.notEqual(readFileSync(configPath, "utf8"), original, "config should differ after apply");
  const { restored } = uninstall(ctx);
  assert.equal(restored.length, 1);
  assert.equal(readFileSync(configPath, "utf8"), original, "config must be restored exactly");
  assert.equal(readManifest(ctx).entries.length, 0, "manifest cleared after uninstall");
});

test("malformed config is flagged and never wired", () => {
  const home = join(fixtures, "malformed");
  const ctx = buildContext({ platform: "linux", homedir: home, cwd: tmp("mnde-onb-cwd-"), stateDir: tmp("mnde-onb-state-"), repoRoot, env: {} });
  const d = runDiscovery(ctx);
  const claude = d.clients.find((c) => c.id === "claude-desktop");
  assert.ok(claude.exists);
  assert.ok(claude.error, "malformed config must be flagged with an error");
  assert.equal(claude.servers.length, 0);
  assert.equal(buildWiringPlan(d, ctx).changeCount, 0, "malformed config must not be wired");
});

test("missing configs produce an empty, safe plan", () => {
  const ctx = buildContext({ platform: "linux", homedir: tmp("mnde-onb-empty-"), cwd: tmp("mnde-onb-cwd-"), stateDir: tmp("mnde-onb-state-"), repoRoot, env: {} });
  const d = runDiscovery(ctx);
  assert.equal(d.summary.serversFound, 0);
  assert.equal(buildWiringPlan(d, ctx).changeCount, 0);
});

test("policy draft categorizes capabilities and never auto-approves", () => {
  assert.equal(categorizeTool({ name: "read_status" }).recommended, "allow");
  assert.equal(categorizeTool({ name: "delete_backups" }).recommended, "deny");
  assert.equal(categorizeTool({ name: "write_file" }).recommended, "approval");
  assert.equal(categorizeTool({ name: "frobnicate" }).recommended, "deny"); // unclassified -> deny

  const draft = draftPolicy(
    [{ name: "fs", client: "claude-desktop", tools: [{ name: "read_file" }, { name: "delete_path" }] }],
    { now: "2026-01-01T00:00:00.000Z" }
  );
  assert.equal(draft.default_decision, "REFUSE");
  assert.equal(draft.review_required, true);
  assert.equal(draft.servers[0].tools.find((t) => t.tool === "read_file").recommended, "allow");
  assert.equal(draft.servers[0].tools.find((t) => t.tool === "delete_path").recommended, "deny");
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL onboarding tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS onboarding tests (${results.length}/${results.length})`);
