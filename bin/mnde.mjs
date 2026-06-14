#!/usr/bin/env node
// MNDe onboarding CLI.
//
//   mnde init              discovery + recommendations (no changes)
//   mnde init --dry-run    full wiring plan (no changes)
//   mnde init --apply      apply approved wiring (creates backups first)
//   mnde uninstall         restore original configurations from backups
//   mnde status            show what is protected, plus policy/authority status
//
// Onboarding only. It does not make authority decisions. Nothing is modified
// unless you run `--apply`, and every `--apply` is reversible with `uninstall`.

import { buildContext, discover, planDeployment, buildDraft, apply, uninstall, status } from "../src/onboarding/index.mjs";

const argv = process.argv.slice(2);
const command = argv[0];
const has = (flag) => argv.includes(flag);

function line(text = "") {
  process.stdout.write(`${text}\n`);
}
function rule() {
  line("------------------------------------------------------------");
}
function banner(text) {
  rule();
  line(text);
  rule();
}

function renderDiscovery(discovery) {
  const env = discovery.environment;
  line("Environment");
  line(`  OS:              ${env.os}`);
  line(`  Node:            ${env.runtime.node}`);
  line(`  Package manager: ${env.packageManager ?? "none detected"}`);
  line(`  Project type:    ${env.projectTypes.join(", ")}`);
  line("");
  line("MCP clients");
  for (const client of discovery.clients) {
    const state = client.error ? "unreadable (skipped)" : client.exists ? `${client.servers.length} server(s)` : "not found";
    line(`  ${client.name.padEnd(22)} ${state}`);
    line(`    ${client.configPath}`);
    if (client.error) line(`    ! ${client.error}`);
    for (const server of client.servers) {
      line(`    - ${server.name}${server.wrapped ? "  [already protected]" : ""}`);
    }
  }
  line("");
  line(`Found ${discovery.summary.serversFound} server(s) across ${discovery.summary.clientsFound} client(s); ${discovery.summary.serversUnwrapped} not yet protected.`);
}

function renderPlan(plan) {
  if (plan.changeCount === 0) {
    line("No changes proposed. Either no MCP clients/servers were found, or everything is already protected.");
    return;
  }
  line(`Proposed wiring (${plan.changeCount} server(s)); MNDe sidecar: ${plan.sidecarUrl}`);
  line("");
  for (const mod of plan.modifications) {
    line(`File: ${mod.configPath}   (${mod.clientName})`);
    line(`  Backup:  ${mod.backupPath}`);
    line(`  Metadata:${mod.backupMetadataPath}`);
    line(`  Restore: ${mod.restoreCommand}`);
    for (const sm of mod.servers) {
      const beforeCmd = `${sm.before?.command ?? "?"} ${(sm.before?.args ?? []).join(" ")}`.trim();
      line(`  - ${sm.server}`);
      line(`      before: ${beforeCmd}`);
      line(`      after:  node mcp/mnde-mcp-proxy.mjs  (MNDe in front; upstream preserved)`);
    }
    line("");
  }
}

async function main() {
  const ctx = buildContext();

  if (command === "init") {
    const { discovery, plan } = planDeployment(ctx);

    if (has("--apply")) {
      banner("MNDe init --apply");
      renderDiscovery(discovery);
      line("");
      const result = apply(ctx);
      if (result.applied.length === 0) {
        line("Nothing to apply. No changes were written.");
        return;
      }
      for (const entry of result.applied) {
        line(`BACKUP CREATED: ${entry.backupPath}`);
        line(`  for: ${entry.configPath} (${entry.clientName})`);
        line(`  protected servers: ${entry.servers.join(", ")}`);
      }
      line("");
      if (result.draftPath) line(`Policy draft written (NOT active, review required): ${result.draftPath}`);
      line("");
      line("Done. MNDe now sits in front of the wired MCP servers.");
      line("Restart your MCP client(s) to pick up the change.");
      line("Undo any time with:  mnde uninstall");
      return;
    }

    // init  and  init --dry-run  both make NO changes.
    banner(has("--dry-run") ? "MNDe init --dry-run" : "MNDe init");
    renderDiscovery(discovery);
    line("");
    renderPlan(plan);

    if (has("--dry-run")) {
      const draft = buildDraft(discovery, ctx);
      line(`Policy draft preview: ${draft.servers.length} server(s), default decision ${draft.default_decision} (review required).`);
      line("");
      banner("NO CHANGES WRITTEN");
      line("This was a dry run. Re-run with --apply to make these changes (backups are created first).");
    } else {
      line("");
      line("No changes were made. Next:");
      line("  mnde init --dry-run    see the exact plan");
      line("  mnde init --apply      apply it (backups created first)");
    }
    return;
  }

  if (command === "uninstall") {
    banner("MNDe uninstall");
    const result = uninstall(ctx);
    if (result.restored.length === 0) {
      line("Nothing to restore. No MNDe wiring is recorded.");
    } else {
      for (const entry of result.restored) line(`RESTORED: ${entry.configPath} (${entry.clientName})`);
      line("");
      line("Original configurations restored from backups. Restart your MCP client(s).");
    }
    if (result.missing.length > 0) {
      line("");
      for (const entry of result.missing) line(`! backup missing for ${entry.configPath}; left unchanged`);
    }
    return;
  }

  if (command === "status") {
    banner("MNDe status");
    const s = status(ctx);
    line("Protected");
    if (s.protected.length === 0) {
      line("  (nothing wired — run `mnde init --dry-run`)");
    } else {
      for (const p of s.protected) {
        line(`  ${p.client}: ${p.servers.join(", ")}`);
        line(`    ${p.configPath}  (applied ${p.appliedAt})`);
      }
    }
    line("");
    line(`Policy:               draft ${s.policy.draftPresent ? "present" : "absent"} (drafts are never enforced)`);
    line(`Authority (local):    ${s.authority.ready ? "READY" : `not configured${s.authority.reason ? ` (${s.authority.reason})` : ""}`}`);
    line(`Receipt verification: ${s.receiptVerification === null ? "no sample found" : s.receiptVerification ? "VERIFIED (sample receipt)" : "FAILED"}`);
    return;
  }

  line("MNDe onboarding CLI");
  line("");
  line("Usage:");
  line("  mnde init              discovery + recommendations (no changes)");
  line("  mnde init --dry-run    full wiring plan (no changes)");
  line("  mnde init --apply      apply approved wiring (backups created first)");
  line("  mnde uninstall         restore original configurations from backups");
  line("  mnde status            show protected clients/servers and authority status");
  process.exitCode = command ? 1 : 0;
}

main().catch((error) => {
  process.stderr.write(`mnde: ${error?.message ?? String(error)}\n`);
  process.exit(1);
});
