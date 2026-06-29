#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { randomBytes } from "../src/crypto/provider.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const identityPath = resolve(repoRoot, ".mnde-test", "identity.json");
const jsonOnly = process.argv.includes("--json");
const supplied = process.argv.find((arg) => /^TESTER-[A-Z0-9-]+$/i.test(arg));

function localId() {
  return `TESTER-LOCAL-${randomBytes(2).toString("hex").toUpperCase()}`;
}

function installationId() {
  return `INSTALL-${randomBytes(8).toString("hex").toUpperCase()}`;
}

function readExisting() {
  if (!existsSync(identityPath)) return null;
  try {
    return JSON.parse(readFileSync(identityPath, "utf8"));
  } catch {
    return null;
  }
}

const existing = readExisting();
const identity = existing ?? {
  tester_id: (supplied ?? process.env.MNDE_TESTER_ID ?? localId()).toUpperCase(),
  installation_id: installationId(),
  created_at: new Date().toISOString(),
  privacy: {
    personal_information: false,
    browsing_activity: false,
    network_transmission_without_consent: false,
    purpose: "Identify feedback and local test artifacts."
  }
};

mkdirSync(dirname(identityPath), { recursive: true });
writeFileSync(identityPath, JSON.stringify(identity, null, 2) + "\n");

if (jsonOnly) {
  process.stdout.write(JSON.stringify(identity));
} else {
  console.log(`Tester ID: ${identity.tester_id}`);
  console.log(`Installation ID: ${identity.installation_id}`);
  console.log(`Saved: ${identityPath}`);
}
