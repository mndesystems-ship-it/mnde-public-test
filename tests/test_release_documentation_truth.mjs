#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(repoRoot, path), "utf8");
const pkg = JSON.parse(read("package.json"));
const readme = read("README.md");
const installer = read("installer/README.md");
const release = read("docs/RELEASE.md");
const runbook = read("docs/release-publication-runbook.md");

function containsInOrder(text, snippets, label) {
  let cursor = 0;
  for (const snippet of snippets) {
    const next = text.indexOf(snippet, cursor);
    assert.ok(next >= 0, `${label} must contain in order: ${snippet}`);
    cursor = next + snippet.length;
  }
}

const sourceCheckoutCommands = [
  "git clone https://github.com/mndesystems-ship-it/mnde-public-test.git",
  "cd mnde-public-test",
  "npm install",
  "npm run reviewer-kit"
];

assert.match(readme, /No desktop installer or downloadable pilot release is currently published\./);
assert.match(readme, /supported public evaluation path is a source checkout/i);
assert.doesNotMatch(readme, /published on GitHub Releases/i);
assert.doesNotMatch(readme, /github\.com\/mndesystems-ship-it\/mnde-public-test\/releases/i);
containsInOrder(readme, sourceCheckoutCommands, "README.md");
assert.match(readme, /FINAL VERDICT: PASS/);
assert.match(readme, /npm run sidecar/);

assert.match(installer, /No MSI, NSIS, EXE, DMG, PKG, or AppImage is available\./);
assert.match(installer, /No downloadable npm\s+tarball is currently published\./);
assert.doesNotMatch(installer, /GitHub Releases/i);
containsInOrder(installer, sourceCheckoutCommands, "installer/README.md");
assert.match(installer, /npm run sidecar/);

assert.match(release, /artifacts are buildable local release\s+candidates; they are not currently published\./i);
containsInOrder(release, ["npm run release", "npm run release:verify"], "docs/RELEASE.md");
containsInOrder(release, [
  "npm init -y",
  "npm install ./mnde-public-test-<version>.tgz",
  "npx mnde-sidecar version",
  "npx mnde-sidecar init",
  "npx mnde-sidecar doctor",
  "npx mnde-sidecar smoke"
], "docs/RELEASE.md packaged installation test");

for (const artifact of [
  "mnde-public-test-<version>.tgz",
  "SHA256SUMS.txt",
  "release-manifest.json"
]) {
  assert.match(runbook, new RegExp(artifact.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

const engineMatch = /^>=(\d+)$/.exec(pkg.engines?.node ?? "");
assert.ok(engineMatch, "documentation truth test expects a package engine of the form >=<major>");
const minimumNodeMajor = engineMatch[1];
assert.match(readme, new RegExp(`Node\\.js ${minimumNodeMajor} or later`));
assert.match(installer, new RegExp(`Node\\.js ${minimumNodeMajor} or later`));
assert.match(release, new RegExp("engines[^\\n]*\\(`>=" + minimumNodeMajor + "`\\)"));
assert.doesNotMatch(`${readme}\n${installer}\n${release}`, /Node\.js 20|`>=20`/);

const escapedVersion = pkg.version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
assert.doesNotMatch(release, new RegExp(`(?:MNDe|version)\\s+${escapedVersion}`, "i"));
assert.match(release, /Version.*package\.json.*"version"/);

const publicDocs = `${readme}\n${installer}\n${release}`;
assert.doesNotMatch(publicDocs, /(?:download|install)\s+(?:an?\s+|the\s+)?(?:MSI|NSIS|EXE|DMG|PKG|AppImage)\b/i);
for (const sentence of publicDocs.replace(/\s+/g, " ").split(/[.!?](?:\s|$)/)) {
  const namesDesktopArtifact = /\b(?:MSI|NSIS|EXE|DMG|PKG|AppImage)\b/i.test(sentence);
  const claimsAvailability = /\b(?:available|published)\b/i.test(sentence);
  if (namesDesktopArtifact && claimsAvailability) {
    assert.match(sentence, /\b(?:no|none|not|unsupported|unpublished|unavailable)\b/i,
      `desktop artifact availability must be explicitly denied: ${sentence}`);
  }
}

console.log("PASS release documentation truth");
