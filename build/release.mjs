#!/usr/bin/env node
// Release builder: produce the customer-consumable MNDe artifact plus the
// integrity metadata needed to answer, without the developer repository:
//   - Which artifact did I receive?
//   - Which version does it claim to be, and from which source commit?
//   - Does its digest match the published release metadata?
//
// Output (default ./release/, gitignored):
//   mnde-public-test-<version>.tgz   the npm tarball (built via prepack)
//   SHA256SUMS.txt                   sha256 digests for every artifact
//   release-manifest.json            version/commit/build/runtime + artifact digests
//
// Lives under build/ (like build-package.mjs): it is release tooling, never
// shipped inside the tarball and never on the packaged runtime path. It does not
// publish, push, sign, or upload anything — it only builds and hashes locally.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const releaseDir = resolve(process.env.MNDE_RELEASE_DIR ?? join(repoRoot, "release"));

// Invoke npm cross-platform without a shell: resolve npm-cli.js next to the
// running node binary (same approach the packaging tests use).
function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}
const npmCliJs = resolveNpmCli();

function runNpm(args, opts = {}) {
  const result = npmCliJs
    ? spawnSync(process.execPath, [npmCliJs, ...args], { encoding: "utf8", ...opts })
    : spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, { encoding: "utf8", shell: !npmCliJs, ...opts });
  if (result.error) throw result.error;
  return result;
}

function npmVersion() {
  try {
    return runNpm(["--version"], { cwd: repoRoot }).stdout.trim();
  } catch {
    return null;
  }
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fail(message) {
  process.stderr.write(`release: ${message}\n`);
  process.exit(1);
}

// The release directory is wiped and recreated every run so a stale tarball from
// a previous version can never be hashed into this release's manifest. Because
// MNDE_RELEASE_DIR accepts an arbitrary path, that recursive delete is guarded:
// we refuse obviously catastrophic destinations (the repo, home, cwd, a
// filesystem root) and refuse to wipe any existing directory that holds files
// other than prior release artifacts. Only a dedicated/empty directory is
// cleaned; anything else is a hard error before a single byte is removed.
function prepareReleaseDir(dir) {
  const norm = resolve(dir);
  const isFilesystemRoot = resolve(norm, "..") === norm;
  const forbidden = new Set([resolve(repoRoot), resolve(homedir()), resolve(process.cwd())]);
  if (isFilesystemRoot || forbidden.has(norm)) {
    fail(`refusing to use ${norm} as the release directory (repo root, home, cwd, or a filesystem root). Set MNDE_RELEASE_DIR to a dedicated directory.`);
  }
  if (existsSync(norm)) {
    const releaseArtifact = /(\.tgz|\.tar\.gz)$/;
    const releaseMeta = new Set(["SHA256SUMS.txt", "release-manifest.json"]);
    const foreign = readdirSync(norm).filter((e) => !releaseArtifact.test(e) && !releaseMeta.has(e));
    if (foreign.length > 0) {
      fail(`release directory ${norm} contains non-release files (${foreign.slice(0, 6).join(", ")}); refusing to delete it. Point MNDE_RELEASE_DIR at an empty or dedicated directory.`);
    }
    rmSync(norm, { recursive: true, force: true });
  }
  mkdirSync(norm, { recursive: true });
}

prepareReleaseDir(releaseDir);

process.stdout.write("release: packing tarball (runs prepack -> build-package.mjs)...\n");
// Require an embedded source commit for a real release: build-package fails
// closed if Git HEAD is unavailable, so we never publish a commit-less artifact.
const packResult = runNpm(["pack", "--json", "--pack-destination", releaseDir], {
  cwd: repoRoot,
  env: { ...process.env, MNDE_REQUIRE_COMMIT: "1" }
});
if (packResult.status !== 0) {
  process.stderr.write(packResult.stdout ?? "");
  process.stderr.write(packResult.stderr ?? "");
  fail("npm pack failed");
}
// prepack writes progress lines before npm's --json array; isolate the JSON.
const jsonStart = packResult.stdout.indexOf("[");
if (jsonStart < 0) fail(`npm pack --json produced no JSON array:\n${packResult.stdout}`);
const packInfo = JSON.parse(packResult.stdout.slice(jsonStart))[0];
const tarballName = packInfo.filename;
const tarballPath = join(releaseDir, tarballName);
if (!existsSync(tarballPath)) fail(`packed tarball missing: ${tarballPath}`);

// Release identity comes from the exact metadata the build embedded into the
// artifact — one authoritative source, not a second guess.
const buildInfoPath = join(repoRoot, "dist", "src", "release", "build-info.json");
const buildInfo = existsSync(buildInfoPath) ? JSON.parse(readFileSync(buildInfoPath, "utf8")) : {};
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

// Defense in depth: even though build-package fails closed without a commit when
// MNDE_REQUIRE_COMMIT=1, never write a release manifest / checksums that claim to
// identify a source commit when they do not.
if (!buildInfo.commit) {
  fail("build produced no embedded source commit; refusing to write a commit-less release manifest.");
}

// Hash every file we actually placed in the release directory (currently just
// the tarball; future desktop artifacts would be hashed the same way).
const artifacts = readdirSync(releaseDir)
  .filter((name) => name !== "SHA256SUMS.txt" && name !== "release-manifest.json")
  .sort()
  .map((name) => {
    const full = join(releaseDir, name);
    return { name, bytes: statSync(full).size, sha256: sha256File(full) };
  });

const sumsBody = `${artifacts.map((a) => `${a.sha256}  ${a.name}`).join("\n")}\n`;
writeFileSync(join(releaseDir, "SHA256SUMS.txt"), sumsBody, "utf8");

const manifest = {
  schema: "mnde.release-manifest.v1",
  product: "MNDe",
  package: pkg.name,
  version: pkg.version,
  commit: buildInfo.commit ?? null,
  commit_short: buildInfo.commit_short ?? null,
  dirty: typeof buildInfo.dirty === "boolean" ? buildInfo.dirty : null,
  build_id: buildInfo.build_id ?? null,
  build_time: buildInfo.build_time ?? null,
  runtime: {
    node: process.versions.node,
    npm: npmVersion(),
    os: `${process.platform}-${process.arch}`
  },
  engines: pkg.engines ?? null,
  artifacts,
  // Wall-clock generation stamp: distinct from build_time (the embedded, digest-
  // bound identity). This one is informational and not covered by the digests.
  generated_at: process.env.MNDE_RELEASE_GENERATED_AT || new Date().toISOString()
};
writeFileSync(join(releaseDir, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

process.stdout.write(`\nrelease: ${releaseDir}\n`);
for (const a of artifacts) process.stdout.write(`  ${a.name}  ${a.bytes} bytes  sha256:${a.sha256.slice(0, 16)}…\n`);
process.stdout.write(`\nversion ${manifest.version}  commit ${manifest.commit_short ?? "unknown"}${manifest.dirty ? " (DIRTY BUILD — do not release)" : ""}\n`);
process.stdout.write("\nVerify a downloaded artifact:\n");
process.stdout.write(`  POSIX:      sha256sum -c SHA256SUMS.txt\n`);
process.stdout.write(`  PowerShell: (Get-FileHash ${tarballName} -Algorithm SHA256).Hash.ToLower()\n`);

if (manifest.dirty) {
  process.stderr.write("\nrelease: WARNING — built from a dirty working tree; commit before cutting a real release.\n");
}
