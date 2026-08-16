#!/usr/bin/env node
// mnde-authority — operate a production authority bundle's signing keys.
//
//   mnde-authority rotate --bundle b.json [--root-key root.pem] --key-id receipt-2 \
//                  (--new-public new.pub.pem | --generate --new-private-out new.key.pem) \
//                  [--role receipt] [--valid-until <iso>] [--now <iso>] --out next.json
//
//   mnde-authority revoke --bundle b.json [--root-key root.pem] --key-id receipt-1 \
//                  [--now <iso>] --out next.json
//
// Omit --root-key when MNDE_EXTERNAL_ROOT_SIGNER_CMD selects isolated/HSM root
// custody. Supplying both external-root mode and --root-key fails closed.
// The root private key is used only to re-sign the bundle. The output is verified
// before it is written; on any error nothing is written and the exit code is
// non-zero (fail-closed). The input bundle is never overwritten unless --force.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { generateAuthorityKeyPair, resolveRootSigner } from "../src/custody/index.mjs";
import { rotateSigningKey, revokeKey } from "../src/custody/lifecycle.mjs";

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) args[key] = true;
      else { args[key] = next; i += 1; }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function die(message, code = 1) {
  process.stderr.write(`mnde-authority: ${message}\n`);
  process.exit(code);
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    die(`cannot read ${label} at ${path}: ${error.message}`);
  }
}
function readText(path, label) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    die(`cannot read ${label} at ${path}: ${error.message}`);
  }
}

function writeBundle(args, next) {
  const out = args.out;
  if (!out) die("missing --out <file>");
  if (!args.force && resolve(out) === resolve(args.bundle)) {
    die("refusing to overwrite the input bundle; choose a new --out (keep the prior bundle for rollback) or pass --force");
  }
  if (!args.force && existsSync(out)) die(`--out ${out} already exists; pass --force to overwrite`);
  writeFileSync(out, `${JSON.stringify(next, null, 2)}\n`, "utf8");
}

function loadRootSigner(bundle, rootKeyPath) {
  const root = {
    keyId: bundle?.root_key?.key_id,
    publicPem: bundle?.root_key?.public_key,
    fingerprint: bundle?.root_key?.fingerprint
  };
  try {
    // In external mode, reject the presence of --root-key before reading it so
    // root PEM bytes never enter this process as a fallback path.
    const externalRoot = typeof process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD === "string"
      && process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD.trim().length > 0;
    if (externalRoot && rootKeyPath) {
      return resolveRootSigner({ env: process.env, root, rootPrivateKeyPem: "configured-via--root-key" });
    }
    const rootPrivateKeyPem = rootKeyPath ? readText(rootKeyPath, "root key") : undefined;
    return resolveRootSigner({ env: process.env, root, rootPrivateKeyPem });
  } catch (error) {
    die(`${error?.code ?? "ERR_ROOT_SIGNER"}: ${error?.message ?? String(error)}`);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];
  const args = parseArgs(argv.slice(1));
  const now = typeof args.now === "string" ? args.now : new Date().toISOString();

  if (command === "rotate") {
    if (!args.bundle || !args["key-id"]) {
      die("usage: rotate --bundle <in> [--root-key <root.pem> | external-root env] --key-id <id> (--new-public <pub.pem> | --generate --new-private-out <priv.pem>) [--role receipt] [--valid-until <iso>] [--now <iso>] --out <out>");
    }
    const bundle = readJson(args.bundle, "bundle");
    const rootSigner = loadRootSigner(bundle, args["root-key"]);

    let publicPem;
    if (args.generate) {
      if (!args["new-private-out"]) die("rotate --generate requires --new-private-out <file> to store the new private key");
      const pair = generateAuthorityKeyPair();
      writeFileSync(args["new-private-out"], pair.privatePem, { mode: 0o600 });
      publicPem = pair.publicPem;
      process.stderr.write(`generated new signing keypair; private key written to ${args["new-private-out"]} (mode 600)\n`);
    } else if (args["new-public"]) {
      publicPem = readText(args["new-public"], "new public key");
    } else {
      die("rotate requires --new-public <pub.pem> or --generate --new-private-out <file>");
    }

    const result = await rotateSigningKey(bundle, {
      role: typeof args.role === "string" ? args.role : "receipt",
      rootSigner,
      newKey: { keyId: args["key-id"], publicPem },
      now,
      ...(typeof args["valid-until"] === "string" ? { validUntil: args["valid-until"] } : {})
    });
    if (!result.ok) die(`rotate failed: ${result.reason}`);
    writeBundle(args, result.bundle);
    process.stdout.write(`rotated ${result.role} key -> new '${result.newKeyId}', retired [${result.retiredKeyIds.join(", ") || "none"}], issued_at ${now}\n`);
    process.stdout.write(`bundle written to ${args.out} (root fingerprint ${result.bundle.root_key.fingerprint})\n`);
    return;
  }

  if (command === "revoke") {
    if (!args.bundle || !args["key-id"]) {
      die("usage: revoke --bundle <in> [--root-key <root.pem> | external-root env] --key-id <id> [--now <iso>] --out <out>");
    }
    const bundle = readJson(args.bundle, "bundle");
    const rootSigner = loadRootSigner(bundle, args["root-key"]);
    const result = await revokeKey(bundle, { rootSigner, keyId: args["key-id"], now });
    if (!result.ok) die(`revoke failed: ${result.reason}`);
    writeBundle(args, result.bundle);
    process.stdout.write(`revoked key '${result.revokedKeyId}', issued_at ${now}\n`);
    process.stdout.write(`bundle written to ${args.out} (root fingerprint ${result.bundle.root_key.fingerprint})\n`);
    return;
  }

  die("usage: mnde-authority <rotate|revoke> ...", 2);
}

main().catch((error) => {
  die(error?.message ?? String(error));
});
