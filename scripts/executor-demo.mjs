// MNDe Executor Demo — authorize, run on ALLOW, refuse otherwise, verify receipts.
//
//   npm run executor-demo
//
// Proves, against a real sidecar and real signed receipts:
//   - ALLOW  -> the function runs, receipt verifies offline
//   - REFUSE -> the function does NOT run, receipt verifies offline
//   - sidecar down -> fail closed, the function does NOT run

import { createMndeExecutor } from "../executor/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const SIDECAR_URL = "http://127.0.0.1:8787";
const RECEIPTS_DIR = "./mnde-receipts/executor-demo";

function print(label, value) {
  console.log(`${label}: ${value}`);
}

async function main() {
  console.log("MNDe Executor Demo\n");
  let pass = true;

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL, testerId: "EXEC-DEMO-001" });
  const mnde = createMndeExecutor({ sidecarUrl: SIDECAR_URL, receiptsDir: RECEIPTS_DIR });

  try {
    // ── ALLOW ────────────────────────────────────────────────────────────────
    let allowRan = false;
    const allow = await mnde.execute({
      action: "read_status",
      input: {},
      run: async () => {
        allowRan = true;
        return { status: "ok" };
      }
    });
    console.log("ALLOW action:");
    print("Decision", allow.decision);
    print("Executed", allow.executed ? "YES" : "NO");
    print("Receipt", allow.verified ? "VERIFIED" : "NOT VERIFIED");
    console.log("");
    pass = pass && allow.decision === "ALLOW" && allow.executed === true && allowRan === true && allow.verified === true;

    // ── REFUSE ───────────────────────────────────────────────────────────────
    let refuseRan = false;
    const refuse = await mnde.execute({
      action: "delete_backups",
      input: { path: "backups/", script: "rm -rf backups/" },
      run: async () => {
        refuseRan = true; // must never happen
        return { deleted: true };
      }
    });
    console.log("REFUSE action:");
    print("Decision", refuse.decision);
    print("Executed", refuse.executed ? "YES" : "NO");
    print("Receipt", refuse.verified ? "VERIFIED" : "NOT VERIFIED");
    console.log("");
    pass = pass && refuse.decision === "REFUSE" && refuse.executed === false && refuseRan === false && refuse.verified === true;
  } finally {
    await sidecar.stop();
  }

  // ── Missing sidecar (fail closed) ────────────────────────────────────────────
  const offline = createMndeExecutor({
    sidecarUrl: "http://127.0.0.1:8799", // nothing is listening here
    receiptsDir: RECEIPTS_DIR,
    timeoutMs: 1500
  });
  let offlineRan = false;
  const miss = await offline.execute({
    action: "read_status",
    input: {},
    run: async () => {
      offlineRan = true; // must never happen
      return { status: "ok" };
    }
  });
  console.log("Missing sidecar:");
  print("Decision", miss.decision);
  print("Executed", miss.executed ? "YES" : "NO");
  print("Fail Closed", miss.failClosed ? "YES" : "NO");
  console.log("");
  pass = pass && miss.decision === "REFUSE" && miss.executed === false && offlineRan === false && miss.failClosed === true;

  console.log(`FINAL VERDICT: ${pass ? "PASS" : "FAIL"}`);
  if (!pass) process.exit(1);
}

main().catch((error) => {
  console.error(error);
  console.log("\nFINAL VERDICT: FAIL");
  process.exit(1);
});
