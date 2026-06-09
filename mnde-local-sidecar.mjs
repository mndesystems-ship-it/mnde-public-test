import http from "node:http";
import cluster from "node:cluster";
import { existsSync, readFileSync } from "node:fs";
import { availableParallelism } from "node:os";
import { dirname, join, parse as parsePath } from "node:path";
import { PerformanceObserver, monitorEventLoopDelay, performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { canonicalizeJson, parseStrictJson } from "./shared/json.ts";
import { canonicalPolicyPayload, policyHash, verifyPolicySignature } from "./shared/policy-trust.ts";
import {
  verifySignedReceipt
} from "./audit/node_runtime.ts";
import {
  DeterministicWorkerPool,
  WORKER_POOL_SATURATED,
  WORKER_TIMEOUT
} from "./sidecar/deterministic_worker_pool.mjs";
import {
  ReceiptPersistenceQueue,
  RECEIPT_QUEUE_SATURATED,
  SYSTEM_SATURATED,
  SystemSaturationController,
  validateReceiptPersistenceConfig
} from "./sidecar/receipt_persistence_queue.mjs";
import {
  ERR_L0_TRANSPORT_SHED,
  ERR_SIDECAR_SATURATED,
  createAdmissionController,
  parseHttpLimitConfig,
  parseL0LimitConfig
} from "./sidecar/http_admission.mjs";
import { buildSidecarRefusalReceipt } from "./sidecar/refusal_receipt.mjs";
import {
  ERR_UNAUTHORIZED_ORIGIN,
  corsHeadersForOrigin,
  createRuntimeInput,
  isAllowedCorsOrigin
} from "./sidecar/runtime_request.mjs";
import { SocketRegistry } from "./sidecar/socket_registry.mjs";
import { ERR_RUNTIME_DEGRADED, ERR_RUNTIME_FATAL, RuntimeWatchdog } from "./sidecar/runtime_watchdog.mjs";
import {
  buildCapabilityObject,
  clampReceiptLimit,
  createAuditBundle,
  readRecentReceipts,
  replayRecentReceipts,
  validatePolicyDocument,
  verifyReceiptContract
} from "./sidecar/production_api.mjs";
import {
  appendAuthAuditEvent,
  authorizeAuthorityAction,
  parseAuthorityAssertion,
  refusalBody
} from "./sidecar/auth_authority.mjs";
import { replayReceiptDeterministically } from "./sidecar/replay_engine.mjs";

const HOST = "127.0.0.1";
const PORT = parseBindPort(process.env.MNDE_BIND_PORT, 8787);
const REPO_ROOT = dirname(fileURLToPath(import.meta.url));
let activePolicyPath = new URL("./mnde-release-package/sidecar-local/policy.v1.signed.json", import.meta.url);
const RECEIPT_LOG_PATH = process.env.MNDE_RECEIPT_LOG ?? join(process.cwd(), "hostile-verifier-proof-bundle", "receipts.jsonl");
const AUTH_AUDIT_LOG_PATH = process.env.MNDE_AUTH_AUDIT_LOG ?? join(process.cwd(), "auth-audit", "auth-events.jsonl");
const CLUSTER_MODE = process.env.MNDE_CLUSTER_MODE === "1";
const CLUSTER_SHARED_RECEIPT_LOG = process.env.MNDE_CLUSTER_SHARED_RECEIPT_LOG === "1";
const CLUSTER_WORKERS = Number.parseInt(process.env.MNDE_CLUSTER_WORKERS ?? String(availableParallelism()), 10);
const HTTP_LIMITS = parseHttpLimitConfig(process.env);
const L0_LIMITS = parseL0LimitConfig(process.env);
const MAX_INFLIGHT = Number.parseInt(process.env.MNDE_MAX_INFLIGHT ?? "128", 10);
const SHED_INFLIGHT = Number.parseInt(process.env.MNDE_SHED_INFLIGHT ?? "64", 10);
const MAX_EVENT_LOOP_LAG_MS = Number.parseInt(process.env.MNDE_MAX_EVENT_LOOP_LAG_MS ?? "80", 10);
const WORKER_POOL_SIZE = Number.parseInt(process.env.MNDE_WORKER_POOL_SIZE ?? String(Math.max(1, availableParallelism() - 1)), 10);
const WORKER_QUEUE_MAX_DEPTH = Number.parseInt(process.env.MNDE_WORKER_QUEUE_MAX_DEPTH ?? String(Math.max(1, WORKER_POOL_SIZE)), 10);
const WORKER_TASK_TIMEOUT_MS = Number.parseInt(process.env.MNDE_WORKER_TASK_TIMEOUT_MS ?? String(Math.max(100, HTTP_LIMITS.request_timeout_ms - 100)), 10);
const INLINE_REFUSAL_RECEIPTS = process.env.MNDE_INLINE_REFUSAL_RECEIPTS === "1";
const TEST_HARNESS_ENABLED = process.env.MNDE_TEST_HARNESS === "1";
const RECEIPT_DURABILITY_MODE = process.env.MNDE_RECEIPT_DURABILITY_MODE ?? "throughput";
const RECEIPT_QUEUE_CONFIG = validateReceiptPersistenceConfig({
  path: receiptPathForWorker(RECEIPT_LOG_PATH),
  durability_mode: RECEIPT_DURABILITY_MODE,
  max_items: Number.parseInt(process.env.MNDE_RECEIPT_QUEUE_MAX_ITEMS ?? "50000", 10),
  max_bytes: Number.parseInt(process.env.MNDE_RECEIPT_QUEUE_MAX_BYTES ?? String(256 * 1024 * 1024), 10),
  max_batch_size: Number.parseInt(process.env.MNDE_RECEIPT_BATCH_MAX_SIZE ?? "256", 10),
  max_batch_age_ms: Number.parseInt(process.env.MNDE_RECEIPT_BATCH_MAX_AGE_MS ?? "10", 10),
  flush_timeout_ms: Number.parseInt(process.env.MNDE_RECEIPT_FLUSH_TIMEOUT_MS ?? "2000", 10)
});
let policy = JSON.parse(readFileSync(activePolicyPath, "utf8"));
let policy_hash = policyHash(policy);
const receiptQueue = new ReceiptPersistenceQueue(RECEIPT_QUEUE_CONFIG);
const workerPool = new DeterministicWorkerPool({
  worker_count: WORKER_POOL_SIZE,
  max_queue_depth: WORKER_QUEUE_MAX_DEPTH,
  task_timeout_ms: WORKER_TASK_TIMEOUT_MS,
  worker_url: new URL("./sidecar/deterministic_worker.mjs", import.meta.url)
});

function parseBindPort(value, fallback) {
  const port = Number.parseInt(value ?? String(fallback), 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fallback;
  return port;
}
const saturationController = new SystemSaturationController({
  max_inflight: MAX_INFLIGHT,
  inflight_shed_threshold: Math.min(SHED_INFLIGHT, MAX_INFLIGHT),
  max_event_loop_lag_ms: MAX_EVENT_LOOP_LAG_MS,
  queue_high_watermark_items: Math.max(1, Math.floor(RECEIPT_QUEUE_CONFIG.max_items * 0.75)),
  queue_high_watermark_bytes: Math.max(1, Math.floor(RECEIPT_QUEUE_CONFIG.max_bytes * 0.75))
});
const admission = createAdmissionController(HTTP_LIMITS);
const socketRegistry = new SocketRegistry({
  idle_timeout_ms: Number.parseInt(process.env.MNDE_SOCKET_IDLE_TIMEOUT_MS ?? String(Math.max(250, serverKeepAliveTimeout() * 2)), 10),
  eviction_interval_ms: Number.parseInt(process.env.MNDE_SOCKET_EVICTION_INTERVAL_MS ?? "250", 10),
  shutdown_grace_ms: Number.parseInt(process.env.MNDE_SOCKET_SHUTDOWN_GRACE_MS ?? "500", 10)
});
const watchdog = new RuntimeWatchdog({
  interval_ms: Number.parseInt(process.env.MNDE_WATCHDOG_INTERVAL_MS ?? "250", 10),
  max_event_loop_lag_ms: Number.parseInt(process.env.MNDE_WATCHDOG_MAX_EVENT_LOOP_LAG_MS ?? String(Math.max(250, MAX_EVENT_LOOP_LAG_MS * 2)), 10),
  fatal_event_loop_lag_ms: Number.parseInt(process.env.MNDE_WATCHDOG_FATAL_EVENT_LOOP_LAG_MS ?? "2000", 10),
  max_open_sockets: Number.parseInt(process.env.MNDE_WATCHDOG_MAX_OPEN_SOCKETS ?? "256", 10),
  fatal_open_sockets: Number.parseInt(process.env.MNDE_WATCHDOG_FATAL_OPEN_SOCKETS ?? "1024", 10)
}, () => {
  const queueMetrics = receiptQueue.metrics();
  const socketMetrics = socketRegistry.metrics();
  return {
    open_sockets: socketMetrics.open,
    receipt_fail_closed: queueMetrics.fail_closed
  };
});
const eventLoopDelay = monitorEventLoopDelay({ resolution: 10 });
eventLoopDelay.enable();
let latestEventLoopLagMs = 0;
setInterval(() => {
  latestEventLoopLagMs = Math.max(0, Math.round(eventLoopDelay.percentile(99) / 1_000_000));
  eventLoopDelay.reset();
}, 500).unref();
let inflight = 0;
let l0ActiveConnections = 0;
const counters = {
  l0_shed_total: 0,
  l0_shed_destroy_total: 0,
  l0_shed_503_total: 0,
  l0_preparse_destroy_sheds: 0,
  l0_malformed_destroy_sheds: 0,
  l0_timeout_destroy_sheds: 0,
  l0_overload_503_sheds: 0,
  l0_connections_accepted_total: 0,
  l0_connections_closed_total: 0,
  completed_http_responses: 0,
  requests: 0,
  refused_overload: 0,
  flush_failures: 0,
  unsigned_allows_blocked: 0,
  refused_system_saturated: 0,
  refused_worker_pool_saturated: 0,
  refused_receipt_queue_saturated: 0,
  admission_refusals: 0,
  worker_refusals: 0,
  receipt_refusals: 0,
  saturation_inflight: 0,
  saturation_event_loop_lag: 0,
  saturation_receipt_queue_depth: 0,
  saturation_receipt_queue_bytes: 0,
  request_timeout_refusals: 0,
  browser_origin_requests: 0,
  watchdog_interventions: 0,
  malformed_receipt_lines: 0
};
const latencyTotals = {
  parse_ms: 0,
  preflight_ms: 0,
  orbit_ms: 0,
  arm_ms: 0,
  ramona_ms: 0,
  custody_ms: 0,
  canonicalize_ms: 0,
  receipt_build_ms: 0,
  signing_ms: 0,
  worker_queue_wait_ms: 0,
  worker_exec_ms: 0,
  receipt_enqueue_ms: 0,
  persistence_flush_ms: 0,
  response_serialize_ms: 0,
  response_flush_ms: 0,
  total_server_ms: 0,
  request_admission_wait_ms: 0,
  request_body_read_ms: 0,
  request_parse_ms: 0,
  event_loop_lag_ms: 0
};
const socketTimings = new WeakMap();

function serverKeepAliveTimeout() {
  return L0_LIMITS.enable ? L0_LIMITS.keepalive_timeout_ms : HTTP_LIMITS.keep_alive_timeout_ms;
}

function telemetrySafe(value) {
  if (typeof value === "number") return Number.isFinite(value) ? Math.round(value) : 0;
  if (Array.isArray(value)) return value.map((item) => telemetrySafe(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, telemetrySafe(item)]));
  }
  return value;
}

function ms(value = performance.now()) {
  return Math.max(0, Math.round(value));
}
const runtimeStats = {
  gc_count: 0,
  gc_pause_ms_total: 0,
  gc_pause_ms_max: 0,
  heap_used_bytes: 0,
  heap_total_bytes: 0,
  rss_bytes: 0
};
new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    const duration = Math.max(0, Math.round(entry.duration));
    runtimeStats.gc_count += 1;
    runtimeStats.gc_pause_ms_total += duration;
    runtimeStats.gc_pause_ms_max = Math.max(runtimeStats.gc_pause_ms_max, duration);
  }
}).observe({ entryTypes: ["gc"] });
setInterval(() => {
  const memory = process.memoryUsage();
  runtimeStats.heap_used_bytes = memory.heapUsed;
  runtimeStats.heap_total_bytes = memory.heapTotal;
  runtimeStats.rss_bytes = memory.rss;
}, 500).unref();

function receiptPathForWorker(basePath) {
  if (!cluster.isWorker || !CLUSTER_MODE || CLUSTER_SHARED_RECEIPT_LOG) return basePath;
  const parsed = parsePath(basePath);
  return join(parsed.dir, `${parsed.name}.worker-${cluster.worker.id}${parsed.ext || ".jsonl"}`);
}

if (cluster.isPrimary && CLUSTER_MODE) {
  for (let i = 0; i < CLUSTER_WORKERS; i += 1) cluster.fork();
  cluster.on("exit", (worker, code) => {
    process.stderr.write(`MNDe sidecar worker ${worker.id} exited with code ${code}; restarting fail-closed worker\n`);
    cluster.fork();
  });
} else {
  await receiptQueue.start();
  workerPool.start();
}
if (cluster.isPrimary && CLUSTER_MODE) {
  await new Promise(() => {});
}

function testTimingHeaders(timings) {
  if (!TEST_HARNESS_ENABLED) return {};
  return {
    "x-mnde-server-ms": String(Math.max(0, timings?.total_server_ms ?? 0)),
    "x-mnde-admission-ms": String(Math.max(0, timings?.request_admission_wait_ms ?? 0)),
    "x-mnde-parse-ms": String(Math.max(0, timings?.request_parse_ms ?? timings?.parse_ms ?? 0)),
    "x-mnde-worker-wait-ms": String(Math.max(0, timings?.worker_queue_wait_ms ?? 0)),
    "x-mnde-worker-exec-ms": String(Math.max(0, timings?.worker_exec_ms ?? 0)),
    "x-mnde-response-flush-ms": String(Math.max(0, timings?.response_flush_ms ?? 0)),
    "x-mnde-process-id": String(process.pid)
  };
}

const L0_503_BYTES = Buffer.from(`${canonicalizeJson({
  schema_version: "mnde.api.response.v1",
  decision: "REFUSE",
  reason_code: ERR_L0_TRANSPORT_SHED,
  request_hash: null,
  decision_hash: null,
  receipt: null,
  l0_transport_shed: true
})}\n`, "utf8");

function l0ShedDecision(req, res) {
  counters.l0_shed_total += 1;
  try {
    if (res.destroyed || req.socket?.destroyed) {
      counters.l0_shed_destroy_total += 1;
      counters.l0_malformed_destroy_sheds += 1;
      req.socket?.destroy();
      return true;
    }
    counters.l0_shed_503_total += 1;
    counters.l0_overload_503_sheds += 1;
    res.writeHead(503, {
      "cache-control": "no-store",
      "connection": "close",
      "content-length": L0_503_BYTES.byteLength,
      "content-type": "application/json; charset=utf-8"
    });
    res.shouldKeepAlive = false;
    res.end(L0_503_BYTES, () => {
      counters.completed_http_responses += 1;
    });
  } catch {
    counters.l0_shed_destroy_total += 1;
    counters.l0_malformed_destroy_sheds += 1;
    counters.l0_shed_503_total = Math.max(0, counters.l0_shed_503_total - 1);
    counters.l0_overload_503_sheds = Math.max(0, counters.l0_overload_503_sheds - 1);
    req.socket?.destroy();
  }
  return true;
}

function response(res, status, body, timings) {
  if (res.writableEnded || res.destroyed) return;
  const serializationStarted = performance.now();
  const bytes = Buffer.from(`${canonicalizeJson(body)}\n`, "utf8");
  if (timings) timings.response_serialize_ms = Math.max(0, Math.round(performance.now() - serializationStarted));
  res.writeHead(status, {
    ...corsHeadersForOrigin(res.req?.headers?.origin),
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "cache-control": "no-store",
    "connection": "close",
    "content-type": "application/json; charset=utf-8",
    "content-length": bytes.byteLength,
    ...testTimingHeaders(timings)
  });
  const writeStarted = performance.now();
  res.end(bytes, () => {
    counters.completed_http_responses += 1;
    if (timings) timings.response_flush_ms = Math.max(0, Math.round(performance.now() - writeStarted));
    res.req?.socket?.destroySoon?.();
  });
}

async function persistRefusal(reason_code, extra = {}, timings = {}) {
  const receipt = buildSidecarRefusalReceipt({
    raw_body: extra.raw_body ?? "",
    reason_code,
    policy_hash,
    policy_version: policy.policy_version,
    timings,
    request_id: extra.request_id ?? null,
    request_hash: extra.request_hash ?? null,
    decision_hash: extra.decision_hash ?? null
  });
  const queued = await receiptQueue.enqueue(receipt);
  if (!queued.ok) {
    counters.refused_overload += 1;
    counters.refused_receipt_queue_saturated += queued.reason_code === RECEIPT_QUEUE_SATURATED ? 1 : 0;
    counters.receipt_refusals += 1;
    return { ok: false, reason_code: queued.reason_code, receipt };
  }
  if (RECEIPT_QUEUE_CONFIG.durability_mode === "strict_audit") {
    await queued.durable;
  }
  return { ok: true, receipt };
}

async function fail(res, reason_code, status = 200, extra = {}, timings = {}) {
  const persisted = await persistRefusal(reason_code, extra, timings);
  const finalReason = persisted.ok ? reason_code : persisted.reason_code;
  const { raw_body: _rawBody, ...publicExtra } = extra;
  response(res, status, {
    schema_version: "mnde.api.response.v1",
    decision: "REFUSE",
    reason_code: finalReason,
    request_hash: persisted.receipt?.request_hash ?? extra.request_hash ?? null,
    decision_hash: persisted.receipt?.decision_output?.decision_hash ?? extra.decision_hash ?? null,
    receipt: null,
    receipt_persisted: persisted.ok,
    ...publicExtra
  }, timings);
}

function recordAdmissionRefusal(reason_code) {
  counters.refused_overload += 1;
  counters.admission_refusals += 1;
  if (reason_code === WORKER_POOL_SATURATED) {
    counters.refused_worker_pool_saturated += 1;
    counters.worker_refusals += 1;
  }
}

function readBody(req, timings) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      if (timings) timings.request_body_read_ms = Math.max(0, Math.round(performance.now() - started));
      fn(value);
    };
    req.on("data", (chunk) => {
      size += chunk.byteLength;
      if (size > HTTP_LIMITS.max_request_body_bytes) {
        req.pause();
        req.resume();
        finish(reject, new Error("ERR_BODY_TOO_LARGE"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(resolve, Buffer.concat(chunks).toString("utf8")));
    req.on("error", (error) => finish(reject, error));
  });
}

async function readStrictObject(req, timings) {
  const raw = await readBody(req, timings);
  const started = performance.now();
  const parsed = parseStrictJson(raw);
  timings.request_parse_ms = Math.max(0, Math.round(performance.now() - started));
  timings.parse_ms = timings.request_parse_ms;
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) {
    throw new Error(parsed.ok ? "ERR_REQUEST_SCHEMA_INVALID" : parsed.reason.toUpperCase());
  }
  return { value: parsed.value, raw };
}

function apiResponseFromReceipt(receipt) {
  const decision = receipt.decision_output;
  const body = {
    schema_version: "mnde.api.response.v1",
    decision: decision.decision,
    reason_code: decision.reason_code,
    request_hash: decision.request_hash,
    decision_hash: decision.decision_hash,
    total_cost_usd: decision.total_cost_usd,
    allowed_cost_usd: decision.allowed_cost_usd,
    prevented_cost_usd: decision.prevented_cost_usd,
    policy_version: decision.policy_version,
    policy_hash: decision.policy_hash
  };
  if (decision.decision === "ALLOW" || INLINE_REFUSAL_RECEIPTS) {
    body.receipt = receipt;
  } else {
    body.receipt_persisted = true;
  }
  return body;
}

function receiptFromInput(input) {
  return input?.receipt && typeof input.receipt === "object" ? input.receipt : input;
}

function isDecisionRoute(pathname) {
  return pathname === "/v1/decisions" || pathname === "/decide";
}

function authorityActionName(pathname) {
  if (pathname === "/policy/activate") return "policy.activate";
  if (pathname === "/audit/bundle") return "audit.bundle";
  if (pathname === "/replay/recent") return "replay.recent";
  if (pathname === "/receipts/verify" || pathname === "/verify") return "receipt.verify";
  return pathname;
}

function auditAuthority(pathname, authz, result, target = null, decision_hash = null, reason = null) {
  try {
    appendAuthAuditEvent(AUTH_AUDIT_LOG_PATH, {
      actor: authz.actor,
      action: authorityActionName(pathname),
      target,
      result,
      decision_hash,
      reason
    });
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event: "mnde.auth_audit_write_failed", error: error instanceof Error ? error.message : String(error) })}\n`);
  }
}

function authorizeRequest(req, pathname, target = null) {
  const authz = authorizeAuthorityAction(pathname, parseAuthorityAssertion(req.headers));
  if (!authz.ok) auditAuthority(pathname, authz, "REFUSE", target, null, authz.reason);
  return authz;
}

async function handleDecide(req, res) {
  const totalStarted = performance.now();
  const timings = {
    parse_ms: 0,
    preflight_ms: 0,
    orbit_ms: 0,
    arm_ms: 0,
    ramona_ms: 0,
    custody_ms: 0,
    canonicalize_ms: 0,
    receipt_build_ms: 0,
    signing_ms: 0,
    worker_queue_wait_ms: 0,
    worker_exec_ms: 0,
    receipt_enqueue_ms: 0,
    persistence_flush_ms: 0,
    response_serialize_ms: 0,
    response_flush_ms: 0,
    total_server_ms: 0,
    request_admission_wait_ms: 0,
    request_body_read_ms: 0,
    request_parse_ms: 0,
    active_requests: 0,
    active_sockets: 0,
    event_loop_lag_ms: latestEventLoopLagMs
  };
  const socketState = socketTimings.get(req.socket);
  timings.socket_accepted_ms = socketState?.accepted_at_ms ? ms(socketState.accepted_at_ms) : 0;
  timings.first_byte_ms = socketState?.first_byte_at_ms ? ms(socketState.first_byte_at_ms) : 0;
  timings.request_event_ms = ms(totalStarted);
  timings.pre_request_queue_delay_ms = socketState?.accepted_at_ms ? Math.max(0, Math.round(totalStarted - socketState.accepted_at_ms)) : 0;
  counters.requests += 1;
  if (req.headers.origin) counters.browser_origin_requests += 1;
  if (!watchdog.canAcceptDecisions()) {
    counters.watchdog_interventions += 1;
    watchdog.markIntervention();
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, watchdog.snapshot().fatal ? ERR_RUNTIME_FATAL : ERR_RUNTIME_DEGRADED, 200, { runtime_degraded: watchdog.snapshot() }, timings);
    return;
  }
  const socketLimit = admission.noteSocketRequest(req.socket);
  if (!socketLimit.ok) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, socketLimit.reason_code, 200, { saturation_signal: "socket_request_limit" }, timings);
    req.socket.destroySoon?.();
    return;
  }
  const admitted = admission.tryAcquireRequest();
  timings.request_admission_wait_ms = admitted.admission_wait_ms ?? 0;
  timings.slot_allocation_ms = ms();
  if (!admitted.ok) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, admitted.reason_code, 200, { saturation_signal: "active_requests" }, timings);
    return;
  }
  const admissionSnapshot = admission.snapshot();
  timings.active_requests = admissionSnapshot.active_requests;
  timings.active_sockets = admissionSnapshot.active_sockets;
  const queueMetricsAtStart = receiptQueue.metrics();
  const saturation = saturationController.shouldRefuse({
    inflight,
    event_loop_lag_ms: latestEventLoopLagMs,
    queue_depth: queueMetricsAtStart.queue_depth,
    queue_bytes: queueMetricsAtStart.queue_bytes
  });
  if (!saturation.ok) {
    counters.refused_overload += 1;
    counters.refused_system_saturated += 1;
    if (saturation.saturation_signal === "inflight") counters.saturation_inflight += 1;
    if (saturation.saturation_signal === "event_loop_lag") counters.saturation_event_loop_lag += 1;
    if (saturation.saturation_signal === "receipt_queue_depth") counters.saturation_receipt_queue_depth += 1;
    if (saturation.saturation_signal === "receipt_queue_bytes") counters.saturation_receipt_queue_bytes += 1;
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, SYSTEM_SATURATED, 200, { saturation_signal: saturation.saturation_signal }, timings);
    admitted.release();
    return;
  }
  inflight += 1;
  try {
    if (TEST_HARNESS_ENABLED && req.headers["x-mnde-custody-mode"] === "timeout") {
      const custodyStarted = performance.now();
      timings.custody_ms = Math.max(0, Math.round(performance.now() - custodyStarted));
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, "ERR_CUSTODY_SIGNER_TIMEOUT", 200, { timings }, timings);
      return;
    }
    const { value: request, raw } = await readStrictObject(req, timings);
    timings.body_read_complete_ms = ms();
    const runtimeInput = createRuntimeInput(request, policy);
    timings.execution_start_ms = ms();
    const submitted = workerPool.submit(canonicalizeJson(runtimeInput));
    if (!submitted.ok) {
      recordAdmissionRefusal(submitted.reason_code);
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, submitted.reason_code, 200, { saturation_signal: "worker_pool_queue", raw_body: raw }, timings);
      return;
    }
    const workerReply = await submitted.result;
    timings.execution_finish_ms = ms();
    timings.worker_queue_wait_ms = Math.max(0, Math.round(workerReply.queue_wait_ms ?? 0));
    timings.worker_exec_ms = Math.max(0, Math.round(workerReply.exec_ms ?? 0));
    Object.assign(timings, workerReply.timings ?? {});
    if (!workerReply.ok) {
      counters.worker_refusals += 1;
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, workerReply.reason_code, 200, { timings, raw_body: raw }, timings);
      return;
    }
    const result = workerReply.result;
    if ("parse_boundary" in result) {
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, result.reason_code, 200, {
        request_hash: result.request_hash,
        decision_hash: result.decision_hash,
        timings,
        raw_body: raw
      }, timings);
      return;
    }
    if (result.receipt.decision_output.decision === "ALLOW" && !result.receipt.signature && !result.receipt.verifiable_signature) {
      counters.unsigned_allows_blocked += 1;
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, "ERR_RECEIPT_SIGNATURE_INVALID", 200, { timings, raw_body: raw }, timings);
      return;
    }
    const queueStarted = performance.now();
    const queued = await receiptQueue.enqueue(result.receipt);
    timings.receipt_enqueue_ms = Math.max(0, Math.round(performance.now() - queueStarted));
    if (!queued.ok) {
      counters.refused_overload += 1;
      counters.refused_receipt_queue_saturated += queued.reason_code === RECEIPT_QUEUE_SATURATED ? 1 : 0;
      counters.receipt_refusals += 1;
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, queued.reason_code, 200, {
        request_hash: result.receipt.request_hash,
        decision_hash: result.receipt.decision_output.decision_hash,
        timings,
        raw_body: raw
      }, timings);
      return;
    }
    if (RECEIPT_QUEUE_CONFIG.durability_mode === "strict_audit") {
      const durable = await queued.durable;
      timings.persistence_flush_ms = durable.persistence_flush_ms ?? 0;
    }
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    response(res, 200, { ...apiResponseFromReceipt(result.receipt), timings }, timings);
  } catch (error) {
    if (error?.message?.startsWith("ERR_RECEIPT_FLUSH_FAILED")) counters.flush_failures += 1;
    if (error?.message === WORKER_TIMEOUT) counters.request_timeout_refusals += 1;
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, error.message?.startsWith("ERR_") ? error.message : "ERR_RUNTIME_ERROR", 400, {}, timings);
  } finally {
    inflight -= 1;
    admitted.release();
  }
}

async function handleVerify(req, res) {
  const authz = authorizeRequest(req, new URL(req.url, `http://${HOST}:${PORT}`).pathname);
  if (!authz.ok) {
    response(res, 403, refusalBody(authz.reason, authz.actor, "receipt.verify"));
    return;
  }
  try {
    const input = await readStrictObject(req, {});
    const result = verifyReceiptContract(input.value, verifySignedReceipt);
    auditAuthority(new URL(req.url, `http://${HOST}:${PORT}`).pathname, authz, result.status === "VALID" ? "ALLOW" : "REFUSE", result.receipt_id, result.decision_hash, result.reason);
    response(res, 200, result);
  } catch (error) {
    auditAuthority(new URL(req.url, `http://${HOST}:${PORT}`).pathname, authz, "REFUSE", "receipt.verify", null, "ERR_RECEIPT_VERIFY_FAILED");
    response(res, 200, {
      status: "INVALID",
      receipt_id: null,
      request_hash: null,
      decision_hash: null,
      policy_hash: null,
      reason: error.message?.startsWith("ERR_") ? error.message : "ERR_RECEIPT_VERIFY_FAILED"
    });
  }
}

function currentPolicyResponse() {
  return {
    status: "ACTIVE",
    policy: policy.policy_version,
    policy_hash,
    reason: null
  };
}

function verifyPolicyTrust(publicKeyHex, policyDocument, signatureHex) {
  return verifyPolicySignature(publicKeyHex, canonicalPolicyPayload(policyDocument), signatureHex);
}

async function handlePolicyActivate(req, res) {
  const authz = authorizeRequest(req, "/policy/activate");
  if (!authz.ok) {
    response(res, 403, refusalBody(authz.reason, authz.actor, "policy.activate"));
    return;
  }
  try {
    const input = await readStrictObject(req, {});
    const policyPath = input.value?.policy_path;
    if (typeof policyPath !== "string" || !policyPath.trim()) {
      auditAuthority("/policy/activate", authz, "REFUSE", "missing policy path", null, "policy_path is required");
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: "policy_path is required" });
      return;
    }
    if (!existsSync(policyPath)) {
      auditAuthority("/policy/activate", authz, "REFUSE", policyPath, null, "policy file does not exist");
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: "policy file does not exist" });
      return;
    }
    const candidate = JSON.parse(readFileSync(policyPath, "utf8"));
    const validation = validatePolicyDocument(candidate, verifyPolicyTrust);
    if (!validation.ok) {
      auditAuthority("/policy/activate", authz, "REFUSE", policyPath, null, validation.reason);
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: validation.reason });
      return;
    }
    policy = candidate;
    policy_hash = policyHash(policy);
    activePolicyPath = policyPath;
    auditAuthority("/policy/activate", authz, "ALLOW", policyPath, policy_hash, null);
    response(res, 200, currentPolicyResponse());
  } catch (error) {
    auditAuthority("/policy/activate", authz, "REFUSE", "policy.activate", null, error instanceof Error ? error.message : "policy activation failed");
    response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: error instanceof Error ? error.message : "policy activation failed" });
  }
}

function recentReceiptsForApi(url) {
  const limit = clampReceiptLimit(url.searchParams.get("limit"));
  return readRecentReceipts(RECEIPT_LOG_PATH, limit, (warning) => {
    counters.malformed_receipt_lines += 1;
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event: "mnde.receipt_history_malformed", ...warning })}\n`);
  });
}

function replayRecentForApi(limit) {
  return replayRecentReceipts(RECEIPT_LOG_PATH, limit, verifySignedReceipt, replayReceiptDeterministically);
}

function readinessSnapshot() {
  const queueMetrics = receiptQueue.metrics();
  const workerMetrics = workerPool.metrics();
  const watchdogState = watchdog.snapshot();
  return {
    ok: !queueMetrics.fail_closed && !watchdogState.fatal,
    degraded: queueMetrics.fail_closed || watchdogState.degraded,
    degraded_reason: queueMetrics.fail_closed_reason ?? watchdogState.degraded_reason,
    active_policy_version: policy.policy_version,
    policy_hash,
    worker_id: cluster.worker?.id ?? 0,
    inflight,
    event_loop_lag_ms: latestEventLoopLagMs,
    receipt_queue: telemetrySafe(queueMetrics),
    worker_pool: telemetrySafe(workerMetrics),
    watchdog: telemetrySafe(watchdogState),
    durability_mode: RECEIPT_QUEUE_CONFIG.durability_mode
  };
}

function auditBundleForApi() {
  const queueMetrics = receiptQueue.metrics();
  const workerMetrics = workerPool.metrics();
  return createAuditBundle({
    outputRoot: join(process.cwd(), "audit-bundles"),
    recentReceipts: readRecentReceipts(RECEIPT_LOG_PATH, 100, () => {
      counters.malformed_receipt_lines += 1;
    }),
    replaySummary: replayRecentForApi(100),
    metricsText: metricsText(queueMetrics, workerMetrics),
    readySnapshot: readinessSnapshot(),
    policySummary: currentPolicyResponse()
  });
}

async function handleReplay(req, res) {
  try {
    const input = await readStrictObject(req, {});
    const receipt = receiptFromInput(input.value);
    if (!verifySignedReceipt(receipt)) {
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt?.request_hash ?? null,
        original: receipt?.decision_output ?? null,
        replayed: null,
        drift: true,
        mismatches: [{ field: "signature", original: "valid", replayed: "invalid" }]
      });
      return;
    }
    const submitted = workerPool.submit(receipt.canonical_request);
    if (!submitted.ok) {
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt.request_hash,
        original: receipt.decision_output,
        replayed: null,
        drift: true,
        mismatches: [{ field: "worker_pool", original: "available", replayed: submitted.reason_code }]
      });
      return;
    }
    const workerReply = await submitted.result;
    if (!workerReply.ok) {
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt.request_hash,
        original: receipt.decision_output,
        replayed: null,
        drift: true,
        mismatches: [{ field: "worker_pool", original: "ok", replayed: workerReply.reason_code }]
      });
      return;
    }
    const replay = workerReply.result;
    if ("parse_boundary" in replay) {
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt.request_hash,
        original: receipt.decision_output,
        replayed: null,
        drift: true,
        mismatches: [{ field: "replay", original: receipt.decision_output.reason_code, replayed: replay.reason_code }]
      });
      return;
    }
    const original = receipt.decision_output;
    const replayed = replay.receipt.decision_output;
    const mismatches = Object.keys(original)
      .filter((key) => original[key] !== replayed[key])
      .map((key) => ({ field: key, original: original[key], replayed: replayed[key] }));
    response(res, 200, {
      schema_version: "mnde.receipt_replay.v1",
      request_hash: receipt.request_hash,
      original,
      replayed,
      drift: mismatches.length > 0,
      mismatches
    });
  } catch (error) {
    response(res, 400, {
      schema_version: "mnde.receipt_replay.v1",
      drift: true,
      reason_code: error.message?.startsWith("ERR_") ? error.message : "ERR_REPLAY_FAILED",
      mismatches: []
    });
  }
}

const server = http.createServer(async (req, res) => {
  watchdog.heartbeat("request");
  socketRegistry.markRequest(req.socket);
  const pathname = new URL(req.url, `http://${HOST}:${PORT}`).pathname;
  if (!isAllowedCorsOrigin(req.headers.origin)) {
    response(res, 403, {
      schema_version: "mnde.api.response.v1",
      decision: "REFUSE",
      reason_code: ERR_UNAUTHORIZED_ORIGIN,
      request_hash: null,
      decision_hash: null,
      receipt: null
    });
    return;
  }
  if (req.method === "OPTIONS") {
    response(res, 204, {});
    return;
  }
  if (req.method === "GET" && pathname === "/healthz") {
    watchdog.heartbeat("healthz");
    response(res, 200, {
      ok: true,
      degraded: watchdog.snapshot().degraded,
      fatal: watchdog.snapshot().fatal,
      event_loop_lag_ms: latestEventLoopLagMs,
      worker_id: cluster.worker?.id ?? 0
    });
    return;
  }
  if (req.method === "GET" && pathname === "/identity") {
    response(res, 200, {
      schema_version: "mnde.sidecar_identity.v1",
      repo_root: REPO_ROOT,
      process_id: process.pid,
      policy_hash,
      policy_version: policy.policy_version,
      started_at_ms: Math.round(performance.timeOrigin)
    });
    return;
  }
  if (req.method === "GET" && pathname === "/readyz") {
    const socketMetrics = socketRegistry.metrics();
    response(res, 200, {
      ...readinessSnapshot(),
      max_inflight: MAX_INFLIGHT,
      shed_inflight: Math.min(SHED_INFLIGHT, MAX_INFLIGHT),
      sockets: telemetrySafe(socketMetrics),
    });
    return;
  }
  if (req.method === "GET" && pathname === "/metrics") {
    const queueMetrics = receiptQueue.metrics();
    const workerMetrics = workerPool.metrics();
    const body = Buffer.from(metricsText(queueMetrics, workerMetrics), "utf8");
    res.writeHead(200, {
      ...corsHeadersForOrigin(req.headers.origin),
      "cache-control": "no-store",
      "connection": "close",
      "content-length": body.byteLength,
      "content-type": "text/plain; version=0.0.4; charset=utf-8"
    });
    res.end(body);
    return;
  }
  if (req.method === "POST" && isDecisionRoute(pathname)) {
    if (L0_LIMITS.enable && l0ActiveConnections > L0_LIMITS.max_connections) {
      l0ShedDecision(req, res);
      return;
    }
    await handleDecide(req, res);
    return;
  }
  if (req.method === "GET" && pathname === "/receipts/recent") {
    response(res, 200, recentReceiptsForApi(new URL(req.url, `http://${HOST}:${PORT}`)));
    return;
  }
  if (req.method === "POST" && (pathname === "/verify" || pathname === "/receipts/verify")) {
    await handleVerify(req, res);
    return;
  }
  if (req.method === "POST" && pathname === "/replay/recent") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, refusalBody(authz.reason, authz.actor, "replay.recent"));
      return;
    }
    try {
      const input = await readStrictObject(req, {});
      const result = replayRecentForApi(input.value?.limit);
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", `limit:${input.value?.limit ?? 100}`, result.policy_hash, result.status);
      response(res, 200, result);
    } catch {
      const result = replayRecentForApi(100);
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", "limit:100", result.policy_hash, result.status);
      response(res, 200, result);
    }
    return;
  }
  if (req.method === "POST" && pathname === "/replay") {
    await handleReplay(req, res);
    return;
  }
  if (req.method === "GET" && pathname === "/policy/current") {
    response(res, 200, currentPolicyResponse());
    return;
  }
  if (req.method === "POST" && pathname === "/policy/activate") {
    await handlePolicyActivate(req, res);
    return;
  }
  if (req.method === "POST" && pathname === "/audit/bundle") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, refusalBody(authz.reason, authz.actor, "audit.bundle"));
      return;
    }
    try {
      const result = auditBundleForApi();
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", result.bundle_path, null, result.reason);
      response(res, 200, result);
    } catch (error) {
      auditAuthority(pathname, authz, "REFUSE", "audit.bundle", null, error instanceof Error ? error.message : "audit bundle failed");
      response(res, 200, { status: "FAIL", bundle_path: null, created_at: new Date().toISOString(), files: [], reason: error instanceof Error ? error.message : "audit bundle failed" });
    }
    return;
  }
  if (req.method === "GET" && pathname === "/capabilities") {
    response(res, 200, buildCapabilityObject({
      health: true,
      ready: true,
      metrics: true,
      receipts_recent: true,
      receipt_verify: true,
      replay_recent: true,
      policy_activation: true,
      audit_bundle: true
    }));
    return;
  }
  await fail(res, "ERR_NOT_FOUND", 404);
});
server.on("connection", (socket) => {
  socket.on("error", () => {});
  const socketAdmission = admission.tryAcquireSocket(socket);
  if (!socketAdmission.ok) {
    counters.admission_refusals += 1;
    counters.refused_overload += 1;
    socket.destroy();
    return;
  }
  const socketState = socketRegistry.track(socket);
  l0ActiveConnections += 1;
  let l0Closed = false;
  const recordL0Close = () => {
    if (l0Closed) return;
    l0Closed = true;
    l0ActiveConnections = Math.max(0, l0ActiveConnections - 1);
    counters.l0_connections_closed_total += 1;
    socketAdmission.release();
    const state = socketTimings.get(socket);
    if (state) state.close_at_ms = performance.now();
  };
  socket.on("close", recordL0Close);
  socketTimings.set(socket, {
    accepted_at_ms: socketState.opened_at_ms,
    first_byte_at_ms: 0,
    close_at_ms: 0
  });
  counters.l0_connections_accepted_total += 1;
  socket.prependOnceListener("data", () => {
    const state = socketTimings.get(socket);
    if (state && state.first_byte_at_ms === 0) state.first_byte_at_ms = performance.now();
  });
});
server.on("clientError", (_error, socket) => {
  counters.l0_shed_total += 1;
  counters.l0_shed_destroy_total += 1;
  counters.l0_malformed_destroy_sheds += 1;
  socket.destroy();
});
server.on("timeout", (socket) => {
  counters.l0_shed_total += 1;
  counters.l0_shed_destroy_total += 1;
  counters.l0_timeout_destroy_sheds += 1;
  socket.destroy();
});
server.maxRequestsPerSocket = HTTP_LIMITS.max_requests_per_socket;
server.maxHeadersCount = 64;
server.maxConnections = L0_LIMITS.enable ? L0_LIMITS.hybrid_503_connections : Number.MAX_SAFE_INTEGER;
server.keepAliveTimeout = L0_LIMITS.enable ? L0_LIMITS.keepalive_timeout_ms : HTTP_LIMITS.keep_alive_timeout_ms;
server.headersTimeout = L0_LIMITS.enable ? L0_LIMITS.headers_timeout_ms : HTTP_LIMITS.headers_timeout_ms;
server.requestTimeout = HTTP_LIMITS.request_timeout_ms;
server.timeout = HTTP_LIMITS.request_timeout_ms;

server.listen(PORT, HOST, L0_LIMITS.enable ? L0_LIMITS.backlog : Number.parseInt(process.env.MNDE_LISTEN_BACKLOG ?? "4096", 10), () => {
  socketRegistry.start();
  watchdog.start();
  process.stdout.write(`MNDe local sidecar listening on http://${HOST}:${PORT} worker=${cluster.worker?.id ?? 0} durability=${RECEIPT_QUEUE_CONFIG.durability_mode}\n`);
});

function recordTimings(timings) {
  for (const key of Object.keys(latencyTotals)) {
    latencyTotals[key] += timings[key] ?? 0;
  }
}

function metricLine(name, value) {
  return `${name} ${Number.isFinite(value) ? value : 0}\n`;
}

function metricsText(queueMetrics, workerMetrics) {
  const completed = Math.max(1, counters.requests);
  let out = "# TYPE mnde_local_demo_info gauge\nmnde_local_demo_info 1\n";
  out += metricLine("mnde_sidecar_inflight", inflight);
  out += metricLine("mnde_l0_enabled", L0_LIMITS.enable ? 1 : 0);
  out += metricLine("mnde_l0_max_connections", L0_LIMITS.max_connections);
  out += metricLine("mnde_l0_hybrid_503_connections", L0_LIMITS.hybrid_503_connections);
  out += metricLine("mnde_l0_active_connections", l0ActiveConnections);
  out += metricLine("mnde_l0_backlog", L0_LIMITS.backlog);
  out += metricLine("mnde_l0_shed_total", counters.l0_shed_total);
  out += metricLine("mnde_l0_shed_destroy_total", counters.l0_shed_destroy_total);
  out += metricLine("mnde_l0_shed_503_total", counters.l0_shed_503_total);
  out += metricLine("mnde_l0_preparse_destroy_sheds", counters.l0_preparse_destroy_sheds);
  out += metricLine("mnde_l0_malformed_destroy_sheds", counters.l0_malformed_destroy_sheds);
  out += metricLine("mnde_l0_timeout_destroy_sheds", counters.l0_timeout_destroy_sheds);
  out += metricLine("mnde_l0_overload_503_sheds", counters.l0_overload_503_sheds);
  out += metricLine("mnde_l0_connections_accepted_total", counters.l0_connections_accepted_total);
  out += metricLine("mnde_l0_connections_closed_total", counters.l0_connections_closed_total);
  out += metricLine("mnde_sidecar_accepted_requests", counters.requests);
  out += metricLine("mnde_sidecar_completed_http_responses", counters.completed_http_responses);
  const admissionSnapshot = admission.snapshot();
  out += metricLine("mnde_sidecar_active_requests", admissionSnapshot.active_requests);
  out += metricLine("mnde_sidecar_active_sockets", admissionSnapshot.active_sockets);
  out += metricLine("mnde_sidecar_max_inflight", MAX_INFLIGHT);
  out += metricLine("mnde_sidecar_shed_inflight", Math.min(SHED_INFLIGHT, MAX_INFLIGHT));
  out += metricLine("mnde_event_loop_lag_p99_ms", latestEventLoopLagMs);
  out += metricLine("mnde_sidecar_requests_total", counters.requests);
  out += metricLine("mnde_sidecar_refused_overload_total", counters.refused_overload);
  out += metricLine("mnde_sidecar_refused_by_admission_total", admissionSnapshot.refused_by_admission_total);
  out += metricLine("mnde_sidecar_refused_by_worker_pool_total", counters.refused_worker_pool_saturated);
  out += metricLine("mnde_sidecar_refused_by_receipt_queue_total", counters.refused_receipt_queue_saturated);
  out += metricLine("mnde_sidecar_admission_refusals_total", counters.admission_refusals);
  out += metricLine("mnde_sidecar_worker_refusals_total", counters.worker_refusals);
  out += metricLine("mnde_sidecar_refused_worker_pool_saturated_total", counters.refused_worker_pool_saturated);
  out += metricLine("mnde_sidecar_refused_system_saturated_total", counters.refused_system_saturated);
  out += metricLine("mnde_sidecar_saturation_inflight_total", counters.saturation_inflight);
  out += metricLine("mnde_sidecar_saturation_event_loop_lag_total", counters.saturation_event_loop_lag);
  out += metricLine("mnde_sidecar_saturation_receipt_queue_depth_total", counters.saturation_receipt_queue_depth);
  out += metricLine("mnde_sidecar_saturation_receipt_queue_bytes_total", counters.saturation_receipt_queue_bytes);
  out += metricLine("mnde_sidecar_unsigned_allows_blocked_total", counters.unsigned_allows_blocked);
  out += metricLine("mnde_sidecar_request_timeout_refusals_total", counters.request_timeout_refusals);
  out += metricLine("mnde_sidecar_browser_origin_requests_total", counters.browser_origin_requests);
  out += metricLine("mnde_watchdog_interventions_total", counters.watchdog_interventions);
  out += metricLine("mnde_receipt_history_malformed_lines_total", counters.malformed_receipt_lines);
  const socketMetrics = socketRegistry.metrics();
  out += metricLine("mnde_open_sockets", socketMetrics.open);
  out += metricLine("mnde_idle_sockets", socketMetrics.idle);
  out += metricLine("mnde_idle_sockets_destroyed_total", socketMetrics.idle_destroyed);
  const watchdogState = watchdog.snapshot();
  out += metricLine("mnde_runtime_degraded", watchdogState.degraded ? 1 : 0);
  out += metricLine("mnde_runtime_fatal", watchdogState.fatal ? 1 : 0);
  out += metricLine("mnde_watchdog_event_loop_lag_ms", watchdogState.event_loop_lag_ms);
  out += metricLine("mnde_worker_timeouts_total", workerMetrics.timeout_count ?? 0);
  out += metricLine("mnde_worker_restarts_total", workerMetrics.restart_count ?? 0);
  out += metricLine("mnde_receipt_queue_depth", queueMetrics.queue_depth);
  out += metricLine("mnde_receipt_queue_bytes", queueMetrics.queue_bytes);
  out += metricLine("mnde_receipt_queue_saturated_total", queueMetrics.saturated);
  out += metricLine("mnde_receipt_flush_failures_total", queueMetrics.flush_failures);
  out += metricLine("mnde_receipt_flush_timeouts_total", queueMetrics.flush_timeouts ?? 0);
  out += metricLine("mnde_receipt_flush_last_ms", queueMetrics.last_flush_ms);
  out += metricLine("mnde_receipt_flush_count", queueMetrics.flush_count);
  out += metricLine("mnde_receipt_flushed_receipts_total", queueMetrics.flushed_receipts);
  out += metricLine("mnde_receipt_flush_avg_batch_size", queueMetrics.flush_count === 0 ? 0 : Math.round(queueMetrics.flushed_receipts / queueMetrics.flush_count));
  out += metricLine("mnde_worker_queue_depth", workerMetrics.queue_depth);
  out += metricLine("mnde_worker_queue_wait_ms", workerMetrics.queue_wait_ms_avg);
  out += metricLine("mnde_worker_queue_wait_ms_max", workerMetrics.queue_wait_ms_max);
  out += metricLine("mnde_worker_exec_ms", workerMetrics.exec_ms_avg);
  out += metricLine("mnde_worker_exec_ms_max", workerMetrics.exec_ms_max);
  out += metricLine("mnde_worker_busy_ratio", workerMetrics.busy_ratio);
  out += metricLine("mnde_worker_refusals_total", workerMetrics.refused);
  for (const worker of workerMetrics.workers) {
    out += metricLine(`mnde_worker_${worker.worker_id}_throughput_total`, worker.throughput);
  }
  out += metricLine("mnde_gc_count_total", runtimeStats.gc_count);
  out += metricLine("mnde_gc_pause_ms_total", runtimeStats.gc_pause_ms_total);
  out += metricLine("mnde_gc_pause_ms_max", runtimeStats.gc_pause_ms_max);
  out += metricLine("mnde_heap_used_bytes", runtimeStats.heap_used_bytes);
  out += metricLine("mnde_heap_total_bytes", runtimeStats.heap_total_bytes);
  out += metricLine("mnde_rss_bytes", runtimeStats.rss_bytes);
  for (const [key, total] of Object.entries(latencyTotals)) {
    out += metricLine(`mnde_latency_avg_${key}`, total / completed);
  }
  return out;
}

async function shutdown() {
  watchdog.stop();
  server.close();
  await receiptQueue.shutdown();
  await workerPool.shutdown();
  await socketRegistry.shutdown();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
