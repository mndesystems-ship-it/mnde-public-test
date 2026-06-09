import { parentPort, workerData } from "node:worker_threads";
import { performance } from "node:perf_hooks";
import { executeDeterministicPipeline, resetRuntimeState } from "../audit/node_runtime.ts";

parentPort.on("message", (message) => {
  const started = performance.now();
  const timings = {};
  try {
    resetRuntimeState();
    const result = executeDeterministicPipeline(message.raw_input, { timings });
    parentPort.postMessage({
      ok: true,
      task_id: message.task_id,
      worker_id: workerData.worker_id,
      result,
      timings,
      exec_ms: Math.max(0, Math.round(performance.now() - started))
    });
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      task_id: message.task_id,
      worker_id: workerData.worker_id,
      reason_code: error.message?.startsWith("ERR_") ? error.message : "ERR_RUNTIME_ERROR",
      exec_ms: Math.max(0, Math.round(performance.now() - started))
    });
  }
});
