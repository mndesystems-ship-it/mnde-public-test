// Minimal MCP stdio client (newline-delimited JSON-RPC) for demos and tests.
//
// Not part of the product surface — it exists so the demo and test suite can
// drive the MNDe MCP server over a real stdio transport, exactly as a true MCP
// client (Claude Desktop, MCP Inspector) would.

import { spawn } from "node:child_process";

export function createStdioClient(command, args, env = {}, options = {}) {
  const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });

  const pending = new Map();
  let nextId = 1;
  let buffer = "";
  let stderr = "";
  let closed = false;

  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (message.id !== undefined && message.id !== null && pending.has(message.id)) {
        const { resolve, reject, timer } = pending.get(message.id);
        pending.delete(message.id);
        clearTimeout(timer);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
      } else if (typeof options.onUnmatched === "function") {
        // Upstream-initiated message (notification or server request): relay it.
        options.onUnmatched(message);
      }
    }
  });

  function rejectPending(error) {
    for (const [, { reject, timer }] of pending) {
      clearTimeout(timer);
      reject(error);
    }
    pending.clear();
  }

  child.on("error", (error) => {
    closed = true;
    rejectPending(error);
  });

  child.on("exit", (code) => {
    closed = true;
    const error = new Error(`process exited (code ${code})`);
    rejectPending(error);
  });

  function request(method, params, timeoutMs = 15_000) {
    if (closed) return Promise.reject(new Error("process is not running"));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error(`MCP request timed out: ${method}\n${stderr}`));
        }
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer });
      try {
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`, (error) => {
          if (!error || !pending.has(id)) return;
          pending.delete(id);
          clearTimeout(timer);
          reject(error);
        });
      } catch (error) {
        pending.delete(id);
        clearTimeout(timer);
        reject(error);
      }
    });
  }

  function notify(method, params) {
    if (closed) return;
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  async function stop() {
    if (closed) return;
    await new Promise((resolveStop) => {
      let finished = false;
      let terminateTimer;
      let forceTimer;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(terminateTimer);
        clearTimeout(forceTimer);
        resolveStop();
      };
      child.once("exit", finish);
      terminateTimer = setTimeout(() => {
        if (!closed) child.kill();
      }, 250);
      forceTimer = setTimeout(() => {
        if (!closed) child.kill();
        finish();
      }, 2000);
      terminateTimer.unref();
      forceTimer.unref();
      try {
        child.stdin.end();
      } catch {
        child.kill();
      }
    });
  }

  return { request, notify, stop, getStderr: () => stderr };
}
