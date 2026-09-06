#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import process from "node:process";
import { decodeGuardRunnerPlan, revalidateGuardRunnerPlan } from "./catalog-core.mjs";
import {
  BASE_CHILD_ENVIRONMENT,
  MARKER_ENVIRONMENT,
  buildStrictServerEnvironment
} from "./guarded-runtime.mjs";
import { BoundedJSONLineDecoder, MAX_CLIENT_FRAME_BYTES, MCPWireGuard } from "./wire-guard.mjs";

const CONTROL_ENVIRONMENT = Object.freeze([
  "LOCAL_HARNESS_STRICT_LOCAL",
  "LOCAL_HARNESS_WORKSPACE_ROOTS",
  "LOCAL_HARNESS_READONLY_ROOTS",
  "LOCAL_HARNESS_SANDBOX_TEMP"
]);
// macOS inserts this CoreFoundation locale hint after execve even when the
// caller supplied an exact environment. It is tolerated only in the guard and
// is not copied into the actual MCP server environment.
const PLATFORM_INJECTED_ENVIRONMENT = Object.freeze(["__CF_USER_TEXT_ENCODING"]);
const STDERR_BUDGET = 1024 * 1024;
const TERMINATION_GRACE_MS = 1500;

function stop(message, code = 125) {
  const error = new Error(message);
  error.exitCode = code;
  throw error;
}

function parseSingleRoot(value) {
  let decoded;
  try {
    decoded = JSON.parse(value);
  } catch {
    stop("guard workspace roots are invalid");
  }
  if (!Array.isArray(decoded) || decoded.length !== 1 || typeof decoded[0] !== "string") {
    stop("guard workspace roots must name exactly one project");
  }
  return decoded[0];
}

function assertBootstrapContract(plan, environment) {
  if (environment.LOCAL_HARNESS_MCP_GUARD_CHILD !== "1") stop("guard-child marker is missing");
  const markerRoot = parseSingleRoot(environment.LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS);
  if (markerRoot !== plan.project.canonicalPath) stop("guard-child project marker does not match the activation plan");
  if (environment.LOCAL_HARNESS_STRICT_LOCAL !== "1") stop("guard child was not launched in Strict Local mode");
  if (environment.LOCAL_HARNESS_WORKSPACE_ROOTS !== JSON.stringify([plan.project.canonicalPath])) {
    stop("native sandbox project roots do not match the activation plan");
  }
  if (environment.LOCAL_HARNESS_READONLY_ROOTS !== "[]") stop("native sandbox unexpectedly exposed extra read-only roots");
  if (environment.LOCAL_HARNESS_SANDBOX_TEMP !== environment.LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP) {
    stop("native sandbox temp root does not match the guard marker");
  }
  const allowed = new Set([
    ...BASE_CHILD_ENVIRONMENT,
    ...MARKER_ENVIRONMENT,
    ...CONTROL_ENVIRONMENT,
    ...PLATFORM_INJECTED_ENVIRONMENT,
    ...plan.credentialVariables
  ]);
  for (const key of Object.keys(environment)) {
    if (!allowed.has(key)) stop(`native preloader left unexpected environment variable ${key}`);
  }
}

function safeDiagnostic(value) {
  return String(value ?? "guard failure")
    .replace(/[\0\r\n\t]/g, " ")
    .slice(0, 512);
}

let plan;
let serverEnvironment;
try {
  const encodedPlan = process.env.LOCAL_HARNESS_MCP_GUARD_PLAN;
  plan = decodeGuardRunnerPlan(encodedPlan);
  assertBootstrapContract(plan, process.env);
  if (realpathSync(process.cwd()) !== plan.workingDirectory) stop("guard child working directory changed");
  revalidateGuardRunnerPlan(plan);
  serverEnvironment = buildStrictServerEnvironment(process.env, plan.credentialVariables);
} catch (error) {
  process.stderr.write(`mcp-stdio-guard: ${safeDiagnostic(error?.message)}\n`);
  process.exit(125);
}

for (const name of [...MARKER_ENVIRONMENT, ...CONTROL_ENVIRONMENT]) delete process.env[name];

const wire = new MCPWireGuard(plan.limits);
const clientDecoder = new BoundedJSONLineDecoder(MAX_CLIENT_FRAME_BYTES);
const serverDecoder = new BoundedJSONLineDecoder(wire.maximumServerFrameBytes);
const callTimers = new Map();
let startupTimer;
let terminationTimer;
let stderrBytes = 0;
let stopping = false;
let childClosed = false;
let finalExitCode = 0;

const child = spawn(plan.command, plan.arguments, {
  cwd: plan.workingDirectory,
  env: serverEnvironment,
  stdio: ["pipe", "pipe", "pipe"],
  shell: false,
  windowsHide: true,
  detached: process.platform !== "win32"
});

function clearTimers() {
  if (startupTimer !== undefined) clearTimeout(startupTimer);
  startupTimer = undefined;
  if (terminationTimer !== undefined) clearTimeout(terminationTimer);
  terminationTimer = undefined;
  for (const timer of callTimers.values()) clearTimeout(timer);
  callTimers.clear();
}

function signalProcessTree(signal) {
  if (!child.pid || childClosed) return;
  try {
    if (process.platform !== "win32") process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch {}
  }
}

function terminate(reason, exitCode = 70) {
  if (stopping) return;
  stopping = true;
  finalExitCode = exitCode;
  if (exitCode !== 0) process.stderr.write(`mcp-stdio-guard(${plan.serverName}): ${safeDiagnostic(reason)}\n`);
  if (startupTimer !== undefined) clearTimeout(startupTimer);
  startupTimer = undefined;
  for (const timer of callTimers.values()) clearTimeout(timer);
  callTimers.clear();
  try { process.stdin.pause(); } catch {}
  try { child.stdin.end(); } catch {}
  signalProcessTree("SIGTERM");
  terminationTimer = setTimeout(() => signalProcessTree("SIGKILL"), TERMINATION_GRACE_MS);
  terminationTimer.unref();
}

function forward(destination, source, value) {
  if (stopping || destination.destroyed || destination.writableEnded) return;
  const bytes = `${JSON.stringify(value)}\n`;
  if (!destination.write(bytes)) {
    source.pause();
    destination.once("drain", () => {
      if (!stopping) source.resume();
    });
  }
}

function startToolTimer(key) {
  const timer = setTimeout(() => terminate("tool call exceeded its approved timeout"), plan.limits.toolCallTimeoutMilliseconds);
  timer.unref();
  callTimers.set(key, timer);
}

function settleToolTimer(key) {
  const timer = callTimers.get(key);
  if (timer !== undefined) clearTimeout(timer);
  callTimers.delete(key);
}

startupTimer = setTimeout(() => terminate("startup and initial tool discovery exceeded the approved timeout"), plan.limits.startupTimeoutMilliseconds);
startupTimer.unref();

process.stdin.on("data", (chunk) => {
  if (stopping) return;
  try {
    for (const frame of clientDecoder.append(chunk)) {
      const decision = wire.inspectClient(frame.value, frame.bytes);
      if (decision.method === "tools/call" && decision.requestKey !== undefined) startToolTimer(decision.requestKey);
      if (decision.cancelledToolCallKey !== undefined) {
        terminate("cancelled tool call forced server quiescence");
        return;
      }
      if (decision.forward) forward(child.stdin, process.stdin, frame.value);
    }
  } catch (error) {
    terminate(error?.message ?? "invalid client frame");
  }
});

process.stdin.on("end", () => {
  try { clientDecoder.finish(); } catch {}
  terminate("client transport closed", 0);
});
process.stdin.on("error", () => terminate("client transport failed"));

child.stdout.on("data", (chunk) => {
  if (stopping) return;
  try {
    for (const frame of serverDecoder.append(chunk)) {
      const decision = wire.inspectServer(frame.value, frame.bytes);
      if (decision.settledRequestKey !== undefined) settleToolTimer(decision.settledRequestKey);
      if (decision.startupComplete) {
        if (startupTimer !== undefined) clearTimeout(startupTimer);
        startupTimer = undefined;
      }
      if (decision.forward) forward(process.stdout, child.stdout, frame.value);
    }
  } catch (error) {
    terminate(error?.message ?? "invalid server frame");
  }
});
child.stdout.on("error", () => terminate("MCP server stdout failed"));

child.stderr.on("data", (chunk) => {
  stderrBytes += chunk.length;
  if (stderrBytes > STDERR_BUDGET) terminate("MCP server exceeded its stderr budget");
});
child.stderr.on("error", () => terminate("MCP server stderr failed"));

child.on("error", () => terminate("reviewed MCP executable could not be started"));
child.on("close", (code, signal) => {
  childClosed = true;
  try { serverDecoder.finish(); } catch (error) {
    if (!stopping) finalExitCode = 70;
  }
  clearTimers();
  if (!stopping && (signal !== null || code !== 0)) {
    process.stderr.write(`mcp-stdio-guard(${plan.serverName}): reviewed MCP server stopped unexpectedly\n`);
    finalExitCode = 70;
  }
  try { process.stdout.end(); } catch {}
  process.exitCode = finalExitCode;
});

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => terminate("guard received a shutdown signal", 0));
}
