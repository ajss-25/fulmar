import {
  closeSync,
  constants as fsConstants,
  fsyncSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

delete process.env.LOCAL_HARNESS_PERFORMANCE_PLUGIN;
const nativeTelemetryLockHelper = process.env.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER;
delete process.env.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER;
const automaticContinuationDiagnostics = process.env.LOCAL_HARNESS_AUTOMATIC_CONTINUATION_DIAGNOSTICS === "1";
delete process.env.LOCAL_HARNESS_AUTOMATIC_CONTINUATION_DIAGNOSTICS;

const SESSION_PREFIX = "local-harness-performance-v1";
const SESSION_PATTERN = /^local-harness-performance-v1-([a-z][a-z0-9]{0,31})-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const PROFILE_NAME_PATTERN = /^[a-z][a-z0-9]{0,31}$/;
const PROFILE_KEYS = Object.freeze(["maxOutputTokens"]);
const CONTEXT_ENFORCEMENT_KEYS = Object.freeze(["provider", "model", "contextWindowTokens"]);
const PROVIDER_LABEL_PATTERN = /^[^\u0000-\u001f\u007f]{1,256}$/u;
const MINIMUM_CONTEXT_TOKENS = 1_024;
const MAXIMUM_CONTEXT_TOKENS = 262_144;
const MINIMUM_OUTPUT_TOKENS = 256;
const MAXIMUM_OUTPUT_TOKENS = 65_536;
const MAXIMUM_PROFILES = 16;
const TELEMETRY_SCHEMA_VERSION = 1;
const TELEMETRY_FILE_NAME = "performance-telemetry.json";
const TELEMETRY_MAXIMUM_RECORDS = 100;
const TELEMETRY_MAXIMUM_PENDING_RECORDS = 128;
const TELEMETRY_MAXIMUM_AGE_MILLISECONDS = 24 * 60 * 60 * 1_000;
const TELEMETRY_MAXIMUM_FILE_BYTES = 256 * 1_024;
const TELEMETRY_MAXIMUM_LABEL_BYTES = 512;
const TELEMETRY_MAXIMUM_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1_000;
const THERMAL_POLICY_SCHEMA_VERSION = 1;
const THERMAL_POLICY_FILE_NAME = "thermal-workload-policy.json";
const THERMAL_POLICY_MAXIMUM_BYTES = 1_024;
const THERMAL_ECO_OUTPUT_TOKENS = 2_048;
const THERMAL_ECO_DELAY_MILLISECONDS = 5_000;
// A local model may spend its entire ordinary allowance reasoning after tools
// have already returned. At Qwen's measured on-device rate that can make a
// completed edit look hung for many minutes. Keep later calls in the same turn
// large enough to issue another compact tool call or a useful final answer,
// while the existing bounded continuation controller preserves unfinished work.
// Remote routes never receive this local-runtime tuning value.
const LOCAL_POST_TOOL_OUTPUT_TOKENS = 512;
const AUTOMATIC_CONTINUATION_MAXIMUM = 12;
const AUTOMATIC_CONTINUATION_SOURCE = "fulmar-automatic-continuation";
const AUTOMATIC_CONTINUATION_PROMPT = Object.freeze([{
  type: "text",
  text: "Continue the unfinished user task from exactly where the previous response stopped. Do not repeat completed work. If a tool call or file edit was cut off before execution, issue it again in full now. Keep working until the user's request is genuinely complete."
}]);
const AUTOMATIC_CONTINUATION_BUDGET_PROMPT = Object.freeze([{
  type: "text",
  text: "Fulmar has reached its bounded automatic-continuation safety budget. Do not start more tool work in this turn. Briefly tell the user what was completed, what remains, and the safest next action."
}]);
const THERMAL_POLICY_KEYS = Object.freeze([
  "schemaVersion", "mode", "ecoMaxOutputTokens", "minimumDelayMilliseconds"
]);
const TELEMETRY_RECORD_KEYS = Object.freeze([
  "schemaVersion", "id", "provider", "model", "profile", "startedAtMilliseconds",
  "completedAtMilliseconds", "firstTokenAtMilliseconds", "elapsedMilliseconds",
  "outputTokens", "outputTokenCountSource", "outcome", "failureCategory"
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isPlainObject(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function profileError(message) {
  return new Error(`Fulmar performance profile configuration is invalid: ${message}`);
}

/**
 * Decode and validate the native process boundary. Values are deliberately
 * bounded before they can influence an LLM request; malformed or partial
 * configuration prevents the reviewed runtime from starting.
 */
function decodePerformanceEnvironment(environment) {
  const rawCatalog = environment?.LOCAL_HARNESS_PERFORMANCE_PROFILES;
  const defaultProfile = environment?.LOCAL_HARNESS_PERFORMANCE_PROFILE;
  if (typeof rawCatalog !== "string" || rawCatalog.length === 0 || rawCatalog.length > 16_384) {
    throw profileError("the profile catalog is missing or too large");
  }
  if (typeof defaultProfile !== "string" || !PROFILE_NAME_PATTERN.test(defaultProfile)) {
    throw profileError("the selected profile is missing or malformed");
  }

  let decoded;
  try {
    decoded = JSON.parse(rawCatalog);
  } catch {
    throw profileError("the profile catalog is not valid JSON");
  }
  if (!isPlainObject(decoded)) throw profileError("the profile catalog must be an object");
  const entries = Object.entries(decoded);
  if (entries.length === 0 || entries.length > MAXIMUM_PROFILES) {
    throw profileError("the profile catalog has an invalid number of entries");
  }

  const profiles = Object.create(null);
  for (const [profile, value] of entries) {
    if (!PROFILE_NAME_PATTERN.test(profile)) throw profileError(`profile name ${JSON.stringify(profile)} is malformed`);
    if (!isPlainObject(value) || !exactKeys(value, PROFILE_KEYS)) {
      throw profileError(`profile ${JSON.stringify(profile)} has an unexpected schema`);
    }
    const maxOutputTokens = value.maxOutputTokens;
    if (!Number.isSafeInteger(maxOutputTokens)
      || maxOutputTokens < MINIMUM_OUTPUT_TOKENS
      || maxOutputTokens > MAXIMUM_OUTPUT_TOKENS) {
      throw profileError(`profile ${JSON.stringify(profile)} has an invalid output cap`);
    }
    profiles[profile] = Object.freeze({ maxOutputTokens });
  }
  if (!Object.hasOwn(profiles, defaultProfile)) {
    throw profileError("the selected profile is absent from the catalog");
  }

  const rawEnforcement = environment?.LOCAL_HARNESS_CONTEXT_ENFORCEMENT;
  const rawActiveProvider = environment?.LOCAL_HARNESS_ACTIVE_PROVIDER;
  let activeProvider;
  if (rawActiveProvider !== undefined) {
    if (typeof rawActiveProvider !== "string" || !PROVIDER_LABEL_PATTERN.test(rawActiveProvider)) {
      throw profileError("the active provider is malformed");
    }
    activeProvider = rawActiveProvider;
  }
  let contextEnforcement;
  if (rawEnforcement !== undefined) {
    if (typeof rawEnforcement !== "string" || rawEnforcement.length === 0 || rawEnforcement.length > 4_096) {
      throw profileError("the context-enforcement route is malformed");
    }
    let decodedEnforcement;
    try {
      decodedEnforcement = JSON.parse(rawEnforcement);
    } catch {
      throw profileError("the context-enforcement route is not valid JSON");
    }
    if (!isPlainObject(decodedEnforcement) || !exactKeys(decodedEnforcement, CONTEXT_ENFORCEMENT_KEYS)) {
      throw profileError("the context-enforcement route has an unexpected schema");
    }
    const { provider, model, contextWindowTokens } = decodedEnforcement;
    if (typeof provider !== "string" || provider.length === 0 || provider.length > 256
      || typeof model !== "string" || model.length === 0 || model.length > 512
      || !Number.isSafeInteger(contextWindowTokens)
      || contextWindowTokens < MINIMUM_CONTEXT_TOKENS
      || contextWindowTokens > MAXIMUM_CONTEXT_TOKENS) {
      throw profileError("the context-enforcement route has invalid values");
    }
    contextEnforcement = Object.freeze({ provider, model, contextWindowTokens });
    if (activeProvider !== provider) {
      throw profileError("the local context route does not match the active provider");
    }
  }

  return Object.freeze({
    defaultProfile,
    profiles: Object.freeze(profiles),
    ...(activeProvider === undefined ? {} : { activeProvider }),
    ...(contextEnforcement === undefined ? {} : { contextEnforcement })
  });
}

/** Return only a syntactically valid profile name; the runtime catalog owns admission. */
function taggedPerformanceProfile(sessionId) {
  if (typeof sessionId !== "string" || sessionId.length > 128) return undefined;
  return SESSION_PATTERN.exec(sessionId)?.[1];
}

function freezeTree(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeTree(child);
  return Object.freeze(value);
}

function automaticContinuationMessage(round, maximum, terminal = false) {
  return freezeTree({
    id: randomUUID(),
    role: "user",
    content: terminal
      ? AUTOMATIC_CONTINUATION_BUDGET_PROMPT.map((block) => ({ ...block }))
      : AUTOMATIC_CONTINUATION_PROMPT.map((block) => ({ ...block })),
    source: {
      kind: "plugin",
      plugin: AUTOMATIC_CONTINUATION_SOURCE,
      form: "notice",
      summary: terminal
        ? "Fulmar reached its automatic-continuation safety limit"
        : `Fulmar continued automatically · ${round}/${maximum}`
    }
  });
}

/**
 * Continue a truncated foreground task without impersonating the user. DSH
 * deliberately closes `max-tokens` as a balanced turn, so the supported
 * continuation seam is a fresh, identified follow-up. The controller never
 * reopens a turn, never reconstructs a partial tool call, and never drives a
 * subagent whose parent owns terminal settlement.
 */
function createAutomaticContinuationController({
  maximumContinuations = AUTOMATIC_CONTINUATION_MAXIMUM,
  schedule = queueMicrotask,
  logger,
  diagnostics = false
} = {}) {
  if (!Number.isSafeInteger(maximumContinuations) || maximumContinuations < 1 || maximumContinuations > 32) {
    throw profileError("the automatic-continuation bound is invalid");
  }
  const bySession = new Map();

  function stateFor(agent) {
    const id = String(agent?.id ?? "");
    let state = bySession.get(id);
    if (state === undefined) {
      state = {
        agent,
        continuations: 0,
        lastRequestTurn: undefined,
        pendingContinuation: undefined,
        scheduledContinuation: undefined,
        budgetNoticeQueued: false,
        eligible: agent?.session?.header?.origin !== "subagent"
      };
      bySession.set(id, state);
    }
    return state;
  }

  function pendingWork(agent) {
    return (Array.isArray(agent?.inbox?.nextTurn) && agent.inbox.nextTurn.length > 0)
      || (Array.isArray(agent?.inbox?.nextStep) && agent.inbox.nextStep.length > 0);
  }

  function logFailure(agent, error) {
    const detail = error instanceof Error ? error.message : String(error);
    try {
      logger?.warn?.(`Fulmar automatic continuation could not be queued for agent ${JSON.stringify(String(agent?.id ?? ""))}: ${detail}`);
    } catch {}
  }

  function logDiagnostic(detail) {
    if (!diagnostics) return;
    const line = `Fulmar automatic-continuation diagnostic: ${detail}`;
    try { logger?.warn?.(line); } catch {}
    try { process.stderr.write(`${line}\n`); } catch {}
  }

  function publishContinuationWhenIdle(agent, state) {
    if (state === undefined || state.agent !== agent || agent?.status !== "idle"
        || state.pendingContinuation === undefined
        || state.scheduledContinuation !== undefined) return false;
    const pending = state.pendingContinuation;
    state.scheduledContinuation = pending;
    schedule(() => {
      const current = bySession.get(String(agent.id));
      if (current !== state || current.agent !== agent
          || current.scheduledContinuation !== pending) return;
      current.scheduledContinuation = undefined;
      if (current.pendingContinuation !== pending) return;
      current.pendingContinuation = undefined;
      if (current.agent.status !== "idle" || pendingWork(current.agent)) {
        if (pending.terminal) current.budgetNoticeQueued = false;
        logDiagnostic(`yielded staged continuation for session=${String(agent.id)} to newer user work`);
        return;
      }
      try {
        current.agent.followup(automaticContinuationMessage(
          pending.round,
          maximumContinuations,
          pending.terminal
        ));
        if (!pending.terminal) current.continuations = pending.round;
        logDiagnostic(`queued ${pending.terminal ? "terminal summary" : `round=${pending.round}`} for session=${String(agent.id)}`);
      } catch (error) {
        if (pending.terminal) current.budgetNoticeQueued = false;
        logFailure(current.agent, error);
      }
    });
    return true;
  }

  return Object.freeze({
    created(agent) { stateFor(agent); },
    disposed(agent) { bySession.delete(String(agent?.id ?? "")); },
    requested(payload, resolved) {
      if (!isPlainObject(resolved)
          || typeof resolved.provider !== "string"
          || typeof resolved.model !== "string"
          || !Number.isSafeInteger(payload?.turn)
          || payload.turn < 0) {
        logDiagnostic("ignored an invalid agent/request contract");
        return;
      }
      const state = stateFor(payload?.agent);
      state.lastRequestTurn = payload.turn;
      logDiagnostic(`observed request turn=${payload.turn} session=${String(payload?.agent?.id ?? "missing")}`);
    },
    sessionEvent(session, event) {
      const state = bySession.get(String(session?.id ?? ""));
      if (state === undefined || state.agent?.session !== session) {
        if (event?.type === "turn/end" && event.data?.reason?.kind === "max-tokens") {
          logDiagnostic(`ignored max-tokens turn=${String(event.data?.turn)} because the exact live agent state was absent`);
        }
        return false;
      }
      if (event?.type === "user/message") {
        const source = event.data?.source;
        if (source?.kind === "user") {
          state.continuations = 0;
          // A real user turn always owns the queue. Invalidate both the staged
          // follow-up and its already-published microtask token; the stale
          // callback may still run, but identity checks below make it inert.
          state.pendingContinuation = undefined;
          state.scheduledContinuation = undefined;
          state.budgetNoticeQueued = false;
        }
        return false;
      }
      if (event?.type !== "turn/end") return false;
      const turn = event.data?.turn;
      if (event.data?.reason?.kind !== "max-tokens") {
        state.continuations = 0;
        state.lastRequestTurn = undefined;
        state.pendingContinuation = undefined;
        state.scheduledContinuation = undefined;
        state.budgetNoticeQueued = false;
        return false;
      }
      if (!state.eligible || state.pendingContinuation !== undefined
          || state.scheduledContinuation !== undefined
          || state.lastRequestTurn !== turn || pendingWork(state.agent)) {
        logDiagnostic(
          `ignored max-tokens turn=${String(turn)} eligible=${String(state.eligible)} scheduled=${String(state.scheduledContinuation !== undefined)} `
          + `observedTurn=${String(state.lastRequestTurn)} pending=${String(pendingWork(state.agent))}`
        );
        return false;
      }

      const terminal = state.continuations >= maximumContinuations;
      if (terminal && state.budgetNoticeQueued) return false;
      // Consume this exact observed request before deferring the follow-up. A
      // duplicate delivery of the same durable turn/end event must not enqueue
      // another continuation after the first microtask has run.
      state.lastRequestTurn = undefined;
      if (terminal) state.budgetNoticeQueued = true;
      const round = terminal ? state.continuations : state.continuations + 1;
      state.pendingContinuation = Object.freeze({ round, terminal });
      logDiagnostic(`staged ${terminal ? "terminal summary" : `round=${round}`} until the exact agent becomes idle`);
      // DSH may publish idle immediately before or immediately after its
      // durable turn/end hook. Observe both boundaries so either legal ordering
      // schedules exactly the same tokenized follow-up once.
      publishContinuationWhenIdle(state.agent, state);
      return true;
    },
    status(agent, status) {
      const state = bySession.get(String(agent?.id ?? ""));
      if (status !== "idle") return false;
      return publishContinuationWhenIdle(agent, state);
    },
    state(agent) {
      const value = bySession.get(String(agent?.id ?? ""));
      return value === undefined ? undefined : Object.freeze({
        continuations: value.continuations,
        lastRequestTurn: value.lastRequestTurn,
        pendingContinuation: value.pendingContinuation !== undefined,
        scheduled: value.scheduledContinuation !== undefined,
        budgetNoticeQueued: value.budgetNoticeQueued,
        eligible: value.eligible
      });
    },
    sessionCount() { return bySession.size; }
  });
}

function createPerformanceLimiter(configuration, resolveModelInfo, thermalWorkload) {
  const { defaultProfile, profiles, activeProvider, contextEnforcement } = configuration;
  const bySession = new Map();
  const latestToolResultTurn = new WeakMap();

  function admittedTaggedProfile(sessionId) {
    const tagged = taggedPerformanceProfile(sessionId);
    return tagged !== undefined && Object.hasOwn(profiles, tagged) ? tagged : undefined;
  }

  function resolveProfile(agent) {
    const sessionId = String(agent?.id ?? "");
    const existing = bySession.get(sessionId);
    if (existing !== undefined) return existing;

    const direct = admittedTaggedProfile(sessionId);
    const parentId = agent?.session?.header?.parentSession;
    const inherited = typeof parentId === "string"
      ? (bySession.get(parentId) ?? admittedTaggedProfile(parentId))
      : undefined;
    const profile = direct ?? inherited ?? defaultProfile;
    bySession.set(sessionId, profile);
    return profile;
  }

  return Object.freeze({
    profileFor(agent) {
      const profile = resolveProfile(agent);
      return Object.freeze({ name: profile, ...profiles[profile] });
    },
    created(agent) {
      resolveProfile(agent);
    },
    disposed(agent) {
      bySession.delete(String(agent?.id ?? ""));
    },
    sessionEvent(session, event) {
      if ((typeof session !== "object" && typeof session !== "function") || session === null) return;
      const turn = event?.data?.turn;
      if (!Number.isSafeInteger(turn) || turn < 0) return;
      if (event?.type === "tool/result") {
        latestToolResultTurn.set(session, turn);
      } else if (event?.type === "turn/end" && latestToolResultTurn.get(session) === turn) {
        latestToolResultTurn.delete(session);
      }
    },
    async request(payload, next) {
      const resolved = await next();
      if (!isPlainObject(resolved)) throw profileError("agent/request returned a non-object config");
      if (activeProvider !== undefined && resolved.provider !== activeProvider) {
        throw profileError(
          `this runtime is locked to provider ${activeProvider}; start a fresh verified runtime before using ${resolved.provider}`
        );
      }
      const profile = resolveProfile(payload?.agent);
      const isEnforcedLocalRoute = contextEnforcement !== undefined
        && resolved.provider === contextEnforcement.provider
        && resolved.model === contextEnforcement.model;
      if (contextEnforcement !== undefined && !isEnforcedLocalRoute) {
        throw profileError(
          `this runtime is locked to ${contextEnforcement.provider}/${contextEnforcement.model}; start a fresh verified runtime before using ${resolved.provider}/${resolved.model}`
        );
      }
      if (isEnforcedLocalRoute) {
        if (typeof resolveModelInfo !== "function") {
          throw profileError("the context-enforcement resolver is unavailable");
        }
        const modelInfo = await resolveModelInfo(resolved.provider, resolved.model, payload?.signal);
        const actualContext = modelInfo?.context?.contextWindow;
        if (modelInfo?.provider !== resolved.provider
          || modelInfo?.id !== resolved.model
          || !Number.isSafeInteger(actualContext)
          || actualContext !== contextEnforcement.contextWindowTokens) {
          throw profileError(
            `DSH resolved an unexpected context capacity for ${resolved.provider}/${resolved.model}; expected ${contextEnforcement.contextWindowTokens}`
          );
        }
      }
      const thermalPolicy = isEnforcedLocalRoute && thermalWorkload !== undefined
        ? await thermalWorkload.beforeRequest(resolved, payload?.signal)
        : normalThermalPolicy;
      const profileOutputTokens = profiles[profile].maxOutputTokens;
      const thermalOutputTokens = thermalPolicy.maxOutputTokens ?? profileOutputTokens;
      const hasCompletedToolInTurn = isEnforcedLocalRoute
        && Number.isSafeInteger(payload?.turn)
        && payload.turn >= 0
        && latestToolResultTurn.get(payload?.agent?.session) === payload?.turn;
      // These profiles describe the reviewed on-device runtime. Never replace a
      // cloud or LAN provider's output proposal with a local-machine tuning
      // value: that value can exceed the remote model's hard output capacity.
      // Once a tool has completed, bound only the subsequent request in that
      // same local turn so completion remains responsive. A later turn regains
      // the user's selected profile allowance.
      return isEnforcedLocalRoute
        ? {
            ...resolved,
            maxTokens: Math.min(
              profileOutputTokens,
              thermalOutputTokens,
              hasCompletedToolInTurn ? LOCAL_POST_TOOL_OUTPUT_TOKENS : profileOutputTokens
            )
          }
        : resolved;
    },
    sessionCount() {
      return bySession.size;
    }
  });
}

function currentUID(metadata) {
  return typeof process.getuid === "function" ? process.getuid() : metadata.uid;
}

function secureTelemetryDirectory(path) {
  let canonical;
  let metadata;
  try {
    // The Strict Local preload guards and may replace this public API. Use the
    // stable function itself instead of assuming a `.native` member survives
    // another runtime's interposition.
    canonical = realpathSync(path);
    metadata = lstatSync(path);
  } catch {
    return false;
  }
  return canonical === path
    && metadata.isDirectory()
    && !metadata.isSymbolicLink()
    && metadata.uid === currentUID(metadata)
    && (metadata.mode & 0o077) === 0;
}

function secureTelemetryFile(path, { allowAbsent = true } = {}) {
  let metadata;
  try { metadata = lstatSync(path); }
  catch (error) { return allowAbsent && error?.code === "ENOENT"; }
  return metadata.isFile()
    && !metadata.isSymbolicLink()
    && metadata.uid === currentUID(metadata)
    && metadata.nlink === 1
    && (metadata.mode & 0o077) === 0;
}

function decodeThermalPolicyStorage(environment) {
  const raw = environment?.LOCAL_HARNESS_THERMAL_POLICY_FILE;
  const rawRoot = environment?.LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT;
  if (environment && typeof environment === "object") {
    delete environment.LOCAL_HARNESS_THERMAL_POLICY_FILE;
  }
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 4_096 || raw.includes("\0")
      || typeof rawRoot !== "string" || rawRoot.length === 0 || rawRoot.length > 4_096
      || rawRoot.includes("\0") || basename(rawRoot) !== "Local Harness"
      || !isAbsolute(raw) || normalize(raw) !== raw
      || !isAbsolute(rawRoot) || normalize(rawRoot) !== rawRoot) {
    throw profileError("the adaptive thermal policy path is malformed");
  }
  let root;
  let directory;
  let file;
  try {
    root = realpathSync(rawRoot);
    directory = realpathSync(join(root, "PerformanceTelemetry"));
    file = realpathSync(raw);
  } catch {
    throw profileError("the adaptive thermal policy path is unavailable");
  }
  const expectedDirectory = join(root, "PerformanceTelemetry");
  const expectedFile = join(expectedDirectory, THERMAL_POLICY_FILE_NAME);
  if (root !== rawRoot || directory !== expectedDirectory || file !== expectedFile || raw !== expectedFile
      || !secureTelemetryDirectory(root) || !secureTelemetryDirectory(directory)
      || !secureTelemetryFile(file, { allowAbsent: false })) {
    throw profileError("the adaptive thermal policy storage is unsafe");
  }
  return Object.freeze({ file });
}

const failSafeThermalPolicy = Object.freeze({
  mode: "eco",
  maxOutputTokens: THERMAL_ECO_OUTPUT_TOKENS,
  minimumDelayMilliseconds: THERMAL_ECO_DELAY_MILLISECONDS
});
const normalThermalPolicy = Object.freeze({
  mode: "normal",
  maxOutputTokens: undefined,
  minimumDelayMilliseconds: 0
});

function readThermalPolicy(path) {
  if (path === undefined) return normalThermalPolicy;
  let descriptor;
  try {
    if (!secureTelemetryFile(path, { allowAbsent: false })) return failSafeThermalPolicy;
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.uid !== currentUID(metadata) || metadata.nlink !== 1
        || (metadata.mode & 0o077) !== 0 || metadata.size <= 0
        || metadata.size > THERMAL_POLICY_MAXIMUM_BYTES) return failSafeThermalPolicy;
    const decoded = JSON.parse(readFileSync(descriptor, "utf8"));
    if (!isPlainObject(decoded) || !exactKeys(decoded, THERMAL_POLICY_KEYS)
        || decoded.schemaVersion !== THERMAL_POLICY_SCHEMA_VERSION
        || (decoded.mode !== "normal" && decoded.mode !== "eco")
        || decoded.ecoMaxOutputTokens !== THERMAL_ECO_OUTPUT_TOKENS
        || decoded.minimumDelayMilliseconds !== THERMAL_ECO_DELAY_MILLISECONDS) {
      return failSafeThermalPolicy;
    }
    return decoded.mode === "eco" ? failSafeThermalPolicy : normalThermalPolicy;
  } catch {
    return failSafeThermalPolicy;
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
}

function abortError() {
  const error = new Error("Adaptive thermal delay was cancelled.");
  error.name = "AbortError";
  error.code = "ABORT_ERR";
  return error;
}

function abortableDelay(milliseconds, signal) {
  if (milliseconds <= 0) return Promise.resolve();
  if (signal?.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(finish, milliseconds);
    function finish() {
      signal?.removeEventListener?.("abort", cancelled);
      resolve();
    }
    function cancelled() {
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", cancelled);
      reject(abortError());
    }
    signal?.addEventListener?.("abort", cancelled, { once: true });
  });
}

function createThermalWorkloadController(
  storage,
  contextEnforcement,
  { clock = Date.now, delay = abortableDelay } = {}
) {
  let lastLocalCompletionMilliseconds;
  const matches = (provider, model) => contextEnforcement !== undefined
    && provider === contextEnforcement.provider
    && model === contextEnforcement.model;
  return Object.freeze({
    async beforeRequest(resolved, signal) {
      if (!matches(resolved?.provider, resolved?.model)) return normalThermalPolicy;
      const policy = readThermalPolicy(storage?.file);
      if (policy.mode !== "eco" || lastLocalCompletionMilliseconds === undefined) return policy;
      const elapsed = Math.max(0, clock() - lastLocalCompletionMilliseconds);
      const remaining = Math.max(0, policy.minimumDelayMilliseconds - elapsed);
      if (remaining > 0) await delay(remaining, signal);
      return policy;
    },
    completed(options) {
      if (matches(options?.provider, options?.model)) {
        lastLocalCompletionMilliseconds = clock();
      }
    },
    currentPolicy() { return readThermalPolicy(storage?.file); }
  });
}

function decodeTelemetryStorage(environment) {
  const raw = environment?.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE;
  const rawRoot = environment?.LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT;
  if (environment && typeof environment === "object") {
    delete environment.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE;
    delete environment.LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT;
  }
  if (raw === undefined && rawRoot === undefined) return undefined;
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 4_096 || raw.includes("\0")
      || !isAbsolute(raw) || normalize(raw) !== raw || basename(raw) !== TELEMETRY_FILE_NAME) {
    return undefined;
  }
  if (typeof rawRoot !== "string" || rawRoot.length === 0 || rawRoot.length > 4_096 || rawRoot.includes("\0")
      || !isAbsolute(rawRoot) || normalize(rawRoot) !== rawRoot || basename(rawRoot) !== "Local Harness"
      || !secureTelemetryDirectory(rawRoot)) return undefined;
  const parent = dirname(raw);
  const expected = join(rawRoot, "PerformanceTelemetry", TELEMETRY_FILE_NAME);
  if (raw !== expected || basename(parent) !== "PerformanceTelemetry" || !secureTelemetryDirectory(parent)) return undefined;
  if (!Number.isInteger(fsConstants.O_NOFOLLOW) || !Number.isInteger(fsConstants.O_DIRECTORY)) return undefined;
  return secureTelemetryFile(raw) ? Object.freeze({ file: raw, applicationSupportRoot: rawRoot }) : undefined;
}

function decodeTelemetryFile(environment) {
  return decodeTelemetryStorage(environment)?.file;
}

function safeTelemetryLabel(value, maximumBytes = TELEMETRY_MAXIMUM_LABEL_BYTES) {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maximumBytes) return null;
  if (value.includes("\0") || /[\u0000-\u001f\u007f]/u.test(value)) return null;
  return value;
}

function exactTelemetryRecord(value, nowMilliseconds) {
  if (!isPlainObject(value) || !exactKeys(value, TELEMETRY_RECORD_KEYS)) return undefined;
  if (value.schemaVersion !== TELEMETRY_SCHEMA_VERSION || typeof value.id !== "string" || !UUID_PATTERN.test(value.id)) {
    return undefined;
  }
  const provider = value.provider === null ? null : safeTelemetryLabel(value.provider, 256);
  const model = value.model === null ? null : safeTelemetryLabel(value.model);
  const profile = value.profile === null
    ? null
    : (typeof value.profile === "string" && PROFILE_NAME_PATTERN.test(value.profile) ? value.profile : undefined);
  if ((value.provider !== null && provider === null) || (value.model !== null && model === null) || profile === undefined) {
    return undefined;
  }
  const integers = [
    value.startedAtMilliseconds,
    value.completedAtMilliseconds,
    value.elapsedMilliseconds,
    value.outputTokens
  ];
  if (!integers.every((entry) => Number.isSafeInteger(entry) && entry >= 0)
      || value.elapsedMilliseconds > TELEMETRY_MAXIMUM_AGE_MILLISECONDS
      || value.outputTokens > 10_000_000
      || value.completedAtMilliseconds < value.startedAtMilliseconds
      || value.completedAtMilliseconds - value.startedAtMilliseconds !== value.elapsedMilliseconds
      || value.completedAtMilliseconds > nowMilliseconds + TELEMETRY_MAXIMUM_FUTURE_SKEW_MILLISECONDS
      || value.completedAtMilliseconds < nowMilliseconds - TELEMETRY_MAXIMUM_AGE_MILLISECONDS) {
    return undefined;
  }
  if (value.firstTokenAtMilliseconds !== null
      && (!Number.isSafeInteger(value.firstTokenAtMilliseconds)
        || value.firstTokenAtMilliseconds < value.startedAtMilliseconds
        || value.firstTokenAtMilliseconds > value.completedAtMilliseconds)) {
    return undefined;
  }
  if (!new Set(["providerReported", "estimated"]).has(value.outputTokenCountSource)
      || !new Set(["completed", "cancelled", "failed"]).has(value.outcome)
      || (value.outcome === "failed"
        ? !new Set(["providerUnavailable", "timedOut", "invalidResponse", "toolFailure", "resourcePressure", "unknown"]).has(value.failureCategory)
        : value.failureCategory !== null)) {
    return undefined;
  }
  return Object.freeze({
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    id: value.id.toLowerCase(),
    provider,
    model,
    profile,
    startedAtMilliseconds: value.startedAtMilliseconds,
    completedAtMilliseconds: value.completedAtMilliseconds,
    firstTokenAtMilliseconds: value.firstTokenAtMilliseconds,
    elapsedMilliseconds: value.elapsedMilliseconds,
    outputTokens: value.outputTokens,
    outputTokenCountSource: value.outputTokenCountSource,
    outcome: value.outcome,
    failureCategory: value.failureCategory
  });
}

function loadTelemetryRecords(path, nowMilliseconds) {
  if (!secureTelemetryFile(path)) return [];
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.uid !== currentUID(metadata) || metadata.nlink !== 1
        || (metadata.mode & 0o077) !== 0 || metadata.size > TELEMETRY_MAXIMUM_FILE_BYTES) return [];
    const data = readFileSync(descriptor);
    if (data.length > TELEMETRY_MAXIMUM_FILE_BYTES || data.length === 0) return [];
    const decoded = JSON.parse(data.toString("utf8"));
    if (!isPlainObject(decoded) || !exactKeys(decoded, ["schemaVersion", "records"])
        || decoded.schemaVersion !== TELEMETRY_SCHEMA_VERSION || !Array.isArray(decoded.records)
        || decoded.records.length > TELEMETRY_MAXIMUM_RECORDS) return [];
    const records = decoded.records.map((record) => exactTelemetryRecord(record, nowMilliseconds));
    return records.every(Boolean) ? records : [];
  } catch {
    return [];
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
}

function removeSafeTelemetryTemporary(path) {
  let metadata;
  try { metadata = lstatSync(path); }
  catch (error) { return error?.code === "ENOENT"; }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== currentUID(metadata)
      || metadata.nlink !== 1 || (metadata.mode & 0o077) !== 0
      || metadata.size > TELEMETRY_MAXIMUM_FILE_BYTES) return false;
  try { unlinkSync(path); return true; } catch { return false; }
}

function createNativeTelemetryLockTransaction(
  helperPath,
  applicationSupportRoot,
  telemetryFile,
  {
    acquisitionTimeoutMilliseconds = 2_000,
    transactionTimeoutMilliseconds = 3_000
  } = {}
) {
  if (typeof helperPath !== "string" || !isAbsolute(helperPath) || normalize(helperPath) !== helperPath
      || typeof applicationSupportRoot !== "string" || !isAbsolute(applicationSupportRoot)
      || normalize(applicationSupportRoot) !== applicationSupportRoot
      || typeof telemetryFile !== "string" || !isAbsolute(telemetryFile) || normalize(telemetryFile) !== telemetryFile
      || !Number.isSafeInteger(acquisitionTimeoutMilliseconds) || acquisitionTimeoutMilliseconds < 10
      || acquisitionTimeoutMilliseconds > 10_000
      || !Number.isSafeInteger(transactionTimeoutMilliseconds)
      || transactionTimeoutMilliseconds <= acquisitionTimeoutMilliseconds
      || transactionTimeoutMilliseconds > 30_000) {
    return undefined;
  }
  return async function withNativeTelemetryLock(operation) {
    if (typeof operation !== "function") return false;
    return await new Promise((resolve) => {
      let settled = false;
      let locked = false;
      let stdout = Buffer.alloc(0);
      let stderrBytes = 0;
      let operationResult = false;
      const child = spawn(helperPath, ["telemetry-lock", applicationSupportRoot, telemetryFile], {
        env: { PATH: "/usr/bin:/bin" },
        stdio: ["pipe", "pipe", "pipe"]
      });
      const transactionTimer = setTimeout(() => {
        if (settled) return;
        child.kill("SIGKILL");
        finish(false);
      }, transactionTimeoutMilliseconds);
      let acquisitionTimer = setTimeout(() => {
        if (settled || locked) return;
        child.kill("SIGKILL");
        finish(false);
      }, acquisitionTimeoutMilliseconds);
      const finish = (value) => {
        if (settled) return;
        settled = true;
        if (acquisitionTimer !== undefined) clearTimeout(acquisitionTimer);
        clearTimeout(transactionTimer);
        resolve(value);
      };
      child.on("error", () => finish(false));
      child.stderr.on("data", (chunk) => {
        stderrBytes += chunk.length;
        if (stderrBytes > 4_096) child.kill("SIGKILL");
      });
      child.stdout.on("data", (chunk) => {
        if (locked || settled) return;
        stdout = Buffer.concat([stdout, chunk]);
        if (stdout.length > 64) { child.kill("SIGKILL"); return; }
        const text = stdout.toString("utf8");
        if (text === "BUSY\n") return;
        if (text !== "LOCKED\n") return;
        locked = true;
        clearTimeout(acquisitionTimer);
        acquisitionTimer = undefined;
        Promise.resolve().then(operation).then(
          (value) => {
            if (settled) return;
            operationResult = value === true;
            child.stdin.end();
          },
          () => {
            if (settled) return;
            operationResult = false;
            child.stdin.end();
          }
        );
      });
      child.on("close", (code, signal) => {
        finish(locked && code === 0 && signal === null && stderrBytes === 0
          && stdout.toString("utf8") === "LOCKED\n" && operationResult);
      });
    });
  };
}

async function persistTelemetryRecords(path, records, { beforeRenameForTesting } = {}) {
  const parent = dirname(path);
  if (!secureTelemetryDirectory(parent) || !secureTelemetryFile(path)) return false;
  const temporary = join(parent, `.${TELEMETRY_FILE_NAME}.tmp`);
  if (!removeSafeTelemetryTemporary(temporary)) return false;

  const encoded = Buffer.from(JSON.stringify({
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    records
  }), "utf8");
  if (encoded.length === 0 || encoded.length > TELEMETRY_MAXIMUM_FILE_BYTES) return false;

  let descriptor;
  let renamed = false;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600
    );
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.uid !== currentUID(metadata) || metadata.nlink !== 1
        || (metadata.mode & 0o077) !== 0) return false;
    writeFileSync(descriptor, encoded);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    if (beforeRenameForTesting !== undefined) {
      if (typeof beforeRenameForTesting !== "function") return false;
      await beforeRenameForTesting();
    }
    if (!secureTelemetryDirectory(parent) || !secureTelemetryFile(path)) return false;
    renameSync(temporary, path);
    renamed = true;
    if (!secureTelemetryFile(path, { allowAbsent: false })) return false;
    const directoryDescriptor = openSync(parent, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
    try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
    return true;
  } catch {
    return false;
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
    if (!renamed) removeSafeTelemetryTemporary(temporary);
  }
}

function createPerformanceTelemetryRecorder(
  path,
  {
    now = Date.now,
    uuid = randomUUID,
    lockTransaction,
    afterLoadForTesting,
    beforeRenameForTesting
  } = {}
) {
  if (typeof path !== "string" || typeof lockTransaction !== "function") return undefined;
  let serialized = Promise.resolve();
  let pendingRecords = 0;
  return Object.freeze({
    record(candidate) {
      let reference;
      let record;
      try {
        reference = now();
        record = exactTelemetryRecord(candidate, reference);
      } catch {
        return Promise.resolve(false);
      }
      if (!record || pendingRecords >= TELEMETRY_MAXIMUM_PENDING_RECORDS) return Promise.resolve(false);
      pendingRecords += 1;
      const operation = serialized.then(async () => {
        return await lockTransaction(async () => {
          const records = loadTelemetryRecords(path, reference)
            .filter((existing) => existing.id !== record.id);
          if (afterLoadForTesting !== undefined) {
            if (typeof afterLoadForTesting !== "function") return false;
            await afterLoadForTesting();
          }
          records.push(record);
          records.sort((left, right) => right.completedAtMilliseconds - left.completedAtMilliseconds
            || left.id.localeCompare(right.id));
          return await persistTelemetryRecords(
            path,
            records.slice(0, TELEMETRY_MAXIMUM_RECORDS),
            { beforeRenameForTesting }
          );
        });
      }).catch(() => false);
      const tracked = operation.then(
        (value) => { pendingRecords -= 1; return value; },
        () => { pendingRecords -= 1; return false; }
      );
      serialized = tracked.then(() => undefined, () => undefined);
      return tracked;
    },
    flush() { return serialized; },
    nextID() { return uuid(); }
  });
}

function telemetryFailureCategory(failure) {
  const code = typeof failure?.code === "string" ? failure.code.toUpperCase() : "";
  const status = Number(failure?.status);
  if (code.includes("TIMEOUT") || code.includes("TIMED_OUT")) return "timedOut";
  if (code.includes("RESOURCE") || code.includes("MEMORY") || code.includes("OVERLOAD")) return "resourcePressure";
  if (code.includes("TOOL")) return "toolFailure";
  if (code.includes("INVALID") || code.includes("MALFORMED") || code.includes("PARSE")
      || code.includes("PROTOCOL") || code.includes("CONTEXT")) return "invalidResponse";
  if (code.includes("AUTH") || code.includes("NETWORK") || code.includes("ADAPTER")
      || code.includes("RATE") || code.includes("UNAVAILABLE")
      || (Number.isInteger(status) && status >= 400)) return "providerUnavailable";
  return "unknown";
}

function createTelemetryRecord({
  recorder,
  options,
  startedMonotonic,
  firstTokenMonotonic,
  completedMonotonic,
  completedWallClock,
  outputUTF8Bytes,
  reportedOutputTokens,
  outcome,
  failureCategory
}) {
  const elapsedMilliseconds = Math.max(0, Math.round(completedMonotonic - startedMonotonic));
  const startedAtMilliseconds = Math.max(0, Math.round(completedWallClock - elapsedMilliseconds));
  const firstTokenAtMilliseconds = firstTokenMonotonic === undefined
    ? null
    : Math.min(
      completedWallClock,
      startedAtMilliseconds + Math.max(0, Math.round(firstTokenMonotonic - startedMonotonic))
    );
  const hasReportedTokens = Number.isSafeInteger(reportedOutputTokens) && reportedOutputTokens >= 0;
  const admittedProvider = safeTelemetryLabel(options?.provider, 256);
  const admittedModel = safeTelemetryLabel(options?.model);
  const provider = admittedProvider !== null && admittedModel !== null ? admittedProvider : null;
  const model = admittedProvider !== null && admittedModel !== null ? admittedModel : null;
  return {
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    id: recorder.nextID(),
    provider,
    model,
    profile: taggedPerformanceProfile(String(options?.sessionId ?? "")) ?? null,
    startedAtMilliseconds,
    completedAtMilliseconds: completedWallClock,
    firstTokenAtMilliseconds,
    elapsedMilliseconds,
    outputTokens: hasReportedTokens ? reportedOutputTokens : Math.ceil(outputUTF8Bytes / 4),
    outputTokenCountSource: hasReportedTokens ? "providerReported" : "estimated",
    outcome,
    failureCategory: outcome === "failed" ? (failureCategory ?? "unknown") : null
  };
}

function observePerformanceStream(
  options,
  next,
  recorder,
  { wallClock = Date.now, monotonicClock = () => globalThis.performance.now() } = {}
) {
  return (async function* localHarnessPerformanceTelemetry() {
    const startedMonotonic = monotonicClock();
    let firstTokenMonotonic;
    let outputUTF8Bytes = 0;
    let reportedOutputTokens;
    let terminalRecorded = false;

    const addOutput = (value) => {
      if (typeof value !== "string" || value.length === 0) return;
      if (firstTokenMonotonic === undefined) firstTokenMonotonic = monotonicClock();
      const size = Buffer.byteLength(value, "utf8");
      outputUTF8Bytes = Math.min(Number.MAX_SAFE_INTEGER, outputUTF8Bytes + size);
    };
    const finish = (outcome, failureCategory) => {
      if (terminalRecorded) return false;
      terminalRecorded = true;
      const completedMonotonic = monotonicClock();
      const completedWallClock = Math.max(0, Math.round(wallClock()));
      const record = createTelemetryRecord({
        recorder,
        options,
        startedMonotonic,
        firstTokenMonotonic,
        completedMonotonic,
        completedWallClock,
        outputUTF8Bytes,
        reportedOutputTokens,
        outcome,
        failureCategory
      });
      // Diagnostics are intentionally best-effort. Never make a terminal
      // provider chunk, thrown error, or cancellation await filesystem/lock
      // activity. The recorder owns a bounded queue and swallows failures.
      try { Promise.resolve(recorder.record(record)).catch(() => false); } catch {}
      return true;
    };

    try {
      for await (const chunk of next()) {
        if (chunk?.type === "text-delta" || chunk?.type === "reasoning-delta") addOutput(chunk.text);
        else if (chunk?.type === "tool-call-delta") {
          addOutput(chunk.name);
          addOutput(chunk.argumentsDelta);
        } else if (chunk?.type === "usage" && Number.isSafeInteger(chunk.usage?.outputTokens)
            && chunk.usage.outputTokens >= 0) {
          reportedOutputTokens = chunk.usage.outputTokens;
        } else if (chunk?.type === "finish") {
          if (chunk.reason?.kind === "aborted") finish("cancelled");
          else if (chunk.reason?.kind === "error") finish("failed", telemetryFailureCategory(chunk.reason.failure));
          else finish("completed");
        }
        yield chunk;
      }
      if (!terminalRecorded) finish(options?.signal?.aborted ? "cancelled" : "failed", "invalidResponse");
    } catch (error) {
      finish(options?.signal?.aborted ? "cancelled" : "failed", telemetryFailureCategory(undefined));
      throw error;
    } finally {
      if (!terminalRecorded) finish("cancelled");
    }
  })();
}

function observeThermalWorkloadStream(options, next, controller) {
  return (async function* localHarnessThermalWorkloadObservation() {
    try {
      for await (const chunk of next()) yield chunk;
    } finally {
      controller.completed(options);
    }
  })();
}

const name = "local-harness-performance-profile";
// The web host exposes the global agent lifecycle events but no root `agent`
// service. Only `llm` is dereferenced by this plugin; requiring `agent` leaves
// the reviewed patch pending forever on a clean web profile.
const inject = ["llm"];

function apply(ctx) {
  const thermalPolicyStorage = decodeThermalPolicyStorage(process.env);
  const telemetryStorage = decodeTelemetryStorage(process.env);
  const telemetryLock = telemetryStorage === undefined
    ? undefined
    : createNativeTelemetryLockTransaction(
      nativeTelemetryLockHelper,
      telemetryStorage.applicationSupportRoot,
      telemetryStorage.file
    );
  const telemetry = createPerformanceTelemetryRecorder(telemetryStorage?.file, {
    lockTransaction: telemetryLock
  });
  const configuration = decodePerformanceEnvironment(process.env);
  if (configuration.contextEnforcement !== undefined
    && typeof ctx?.llm?.resolveModelInfo !== "function") {
    throw profileError("DSH did not expose exact model resolution");
  }
  const thermalWorkload = createThermalWorkloadController(
    thermalPolicyStorage,
    configuration.contextEnforcement
  );
  const limiter = createPerformanceLimiter(
    configuration,
    (provider, model, signal) => ctx.llm.resolveModelInfo(provider, model, signal),
    thermalWorkload
  );
  const automaticContinuation = createAutomaticContinuationController({
    logger: ctx?.logger,
    diagnostics: automaticContinuationDiagnostics
  });
  ctx.on("agent/created", ({ agent }) => {
    limiter.created(agent);
    automaticContinuation.created(agent);
  }, { global: true });
  ctx.on("agent/disposed", ({ agent }) => {
    limiter.disposed(agent);
    automaticContinuation.disposed(agent);
  }, { global: true });
  ctx.on("agent/status", ({ agent, status }) => {
    automaticContinuation.status(agent, status);
  }, { global: true });
  // Call next first so model-selection middleware can resolve the exact route;
  // this reviewed boundary owns the cap only for the exact synchronized local
  // route and preserves remote-provider limits byte-for-byte.
  ctx.on("agent/request", async (payload, next) => {
    const resolved = await limiter.request(payload, next);
    automaticContinuation.requested(payload, resolved);
    return resolved;
  }, { global: true });
  ctx.on("session/event", (session, event) => {
    limiter.sessionEvent(session, event);
    automaticContinuation.sessionEvent(session, event);
  }, { global: true });
  if (telemetry || thermalPolicyStorage !== undefined) {
    ctx.on("llm/stream", (options, next) => {
      const thermalStream = () => observeThermalWorkloadStream(options, next, thermalWorkload);
      return telemetry
        ? observePerformanceStream(options, thermalStream, telemetry)
        : thermalStream();
    }, { global: true });
  }
}

export {
  SESSION_PREFIX,
  LOCAL_POST_TOOL_OUTPUT_TOKENS,
  apply,
  createNativeTelemetryLockTransaction,
  createAutomaticContinuationController,
  createThermalWorkloadController,
  createPerformanceTelemetryRecorder,
  createPerformanceLimiter,
  decodeTelemetryFile,
  decodeTelemetryStorage,
  decodePerformanceEnvironment,
  decodeThermalPolicyStorage,
  inject,
  name,
  observePerformanceStream,
  observeThermalWorkloadStream,
  readThermalPolicy,
  taggedPerformanceProfile
};
