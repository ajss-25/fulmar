import { LlmError } from "@deepseek-ai/dsh-llm";

delete process.env.LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN;

const name = "local-harness-client-security-bridge";
const inject = ["llm", "apiProxy"];
// Increment only when both host and browser classifiers, their parity matrix,
// and the pinned DSH frame-shape contract have been updated together.
const providerFailureTaxonomyVersion = 1;
const maximumRetryAfterMilliseconds = 86_400_000;

const safeFailures = Object.freeze({
  ABORTED: Object.freeze({
    code: "ABORTED",
    message: "The model request was cancelled."
  }),
  MISSING_CREDENTIAL: Object.freeze({
    code: "MISSING_CREDENTIAL",
    message: "No API key is configured for this model. Open Models & Providers to add one."
  }),
  KEYCHAIN_AUTHORIZATION_REQUIRED: Object.freeze({
    code: "KEYCHAIN_AUTHORIZATION_REQUIRED",
    message: "macOS Keychain access needs attention. Open Models & Providers to repair this credential."
  }),
  CREDENTIAL_RECOVERY_REQUIRED: Object.freeze({
    code: "CREDENTIAL_RECOVERY_REQUIRED",
    message: "This credential needs recovery. Open Models & Providers to repair it."
  }),
  CREDENTIAL_TRANSACTION_BUSY: Object.freeze({
    code: "CREDENTIAL_TRANSACTION_BUSY",
    message: "Another credential update is still finishing. Wait a moment and try again."
  }),
  INVALID_CREDENTIAL: Object.freeze({
    code: "INVALID_CREDENTIAL",
    message: "The configured API key is not usable. Open Models & Providers to replace it."
  }),
  AUTH: Object.freeze({
    code: "AUTH",
    message: "The provider rejected this credential. Open Models & Providers to check the API key."
  }),
  QUOTA: Object.freeze({
    code: "QUOTA",
    message: "The provider account has insufficient credit or quota for this request."
  }),
  RATE_LIMIT: Object.freeze({
    code: "RATE_LIMIT",
    message: "The provider is rate limiting requests. Try again shortly."
  }),
  SERVER: Object.freeze({
    code: "SERVER",
    message: "The provider is temporarily unavailable. Try again shortly."
  }),
  TRANSPORT: Object.freeze({
    code: "TRANSPORT",
    message: "The provider connection failed. Check the connection and try again."
  }),
  TIMEOUT: Object.freeze({
    code: "TIMEOUT",
    message: "The model request timed out. Try again."
  }),
  STREAM_CLOSED: Object.freeze({
    code: "STREAM_CLOSED",
    message: "The provider connection ended before the response completed. Try again."
  }),
  EMPTY_RESPONSE: Object.freeze({
    code: "EMPTY_RESPONSE",
    message: "The model returned no response. Try again."
  }),
  NO_ADAPTER: Object.freeze({
    code: "NO_ADAPTER",
    message: "This model route is unavailable. Choose another model or repair it in Models & Providers."
  }),
  CONTEXT_WINDOW_EXCEEDED: Object.freeze({
    code: "CONTEXT_WINDOW_EXCEEDED",
    message: "This task is too large for the model context. Shorten it or start a fresh session."
  }),
  MODEL_CONFIGURATION: Object.freeze({
    code: "MODEL_CONFIGURATION",
    message: "This model cannot accept the current request. Check Models & Providers or choose another model."
  }),
  UNKNOWN: Object.freeze({
    code: "UNKNOWN",
    message: "The model request failed. Try again or check Models & Providers."
  })
});

const aliases = new Map([
  ["AUTH_ERROR", "AUTH"],
  ["AUTH_FAILED", "AUTH"],
  ["AUTHENTICATION_ERROR", "AUTH"],
  ["AUTHENTICATION_FAILED", "AUTH"],
  ["CREDENTIAL_REJECTED", "AUTH"],
  ["INVALID_API_KEY", "INVALID_CREDENTIAL"],
  ["UNAUTHORIZED", "AUTH"],
  ["BILLING_ERROR", "QUOTA"],
  ["CREDIT_BALANCE_EXHAUSTED", "QUOTA"],
  ["INSUFFICIENT_BALANCE", "QUOTA"],
  ["INSUFFICIENT_CREDIT", "QUOTA"],
  ["INSUFFICIENT_QUOTA", "QUOTA"],
  ["ORGANIZATION_SPEND_LIMIT_EXCEEDED", "QUOTA"],
  ["ORGANIZATION_USAGE_LIMIT_EXCEEDED", "QUOTA"],
  ["PAYMENT_REQUIRED", "QUOTA"],
  ["PROJECT_SPEND_LIMIT_EXCEEDED", "QUOTA"],
  ["RATE_LIMIT_EXCEEDED", "RATE_LIMIT"],
  ["RATE_LIMITED", "RATE_LIMIT"],
  ["TOO_MANY_REQUESTS", "RATE_LIMIT"],
  ["PROVIDER_UNAVAILABLE", "SERVER"],
  ["SERVICE_UNAVAILABLE", "SERVER"],
  ["UPSTREAM_UNAVAILABLE", "SERVER"],
  ["ECONNABORTED", "TRANSPORT"],
  ["ECONNREFUSED", "TRANSPORT"],
  ["ECONNRESET", "TRANSPORT"],
  ["ENETDOWN", "TRANSPORT"],
  ["ENETUNREACH", "TRANSPORT"],
  ["EPIPE", "TRANSPORT"],
  ["ETIMEDOUT", "TIMEOUT"],
  ["LLM_STREAM_IDLE_TIMEOUT", "TIMEOUT"]
]);

const modelConfigurationCodes = new Set([
  "DISCOVERY_FAILED",
  "DISCOVERY_UNSUPPORTED",
  "INVALID_ARGS",
  "INVALID_CATALOG",
  "INVALID_DIRECTORY",
  "INVALID_DISCOVERY",
  "INVALID_MODEL_CONTEXT",
  "INVALID_MODEL_INFO",
  "INVALID_MODEL_MAX_TOKENS",
  "INVALID_MODEL_REASONING",
  "INVALID_OPTION",
  "INVALID_PREPARED_CALL",
  "NO_CREDENTIAL_STORE",
  "NO_DISCOVERY",
  "UNKNOWN_MODEL",
  "UNSTORABLE_PROVIDER_ID",
  "UNSUPPORTED_CONTENT",
  "UNSUPPORTED_OPTION",
  "UNSUPPORTED_REASONING_EFFORT"
]);

const credentialRecoveryCodes = new Set([
  "CREDENTIAL_RECORD_PROTOCOL_FAILED",
  "CREDENTIAL_STATE_UNAVAILABLE",
  "CREDENTIAL_STATE_UNSAFE",
  "CREDENTIAL_VERIFICATION_FAILED"
]);

function ownData(value, key) {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function canonicalCode(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) return "";
  if (!/^[A-Za-z0-9_. -]+$/u.test(value)) return "";
  return value.trim().toUpperCase().replace(/[. -]+/gu, "_");
}

function failureFacts(value) {
  const carried = ownData(value, "failure");
  const source = (typeof carried === "object" && carried !== null) ? carried : value;
  const code = canonicalCode(ownData(source, "code") ?? ownData(value, "code"));
  const statusValue = ownData(source, "status");
  const retryValue = ownData(source, "providerRetryAfterMs");
  return Object.freeze({
    code,
    status: Number.isInteger(statusValue) && statusValue >= 100 && statusValue <= 599
      ? statusValue
      : undefined,
    providerRetryAfterMs: Number.isFinite(retryValue)
      && retryValue > 0 && retryValue <= maximumRetryAfterMilliseconds
      ? retryValue
      : undefined
  });
}

function safeFailureTemplate(facts, aborted) {
  if (aborted || facts.code === "ABORTED") return safeFailures.ABORTED;
  if (facts.code === "MISSING_CREDENTIAL") return safeFailures.MISSING_CREDENTIAL;
  if (facts.code === "KEYCHAIN_AUTHORIZATION_REQUIRED") return safeFailures.KEYCHAIN_AUTHORIZATION_REQUIRED;
  if (facts.code === "CREDENTIAL_RECOVERY_REQUIRED") return safeFailures.CREDENTIAL_RECOVERY_REQUIRED;
  if (facts.code === "CREDENTIAL_TRANSACTION_BUSY") return safeFailures.CREDENTIAL_TRANSACTION_BUSY;
  if (credentialRecoveryCodes.has(facts.code)) return safeFailures.CREDENTIAL_RECOVERY_REQUIRED;
  if (facts.code === "INVALID_CREDENTIAL" || aliases.get(facts.code) === "INVALID_CREDENTIAL") {
    return safeFailures.INVALID_CREDENTIAL;
  }
  if (facts.status === 401 || facts.status === 403) return safeFailures.AUTH;
  if (facts.code === "AUTH" || aliases.get(facts.code) === "AUTH") return safeFailures.AUTH;
  if (facts.status === 402 || facts.code === "QUOTA" || aliases.get(facts.code) === "QUOTA") return safeFailures.QUOTA;
  if (facts.status === 429 || facts.code === "RATE_LIMIT" || aliases.get(facts.code) === "RATE_LIMIT") {
    return safeFailures.RATE_LIMIT;
  }
  if ((facts.status !== undefined && facts.status >= 500)
    || facts.code === "SERVER" || aliases.get(facts.code) === "SERVER") return safeFailures.SERVER;
  if (facts.code === "TRANSPORT" || aliases.get(facts.code) === "TRANSPORT") return safeFailures.TRANSPORT;
  if (facts.code === "TIMEOUT" || aliases.get(facts.code) === "TIMEOUT") return safeFailures.TIMEOUT;
  if (facts.code === "STREAM_CLOSED") return safeFailures.STREAM_CLOSED;
  if (facts.code === "EMPTY_RESPONSE") return safeFailures.EMPTY_RESPONSE;
  if (facts.code === "NO_ADAPTER") return safeFailures.NO_ADAPTER;
  if (facts.code === "CONTEXT_WINDOW_EXCEEDED") return safeFailures.CONTEXT_WINDOW_EXCEEDED;
  if (modelConfigurationCodes.has(facts.code)) return safeFailures.MODEL_CONFIGURATION;
  return safeFailures.UNKNOWN;
}

function sanitizeProviderFailure(value, { aborted = false } = {}) {
  const facts = failureFacts(value);
  const template = safeFailureTemplate(facts, aborted);
  return Object.freeze({
    message: template.message,
    code: template.code,
    ...(facts.status === undefined ? {} : { status: facts.status }),
    ...(facts.providerRetryAfterMs === undefined ? {} : {
      providerRetryAfterMs: facts.providerRetryAfterMs
    })
  });
}

function sanitizeFinishChunk(chunk) {
  if (ownData(chunk, "type") !== "finish") return chunk;
  const reason = ownData(chunk, "reason");
  const kind = ownData(reason, "kind");
  if (kind !== "error" && kind !== "aborted") return chunk;
  return Object.freeze({
    type: "finish",
    reason: Object.freeze({
      kind,
      failure: sanitizeProviderFailure(ownData(reason, "failure"), { aborted: kind === "aborted" })
    })
  });
}

function sanitizeCancellationCause(value) {
  const kind = ownData(value, "kind");
  if (kind === "user" || kind === "parent" || kind === "disposed" || kind === "legacy") {
    return Object.freeze({ kind });
  }
  if (kind === "hook") {
    return Object.freeze({ kind: "hook", reason: "A background policy stopped this task." });
  }
  return Object.freeze({ kind: "legacy" });
}

function sanitizePersistedEvent(event) {
  const type = ownData(event, "type");
  const data = ownData(event, "data");
  if (typeof data !== "object" || data === null) return event;
  if (type === "assistant/chunk") {
    const chunk = ownData(data, "chunk");
    const safeChunk = sanitizeFinishChunk(chunk);
    return safeChunk === chunk ? event : { ...event, data: { ...data, chunk: safeChunk } };
  }
  if (type === "llm/retry") {
    return { ...event, data: { ...data, failure: sanitizeProviderFailure(ownData(data, "failure")) } };
  }
  if (type === "turn/end") {
    const reason = ownData(data, "reason");
    const kind = ownData(reason, "kind");
    if (kind !== "error" && kind !== "aborted") return event;
    return {
      ...event,
      data: {
        ...data,
        reason: kind === "error"
          ? { kind, error: sanitizeProviderFailure(ownData(reason, "error")) }
          : { kind, reason: sanitizeCancellationCause(ownData(reason, "reason")) }
      }
    };
  }
  if (type === "compaction/end" && typeof ownData(data, "error") === "string") {
    return { ...event, data: { ...data, error: "Compaction could not complete safely." } };
  }
  return event;
}

function sanitizedHistoryFailureReply(reply) {
  const type = ownData(reply, "type");
  const rpcId = ownData(reply, "rpcId");
  return {
    ...(type === "response" ? { type } : {}),
    ...(typeof rpcId === "string" && rpcId.length > 0 && rpcId.length <= 128
      && /^[A-Za-z0-9._:-]+$/u.test(rpcId) ? { rpcId } : {}),
    result: {
      ok: false,
      error: {
        code: "internal",
        message: "Fulmar could not load this task history safely.",
        details: {}
      }
    }
  };
}

function sanitizeHistoryReply(reply) {
  const result = ownData(reply, "result");
  if (ownData(result, "ok") !== true) return sanitizedHistoryFailureReply(reply);
  const value = ownData(result, "value");
  const events = ownData(value, "events");
  if (!Array.isArray(events)) return sanitizedHistoryFailureReply(reply);
  return {
    ...reply,
    result: {
      ...result,
      value: {
        ...value,
        events: events.map((entry) => ({
          ...entry,
          event: sanitizePersistedEvent(ownData(entry, "event"))
        }))
      }
    }
  };
}

function installHistoryBoundary(ctx) {
  const targets = [ctx.apiProxy?.sessions, ctx.apiProxy?.subagents];
  if (targets.some((target) => target === undefined || typeof target.history !== "function")) {
    throw new Error("Fulmar could not bind the provider-history privacy boundary.");
  }
  const restores = [];
  for (const target of targets) {
    const prior = target.history;
    const replacement = async function localHarnessSanitizedHistory(...args) {
      return sanitizeHistoryReply(await Reflect.apply(prior, this, args));
    };
    target.history = replacement;
    restores.push(() => {
      if (target.history === replacement) target.history = prior;
    });
  }
  ctx.effect(() => () => {
    for (const restore of restores.reverse()) restore();
  }, "local-harness: remove provider-history privacy boundary");
}

function installRawSessionExportBoundary(ctx) {
  const owner = ctx.apiProxy?.downloads;
  const prior = owner?.sessionLog;
  if (owner === undefined || typeof prior !== "function") {
    throw new Error("Fulmar could not bind the raw-session-export privacy boundary.");
  }
  const replacement = async function localHarnessBlockedRawSessionExport() {
    return new Response(
      "Raw Harness-log export is unavailable because retained logs can contain private provider diagnostics. Use Fulmar Task History transcript export instead.",
      {
        status: 409,
        headers: {
          "cache-control": "no-store",
          "content-type": "text/plain; charset=utf-8"
        }
      }
    );
  };
  owner.sessionLog = replacement;
  ctx.effect(() => () => {
    if (owner.sessionLog === replacement) owner.sessionLog = prior;
  }, "local-harness: remove raw-session-export privacy boundary");
}

function installPreparationBoundary(ctx) {
  const owner = ctx.llm;
  const prior = owner?.prepareCall;
  if (owner === undefined || typeof prior !== "function") {
    throw new Error("Fulmar could not bind the model-preparation privacy boundary.");
  }
  const hadOwn = Object.hasOwn(owner, "prepareCall");
  const replacement = async function localHarnessSanitizedPreparation(config, signal) {
    try {
      return await Reflect.apply(prior, this, [config, signal]);
    } catch (error) {
      throw safeLlmError(error, signal?.aborted === true);
    }
  };
  owner.prepareCall = replacement;
  ctx.effect(() => () => {
    if (owner.prepareCall !== replacement) return;
    if (hadOwn) owner.prepareCall = prior;
    else delete owner.prepareCall;
  }, "local-harness: remove model-preparation privacy boundary");
}

function safeLlmError(value, aborted) {
  const failure = sanitizeProviderFailure(value, { aborted });
  return new LlmError(failure.message, failure.code, {
    ...(failure.status === undefined ? {} : { status: failure.status }),
    ...(failure.providerRetryAfterMs === undefined ? {} : {
      providerRetryAfterMs: failure.providerRetryAfterMs
    })
  });
}

function sanitizeProviderStream(options, next) {
  return (async function* () {
    try {
      for await (const chunk of next()) yield sanitizeFinishChunk(chunk);
    } catch (error) {
      throw safeLlmError(error, options?.signal?.aborted === true);
    }
  })();
}

function apply(ctx) {
  installHistoryBoundary(ctx);
  installRawSessionExportBoundary(ctx);
  installPreparationBoundary(ctx);
  ctx.on("llm/stream", (options, next) => sanitizeProviderStream(options, next), {
    global: true,
    prepend: true
  });
}

export {
  apply,
  failureFacts,
  inject,
  maximumRetryAfterMilliseconds,
  name,
  providerFailureTaxonomyVersion,
  safeFailures,
  sanitizeFinishChunk,
  sanitizeHistoryReply,
  sanitizePersistedEvent,
  sanitizeProviderFailure,
  sanitizeProviderStream
};
