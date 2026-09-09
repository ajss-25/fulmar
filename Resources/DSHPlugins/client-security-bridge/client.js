window.__ModuleLoader__.load({
  id: "@local-harness/dsh-client-security-bridge",
  factory: () => {
    const module = { exports: {} };
    const exports = module.exports;
    const inject = ["sessions", "workspaces", "conversation"];
    const automaticContinuationCopy = Object.freeze({
      "Output token limit reached": "Continuing automatically",
      "The reply was cut off; earlier output is preserved in the conversation. Send \"continue\" to let the model resume.":
        "The completed segment is preserved. Fulmar is continuing the unfinished task automatically, with a bounded safety limit. You can stop it at any time.",
      "已达到输出 token 上限": "正在自动继续",
      "回答被截断，已有输出保留在对话中。发送“继续”可让模型接着输出。":
        "已保留完成的内容。Fulmar 正在有界限的安全机制下自动继续未完成的任务，您可随时停止。"
    });
    // Kept deliberately duplicated in this dependency-free browser bundle.
    // ProviderFailureSanitizerTests pins semantic parity with the host module.
    const providerFailureTaxonomyVersion = 1;
    const maximumRetryAfterMilliseconds = 86_400_000;
    const maximumResidentSessionsToResanitize = 64;
    const safeFailureCopy = Object.freeze({
      ABORTED: Object.freeze({ code: "ABORTED", message: "The model request was cancelled." }),
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
      TIMEOUT: Object.freeze({ code: "TIMEOUT", message: "The model request timed out. Try again." }),
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
    const safeFailureAliases = new Map([
      ["AUTH_ERROR", "AUTH"], ["AUTH_FAILED", "AUTH"],
      ["AUTHENTICATION_ERROR", "AUTH"], ["AUTHENTICATION_FAILED", "AUTH"],
      ["CREDENTIAL_REJECTED", "AUTH"], ["UNAUTHORIZED", "AUTH"],
      ["INVALID_API_KEY", "INVALID_CREDENTIAL"],
      ["BILLING_ERROR", "QUOTA"], ["CREDIT_BALANCE_EXHAUSTED", "QUOTA"],
      ["INSUFFICIENT_BALANCE", "QUOTA"], ["INSUFFICIENT_CREDIT", "QUOTA"],
      ["INSUFFICIENT_QUOTA", "QUOTA"], ["ORGANIZATION_SPEND_LIMIT_EXCEEDED", "QUOTA"],
      ["ORGANIZATION_USAGE_LIMIT_EXCEEDED", "QUOTA"], ["PAYMENT_REQUIRED", "QUOTA"],
      ["PROJECT_SPEND_LIMIT_EXCEEDED", "QUOTA"],
      ["RATE_LIMIT_EXCEEDED", "RATE_LIMIT"], ["RATE_LIMITED", "RATE_LIMIT"],
      ["TOO_MANY_REQUESTS", "RATE_LIMIT"],
      ["PROVIDER_UNAVAILABLE", "SERVER"], ["SERVICE_UNAVAILABLE", "SERVER"],
      ["UPSTREAM_UNAVAILABLE", "SERVER"],
      ["ECONNABORTED", "TRANSPORT"], ["ECONNREFUSED", "TRANSPORT"],
      ["ECONNRESET", "TRANSPORT"], ["ENETDOWN", "TRANSPORT"],
      ["ENETUNREACH", "TRANSPORT"], ["EPIPE", "TRANSPORT"],
      ["ETIMEDOUT", "TIMEOUT"], ["LLM_STREAM_IDLE_TIMEOUT", "TIMEOUT"]
    ]);
    const credentialRecoveryCodes = new Set([
      "CREDENTIAL_RECORD_PROTOCOL_FAILED", "CREDENTIAL_STATE_UNAVAILABLE",
      "CREDENTIAL_STATE_UNSAFE", "CREDENTIAL_VERIFICATION_FAILED"
    ]);
    const modelConfigurationCodes = new Set([
      "DISCOVERY_FAILED", "DISCOVERY_UNSUPPORTED", "INVALID_ARGS", "INVALID_CATALOG",
      "INVALID_DIRECTORY", "INVALID_DISCOVERY", "INVALID_MODEL_CONTEXT", "INVALID_MODEL_INFO",
      "INVALID_MODEL_MAX_TOKENS", "INVALID_MODEL_REASONING", "INVALID_OPTION",
      "INVALID_PREPARED_CALL", "NO_CREDENTIAL_STORE", "NO_DISCOVERY", "UNKNOWN_MODEL",
      "UNSTORABLE_PROVIDER_ID", "UNSUPPORTED_CONTENT", "UNSUPPORTED_OPTION",
      "UNSUPPORTED_REASONING_EFFORT"
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

    function boundedDataMethod(value, key) {
      if ((typeof value !== "object" && typeof value !== "function") || value === null) return undefined;
      let owner = value;
      // Pinned DSH instances keep these methods on their immediate class
      // prototype. Inspect at most that one prototype, and never invoke an
      // accessor supplied by persisted or provider-controlled data.
      for (let depth = 0; depth <= 1 && owner !== null; depth += 1) {
        try {
          const descriptor = Object.getOwnPropertyDescriptor(owner, key);
          if (descriptor !== undefined) {
            return Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
          }
          owner = Object.getPrototypeOf(owner);
        } catch {
          return undefined;
        }
      }
      return undefined;
    }

    function canonicalFailureCode(value) {
      if (typeof value !== "string" || value.length === 0 || value.length > 128) return "";
      if (!/^[A-Za-z0-9_. -]+$/u.test(value)) return "";
      return value.trim().toUpperCase().replace(/[. -]+/gu, "_");
    }

    function clientFailureFacts(value) {
      const carried = ownData(value, "failure");
      const source = typeof carried === "object" && carried !== null ? carried : value;
      const code = canonicalFailureCode(ownData(source, "code") ?? ownData(value, "code"));
      const statusValue = ownData(source, "status");
      const retryValue = ownData(source, "providerRetryAfterMs");
      return {
        code,
        status: Number.isInteger(statusValue) && statusValue >= 100 && statusValue <= 599
          ? statusValue : undefined,
        providerRetryAfterMs: Number.isFinite(retryValue)
          && retryValue > 0 && retryValue <= maximumRetryAfterMilliseconds
          ? retryValue : undefined
      };
    }

    function clientFailureTemplate(facts, aborted) {
      if (aborted || facts.code === "ABORTED") return safeFailureCopy.ABORTED;
      if (facts.code === "MISSING_CREDENTIAL") return safeFailureCopy.MISSING_CREDENTIAL;
      if (facts.code === "KEYCHAIN_AUTHORIZATION_REQUIRED") return safeFailureCopy.KEYCHAIN_AUTHORIZATION_REQUIRED;
      if (facts.code === "CREDENTIAL_RECOVERY_REQUIRED") return safeFailureCopy.CREDENTIAL_RECOVERY_REQUIRED;
      if (facts.code === "CREDENTIAL_TRANSACTION_BUSY") return safeFailureCopy.CREDENTIAL_TRANSACTION_BUSY;
      if (credentialRecoveryCodes.has(facts.code)) return safeFailureCopy.CREDENTIAL_RECOVERY_REQUIRED;
      if (facts.code === "INVALID_CREDENTIAL" || safeFailureAliases.get(facts.code) === "INVALID_CREDENTIAL") {
        return safeFailureCopy.INVALID_CREDENTIAL;
      }
      if (facts.status === 401 || facts.status === 403) return safeFailureCopy.AUTH;
      if (facts.code === "AUTH" || safeFailureAliases.get(facts.code) === "AUTH") return safeFailureCopy.AUTH;
      if (facts.status === 402 || facts.code === "QUOTA" || safeFailureAliases.get(facts.code) === "QUOTA") {
        return safeFailureCopy.QUOTA;
      }
      if (facts.status === 429 || facts.code === "RATE_LIMIT"
        || safeFailureAliases.get(facts.code) === "RATE_LIMIT") return safeFailureCopy.RATE_LIMIT;
      if ((facts.status !== undefined && facts.status >= 500) || facts.code === "SERVER"
        || safeFailureAliases.get(facts.code) === "SERVER") return safeFailureCopy.SERVER;
      if (facts.code === "TRANSPORT" || safeFailureAliases.get(facts.code) === "TRANSPORT") {
        return safeFailureCopy.TRANSPORT;
      }
      if (facts.code === "TIMEOUT" || safeFailureAliases.get(facts.code) === "TIMEOUT") {
        return safeFailureCopy.TIMEOUT;
      }
      if (facts.code === "STREAM_CLOSED") return safeFailureCopy.STREAM_CLOSED;
      if (facts.code === "EMPTY_RESPONSE") return safeFailureCopy.EMPTY_RESPONSE;
      if (facts.code === "NO_ADAPTER") return safeFailureCopy.NO_ADAPTER;
      if (facts.code === "CONTEXT_WINDOW_EXCEEDED") return safeFailureCopy.CONTEXT_WINDOW_EXCEEDED;
      if (modelConfigurationCodes.has(facts.code)) return safeFailureCopy.MODEL_CONFIGURATION;
      return safeFailureCopy.UNKNOWN;
    }

    function sanitizeClientFailure(value, { aborted = false } = {}) {
      const facts = clientFailureFacts(value);
      const template = clientFailureTemplate(facts, aborted);
      return Object.freeze({
        message: template.message,
        code: template.code,
        ...(facts.status === undefined ? {} : { status: facts.status }),
        ...(facts.providerRetryAfterMs === undefined ? {} : {
          providerRetryAfterMs: facts.providerRetryAfterMs
        })
      });
    }

    function sanitizeClientFinishChunk(chunk) {
      if (ownData(chunk, "type") !== "finish") return chunk;
      const reason = ownData(chunk, "reason");
      const kind = ownData(reason, "kind");
      if (kind !== "error" && kind !== "aborted") return chunk;
      return {
        type: "finish",
        reason: {
          kind,
          failure: sanitizeClientFailure(ownData(reason, "failure"), { aborted: kind === "aborted" })
        }
      };
    }

    function sanitizeCancellationCause(value) {
      const kind = ownData(value, "kind");
      if (kind === "user" || kind === "parent" || kind === "disposed" || kind === "legacy") {
        return { kind };
      }
      if (kind === "hook") return { kind: "hook", reason: "A background policy stopped this task." };
      return { kind: "legacy" };
    }

    function sanitizeSessionEvent(event) {
      const type = ownData(event, "type");
      const data = ownData(event, "data");
      if (typeof data !== "object" || data === null) return event;
      if (type === "assistant/chunk") {
        const chunk = ownData(data, "chunk");
        const safeChunk = sanitizeClientFinishChunk(chunk);
        return safeChunk === chunk ? event : { ...event, data: { ...data, chunk: safeChunk } };
      }
      if (type === "llm/retry") {
        return { ...event, data: { ...data, failure: sanitizeClientFailure(ownData(data, "failure")) } };
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
              ? { kind, error: sanitizeClientFailure(ownData(reason, "error")) }
              : { kind, reason: sanitizeCancellationCause(ownData(reason, "reason")) }
          }
        };
      }
      if (type === "compaction/end" && typeof ownData(data, "error") === "string") {
        return { ...event, data: { ...data, error: "Compaction could not complete safely." } };
      }
      return event;
    }

    function sanitizeMuxEnvelope(envelope) {
      const payload = ownData(envelope, "payload");
      if (ownData(payload, "type") !== "session/event") return envelope;
      return { ...envelope, payload: { ...payload, event: sanitizeSessionEvent(ownData(payload, "event")) } };
    }

    function sanitizeHostEnvelope(envelope) {
      const payload = ownData(envelope, "payload");
      if (ownData(payload, "type") !== "host/agent-error") return envelope;
      return {
        ...envelope,
        payload: {
          ...payload,
          message: safeFailureCopy.UNKNOWN.message
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
            events: events.map((entry) => {
              const event = ownData(entry, "event");
              return { ...entry, event: sanitizeSessionEvent(event) };
            })
          }
        }
      };
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

    function installInFlightOlderPageBoundary(
      session,
      conversation,
      resync,
      { registerRestore, isActive }
    ) {
      if (ownData(session, "loadingOlder") !== true) return;
      const prior = boundedDataMethod(conversation, "prepend");
      if (typeof prior !== "function") {
        throw new Error("Fulmar could not guard a pre-bridge history page safely.");
      }
      const ownDescriptor = Object.getOwnPropertyDescriptor(conversation, "prepend");
      let installed = true;
      let timer;
      let polls = 0;
      const restore = () => {
        if (!installed) return;
        installed = false;
        if (timer !== undefined) clearTimeout(timer);
        const current = Object.getOwnPropertyDescriptor(conversation, "prepend");
        if (current?.value !== replacement) return;
        if (ownDescriptor === undefined) delete conversation.prepend;
        else Object.defineProperty(conversation, "prepend", ownDescriptor);
      };
      const reload = () => {
        Promise.resolve().then(() => {
          if (!isActive()) return;
          const task = Reflect.apply(resync, session, []);
          Promise.resolve(task).catch(() => {
            console.error("Fulmar could not reload a sanitized historical task.");
          });
        });
      };
      const replacement = function localHarnessSanitizedLegacyPrepend(entries, hasMore) {
        try {
          if (!Array.isArray(entries)) {
            throw new Error("Fulmar refused an invalid pre-bridge history page.");
          }
          const safeEntries = entries.map((entry) => ({
            event: sanitizeSessionEvent(ownData(entry, "event")),
            ...(ownData(entry, "view") === undefined ? {} : { view: ownData(entry, "view") })
          }));
          return Reflect.apply(prior, this, [safeEntries, hasMore === true]);
        } finally {
          restore();
          reload();
        }
      };
      Object.defineProperty(conversation, "prepend", {
        configurable: true,
        enumerable: ownDescriptor?.enumerable ?? false,
        writable: true,
        value: replacement
      });
      registerRestore(restore);

      // Error/empty-return paths can complete without calling prepend. Polling
      // is bounded; after the bound the passive one-shot method guard remains
      // until completion or bridge disposal and consumes no further resources.
      const poll = () => {
        if (!installed) return;
        if (ownData(session, "loadingOlder") !== true) {
          restore();
          return;
        }
        polls += 1;
        if (polls < 600) timer = setTimeout(poll, 25);
      };
      timer = setTimeout(poll, 25);
    }

    function resanitizeResidentSessions(manager, options = {}) {
      const registerRestore = typeof options.registerRestore === "function"
        ? options.registerRestore
        : () => {};
      const isActive = typeof options.isActive === "function" ? options.isActive : () => true;
      const resident = ownData(manager, "sessions");
      if (resident === undefined) return 0;
      let size;
      let iterator;
      try {
        const sizeGetter = Object.getOwnPropertyDescriptor(Map.prototype, "size")?.get;
        if (typeof sizeGetter !== "function") throw new TypeError("Map size is unavailable");
        size = Reflect.apply(sizeGetter, resident, []);
        iterator = Reflect.apply(Map.prototype.values, resident, []);
      } catch {
        throw new Error("Fulmar refused an invalid resident-session privacy repair.");
      }
      if (!Number.isSafeInteger(size) || size < 0 || size > maximumResidentSessionsToResanitize) {
        throw new Error("Fulmar refused an unbounded resident-session privacy repair.");
      }
      let repaired = 0;
      for (const session of iterator) {
        if (repaired >= maximumResidentSessionsToResanitize) {
          throw new Error("Fulmar refused an unbounded resident-session privacy repair.");
        }
        if (ownData(session, "openState") === "cold") continue;
        const conversation = ownData(session, "conversation");
        const replaceWindow = boundedDataMethod(conversation, "replaceWindow");
        const resync = boundedDataMethod(session, "resync");
        if (typeof replaceWindow !== "function" || typeof resync !== "function") {
          throw new Error("Fulmar could not clear a pre-bridge conversation window safely.");
        }
        installInFlightOlderPageBoundary(session, conversation, resync, { registerRestore, isActive });
        // Clear the already-derived view synchronously. resync() immediately
        // invalidates an in-flight pre-bridge history request, and its replacement
        // request traverses the wrapped transport below.
        Reflect.apply(replaceWindow, conversation, [[], false]);
        const task = Reflect.apply(resync, session, []);
        Promise.resolve(task).catch(() => {
          console.error("Fulmar could not reload a sanitized historical task.");
        });
        repaired += 1;
      }
      return repaired;
    }

    function replacementContinuationCopy(text) {
      return Object.prototype.hasOwnProperty.call(automaticContinuationCopy, text)
        ? automaticContinuationCopy[text]
        : text;
    }

    function rewriteAutomaticContinuationCopy(root, documentObject = window.document) {
      if (root === undefined || root === null || documentObject === undefined) return 0;
      let rewritten = 0;
      const rewrite = (node) => {
        if (node?.nodeType !== 3 || typeof node.nodeValue !== "string") return;
        const replacement = replacementContinuationCopy(node.nodeValue);
        if (replacement === node.nodeValue) return;
        node.nodeValue = replacement;
        rewritten += 1;
      };
      rewrite(root);
      if (typeof documentObject.createTreeWalker !== "function") return rewritten;
      const walker = documentObject.createTreeWalker(root, 4);
      for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) rewrite(node);
      return rewritten;
    }

    function installAutomaticContinuationCopy() {
      const documentObject = window.document;
      const Observer = window.MutationObserver;
      if (documentObject?.documentElement === undefined || typeof Observer !== "function") return () => {};
      rewriteAutomaticContinuationCopy(documentObject.documentElement, documentObject);
      const observer = new Observer((records) => {
        for (const record of records) {
          if (record.type === "characterData") rewriteAutomaticContinuationCopy(record.target, documentObject);
          for (const node of record.addedNodes ?? []) rewriteAutomaticContinuationCopy(node, documentObject);
        }
      });
      observer.observe(documentObject.documentElement, {
        childList: true,
        characterData: true,
        subtree: true
      });
      return () => observer.disconnect();
    }

    async function prepareNativeTurn(sessionId, signal) {
      if (typeof sessionId !== "string" || sessionId.length === 0) {
        throw new Error("Fulmar cannot checkpoint an unidentified session.");
      }
      const handler = window.webkit?.messageHandlers?.localHarnessRecovery;
      if (handler === undefined || typeof handler.postMessage !== "function") {
        throw new Error("Fulmar native recovery is unavailable.");
      }
      if (signal?.aborted === true) throw signal.reason ?? new Error("Prompt cancelled.");
      const operationID = globalThis.crypto?.randomUUID?.();
      if (typeof operationID !== "string"
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(operationID)) {
        throw new Error("Fulmar could not allocate a recovery operation identity.");
      }
      // Queue native preparation before arming cancellation. If the signal
      // flips in the tiny interval after the initial check, the immediate
      // post-listener check below sends a cancellation for an operation that
      // native has already observed; cancellation can never be lost or arrive
      // only before its matching prepare request.
      const preparationPromise = Promise.resolve(handler.postMessage({
        version: 2,
        action: "prepare",
        operationID,
        sessionID: sessionId
      }));
      let abortListener;
      let abortSettled = false;
      const abortPromise = new Promise((_, reject) => {
        if (signal === undefined) return;
        abortListener = () => {
          if (abortSettled) return;
          abortSettled = true;
          // Posting the cancellation is intentionally independent of awaiting
          // the original reply. Native owns the Task and journal token, so an
          // abandoned browser promise cannot keep copying in the background.
          Promise.resolve(handler.postMessage({
            version: 2,
            action: "cancel",
            operationID
          })).catch(() => {});
          reject(signal.reason ?? new Error("Prompt cancelled."));
        };
        signal.addEventListener("abort", abortListener, { once: true });
        if (signal.aborted === true) abortListener();
      });
      let reply;
      try {
        reply = await Promise.race([
          preparationPromise,
          abortPromise
        ]);
      } finally {
        if (signal !== undefined && abortListener !== undefined) {
          signal.removeEventListener("abort", abortListener);
        }
      }
      if (typeof reply !== "object" || reply === null || reply.ok !== true) {
        throw new Error("Fulmar did not confirm a recovery point.");
      }
      if (reply.mode !== "protected" && reply.mode !== "readOnly") {
        throw new Error("Fulmar returned an invalid recovery protection mode.");
      }
      return Object.freeze({
        mode: reply.mode,
        message: typeof reply.message === "string" ? reply.message : undefined
      });
    }

    async function allocateNativeSession() {
      const handler = window.webkit?.messageHandlers?.localHarnessPerformance;
      if (handler === undefined || typeof handler.postMessage !== "function") {
        throw new Error("Fulmar native performance policy is unavailable.");
      }
      const reply = await handler.postMessage({ version: 1 });
      if (typeof reply !== "object" || reply === null || reply.ok !== true
        || typeof reply.sessionID !== "string" || reply.sessionID.length === 0
        || typeof reply.workspacePath !== "string" || reply.workspacePath.length === 0) {
        throw new Error("Fulmar did not provide a performance-bound session identity and approved Workspace.");
      }
      return Object.freeze({ sessionID: reply.sessionID, workspacePath: reply.workspacePath });
    }

    function waitForCurrent(sessions, expected, timeoutMilliseconds = 15_000) {
      if (sessions.list.getSnapshot().current === expected) return Promise.resolve(expected);
      return new Promise((resolve, reject) => {
        let settled = false;
        let unsubscribe = () => {};
        const finish = (error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          unsubscribe();
          if (error === undefined) resolve(expected);
          else reject(error);
        };
        const check = () => {
          if (sessions.list.getSnapshot().current === expected) finish();
        };
        const timer = setTimeout(() => {
          finish(new Error("Fulmar could not confirm the new session selection."));
        }, timeoutMilliseconds);
        unsubscribe = sessions.list.subscribe(check);
        check();
      });
    }

    function approvedWorkspace(workspaces, workspacePath) {
      const workspaceState = workspaces.list.getSnapshot();
      if (workspaceState.baselinesReady !== true) return undefined;
      return workspaceState.items.find((workspace) => workspace.path === workspacePath);
    }

    function waitForWorkspaceBaseline(workspaces, timeoutMilliseconds = 15_000) {
      if (workspaces.list.getSnapshot().baselinesReady === true) return Promise.resolve();
      return new Promise((resolve, reject) => {
        let settled = false;
        let unsubscribe = () => {};
        const finish = (error) => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          clearInterval(poll);
          unsubscribe();
          if (error === undefined) resolve();
          else reject(error);
        };
        const check = () => {
          if (workspaces.list.getSnapshot().baselinesReady === true) finish();
        };
        const deadline = setTimeout(() => {
          finish(new Error("Fulmar could not confirm the Workspace baseline for a fresh session."));
        }, timeoutMilliseconds);
        const poll = setInterval(check, 50);
        if (typeof workspaces.list.subscribe === "function") unsubscribe = workspaces.list.subscribe(check);
        check();
      });
    }

    async function ensureApprovedWorkspace(workspaces, workspacePath) {
      await waitForWorkspaceBaseline(workspaces);
      const existing = approvedWorkspace(workspaces, workspacePath);
      if (existing !== undefined) return existing;
      const created = await workspaces.create({ path: workspacePath });
      if (typeof created !== "object" || created === null
        || typeof created.workspaceId !== "string" || created.workspaceId.length === 0
        || created.path !== workspacePath) {
        throw new Error("Harness did not register the native-approved Workspace.");
      }
      return created;
    }

    function blankTopLevelSession(sessions, sessionId) {
      const summary = sessions.list.getSnapshot().byId[sessionId];
      return summary?.blank === true && summary.parentSessionId === undefined ? summary : undefined;
    }

    function waitForBlankTopLevelSession(sessions, sessionId, timeoutMilliseconds = 15_000) {
      if (blankTopLevelSession(sessions, sessionId) !== undefined) return Promise.resolve();
      return new Promise((resolve, reject) => {
        let settled = false;
        let unsubscribe = () => {};
        const finish = (error) => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          clearInterval(poll);
          unsubscribe();
          if (error === undefined) resolve();
          else reject(error);
        };
        const check = () => {
          if (blankTopLevelSession(sessions, sessionId) !== undefined) finish();
        };
        const deadline = setTimeout(() => {
          finish(new Error("Harness did not publish a blank top-level session."));
        }, timeoutMilliseconds);
        const poll = setInterval(check, 50);
        if (typeof sessions.list.subscribe === "function") unsubscribe = sessions.list.subscribe(check);
        check();
      });
    }

    function apply(ctx) {
      const sessions = ctx.sessions;
      const workspaces = ctx.workspaces;
      const conversation = ctx.conversation;
      let operation = null;
      let active = true;

      const existing = Object.getOwnPropertyDescriptor(window, "__localHarnessSecurityBridge");
      if (existing !== undefined) {
        throw new Error("Fulmar security bridge was already registered.");
      }

      const ownCreate = Object.prototype.hasOwnProperty.call(sessions, "create");
      const priorCreate = sessions.create;
      const ownSend = Object.prototype.hasOwnProperty.call(conversation, "send");
      const ownSendSession = Object.prototype.hasOwnProperty.call(conversation, "sendSession");
      const priorSend = conversation.send;
      const priorSendSession = conversation.sendSession;
      if (typeof priorCreate !== "function" || typeof workspaces.create !== "function"
        || typeof priorSend !== "function" || typeof priorSendSession !== "function") {
        throw new Error("Fulmar could not bind the Harness conversation checkpoint gate.");
      }
      const transportRestores = [];
      const wrapTransport = (owner, key, transform) => {
        if ((typeof owner !== "object" && typeof owner !== "function") || owner === null) return;
        const prior = owner[key];
        if (typeof prior !== "function") return;
        const own = Object.prototype.hasOwnProperty.call(owner, key);
        const replacement = async function localHarnessSanitizedTransport(...args) {
          return transform(await Reflect.apply(prior, this, args));
        };
        owner[key] = replacement;
        transportRestores.push(() => {
          if (owner[key] !== replacement) return;
          if (own) owner[key] = prior;
          else delete owner[key];
        });
      };
      const wrapEnvelope = (owner, key, transform) => {
        if ((typeof owner !== "object" && typeof owner !== "function") || owner === null) return;
        const prior = owner[key];
        if (typeof prior !== "function") return;
        const own = Object.prototype.hasOwnProperty.call(owner, key);
        const replacement = function localHarnessSanitizedEnvelope(envelope) {
          return Reflect.apply(prior, this, [transform(envelope)]);
        };
        owner[key] = replacement;
        transportRestores.push(() => {
          if (owner[key] !== replacement) return;
          if (own) owner[key] = prior;
          else delete owner[key];
        });
      };
      // New failures are sanitized before DSH retry/persistence in the host
      // half. These transport guards also make old on-disk session rows safe
      // to render after an upgrade; they deliberately do not rewrite or erase
      // a user's historical session files.
      wrapEnvelope(sessions, "handleMuxEnvelope", sanitizeMuxEnvelope);
      wrapEnvelope(sessions, "handleHostEnvelope", sanitizeHostEnvelope);
      const sessionAPI = sessions.manager?.api;
      wrapTransport(sessionAPI?.sessions, "history", sanitizeHistoryReply);
      wrapTransport(sessionAPI?.subagents, "history", sanitizeHistoryReply);
      try {
        resanitizeResidentSessions(sessions.manager, {
          registerRestore(restore) { transportRestores.push(restore); },
          isActive() { return active; }
        });
      } catch (error) {
        active = false;
        for (const restore of transportRestores.reverse()) restore();
        throw error;
      }
      const removeAutomaticContinuationCopy = installAutomaticContinuationCopy();
      sessions.create = async function localHarnessPerformanceBoundCreate(options = {}) {
        if (typeof options !== "object" || options === null || Array.isArray(options)) {
          throw new Error("Fulmar rejected invalid session creation options.");
        }
        const allocation = await allocateNativeSession();
        const workspace = await ensureApprovedWorkspace(workspaces, allocation.workspacePath);
        // DSH can restore an older recent Workspace from its private state. It
        // is advisory only: every genuinely new browser session is rebound to
        // the native Workspace and its performance-scoped identity. Reuse is
        // accepted only for an already-blank session in that exact Workspace;
        // the Host performs the remaining blank-membership checks.
        const approvedReuse = options.reuseWorkspaceBlank === true
          && options.workspaceId === workspace.workspaceId
          && typeof options.sessionId === "string" && options.sessionId.length > 0;
        const effective = approvedReuse ? options : {
          workspaceId: workspace.workspaceId,
          sessionId: allocation.sessionID
        };
        return Reflect.apply(priorCreate, this, [effective]);
      };
      conversation.send = async function localHarnessCheckpointedSend(text) {
        const scoped = typeof this.scopedSession === "function" ? this.scopedSession("send") : undefined;
        if (scoped === undefined) throw new Error("Fulmar could not identify the prompt session.");
        await prepareNativeTurn(scoped.sessionId);
        return Reflect.apply(priorSend, this, [text]);
      };
      conversation.sendSession = async function localHarnessCheckpointedSendSession(
        session,
        text,
        imageIds,
        mode,
        signal
      ) {
        await prepareNativeTurn(session?.sessionId, signal);
        return Reflect.apply(priorSendSession, this, [session, text, imageIds, mode, signal]);
      };

      const bridge = Object.freeze({
        version: 2,
        startFreshSession() {
          if (operation !== null) return operation;
          operation = (async () => {
            const before = sessions.list.getSnapshot().current ?? null;
            // Deliberately call sessions.create directly and omit
            // reuseWorkspaceBlank. workspaces.startSession/connectWorkspace may
            // adopt an old blank session, which is not a fresh-session proof.
            const created = await sessions.create();
            if (typeof created !== "string" || created.length === 0 || created === before) {
              throw new Error("Harness did not create a distinct fresh session.");
            }
            await waitForBlankTopLevelSession(sessions, created);
            sessions.open(created);
            const current = await waitForCurrent(sessions, created);
            return Object.freeze({ before, created, current });
          })().finally(() => {
            operation = null;
          });
          return operation;
        }
      });

      Object.defineProperty(window, "__localHarnessSecurityBridge", {
        configurable: true,
        enumerable: false,
        writable: false,
        value: bridge
      });
      ctx.effect(() => () => {
        active = false;
        removeAutomaticContinuationCopy();
        for (const restore of transportRestores.reverse()) restore();
        if (ownCreate) sessions.create = priorCreate;
        else delete sessions.create;
        if (ownSend) conversation.send = priorSend;
        else delete conversation.send;
        if (ownSendSession) conversation.sendSession = priorSendSession;
        else delete conversation.sendSession;
        const installed = Object.getOwnPropertyDescriptor(window, "__localHarnessSecurityBridge");
        if (installed?.value === bridge) delete window.__localHarnessSecurityBridge;
      }, "local-harness: remove native session bridge");
    }

    exports.apply = apply;
    exports.inject = inject;
    exports.replacementContinuationCopy = replacementContinuationCopy;
    exports.providerFailureTaxonomyVersion = providerFailureTaxonomyVersion;
    exports.rewriteAutomaticContinuationCopy = rewriteAutomaticContinuationCopy;
    exports.sanitizeClientFailure = sanitizeClientFailure;
    exports.sanitizeClientFinishChunk = sanitizeClientFinishChunk;
    exports.sanitizeSessionEvent = sanitizeSessionEvent;
    exports.sanitizeMuxEnvelope = sanitizeMuxEnvelope;
    exports.sanitizeHostEnvelope = sanitizeHostEnvelope;
    exports.sanitizeHistoryReply = sanitizeHistoryReply;
    exports.resanitizeResidentSessions = resanitizeResidentSessions;
    return module.exports;
  }
});
