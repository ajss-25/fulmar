import assert from "node:assert/strict";
import { randomUUID as systemRandomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import test, { after } from "node:test";
import { pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";

const bundleURL = pathToFileURL(new URL("../../Resources/DSHPlugins/client-security-bridge/client.js", import.meta.url).pathname);
const bundleSource = readFileSync(bundleURL, "utf8");
const pinnedClientRuntimeSource = readFileSync(
  new URL("../../VendorRuntime/node_modules/@deepseek-ai/dsh-client-runtime/lib/client.js", import.meta.url),
  "utf8"
);
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const previousWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");

after(() => {
  if (previousWindowDescriptor) Object.defineProperty(globalThis, "window", previousWindowDescriptor);
  else Reflect.deleteProperty(globalThis, "window");
});

async function loadPlugin() {
  let registration;
  globalThis.window = {
    __ModuleLoader__: {
      load(value) { registration = value; }
    }
  };
  await import(`${bundleURL.href}?test=${Math.random()}`);
  assert.equal(registration.id, "@local-harness/dsh-client-security-bridge");
  return registration.factory(() => {
    throw new Error("The bridge bundle must have no external modules.");
  });
}

function loadPluginInBrowserRealm(options = {}) {
  let registration;
  const pageWindow = {
    __ModuleLoader__: {
      load(value) { registration = value; }
    },
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval
  };
  if (!Object.hasOwn(options, "crypto")) {
    pageWindow.crypto = Object.freeze({ randomUUID: systemRandomUUID });
  } else if (options.crypto !== undefined) {
    pageWindow.crypto = options.crypto;
  }
  pageWindow.window = pageWindow;
  assert.equal(runInNewContext(
    "window === globalThis && window.crypto === globalThis.crypto",
    pageWindow
  ), true);
  runInNewContext(bundleSource, pageWindow, {
    filename: "client-security-bridge-browser-realm.js",
    timeout: 2_000
  });
  assert.equal(registration.id, "@local-harness/dsh-client-security-bridge");
  return {
    pageWindow,
    plugin: registration.factory(() => {
      throw new Error("The bridge bundle must have no external modules.");
    })
  };
}

function loadPinnedRuntimeAndPluginInBrowserRealm() {
  const registrations = new Map();
  const pageWindow = {
    __ModuleLoader__: {
      load(value) { registrations.set(value.id, value); }
    },
    console,
    queueMicrotask,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    structuredClone,
    URL,
    AbortController,
    TextEncoder,
    TextDecoder,
    crypto: Object.freeze({ randomUUID: systemRandomUUID })
  };
  pageWindow.window = pageWindow;
  runInNewContext(pinnedClientRuntimeSource, pageWindow, {
    filename: "pinned-dsh-client-runtime-browser-realm.js",
    timeout: 5_000
  });
  runInNewContext(bundleSource, pageWindow, {
    filename: "client-security-bridge-pinned-runtime-realm.js",
    timeout: 2_000
  });
  const runtimeRegistration = registrations.get("@deepseek-ai/dsh-client-runtime");
  const bridgeRegistration = registrations.get("@local-harness/dsh-client-security-bridge");
  assert.ok(runtimeRegistration);
  assert.ok(bridgeRegistration);
  const runtime = runtimeRegistration.factory((id) => {
    if (id === "@deepseek-ai/cordis") {
      return { Service: class {}, Context: { filter: Symbol("filter") } };
    }
    if (id === "@deepseek-ai/dsh-client-ui-slots") {
      return { SlotCore: class { onMutate() {} } };
    }
    throw new Error(`Unexpected pinned client dependency: ${id}`);
  });
  const plugin = bridgeRegistration.factory((id) => {
    throw new Error(`The browser bridge unexpectedly requested: ${id}`);
  });
  return { pageWindow, plugin, runtime };
}

test("replaces the stock manual-continue notice with bounded automatic-continuation copy", async () => {
  const plugin = await loadPlugin();
  assert.equal(
    plugin.replacementContinuationCopy("Output token limit reached"),
    "Continuing automatically"
  );
  const hint = plugin.replacementContinuationCopy(
    "The reply was cut off; earlier output is preserved in the conversation. Send \"continue\" to let the model resume."
  );
  assert.match(hint, /Fulmar is continuing/u);
  assert.match(hint, /bounded safety limit/u);
  assert.doesNotMatch(hint, /Send "continue"/u);
  assert.equal(plugin.replacementContinuationCopy("unrelated copy"), "unrelated copy");
});

test("sanitizes legacy live and replayed provider failures before the conversation runtime sees them", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const secret = "sk-legacy-secret /Users/example/private https://provider.invalid DEEPSEEK_API_KEY request-secret";
  const rawFailure = {
    message: secret,
    code: "QUOTA",
    status: 429,
    providerRetryAfterMs: 2_000,
    requestId: secret
  };
  const historyReply = {
    rpcId: "history-1",
    result: {
      ok: true,
      value: {
        events: [{
          event: {
            type: "turn/end",
            seq: 4,
            time: 4,
            data: { turn: 1, reason: { kind: "error", error: rawFailure } }
          }
        }, {
          event: {
            type: "llm/retry",
            seq: 3,
            time: 3,
            data: { turn: 1, step: 1, failure: rawFailure }
          }
        }, {
          event: {
            type: "assistant/chunk",
            seq: 2,
            time: 2,
            data: {
              turn: 1,
              step: 1,
              chunk: { type: "finish", reason: { kind: "error", failure: rawFailure } }
            }
          }
        }, {
          event: {
            type: "compaction/end",
            seq: 1,
            time: 1,
            data: { compactionId: "compaction-1", turn: 1, error: secret }
          }
        }],
        hasMore: false
      }
    }
  };
  const sessionHistory = async () => historyReply;
  const subagentHistory = async () => historyReply;
  const muxFrames = [];
  const hostFrames = [];
  harness.ctx.sessions.manager = {
    api: {
      sessions: { history: sessionHistory },
      subagents: { history: subagentHistory }
    }
  };
  harness.ctx.sessions.handleMuxEnvelope = (envelope) => muxFrames.push(envelope);
  harness.ctx.sessions.handleHostEnvelope = (envelope) => hostFrames.push(envelope);
  plugin.apply(harness.ctx);

  const replay = await harness.ctx.sessions.manager.api.sessions.history({ sessionId: "old" });
  const replayText = JSON.stringify(replay);
  assert.doesNotMatch(replayText, /sk-legacy|\/Users\/example|provider\.invalid|DEEPSEEK_API_KEY|request-secret/u);
  const [turn, retry, chunk, compaction] = replay.result.value.events.map((entry) => entry.event);
  assert.equal(turn.data.reason.error.code, "QUOTA");
  assert.equal(turn.data.reason.error.message, "The provider account has insufficient credit or quota for this request.");
  assert.equal(retry.data.failure.code, "QUOTA");
  assert.equal(chunk.data.chunk.reason.failure.code, "QUOTA");
  assert.equal(compaction.data.error, "Compaction could not complete safely.");
  assert.doesNotMatch(JSON.stringify(await harness.ctx.sessions.manager.api.subagents.history({})), /sk-legacy/u);

  harness.ctx.sessions.handleMuxEnvelope({
    rpcId: "live-1",
    payload: {
      type: "session/event",
      sessionId: "old",
      event: {
        type: "turn/end",
        seq: 5,
        time: 5,
        data: { turn: 2, reason: { kind: "error", error: rawFailure } }
      }
    }
  });
  assert.equal(muxFrames[0].payload.event.data.reason.error.code, "QUOTA");
  assert.doesNotMatch(JSON.stringify(muxFrames), /sk-legacy|provider\.invalid|request-secret/u);

  harness.ctx.sessions.handleHostEnvelope({
    rpcId: "host-1",
    payload: { type: "host/agent-error", sessionId: "old", message: secret }
  });
  assert.equal(hostFrames[0].payload.message, "The model request failed. Try again or check Models & Providers.");
  assert.doesNotMatch(JSON.stringify(hostFrames), /sk-legacy|provider\.invalid|request-secret/u);

  const aborted = plugin.sanitizeSessionEvent({
    type: "turn/end",
    seq: 6,
    time: 6,
    data: {
      turn: 3,
      reason: { kind: "aborted", reason: { kind: "hook", reason: secret } }
    }
  });
  assert.deepEqual(aborted.data.reason, {
    kind: "aborted",
    reason: { kind: "hook", reason: "A background policy stopped this task." }
  });
  assert.doesNotMatch(JSON.stringify(aborted), /sk-legacy|provider\.invalid|request-secret/u);

  harness.dispose();
  assert.equal(harness.ctx.sessions.manager.api.sessions.history, sessionHistory);
  assert.equal(harness.ctx.sessions.manager.api.subagents.history, subagentHistory);
});

test("legacy display sanitizer uses finite diagnostics for every supported provider class", async () => {
  const plugin = await loadPlugin();
  const secret = "sk-browser-history-secret https://provider.invalid /Users/example/private request-id";
  const cases = [
    [{ code: "MISSING_CREDENTIAL" }, "MISSING_CREDENTIAL"],
    [{ code: "KEYCHAIN_AUTHORIZATION_REQUIRED" }, "KEYCHAIN_AUTHORIZATION_REQUIRED"],
    [{ code: "CREDENTIAL_RECOVERY_REQUIRED" }, "CREDENTIAL_RECOVERY_REQUIRED"],
    [{ code: "AUTH", status: 403 }, "AUTH"],
    [{ code: "QUOTA", status: 402 }, "QUOTA"],
    [{ code: "QUOTA", status: 429 }, "QUOTA"],
    [{ code: "RATE_LIMIT", status: 429 }, "RATE_LIMIT"],
    [{ code: "UNKNOWN", status: 503 }, "SERVER"],
    [{ code: "TRANSPORT" }, "TRANSPORT"],
    [{ code: "TIMEOUT" }, "TIMEOUT"],
    [{ code: "EMPTY_RESPONSE" }, "EMPTY_RESPONSE"],
    [{ code: "NO_ADAPTER" }, "NO_ADAPTER"],
    [{ code: "PROVIDER_SECRET_CODE" }, "UNKNOWN"]
  ];
  for (const [facts, expectedCode] of cases) {
    const safe = plugin.sanitizeClientFailure({
      ...facts,
      message: secret,
      requestId: secret
    });
    assert.equal(safe.code, expectedCode);
    assert.equal(Object.hasOwn(safe, "requestId"), false);
    assert.doesNotMatch(JSON.stringify(safe), /sk-browser|provider\.invalid|\/Users\/example|request-id/u);
  }
});

test("pinned DSH history and live-frame contracts retain the wrapped shapes and late method lookup", async () => {
  // These source assertions are an intentional compatibility tripwire. The
  // bridge reaches through a public JavaScript object graph that is not a
  // separately versioned DSH interface; an upstream layout/timing change must
  // fail qualification rather than silently bypass legacy-row sanitization.
  assert.match(pinnedClientRuntimeSource, /this\.manager = new SessionManager\(api, remote,/u);
  assert.match(pinnedClientRuntimeSource, /let \{ result \} = await this\.history\(\{ maxMessages: 50 \}\);/u);
  assert.match(pinnedClientRuntimeSource, /return this\.address === void 0 \? this\.api\.sessions\.history\(\{/u);
  assert.match(pinnedClientRuntimeSource, /\}\) : this\.api\.subagents\.history\(\{/u);
  assert.match(pinnedClientRuntimeSource, /onMuxEnvelope: \(envelope\) => \{\s*sessions\.handleMuxEnvelope\(envelope\);/u);
  assert.match(pinnedClientRuntimeSource, /onHostEnvelope: \(envelope\) => \{\s*sessions\.handleHostEnvelope\(envelope\);/u);
  assert.match(pinnedClientRuntimeSource, /async resync\(\) \{\s*if \(this\.openState === "cold"\) return;\s*this\.openGeneration\+\+;/u);
  assert.match(pinnedClientRuntimeSource, /if \(generation !== this\.openGeneration\) return;\s*if \(!result\.ok\)/u);
  assert.match(pinnedClientRuntimeSource, /async loadOlder\(\) \{[\s\S]*this\.loadingOlder = true;[\s\S]*this\.conversation\.prepend\(older\.map\(conversationInput\), this\.hasMore\);/u);

  const plugin = await loadPlugin();
  const harness = fixture();
  const delivered = [];
  harness.ctx.sessions.manager = {
    api: {
      sessions: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) },
      subagents: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) }
    }
  };
  harness.ctx.sessions.handleMuxEnvelope = (envelope) => delivered.push(envelope);
  // Mirrors DSH connection.start(): the callback closes over the SessionRuntime
  // object and resolves its method only when a later network frame arrives.
  const callbackRegisteredBeforeClientPlugin = (envelope) => {
    harness.ctx.sessions.handleMuxEnvelope(envelope);
  };
  plugin.apply(harness.ctx);
  callbackRegisteredBeforeClientPlugin({
    rpcId: "late-frame",
    payload: {
      type: "session/event",
      sessionId: "old",
      event: {
        type: "turn/end",
        seq: 1,
        time: 1,
        data: {
          turn: 1,
          reason: {
            kind: "error",
            error: {
              code: "AUTH",
              message: "sk-late-frame https://provider.invalid /Users/example/private",
              requestId: "request-secret"
            }
          }
        }
      }
    }
  });
  assert.equal(delivered[0].payload.event.data.reason.error.code, "AUTH");
  assert.doesNotMatch(JSON.stringify(delivered), /sk-late|provider\.invalid|\/Users\/example|request-secret/u);
  harness.dispose();
});

test("already-open pre-bridge windows are synchronously cleared and reloaded through sanitized history", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const order = [];
  const session = {
    openState: "open",
    conversation: {
      replaceWindow(entries, hasMore) {
        order.push(["clear", entries, hasMore]);
      }
    },
    async resync() {
      order.push(["resync"]);
    }
  };
  harness.ctx.sessions.manager = {
    sessions: new Map([["restored", session]]),
    api: {
      sessions: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) },
      subagents: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) }
    }
  };
  plugin.apply(harness.ctx);
  assert.deepEqual(order, [["clear", [], false], ["resync"]]);
  await Promise.resolve();
  harness.dispose();
});

test("pinned DSH resync invalidates a raw in-flight history pass and installs only the sanitized replacement", async () => {
  const { plugin, runtime } = loadPinnedRuntimeAndPluginInBrowserRealm();
  const secret = "sk-resync-secret https://provider.invalid /Users/example/private request-secret";
  const historyEntry = (seq) => ({
    event: {
      type: "turn/end",
      seq,
      time: seq,
      data: {
        turn: 1,
        reason: {
          kind: "error",
          error: { code: "AUTH", status: 403, message: secret, requestId: secret }
        }
      }
    }
  });
  let initial = true;
  const pending = [];
  const api = {
    sessions: {
      history() {
        if (initial) {
          return Promise.resolve({
            result: { ok: true, value: { events: [historyEntry(1)], hasMore: false } }
          });
        }
        return new Promise((resolve) => pending.push(resolve));
      }
    },
    subagents: {
      history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }),
      list: async () => ({
        result: { ok: true, value: { entries: [], parentAvailable: false } }
      })
    }
  };
  const rootContext = {
    get() { return undefined; },
    effect() {},
    reflect: { provide() {} }
  };
  const sessions = new runtime.SessionRuntime(rootContext, api, {});
  const session = sessions.manager.get("restored");
  await session.open();
  assert.match(JSON.stringify(session.events), /sk-resync-secret/u);
  assert.equal(session.conversation.inputs.size, 1);
  initial = false;
  const staleOpen = session.resync();
  assert.equal(pending.length, 1);
  assert.equal(session.openState, "loading");
  // Pinned DSH resync clears its raw event array but deliberately leaves the
  // already-derived conversation assembler window in place until history lands.
  assert.equal(session.events.length, 0);
  assert.equal(session.conversation.inputs.size, 1);

  const effects = [];
  const context = {
    sessions,
    workspaces: {
      create() {},
      list: {
        getSnapshot() { return { baselinesReady: true, items: [] }; },
        subscribe() { return () => {}; }
      }
    },
    conversation: { send() {}, sendSession() {} },
    effect(factory) { effects.push(factory()); }
  };
  plugin.apply(context);
  assert.equal(session.conversation.inputs.size, 0);
  assert.equal(pending.length, 2);

  // The request already in flight before bridge installation returns hostile
  // bytes after the bridge exists. Pinned Session.resync() must reject this
  // generation before it can replace the cleared conversation window.
  pending[0]({
    result: { ok: true, value: { events: [historyEntry(2)], hasMore: false } }
  });
  await staleOpen;
  assert.equal(session.events.length, 0);
  assert.equal(session.conversation.inputs.size, 0);
  assert.equal(session.openState, "loading");

  // The replacement request traverses the wrapped history method and is the
  // only generation allowed to install a window.
  pending[1]({
    result: { ok: true, value: { events: [historyEntry(3)], hasMore: false } }
  });
  while (session.openState === "loading") await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(session.openState, "open");
  assert.equal(session.events.length, 1);
  assert.equal(session.conversation.inputs.size, 1);
  assert.equal(session.events[0].data.reason.error.code, "AUTH");
  assert.equal(
    session.events[0].data.reason.error.message,
    "The provider rejected this credential. Open Models & Providers to check the API key."
  );
  assert.doesNotMatch(JSON.stringify(session.events), /sk-resync|provider\.invalid|\/Users\/example|request-secret/u);
  for (const dispose of effects.reverse()) dispose?.();
});

test("an already-in-flight older page is sanitized and followed by a clean bounded resync", async () => {
  const { plugin, runtime } = loadPinnedRuntimeAndPluginInBrowserRealm();
  const secret = "sk-older-page-secret https://provider.invalid /Users/example/private request-secret";
  const historyEntry = (seq) => ({
    event: {
      type: "turn/end",
      seq,
      time: seq,
      data: {
        turn: 1,
        reason: {
          kind: "error",
          error: { code: "AUTH", status: 403, message: secret, requestId: secret }
        }
      }
    }
  });
  let initial = true;
  const pending = [];
  const api = {
    sessions: {
      history() {
        if (initial) return Promise.resolve({
          result: { ok: true, value: { events: [historyEntry(3)], hasMore: true } }
        });
        return new Promise((resolve) => pending.push(resolve));
      }
    },
    subagents: {
      history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }),
      list: async () => ({ result: { ok: true, value: { entries: [], parentAvailable: false } } })
    }
  };
  const sessions = new runtime.SessionRuntime({
    get() { return undefined; }, effect() {}, reflect: { provide() {} }
  }, api, {});
  const session = sessions.manager.get("restored-older");
  await session.open();
  initial = false;
  const older = session.loadOlder();
  assert.equal(session.loadingOlder, true);
  assert.equal(pending.length, 1);

  const effects = [];
  plugin.apply({
    sessions,
    workspaces: {
      create() {},
      list: { getSnapshot() { return { baselinesReady: true, items: [] }; }, subscribe() { return () => {}; } }
    },
    conversation: { send() {}, sendSession() {} },
    effect(factory) { effects.push(factory()); }
  });
  assert.equal(pending.length, 2);
  pending[1]({ result: { ok: true, value: { events: [historyEntry(3)], hasMore: true } } });
  while (session.openState === "loading") await new Promise((resolve) => setTimeout(resolve, 0));

  pending[0]({ result: { ok: true, value: { events: [historyEntry(2)], hasMore: false } } });
  await older;
  while (pending.length < 3) await new Promise((resolve) => setTimeout(resolve, 0));
  assert.doesNotMatch(
    JSON.stringify(Array.from(session.conversation.inputs.values())),
    /sk-older|provider\.invalid|\/Users\/example|request-secret/u
  );
  pending[2]({ result: { ok: true, value: { events: [historyEntry(3)], hasMore: false } } });
  while (session.openState === "loading") await new Promise((resolve) => setTimeout(resolve, 0));
  assert.doesNotMatch(
    JSON.stringify({ events: session.events, inputs: Array.from(session.conversation.inputs.values()) }),
    /sk-older|provider\.invalid|\/Users\/example|request-secret/u
  );
  for (const dispose of effects.reverse()) dispose?.();
});

test("disposing the bridge restores an older-page guard before any late repair can run", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const delivered = [];
  const prototype = {
    prepend(entries) { delivered.push(entries); }
  };
  const conversation = Object.assign(Object.create(prototype), {
    replaceWindow() {}
  });
  let resyncCalls = 0;
  const session = {
    openState: "open",
    loadingOlder: true,
    conversation,
    async resync() { resyncCalls += 1; }
  };
  harness.ctx.sessions.manager = {
    sessions: new Map([["resident", session]]),
    api: {
      sessions: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) },
      subagents: { history: async () => ({ result: { ok: true, value: { events: [], hasMore: false } } }) }
    }
  };
  plugin.apply(harness.ctx);
  const staleGuard = Object.getOwnPropertyDescriptor(conversation, "prepend")?.value;
  assert.notEqual(staleGuard, prototype.prepend);
  assert.equal(resyncCalls, 1);
  harness.dispose();
  assert.equal(Object.hasOwn(conversation, "prepend"), false);

  Reflect.apply(staleGuard, conversation, [[{
    event: {
      type: "turn/end",
      data: { reason: { kind: "error", error: { code: "AUTH", message: "sk-disposed-secret" } } }
    }
  }], false]);
  await Promise.resolve();
  assert.equal(resyncCalls, 1);
  assert.doesNotMatch(JSON.stringify(delivered), /sk-disposed/u);
});

test("resident-session repair is bounded and restores transport wrappers on refusal", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const sessionHistory = async () => ({ result: { ok: true, value: { events: [], hasMore: false } } });
  const subagentHistory = async () => ({ result: { ok: true, value: { events: [], hasMore: false } } });
  harness.ctx.sessions.manager = {
    sessions: new Map(Array.from({ length: 65 }, (_, index) => [String(index), { openState: "cold" }])),
    api: {
      sessions: { history: sessionHistory },
      subagents: { history: subagentHistory }
    }
  };
  assert.throws(
    () => plugin.apply(harness.ctx),
    /refused an unbounded resident-session privacy repair/u
  );
  assert.equal(harness.ctx.sessions.manager.api.sessions.history, sessionHistory);
  assert.equal(harness.ctx.sessions.manager.api.subagents.history, subagentHistory);
});

function fixture({
  current = "old",
  recentWorkspaceId = "workspace-1",
  baselinesReady = true,
  sessionPublicationDelay = 0,
  approvedWorkspacePresent = true,
  pageWindow = globalThis.window
} = {}) {
  const allocatedSessionId = "local-harness-performance-v1-balanced-00000000-0000-4000-8000-000000000001";
  const approvedWorkspacePath = "/private/fulmar-workspace";
  const selected = current === null ? undefined : current;
  let snapshot = {
    current: selected,
    ids: selected === undefined ? [] : [selected],
    byId: selected === undefined ? {} : { [selected]: { id: selected, blank: false } }
  };
  const listeners = new Set();
  const workspaceListeners = new Set();
  let workspaceBaselinesReady = baselinesReady;
  let workspaceItems = approvedWorkspacePresent ? [{
    workspaceId: "workspace-1",
    path: approvedWorkspacePath,
    sessionIds: selected === undefined ? [] : [selected]
  }] : [{
    workspaceId: "legacy-workspace",
    path: "/Users/example/legacy-workspace",
    sessionIds: selected === undefined ? [] : [selected]
  }];
  const createCalls = [];
  const workspaceCreateCalls = [];
  const openCalls = [];
  const sessions = {
    list: {
      getSnapshot: () => snapshot,
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }
    },
    async create(options) {
      createCalls.push(options);
      const id = options.sessionId ?? "fresh-1";
      const publish = () => {
        snapshot = {
          current: snapshot.current,
          ids: [...snapshot.ids, id],
          byId: { ...snapshot.byId, [id]: { id, blank: true } }
        };
        for (const listener of listeners) listener();
      };
      if (sessionPublicationDelay > 0) setTimeout(publish, sessionPublicationDelay);
      else publish();
      return id;
    },
    open(id) {
      openCalls.push(id);
      snapshot = { ...snapshot, current: id };
      for (const listener of listeners) listener();
    }
  };
  const workspaces = {
    list: {
      getSnapshot: () => ({
        baselinesReady: workspaceBaselinesReady,
        recentWorkspaceId,
        items: workspaceItems
      }),
      subscribe(listener) { workspaceListeners.add(listener); return () => workspaceListeners.delete(listener); }
    },
    async create(input) {
      workspaceCreateCalls.push(input);
      const existing = workspaceItems.find((workspace) => workspace.path === input.path);
      if (existing !== undefined) return existing;
      const created = { workspaceId: "workspace-approved", path: input.path, sessionIds: [] };
      workspaceItems = [...workspaceItems, created];
      for (const listener of workspaceListeners) listener();
      return created;
    }
  };
  const conversationEvents = [];
  const conversation = {
    scopedSession() { return { sessionId: snapshot.current }; },
    async send(text) { conversationEvents.push(["send", text]); return "sent"; },
    async sendSession(session, text, imageIds, mode) {
      conversationEvents.push(["sendSession", session.sessionId, text, imageIds, mode]);
      return { kind: "success" };
    }
  };
  const performanceCalls = [];
  pageWindow.webkit = {
    messageHandlers: {
      localHarnessRecovery: {
        async postMessage(message) {
          if (message.action === "cancel") {
            conversationEvents.push(["cancel", message.operationID]);
            return { ok: true };
          }
          assert.equal(message.version, 2);
          assert.equal(message.action, "prepare");
          assert.match(message.operationID, /^[0-9a-f-]{36}$/iu);
          conversationEvents.push(["checkpoint", message.sessionID]);
          return { ok: true, mode: "protected" };
        }
      },
      localHarnessPerformance: {
        async postMessage(message) {
          performanceCalls.push(message);
          return { ok: true, sessionID: allocatedSessionId, workspacePath: approvedWorkspacePath };
        }
      }
    }
  };
  let disposer;
  const ctx = {
    sessions,
    workspaces,
    conversation,
    effect(factory) { disposer = factory(); }
  };
  return {
    ctx,
    createCalls,
    workspaceCreateCalls,
    openCalls,
    conversationEvents,
    performanceCalls,
    allocatedSessionId,
    approvedWorkspacePath,
    setBaselinesReady(value) {
      workspaceBaselinesReady = value;
      for (const listener of workspaceListeners) listener();
    },
    dispose: () => disposer?.()
  };
}

test("the browser-realm bridge uses exact Web Crypto UUID v4 identities", async () => {
  const generated = "12345678-1234-4123-8123-1234567890ab";
  let calls = 0;
  const { pageWindow, plugin } = loadPluginInBrowserRealm({
    crypto: Object.freeze({
      randomUUID() {
        calls += 1;
        return generated;
      }
    })
  });
  const harness = fixture({ pageWindow });
  const nativeMessages = [];
  pageWindow.webkit.messageHandlers.localHarnessRecovery.postMessage = async (message) => {
    nativeMessages.push(message);
    return { ok: true, mode: "protected" };
  };
  plugin.apply(harness.ctx);

  assert.deepEqual(await harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "browser realm proof",
    [],
    "queue"
  ), { kind: "success" });
  assert.equal(calls, 1);
  assert.equal(nativeMessages.length, 1);
  assert.equal(nativeMessages[0].operationID, generated);
  assert.match(nativeMessages[0].operationID, uuidV4Pattern);
  assert.deepEqual(harness.conversationEvents, [
    ["sendSession", "old", "browser realm proof", [], "queue"]
  ]);
});

test("missing browser Web Crypto fails closed before native recovery or prompt forwarding", async () => {
  const { pageWindow, plugin } = loadPluginInBrowserRealm({ crypto: undefined });
  const harness = fixture({ pageWindow });
  const nativeMessages = [];
  pageWindow.webkit.messageHandlers.localHarnessRecovery.postMessage = async (message) => {
    nativeMessages.push(message);
    return { ok: true, mode: "protected" };
  };
  plugin.apply(harness.ctx);

  await assert.rejects(
    harness.ctx.conversation.sendSession({ sessionId: "old" }, "must block", [], "queue"),
    /could not allocate a recovery operation identity/u
  );
  assert.deepEqual(nativeMessages, []);
  assert.deepEqual(harness.conversationEvents, []);
});

test("malformed browser recovery identities all fail closed before crossing the native boundary", async (context) => {
  const invalidIdentities = [
    ["undefined", undefined],
    ["null", null],
    ["number", 42],
    ["empty", ""],
    ["non-UUID", "not-a-uuid"],
    ["UUID v1", "12345678-1234-1123-8123-1234567890ab"],
    ["wrong variant", "12345678-1234-4123-7123-1234567890ab"],
    ["braced UUID", "{12345678-1234-4123-8123-1234567890ab}"]
  ];

  for (const [label, identity] of invalidIdentities) {
    await context.test(label, async () => {
      const { pageWindow, plugin } = loadPluginInBrowserRealm({
        crypto: Object.freeze({ randomUUID: () => identity })
      });
      const harness = fixture({ pageWindow });
      const nativeMessages = [];
      pageWindow.webkit.messageHandlers.localHarnessRecovery.postMessage = async (message) => {
        nativeMessages.push(message);
        return { ok: true, mode: "protected" };
      };
      plugin.apply(harness.ctx);

      await assert.rejects(
        harness.ctx.conversation.sendSession({ sessionId: "old" }, "must block", [], "queue"),
        /could not allocate a recovery operation identity/u
      );
      assert.deepEqual(nativeMessages, []);
      assert.deepEqual(harness.conversationEvents, []);
    });
  }
});

test("a throwing browser random source still blocks before native recovery or prompt forwarding", async () => {
  const { pageWindow, plugin } = loadPluginInBrowserRealm({
    crypto: Object.freeze({
      randomUUID() { throw new Error("simulated browser RNG failure"); }
    })
  });
  const harness = fixture({ pageWindow });
  const nativeMessages = [];
  pageWindow.webkit.messageHandlers.localHarnessRecovery.postMessage = async (message) => {
    nativeMessages.push(message);
    return { ok: true, mode: "protected" };
  };
  plugin.apply(harness.ctx);

  await assert.rejects(
    harness.ctx.conversation.sendSession({ sessionId: "old" }, "must block", [], "queue"),
    /simulated browser RNG failure/u
  );
  assert.deepEqual(nativeMessages, []);
  assert.deepEqual(harness.conversationEvents, []);
});

test("parallel prompts and an immediate retry receive one distinct recovery identity each", async () => {
  const identities = [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "00000000-0000-4000-8000-000000000003"
  ];
  let identityIndex = 0;
  const { pageWindow, plugin } = loadPluginInBrowserRealm({
    crypto: Object.freeze({
      randomUUID() {
        const identity = identities[identityIndex];
        identityIndex += 1;
        return identity;
      }
    })
  });
  const harness = fixture({ pageWindow });
  const pending = [];
  pageWindow.webkit.messageHandlers.localHarnessRecovery.postMessage = (message) => {
    let resolve;
    const reply = new Promise((resume) => { resolve = resume; });
    pending.push({ message, resolve });
    return reply;
  };
  plugin.apply(harness.ctx);

  const first = harness.ctx.conversation.sendSession(
    { sessionId: "old" }, "first", [], "queue", new AbortController().signal
  );
  const second = harness.ctx.conversation.sendSession(
    { sessionId: "old" }, "second", [], "queue", new AbortController().signal
  );
  assert.equal(pending.length, 2);
  assert.deepEqual(pending.map((entry) => entry.message.operationID), identities.slice(0, 2));
  assert.equal(new Set(pending.map((entry) => entry.message.operationID)).size, 2);
  pending[0].resolve({ ok: true, mode: "protected" });
  pending[1].resolve({ ok: true, mode: "protected" });
  await Promise.all([first, second]);

  const retry = harness.ctx.conversation.sendSession(
    { sessionId: "old" }, "retry", [], "queue", new AbortController().signal
  );
  assert.equal(pending.length, 3);
  assert.equal(pending[2].message.operationID, identities[2]);
  pending[2].resolve({ ok: true, mode: "protected" });
  await retry;

  assert.equal(identityIndex, 3);
  assert.equal(new Set(pending.map((entry) => entry.message.operationID)).size, 3);
  assert.ok(pending.every((entry) => uuidV4Pattern.test(entry.message.operationID)));
  assert.deepEqual(harness.conversationEvents, [
    ["sendSession", "old", "first", [], "queue"],
    ["sendSession", "old", "second", [], "queue"],
    ["sendSession", "old", "retry", [], "queue"]
  ]);
});

test("creates a distinct blank session in the current workspace and opens it", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  const proof = await window.__localHarnessSecurityBridge.startFreshSession();
  assert.deepEqual(proof, {
    before: "old",
    created: harness.allocatedSessionId,
    current: harness.allocatedSessionId
  });
  assert.deepEqual(harness.createCalls, [{
    workspaceId: "workspace-1",
    sessionId: harness.allocatedSessionId
  }]);
  assert.deepEqual(harness.performanceCalls, [{ version: 1 }]);
  assert.deepEqual(harness.openCalls, [harness.allocatedSessionId]);
  assert.equal(Object.isFrozen(proof), true);
  harness.dispose();
  assert.equal(window.__localHarnessSecurityBridge, undefined);
});

test("registers and uses the native-approved Workspace instead of a restored recent Workspace", async () => {
  const plugin = await loadPlugin();
  const harness = fixture({
    current: null,
    recentWorkspaceId: "legacy-workspace",
    approvedWorkspacePresent: false
  });
  plugin.apply(harness.ctx);
  const proof = await window.__localHarnessSecurityBridge.startFreshSession();
  assert.equal(proof.before, null);
  assert.deepEqual(harness.workspaceCreateCalls, [{ path: harness.approvedWorkspacePath }]);
  assert.deepEqual(harness.createCalls, [{
    workspaceId: "workspace-approved",
    sessionId: harness.allocatedSessionId
  }]);
});

test("performance-binds every ordinary browser session creation", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  const created = await harness.ctx.sessions.create({ workspaceId: "workspace-1" });
  assert.equal(created, harness.allocatedSessionId);
  assert.deepEqual(harness.createCalls, [{
    workspaceId: "workspace-1",
    sessionId: harness.allocatedSessionId
  }]);
  assert.deepEqual(harness.performanceCalls, [{ version: 1 }]);
});

test("preserves explicit blank reuse only inside the native-approved Workspace", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  await harness.ctx.sessions.create({
    workspaceId: "workspace-1",
    sessionId: "reviewed-existing",
    reuseWorkspaceBlank: true
  });
  assert.deepEqual(harness.createCalls, [{
    workspaceId: "workspace-1",
    sessionId: "reviewed-existing",
    reuseWorkspaceBlank: true
  }]);
  assert.deepEqual(harness.performanceCalls, [{ version: 1 }]);
});

test("rebinds stale Workspace creation and reuse requests to a fresh approved session", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  await harness.ctx.sessions.create({
    workspaceId: "legacy-workspace",
    sessionId: "legacy-blank",
    reuseWorkspaceBlank: true
  });
  assert.deepEqual(harness.createCalls, [{
    workspaceId: "workspace-1",
    sessionId: harness.allocatedSessionId
  }]);
});

test("fails closed before session creation when native performance allocation fails", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  window.webkit.messageHandlers.localHarnessPerformance.postMessage = async () => ({ ok: false });
  plugin.apply(harness.ctx);
  await assert.rejects(
    harness.ctx.sessions.create({ workspaceId: "workspace-1" }),
    /did not provide a performance-bound session identity and approved Workspace/
  );
  assert.deepEqual(harness.createCalls, []);
});

test("waits for delayed Workspace baselines and delayed session publication", async () => {
  const plugin = await loadPlugin();
  const harness = fixture({ baselinesReady: false, sessionPublicationDelay: 20 });
  plugin.apply(harness.ctx);
  const proof = window.__localHarnessSecurityBridge.startFreshSession();
  assert.deepEqual(harness.createCalls, []);
  setTimeout(() => harness.setBaselinesReady(true), 20);
  assert.deepEqual(await proof, {
    before: "old",
    created: harness.allocatedSessionId,
    current: harness.allocatedSessionId
  });
  assert.equal(harness.createCalls.length, 1);
});

test("refuses to replace an existing page bridge", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  Object.defineProperty(window, "__localHarnessSecurityBridge", {
    configurable: true,
    value: { spoofed: true }
  });
  assert.throws(() => plugin.apply(harness.ctx), /already registered/);
});

test("coalesces simultaneous native requests into one session creation", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  const first = window.__localHarnessSecurityBridge.startFreshSession();
  const second = window.__localHarnessSecurityBridge.startFreshSession();
  assert.equal(first, second);
  await first;
  assert.equal(harness.createCalls.length, 1);
});

test("blocks every composer prompt on a native checkpoint reply", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  await harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "change files",
    [],
    "queue"
  );
  assert.deepEqual(harness.conversationEvents, [
    ["checkpoint", "old"],
    ["sendSession", "old", "change files", [], "queue"]
  ]);
});

test("an acknowledged old send can pause before priorSend while native closure rejects new checkpoints", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  let resolveAcknowledgedCheckpoint;
  let admissionsClosed = false;
  let checkpointCount = 0;
  window.webkit.messageHandlers.localHarnessRecovery.postMessage = (message) => {
    harness.conversationEvents.push(["checkpoint", message.sessionID]);
    checkpointCount += 1;
    if (checkpointCount === 1) {
      return new Promise((resolve) => {
        resolveAcknowledgedCheckpoint = resolve;
      });
    }
    if (admissionsClosed) {
      return Promise.reject(new Error("Native admissions are closed."));
    }
      return Promise.resolve({ ok: true, mode: "protected" });
  };
  plugin.apply(harness.ctx);

  const acknowledgedSend = harness.ctx.conversation.sendSession(
    { sessionId: "acknowledged-before-close" },
    "old admitted prompt",
    [],
    "queue"
  );
  assert.deepEqual(harness.conversationEvents, [
    ["checkpoint", "acknowledged-before-close"]
  ]);

  // Resolving a promise schedules the bridge continuation; it cannot invoke
  // the captured priorSend until this synchronous stack yields.
  resolveAcknowledgedCheckpoint({ ok: true, mode: "protected" });
  admissionsClosed = true;
  const rejectedSend = harness.ctx.conversation.sendSession(
    { sessionId: "started-after-close" },
    "new rejected prompt",
    [],
    "queue"
  );
  assert.deepEqual(harness.conversationEvents, [
    ["checkpoint", "acknowledged-before-close"],
    ["checkpoint", "started-after-close"]
  ]);

  await assert.rejects(rejectedSend, /Native admissions are closed/);
  assert.deepEqual(await acknowledgedSend, { kind: "success" });
  assert.deepEqual(harness.conversationEvents, [
    ["checkpoint", "acknowledged-before-close"],
    ["checkpoint", "started-after-close"],
    ["sendSession", "acknowledged-before-close", "old admitted prompt", [], "queue"]
  ]);
});

test("blocks the scoped send path on a native checkpoint reply", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  plugin.apply(harness.ctx);
  assert.equal(await harness.ctx.conversation.send("change files"), "sent");
  assert.deepEqual(harness.conversationEvents, [
    ["checkpoint", "old"],
    ["send", "change files"]
  ]);
});

test("removes the abort listener after checkpoint success", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  let listener;
  let removed;
  const signal = {
    aborted: false,
    addEventListener(name, value, options) {
      assert.equal(name, "abort");
      assert.deepEqual(options, { once: true });
      listener = value;
    },
    removeEventListener(name, value) {
      assert.equal(name, "abort");
      removed = value;
    }
  };
  plugin.apply(harness.ctx);
  await harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "change files",
    [],
    "queue",
    signal
  );
  assert.equal(typeof listener, "function");
  assert.equal(removed, listener);
});

test("checkpoint failure prevents the Harness prompt", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  window.webkit.messageHandlers.localHarnessRecovery.postMessage = async () => ({ ok: false });
  plugin.apply(harness.ctx);
  await assert.rejects(
    harness.ctx.conversation.sendSession({ sessionId: "old" }, "unsafe", [], "queue"),
    /did not confirm a recovery point/
  );
  assert.deepEqual(harness.conversationEvents, []);
});

test("abort sends a v2 native cancellation for the exact operation and an immediate retry proceeds", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const messages = [];
  let firstPrepare = true;
  window.webkit.messageHandlers.localHarnessRecovery.postMessage = (message) => {
    messages.push(message);
    if (message.action === "cancel") return Promise.resolve({ ok: true });
    if (firstPrepare) {
      firstPrepare = false;
      return new Promise(() => {});
    }
    return Promise.resolve({ ok: true, mode: "protected" });
  };
  plugin.apply(harness.ctx);

  const controller = new AbortController();
  const abandoned = harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "cancel this",
    [],
    "queue",
    controller.signal
  );
  assert.equal(messages.length, 1);
  const operationID = messages[0].operationID;
  assert.deepEqual(messages[0], {
    version: 2,
    action: "prepare",
    operationID,
    sessionID: "old"
  });
  controller.abort(new Error("user stopped"));
  await assert.rejects(abandoned, /user stopped/);
  assert.deepEqual(messages[1], {
    version: 2,
    action: "cancel",
    operationID
  });
  assert.deepEqual(harness.conversationEvents, []);

  assert.deepEqual(await harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "retry now",
    [],
    "queue",
    new AbortController().signal
  ), { kind: "success" });
  assert.equal(messages[2].action, "prepare");
  assert.notEqual(messages[2].operationID, operationID);
  assert.deepEqual(harness.conversationEvents, [
    ["sendSession", "old", "retry now", [], "queue"]
  ]);
});

test("abort racing listener installation cannot cancel before native prepare or become lost", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  const messages = [];
  window.webkit.messageHandlers.localHarnessRecovery.postMessage = (message) => {
    messages.push(message);
    return message.action === "cancel" ? Promise.resolve({ ok: true }) : new Promise(() => {});
  };
  plugin.apply(harness.ctx);
  let abortedReads = 0;
  let installedListener;
  const racingSignal = {
    reason: new Error("raced stop"),
    get aborted() {
      abortedReads += 1;
      return abortedReads > 1;
    },
    addEventListener(_name, listener) { installedListener = listener; },
    removeEventListener(_name, listener) {
      assert.equal(listener, installedListener);
    }
  };

  await assert.rejects(
    harness.ctx.conversation.sendSession(
      { sessionId: "old" },
      "race cancellation",
      [],
      "queue",
      racingSignal
    ),
    /raced stop/
  );
  assert.equal(messages.length, 2);
  assert.equal(messages[0].action, "prepare");
  assert.equal(messages[1].action, "cancel");
  assert.equal(messages[1].operationID, messages[0].operationID);
  assert.deepEqual(harness.conversationEvents, []);
});

test("typed read-only protection still admits the conversational turn", async () => {
  const plugin = await loadPlugin();
  const harness = fixture();
  window.webkit.messageHandlers.localHarnessRecovery.postMessage = async (message) => ({
    ok: true,
    mode: "readOnly",
    message: `workspace safety for ${message.sessionID}`
  });
  plugin.apply(harness.ctx);

  assert.deepEqual(await harness.ctx.conversation.sendSession(
    { sessionId: "old" },
    "please analyse without editing",
    [],
    "queue"
  ), { kind: "success" });
  assert.deepEqual(harness.conversationEvents, [
    ["sendSession", "old", "please analyse without editing", [], "queue"]
  ]);
});
