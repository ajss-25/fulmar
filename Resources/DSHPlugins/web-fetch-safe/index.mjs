import { WebError } from "@deepseek-ai/dsh-web";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync
} from "node:fs";
import { join } from "node:path";

const name = "local-harness-web-fetch-safe";
const inject = ["web", "systemPrompt"];
const PROVIDER_ID = "fulmar-approved-fetch";
const BRIDGE_SYMBOL = Symbol.for("com.fulmar.runtime.approved-web-fetch.v1");
const MAXIMUM_BODY_BYTES = 2 * 1024 * 1024;
const MAXIMUM_URL_CHARACTERS = 4096;
const WORKSPACE_POLICY_FILE = ".fulmar-workspace-mutation-policy.json";
const WORKSPACE_POLICY_MAXIMUM_BYTES = 1_024;
const READ_ONLY_TOOLS = new Set([
  "read", "read_image", "glob", "grep", "web_fetch", "web_search"
]);

const bridge = globalThis[BRIDGE_SYMBOL];
if (!bridge || typeof bridge.normalize !== "function" || typeof bridge.fetch !== "function") {
  throw new Error("Fulmar's approved web-fetch boundary is unavailable.");
}
// Only this signed adapter retains the narrowly scoped native bridge. Other
// runtime modules loaded later cannot discover it through the global object.
Reflect.deleteProperty(globalThis, BRIDGE_SYMBOL);

function exactKeys(value, expected) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function privateMetadata(metadata, kind) {
  const expectedUID = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
  return kind(metadata) && metadata.uid === expectedUID && (metadata.mode & 0o077) === 0;
}

function decodeWorkspaceMutationPolicy(dshHome = process.env.DSH_HOME) {
  try {
    if (typeof dshHome !== "string" || !dshHome.startsWith("/") || dshHome.includes("\0")) return undefined;
    const homeMetadata = lstatSync(dshHome);
    if (homeMetadata.isSymbolicLink() || !privateMetadata(homeMetadata, (value) => value.isDirectory())) return undefined;
    const policyPath = join(dshHome, WORKSPACE_POLICY_FILE);
    const descriptor = openSync(policyPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      const metadata = fstatSync(descriptor);
      if (!privateMetadata(metadata, (value) => value.isFile()) || metadata.nlink !== 1
          || metadata.size <= 0 || metadata.size > WORKSPACE_POLICY_MAXIMUM_BYTES) return undefined;
      const bytes = readFileSync(descriptor);
      if (bytes.length !== metadata.size || bytes.length > WORKSPACE_POLICY_MAXIMUM_BYTES) return undefined;
      const value = JSON.parse(bytes.toString("utf8"));
      if (!exactKeys(value, ["schemaVersion", "mode", "reason"]) || value.schemaVersion !== 1
          || !["readOnly", "readWrite"].includes(value.mode)
          || !["checkpointRequired", "protectedCheckpoint", "recoverabilityLimit", "recoveryDeadline"].includes(value.reason)
          || (value.mode === "readWrite" && value.reason !== "protectedCheckpoint")
          || (value.mode === "readOnly" && value.reason === "protectedCheckpoint")) return undefined;
      return Object.freeze({ mode: value.mode, reason: value.reason });
    } finally {
      closeSync(descriptor);
    }
  } catch {
    return undefined;
  }
}

function workspaceMutationDecision(toolName, dshHome = process.env.DSH_HOME) {
  const policy = decodeWorkspaceMutationPolicy(dshHome);
  if (policy?.mode === "readWrite") return Object.freeze({ kind: "allow" });
  if (READ_ONLY_TOOLS.has(toolName)) return Object.freeze({ kind: "allow" });
  const detail = policy === undefined
    ? "Fulmar could not authenticate its owner-only workspace policy"
    : policy.reason === "recoveryDeadline"
      ? "Fulmar's bounded recovery scan reached its deadline"
      : policy.reason === "recoverabilityLimit"
        ? "this workspace exceeds Fulmar's bounded recovery limits"
        : "a protected recovery point has not been committed";
  return Object.freeze({
    kind: "deny",
    reason: `${detail}. This turn is read-only: chat, web, search and file reading remain available, but ${JSON.stringify(String(toolName))} and all subagent/mutation tools are blocked.`
  });
}

function normalizeApprovedURL(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAXIMUM_URL_CHARACTERS) {
    throw new WebError("web_fetch requires one bounded HTTPS URL", "WEB_FETCH_INVALID_URL");
  }
  try { return bridge.normalize(value); }
  catch (error) {
    throw new WebError(error?.message ?? "web_fetch rejected the URL", "WEB_FETCH_BLOCKED_URL", { cause: error });
  }
}

function responseKind(contentType) {
  const mediaType = String(contentType ?? "").split(";", 1)[0].trim().toLowerCase();
  if (!/^[!#$%&'*+.^_`|~0-9a-z-]+\/[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(mediaType)) {
    throw new WebError("web_fetch exposes only responses with an explicit supported textual content type", "WEB_FETCH_CONTENT_TYPE");
  }
  if (mediaType === "text/html" || mediaType === "application/xhtml+xml") return "html";
  if (mediaType.startsWith("text/") || mediaType === "application/json"
      || mediaType.endsWith("+json") || mediaType === "application/xml" || mediaType.endsWith("+xml")) return "text";
  throw new WebError("web_fetch exposes only responses with an explicit supported textual content type", "WEB_FETCH_CONTENT_TYPE");
}

async function boundedText(response, signal) {
  if (!response.body) return { content: "", truncated: false };
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const parts = [];
  let received = 0;
  let truncated = false;
  try {
    while (true) {
      if (signal?.aborted) throw signal.reason ?? new Error("web_fetch was cancelled");
      const { done, value } = await reader.read();
      if (done) break;
      const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
      const remaining = MAXIMUM_BODY_BYTES - received;
      if (bytes.byteLength > remaining) {
        if (remaining > 0) parts.push(decoder.decode(bytes.subarray(0, remaining), { stream: true }));
        received = MAXIMUM_BODY_BYTES;
        truncated = true;
        await reader.cancel("Fulmar web-fetch body limit reached").catch(() => {});
        break;
      }
      received += bytes.byteLength;
      parts.push(decoder.decode(bytes, { stream: true }));
    }
    parts.push(decoder.decode());
    return { content: parts.join(""), truncated };
  } catch (error) {
    await reader.cancel("Fulmar web-fetch body read did not complete").catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

class FulmarApprovedFetchProvider {
  id = PROVIDER_ID;

  available() { return true; }

  async fetch(request, signal) {
    const url = normalizeApprovedURL(request?.url);
    let response;
    try { response = await bridge.fetch(url, signal); }
    catch (error) {
      if (signal?.aborted) throw new WebError("web_fetch was cancelled", "WEB_CANCELLED", { cause: error });
      throw new WebError(error?.message ?? "The approved web request failed", "WEB_PROVIDER_ERROR", { cause: error });
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel().catch(() => {});
      throw new WebError("The page redirected to a URL that was not approved; fetch the destination URL explicitly.", "WEB_FETCH_REDIRECT_BLOCKED");
    }
    let kind;
    try {
      kind = responseKind(response.headers.get("content-type"));
    } catch (error) {
      await response.body?.cancel("Fulmar web-fetch rejected the response content type").catch(() => {});
      throw error;
    }
    const body = await boundedText(response, signal);
    return {
      url,
      statusCode: response.status,
      body: { kind, content: body.content },
      truncated: body.truncated
    };
  }
}

function apply(ctx) {
  ctx.web.registerFetchProvider(new FulmarApprovedFetchProvider());
  ctx.on("tools/pre-execute", (exec, next) => {
    const decision = workspaceMutationDecision(exec?.name);
    return decision.kind === "allow" ? next() : Promise.resolve(decision);
  }, { prepend: true, global: true });
  ctx.on("tools/pre-execute", (exec, next) => {
    if (exec.name !== "web_fetch") return next();
    let url;
    try { url = normalizeApprovedURL(exec.arguments?.url); }
    catch { return next(); }
    return Promise.resolve({
      kind: "ask",
      reason: `Allow Fulmar to retrieve this exact public page once? ${url}`
    });
  }, { prepend: true });
  ctx.systemPrompt.section({
    name: "fulmar:web-boundary",
    order: 112,
    text: "Fulmar web access is deliberately capability-scoped. Use web_fetch for a specific public HTTPS URL. Each page requires user approval. When web_fetch succeeds, base factual claims on the returned page, distinguish your own inference, and cite the exact returned URL in the final answer as a Markdown link or plain source URL. If web_fetch is denied, unavailable, or fails, explain that outcome and ask for pasted content when appropriate. Never retry web access through Bash, curl, wget, a programming-language HTTP client, DNS utilities, or another tool. General web search is not available unless a configured search provider is explicitly shown as a tool."
  });
  ctx.systemPrompt.section({
    name: "fulmar:workspace-recovery-boundary",
    order: 111,
    text: "Fulmar enforces an owner-only native workspace recovery policy at the global tool pre-execute boundary. When a turn is marked read-only, you may answer, fetch approved public pages, search when configured, and inspect files with read/read_image/glob/grep. Do not attempt Bash, PowerShell, write, edit, workflow, MCP mutation, job, goal/todo mutation, or subagent tools: they are deliberately denied. Explain the read-only safety condition and continue useful analysis with allowed tools."
  });
}

export {
  FulmarApprovedFetchProvider,
  MAXIMUM_BODY_BYTES,
  PROVIDER_ID,
  apply,
  decodeWorkspaceMutationPolicy,
  inject,
  name,
  normalizeApprovedURL,
  responseKind,
  workspaceMutationDecision
};
