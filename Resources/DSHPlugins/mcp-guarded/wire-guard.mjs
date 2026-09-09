const MAX_CLIENT_FRAME_BYTES = 256 * 1024;
const MAX_PENDING_REQUESTS = 64;
const MAX_LIST_PAGES = 128;
const NOTIFICATION_WINDOW_MS = 10_000;
const MAX_TOOL_LIST_NOTIFICATIONS_PER_WINDOW = 8;
const CLIENT_REQUEST_METHODS = new Set(["initialize", "ping", "tools/list", "tools/call"]);
const CLIENT_NOTIFICATION_METHODS = new Set(["notifications/initialized", "notifications/cancelled"]);
const SERVER_NOTIFICATION_METHODS = new Set(["notifications/tools/list_changed"]);

class MCPWireViolation extends Error {
  constructor(message) {
    super(`mcp-stdio-guard: ${message}`);
    this.name = "MCPWireViolation";
    this.code = "MCP_WIRE_VIOLATION";
  }
}

function violation(message) {
  throw new MCPWireViolation(message);
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function idKey(value) {
  if (typeof value === "string") {
    if (value.length === 0 || Buffer.byteLength(value, "utf8") > 256) violation("JSON-RPC request id is invalid");
    return `s:${value}`;
  }
  if (Number.isSafeInteger(value)) return `n:${value}`;
  violation("JSON-RPC request id must be a bounded string or safe integer");
}

function assertJSONRPCMessage(message, direction) {
  if (!isRecord(message) || message.jsonrpc !== "2.0") violation(`${direction} sent an invalid JSON-RPC message`);
  if (Object.hasOwn(message, "method") && typeof message.method !== "string") violation(`${direction} sent an invalid JSON-RPC method`);
  return message;
}

function serializedBytes(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    violation("message content could not be serialized losslessly");
  }
  return Buffer.byteLength(serialized ?? "null", "utf8");
}

function exactParameterKeys(value, allowed, label) {
  if (value === undefined) return {};
  if (!isRecord(value)) violation(`${label} parameters must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) violation(`${label} parameter ${key} is not supported`);
  }
  return value;
}

class BoundedJSONLineDecoder {
  constructor(maximumFrameBytes) {
    if (!Number.isSafeInteger(maximumFrameBytes) || maximumFrameBytes < 1024) {
      throw new TypeError("maximumFrameBytes must be a safe integer of at least 1024");
    }
    this.maximumFrameBytes = maximumFrameBytes;
    this.buffer = Buffer.alloc(0);
    this.decoder = new TextDecoder("utf-8", { fatal: true });
  }

  append(chunk) {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    if (chunk.length === 0) return [];
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const frames = [];
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline < 0) break;
      if (newline > this.maximumFrameBytes) violation("JSON-RPC frame exceeded its byte limit");
      let line = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (line.at(-1) === 0x0d) line = line.subarray(0, -1);
      if (line.length === 0) violation("empty JSON-RPC frame");
      let text;
      let value;
      try {
        text = this.decoder.decode(line);
        value = JSON.parse(text);
      } catch {
        violation("invalid UTF-8 or JSON in stdio frame");
      }
      frames.push({ value, bytes: line.length });
    }
    if (this.buffer.length > this.maximumFrameBytes) violation("unterminated JSON-RPC frame exceeded its byte limit");
    return frames;
  }

  finish() {
    if (this.buffer.length !== 0) violation("stdio stream ended with an unterminated JSON-RPC frame");
  }
}

class MCPWireGuard {
  constructor(limits) {
    this.maximumDiscoveredTools = limits.maximumDiscoveredTools;
    this.maximumOutputBytes = limits.maximumOutputBytes;
    this.maximumInventoryBytes = limits.maximumInventoryBytes;
    this.maximumServerFrameBytes = Math.max(
      256 * 1024,
      this.maximumInventoryBytes + 65_536,
      this.maximumOutputBytes + 65_536
    );
    if (![this.maximumDiscoveredTools, this.maximumOutputBytes, this.maximumInventoryBytes, this.maximumServerFrameBytes]
      .every(Number.isSafeInteger)) {
      throw new TypeError("wire limits must be safe integers");
    }
    this.pending = new Map();
    this.listState = undefined;
    this.startupComplete = false;
    this.notificationWindowStartedAt = 0;
    this.notificationCount = 0;
  }

  inspectClient(message, frameBytes = serializedBytes(message)) {
    if (frameBytes > MAX_CLIENT_FRAME_BYTES) violation("client request exceeded its byte limit");
    assertJSONRPCMessage(message, "client");
    if (Object.hasOwn(message, "method")) {
      if (Object.hasOwn(message, "id")) return this.#clientRequest(message);
      return this.#clientNotification(message);
    }
    violation("client responses are unsupported because server-initiated requests are disabled");
  }

  #clientRequest(message) {
    if (!CLIENT_REQUEST_METHODS.has(message.method)) violation(`client method ${message.method} is outside the tools-only MCP profile`);
    const key = idKey(message.id);
    if (this.pending.has(key)) violation("client reused an outstanding JSON-RPC request id");
    if (this.pending.size >= MAX_PENDING_REQUESTS) violation("too many outstanding JSON-RPC requests");
    if (message.method === "tools/list") {
      const params = exactParameterKeys(message.params, new Set(["cursor"]), "tools/list");
      const cursor = params.cursor;
      if (cursor !== undefined && (typeof cursor !== "string" || cursor.length === 0 || Buffer.byteLength(cursor, "utf8") > 1024)) {
        violation("tools/list cursor is invalid");
      }
      if (cursor === undefined) {
        if (this.listState || [...this.pending.values()].some((request) => request.method === "tools/list")) {
          violation("overlapping tools/list sequences are not supported");
        }
        this.listState = { count: 0, names: new Set(), bytes: 0, pages: 0, expectedCursor: undefined, cursors: new Set() };
      } else if (!this.listState || this.listState.expectedCursor !== cursor || this.listState.cursors.has(cursor)) {
        violation("tools/list pagination did not follow the server's reviewed cursor chain");
      } else {
        this.listState.cursors.add(cursor);
      }
    } else if (message.method === "tools/call") {
      const params = exactParameterKeys(message.params, new Set(["name", "arguments"]), "tools/call");
      if (typeof params.name !== "string" || params.name.length === 0 || Buffer.byteLength(params.name, "utf8") > 512) {
        violation("tools/call name is invalid");
      }
      if (params.arguments !== undefined && !isRecord(params.arguments)) violation("tools/call arguments must be an object");
    } else if (message.params !== undefined && !isRecord(message.params)) {
      violation(`${message.method} parameters must be an object`);
    }
    this.pending.set(key, { method: message.method });
    return { forward: true, requestKey: key, method: message.method };
  }

  #clientNotification(message) {
    if (!CLIENT_NOTIFICATION_METHODS.has(message.method)) {
      violation(`client notification ${message.method} is outside the tools-only MCP profile`);
    }
    if (message.method === "notifications/cancelled") {
      const params = exactParameterKeys(message.params, new Set(["requestId", "reason"]), "notifications/cancelled");
      const key = idKey(params.requestId);
      const pending = this.pending.get(key);
      return { forward: true, cancelledToolCallKey: pending?.method === "tools/call" ? key : undefined };
    }
    return { forward: true };
  }

  inspectServer(message, frameBytes = serializedBytes(message)) {
    if (frameBytes > this.maximumServerFrameBytes) violation("server frame exceeded its byte limit");
    assertJSONRPCMessage(message, "server");
    if (Object.hasOwn(message, "method")) {
      if (Object.hasOwn(message, "id")) violation("server-initiated requests are disabled by the tools-only MCP profile");
      const now = Date.now();
      if (now - this.notificationWindowStartedAt >= NOTIFICATION_WINDOW_MS) {
        this.notificationWindowStartedAt = now;
        this.notificationCount = 0;
      }
      this.notificationCount += 1;
      if (this.notificationCount > MAX_TOOL_LIST_NOTIFICATIONS_PER_WINDOW) {
        violation("server exceeded the notification rate limit");
      }
      if (!SERVER_NOTIFICATION_METHODS.has(message.method)) {
        return { forward: false };
      }
      return { forward: true };
    }
    if (!Object.hasOwn(message, "id")) violation("server response omitted its JSON-RPC request id");
    const key = idKey(message.id);
    const request = this.pending.get(key);
    if (!request) violation("server responded to an unknown JSON-RPC request id");
    this.pending.delete(key);
    if (Object.hasOwn(message, "error")) {
      if (Object.hasOwn(message, "result") || !isRecord(message.error)) violation("server returned an invalid JSON-RPC error response");
      return { forward: true, settledRequestKey: key, method: request.method };
    }
    if (!Object.hasOwn(message, "result")) violation("server response contains neither result nor error");
    if (request.method === "tools/list") return this.#inspectToolList(message, key);
    if (request.method === "tools/call") {
      const outputBytes = serializedBytes(message.result);
      if (outputBytes > this.maximumOutputBytes) violation("MCP tool result exceeded its approved output-size limit");
    }
    return { forward: true, settledRequestKey: key, method: request.method };
  }

  #inspectToolList(message, key) {
    const result = message.result;
    if (!isRecord(result) || !Array.isArray(result.tools)) violation("tools/list returned an invalid result");
    if (!this.listState) violation("tools/list returned without an active pagination sequence");
    this.listState.pages += 1;
    if (this.listState.pages > MAX_LIST_PAGES) violation("tools/list exceeded its pagination limit");
    this.listState.bytes += serializedBytes(result);
    if (this.listState.bytes > this.maximumInventoryBytes) violation("MCP tool inventory exceeded its schema-size limit");
    for (const tool of result.tools) {
      if (!isRecord(tool) || typeof tool.name !== "string" || tool.name.length === 0 || Buffer.byteLength(tool.name, "utf8") > 512) {
        violation("tools/list returned an invalid tool identity");
      }
      if (this.listState.names.has(tool.name)) violation("tools/list returned a duplicate tool identity");
      this.listState.names.add(tool.name);
      this.listState.count += 1;
      if (this.listState.count > this.maximumDiscoveredTools) violation("MCP server exceeded its approved tool-count limit");
    }
    const nextCursor = result.nextCursor;
    if (nextCursor !== undefined && (typeof nextCursor !== "string" || nextCursor.length === 0 || Buffer.byteLength(nextCursor, "utf8") > 1024)) {
      violation("tools/list returned an invalid pagination cursor");
    }
    let startupComplete = false;
    if (nextCursor === undefined) {
      this.listState = undefined;
      if (!this.startupComplete) {
        this.startupComplete = true;
        startupComplete = true;
      }
    } else {
      this.listState.expectedCursor = nextCursor;
    }
    return { forward: true, settledRequestKey: key, method: "tools/list", startupComplete };
  }
}

export {
  BoundedJSONLineDecoder,
  CLIENT_NOTIFICATION_METHODS,
  CLIENT_REQUEST_METHODS,
  MAX_CLIENT_FRAME_BYTES,
  MCPWireGuard,
  MCPWireViolation,
  SERVER_NOTIFICATION_METHODS,
  idKey,
  serializedBytes
};
