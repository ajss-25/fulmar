import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { CredentialProvider, credentialRef, parseCredentialKey } from "@deepseek-ai/dsh-credentials";
import z from "@deepseek-ai/schemastery";

const helperPath = process.env.LOCAL_HARNESS_CREDENTIAL_HELPER;
const forbidCredentialHelper = process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER === "1";
const localOllamaCredential = process.env.OLLAMA_API_KEY === "local-ollama" ? "local-ollama" : undefined;
const configuredTimeout = Number(process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS);
const helperTimeoutMilliseconds = Number.isSafeInteger(configuredTimeout)
  && configuredTimeout >= 100 && configuredTimeout <= 30_000 ? configuredTimeout : 10_000;
const recordMutationTimeoutMilliseconds = Number.isSafeInteger(configuredTimeout)
  && configuredTimeout >= 100 && configuredTimeout <= 30_000 ? configuredTimeout : 30_000;
const recordLockTimeoutMilliseconds = Number.isSafeInteger(configuredTimeout)
  && configuredTimeout >= 100 && configuredTimeout <= 30_000 ? configuredTimeout : 35_000;
delete process.env.LOCAL_HARNESS_CREDENTIAL_PLUGIN;
delete process.env.LOCAL_HARNESS_CREDENTIAL_HELPER;
delete process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS;
delete process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER;
delete process.env.OLLAMA_API_KEY;
if (!helperPath) throw new Error("credentials-keychain: native helper path is missing");

const maximumHelperOutputBytes = 1_048_576;
const maximumHelperStderrBytes = 65_536;
const maximumCredentialRecordNodes = 65_536;
const terminationGraceMilliseconds = 250;
const foregroundRecoverySource = "Fulmar credential recovery required";
const foregroundRecoveryCodes = new Set([
  "KEYCHAIN_AUTHORIZATION_REQUIRED",
  "CREDENTIAL_RECOVERY_REQUIRED"
]);

function helperError(message, code) {
  const safeMessage = `credentials-keychain: ${message}`;
  const error = new Error(safeMessage);
  if (code !== undefined) {
    error.code = code;
    // dsh-llm deliberately trusts a foreign error code only when the same
    // value is carried in an immutable serializable failure snapshot. Keep
    // Keychain repair states machine-routable without ever adding helper
    // stderr, a credential value, or a Keychain record reference.
    error.failure = Object.freeze({ message: safeMessage, code });
  }
  return error;
}

function helperExitError(code) {
  if (code === 5) return helperError("macOS Keychain authorization is required; open Fulmar Models & Providers to repair this cloud credential", "KEYCHAIN_AUTHORIZATION_REQUIRED");
  if (code === 6) return helperError("an interrupted or externally changed credential requires an explicit recovery choice in Fulmar Models & Providers", "CREDENTIAL_RECOVERY_REQUIRED");
  if (code === 7) return helperError("another credential transaction is still finishing; wait a moment and try again", "CREDENTIAL_TRANSACTION_BUSY");
  if (code === 8) return helperError("credential ownership or integrity checks failed; no Keychain value was changed", "CREDENTIAL_STATE_UNSAFE");
  if (code === 9) return helperError("credential recovery state could not be persisted safely", "CREDENTIAL_STATE_UNAVAILABLE");
  if (code === 10) return helperError("the final Keychain value could not be verified; recovery remains fail-closed", "CREDENTIAL_VERIFICATION_FAILED");
  if (code === 11) return helperError("native record modification protocol failed", "CREDENTIAL_RECORD_PROTOCOL_FAILED");
  return helperError(`native helper failed (${code ?? "signal"})`);
}

function runHelper(command, subject, input, { signal } = {}) {
  if (forbidCredentialHelper) {
    return Promise.reject(helperError("native helper is forbidden by the on-device acceptance boundary"));
  }
  if (input !== undefined && (!Buffer.isBuffer(input) || input.length > maximumHelperOutputBytes)) {
    return Promise.reject(helperError("helper input exceeded its size limit"));
  }
  if (signal?.aborted) return Promise.reject(helperError("native helper was cancelled"));
  return new Promise((resolve, reject) => {
    const child = spawn(helperPath, subject === undefined ? [command] : [command, subject], {
      env: { HOME: process.env.HOME, USER: process.env.USER, LOGNAME: process.env.LOGNAME, PATH: "/usr/bin:/bin" }, stdio: ["pipe", "pipe", "pipe"]
    });
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let pendingFailure;
    let closed = false;
    let killTimer;
    const started = performance.now();

    const requestTermination = (error) => {
      if (pendingFailure === undefined) pendingFailure = error;
      if (closed) return;
      try { child.stdin.destroy(); } catch {}
      try { child.kill("SIGTERM"); } catch {}
      if (killTimer === undefined) {
        killTimer = setTimeout(() => {
          if (!closed) {
            try { child.kill("SIGKILL"); } catch {}
          }
        }, terminationGraceMilliseconds);
        killTimer.unref?.();
      }
    };
    const timeout = setTimeout(() => {
      const elapsed = Math.max(0, performance.now() - started);
      requestTermination(helperError(`native helper timed out after ${Math.floor(elapsed)} ms`));
    }, helperTimeoutMilliseconds);
    timeout.unref?.();
    const aborted = () => requestTermination(helperError("native helper was cancelled"));
    signal?.addEventListener("abort", aborted, { once: true });

    child.stdout.on("data", (chunk) => {
      if (pendingFailure !== undefined) return;
      stdoutBytes += chunk.length;
      if (stdoutBytes > maximumHelperOutputBytes) {
        requestTermination(helperError("helper response exceeded its size limit"));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > maximumHelperStderrBytes) {
        requestTermination(helperError("helper diagnostic output exceeded its size limit"));
      }
      // Diagnostic bytes are deliberately drained but never retained or
      // reflected into an error because a faulty helper could echo a secret.
    });
    child.stdin.on("error", () => {
      requestTermination(helperError("native helper input failed"));
    });
    child.on("error", () => {
      requestTermination(helperError("native helper could not be started"));
    });
    child.on("close", (code) => {
      closed = true;
      clearTimeout(timeout);
      if (killTimer !== undefined) clearTimeout(killTimer);
      signal?.removeEventListener("abort", aborted);
      if (pendingFailure !== undefined) { reject(pendingFailure); return; }
      if (code === 0) resolve(Buffer.concat(stdout));
      else if (code === 3 && (command === "get" || command === "get-record")) resolve(undefined);
      else reject(helperExitError(code));
    });
    try { child.stdin.end(input); }
    catch { requestTermination(helperError("native helper input failed")); }
  });
}

function assertRecord(record) {
  try {
    const seen = new WeakSet();
    let nodes = 0;
    const normalize = (value, depth = 0) => {
      if (depth > 64 || ++nodes > maximumCredentialRecordNodes) throw new TypeError("invalid record");
      if (value === null || typeof value === "string" || typeof value === "boolean") return value;
      if (typeof value === "number" && Number.isFinite(value)) return value;
      if (typeof value !== "object" || seen.has(value)) throw new TypeError("invalid record");
      seen.add(value);

      if (Array.isArray(value)) {
        const keys = Reflect.ownKeys(value);
        const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
        const length = lengthDescriptor !== undefined && Object.hasOwn(lengthDescriptor, "value")
          ? lengthDescriptor.value
          : undefined;
        if (!Number.isSafeInteger(length) || length < 0 || length > maximumCredentialRecordNodes
          || keys.length !== length + 1 || !keys.every((key) => key === "length"
            || (typeof key === "string" && /^(0|[1-9][0-9]*)$/u.test(key)))) {
          throw new TypeError("invalid record");
        }
        const normalized = [];
        for (let index = 0; index < length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
          if (descriptor === undefined || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
            throw new TypeError("invalid record");
          }
          normalized.push(normalize(descriptor.value, depth + 1));
        }
        return normalized;
      }

      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError("invalid record");
      const keys = Reflect.ownKeys(value);
      if (keys.length > maximumCredentialRecordNodes) throw new TypeError("invalid record");
      const normalized = {};
      for (const key of keys) {
        if (typeof key !== "string" || key === "toJSON") throw new TypeError("invalid record");
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
          throw new TypeError("invalid record");
        }
        Object.defineProperty(normalized, key, {
          configurable: true,
          enumerable: true,
          writable: true,
          value: normalize(descriptor.value, depth + 1)
        });
      }
      return normalized;
    };
    const serialize = (value) => {
      if (value === null) return "null";
      if (typeof value === "string") return JSON.stringify(value);
      if (typeof value === "boolean") return value ? "true" : "false";
      if (typeof value === "number") return Object.is(value, -0) ? "0" : String(value);
      if (Array.isArray(value)) return `[${value.map((entry) => serialize(entry)).join(",")}]`;
      return `{${Reflect.ownKeys(value).map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (typeof key !== "string" || descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
          throw new TypeError("invalid record");
        }
        return `${JSON.stringify(key)}:${serialize(descriptor.value)}`;
      }).join(",")}}`;
    };

    const normalized = normalize(record);
    const keys = Reflect.ownKeys(normalized);
    const kind = Object.getOwnPropertyDescriptor(normalized, "kind")?.value;
    if (kind === "api-key") {
      if (!keys.every((key) => key === "kind" || key === "key" || key === "env")) {
        throw new TypeError("invalid record");
      }
      const key = Object.getOwnPropertyDescriptor(normalized, "key")?.value;
      if (key !== undefined && (typeof key !== "string" || key.length === 0)) {
        throw new TypeError("invalid record");
      }
      const env = Object.getOwnPropertyDescriptor(normalized, "env")?.value;
      if (env !== undefined) {
        if (typeof env !== "object" || env === null || Array.isArray(env)) throw new TypeError("invalid record");
        for (const name of Reflect.ownKeys(env)) {
          const value = Object.getOwnPropertyDescriptor(env, name)?.value;
          if (typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)
            || typeof value !== "string" || value.length === 0) throw new TypeError("invalid record");
        }
      }
    } else if (kind === "grant") {
      if (!Object.hasOwn(normalized, "payload")
        || !keys.every((key) => key === "kind" || key === "payload")) throw new TypeError("invalid record");
    } else {
      throw new TypeError("invalid record");
    }
    const serialized = serialize(normalized);
    if (Buffer.byteLength(serialized) > maximumHelperOutputBytes) throw new TypeError("invalid record");
    return { normalized, serialized };
  } catch {
    throw helperError("credential record is invalid", "CREDENTIAL_RECORD_PROTOCOL_FAILED");
  }
}

function modifyRecordLocked(key, mutate) {
  if (forbidCredentialHelper) return Promise.reject(helperError("native helper is forbidden by the on-device acceptance boundary"));
  return new Promise((resolve, reject) => {
    const child = spawn(helperPath, ["modify-record-locked", key], {
      env: { HOME: process.env.HOME, USER: process.env.USER, LOGNAME: process.env.LOGNAME, PATH: "/usr/bin:/bin" }, stdio: ["pipe", "pipe", "pipe"]
    });
    let output = Buffer.alloc(0);
    let expectedCurrent;
    let current;
    let returnValue;
    let changed = false;
    let mutationStarted = false;
    let expectedCommittedOutput;
    let pendingFailure;
    let closed = false;
    let killTimer;
    let stderrBytes = 0;
    let inputEnded = false;
    let timeout;
    const terminate = (error) => {
      if (pendingFailure === undefined) pendingFailure = error;
      try { child.stdin.destroy(); } catch {}
      try { child.kill("SIGTERM"); } catch {}
      if (killTimer === undefined) killTimer = setTimeout(() => { if (!closed) try { child.kill("SIGKILL"); } catch {} }, terminationGraceMilliseconds);
    };
    const armTimeout = (milliseconds, phase) => {
      if (timeout !== undefined) clearTimeout(timeout);
      timeout = setTimeout(() => terminate(helperError(`native record modification ${phase} timed out`)), milliseconds);
      timeout.unref?.();
    };
    armTimeout(recordLockTimeoutMilliseconds, "lock wait");
    child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > maximumHelperStderrBytes) terminate(helperError("helper diagnostic output exceeded its size limit")); });
    child.stdin.on("error", () => { if (!inputEnded) terminate(helperError("native helper input failed")); });
    child.on("error", () => terminate(helperError("native helper could not be started")));
    child.stdout.on("data", (chunk) => {
      if (pendingFailure !== undefined) return;
      output = Buffer.concat([output, chunk]);
      if (output.length > maximumHelperOutputBytes + 128) { terminate(helperError("helper response exceeded its size limit")); return; }
      if (expectedCurrent === undefined) {
        const newline = output.indexOf(0x0a);
        if (newline < 0) { if (output.length > 64) terminate(helperError("invalid native record protocol")); return; }
        const match = /^CURRENT (-1|0|[1-9][0-9]*)$/u.exec(output.subarray(0, newline).toString("utf8"));
        if (!match) { terminate(helperError("invalid native record protocol")); return; }
        expectedCurrent = Number(match[1]);
        if (expectedCurrent > maximumHelperOutputBytes) { terminate(helperError("helper response exceeded its size limit")); return; }
        output = output.subarray(newline + 1);
        armTimeout(recordMutationTimeoutMilliseconds, "callback");
      }
      if (!mutationStarted && output.length >= Math.max(0, expectedCurrent)) {
        mutationStarted = true;
        const bytes = expectedCurrent < 0 ? undefined : output.subarray(0, expectedCurrent);
        output = output.subarray(Math.max(0, expectedCurrent));
        try {
          current = bytes === undefined ? undefined : JSON.parse(bytes.toString("utf8"));
          if (current !== undefined) current = assertRecord(current).normalized;
        }
        catch {
          terminate(helperError("stored credential record is invalid", "CREDENTIAL_RECORD_PROTOCOL_FAILED"));
          return;
        }
        Promise.resolve().then(() => mutate(current)).then((next) => {
          if (pendingFailure !== undefined) return;
          if (next === undefined) {
            returnValue = current;
            expectedCommittedOutput = Buffer.concat([Buffer.from("COMMITTED\n"), bytes ?? Buffer.alloc(0)]);
            inputEnded = true;
            child.stdin.end("UNCHANGED\n");
          }
          else {
            let checked;
            try { checked = assertRecord(next); }
            catch (error) { terminate(error); return; }
            const serialized = Buffer.from(checked.serialized, "utf8");
            changed = true;
            returnValue = checked.normalized;
            expectedCommittedOutput = Buffer.concat([Buffer.from("COMMITTED\n"), serialized]);
            inputEnded = true;
            child.stdin.end(Buffer.concat([Buffer.from(`STORE ${serialized.length}\n`, "utf8"), serialized]));
          }
        }, () => terminate(helperError(
          "credential record mutation failed safely",
          "CREDENTIAL_RECORD_PROTOCOL_FAILED"
        )));
      }
    });
    child.on("close", (code) => {
      closed = true; clearTimeout(timeout); if (killTimer !== undefined) clearTimeout(killTimer);
      if (pendingFailure !== undefined) { reject(pendingFailure); return; }
      if (code === 0 && expectedCommittedOutput !== undefined && output.equals(expectedCommittedOutput)) { resolve({ value: returnValue, changed }); return; }
      if (code === 0) { reject(helperError("invalid native record protocol")); return; }
      reject(helperExitError(code));
    });
  });
}

class KeychainCredentialProvider extends CredentialProvider {
  static Config = z.object({});
  credentialOperations = Promise.resolve();
  recordOperations = Promise.resolve();

  async resolve(reference) {
    credentialRef(reference);
    await this.credentialOperations;
    // The app-owned Ollama route uses a fixed, non-secret readiness marker.
    // Never put a local inference turn behind macOS Keychain authorization:
    // an unrelated legacy/cloud item or a changed development signature must
    // not be able to stall, prompt, or fail otherwise private Qwen work.
    if (reference === "OLLAMA_API_KEY" && localOllamaCredential) {
      return { value: localOllamaCredential, source: "Local Ollama runtime" };
    }
    const value = await runHelper("get", reference);
    if (value !== undefined) return { value: value.toString("utf8"), source: "macOS Keychain" };
    return undefined;
  }
  async describe(reference) {
    credentialRef(reference);
    await this.credentialOperations;
    if (reference === "OLLAMA_API_KEY" && localOllamaCredential) {
      return { configured: true, source: "Local Ollama runtime", writable: true };
    }
    try {
      const stored = (await runHelper("describe", reference)).toString("utf8") === "1";
      return { configured: stored, source: stored ? "macOS Keychain" : undefined, writable: true };
    } catch (error) {
      // `credentials.describe` has no typed attention field in DSH 0.1.1-rc.1.
      // Return a value-free, read-only marker for only the two states that the
      // native foreground repair flow can resolve. Other helper failures keep
      // failing normally instead of being misrepresented as a recoverable key.
      if (foregroundRecoveryCodes.has(error?.code)) {
        return { configured: false, source: foregroundRecoverySource, writable: false };
      }
      throw error;
    }
  }
  enqueueCredentialOperation(operation) {
    const queued = this.credentialOperations.then(operation);
    this.credentialOperations = queued.then(() => undefined, () => undefined);
    return queued;
  }
  set(reference, value) { credentialRef(reference); if (value.length === 0) return Promise.reject(new Error("credentials-keychain: empty credentials are not permitted")); return this.enqueueCredentialOperation(async () => { await runHelper("set", reference, Buffer.from(value, "utf8")); this.notifyUpdated(reference); }); }
  unset(reference) { credentialRef(reference); return this.enqueueCredentialOperation(async () => { await runHelper("unset", reference); this.notifyUpdated(reference); }); }
  async readRecord(key) {
    parseCredentialKey(key);
    const value = await runHelper("get-record", key);
    if (value === undefined) return undefined;
    try {
      return assertRecord(JSON.parse(value.toString("utf8"))).normalized;
    } catch {
      throw helperError("stored credential record is invalid", "CREDENTIAL_RECORD_PROTOCOL_FAILED");
    }
  }
  async describeRecord(key) { parseCredentialKey(key); const record = await this.readRecord(key); return record === undefined ? { configured: false, writable: true } : { configured: true, kind: record.kind, writable: true }; }
  async listRecords() { const entries = JSON.parse((await runHelper("list-records")).toString("utf8")); return entries.map(({ key, kind }) => ({ key: parseCredentialKey(key), kind })); }
  enqueueRecordOperation(operation) {
    const queued = this.recordOperations.then(operation);
    this.recordOperations = queued.then(() => undefined, () => undefined);
    return queued;
  }
  modifyRecord(key, mutate) {
    parseCredentialKey(key);
    return this.enqueueRecordOperation(async () => { const result = await modifyRecordLocked(key, mutate); if (result.changed) this.notifyRecordUpdated(key); return result.value; });
  }
  deleteRecord(key) {
    parseCredentialKey(key);
    return this.enqueueRecordOperation(async () => { await runHelper("unset-record", key); this.notifyRecordUpdated(key); });
  }
}

export { KeychainCredentialProvider, runHelper };
export default KeychainCredentialProvider;
