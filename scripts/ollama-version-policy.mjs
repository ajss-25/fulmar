import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const maximumOllamaVersionResponseBytes = 256;
export const minimumOllamaVersion = "0.33.2";
export const testedOllamaVersion = "0.33.2";
export const qualifiedOllamaSeries = "0.33.x";

const stablePattern = /^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;
const responsePattern = /^[ \t\r\n]*\{[ \t\r\n]*"version"[ \t\r\n]*:[ \t\r\n]*"([^"\\]{1,64})"[ \t\r\n]*\}[ \t\r\n]*$/u;

function fail(message) {
  throw new Error(message);
}

export function parseStableOllamaVersion(rawValue) {
  if (typeof rawValue !== "string" || Buffer.byteLength(rawValue, "utf8") > 64) {
    fail("Ollama version is not one bounded stable semantic version");
  }
  const match = stablePattern.exec(rawValue);
  if (!match) fail("Ollama version is not one bounded stable semantic version");
  const core = match.slice(1, 4).map((value) => Number(value));
  if (core.some((value) => !Number.isSafeInteger(value) || value > 2_147_483_647)) {
    fail("Ollama version contains an out-of-range component");
  }
  return Object.freeze({
    rawValue,
    major: core[0],
    minor: core[1],
    patch: core[2],
    buildMetadata: match[4] ?? null
  });
}

export function compareOllamaVersions(left, right) {
  for (const key of ["major", "minor", "patch"]) {
    if (left[key] !== right[key]) return left[key] < right[key] ? -1 : 1;
  }
  return 0;
}

export function requireCompatibleOllamaVersion(rawValue) {
  const actual = parseStableOllamaVersion(rawValue);
  const minimum = parseStableOllamaVersion(minimumOllamaVersion);
  if (compareOllamaVersions(actual, minimum) < 0) {
    fail(`Ollama ${actual.rawValue} is too old; update to ${minimumOllamaVersion} or later`);
  }
  if (actual.major !== minimum.major || actual.minor !== minimum.minor) {
    fail(`Ollama ${actual.rawValue} is newer than Fulmar's release-qualified ${qualifiedOllamaSeries} range; install a Fulmar update that qualifies this release or restore ${qualifiedOllamaSeries} (${minimumOllamaVersion} or later)`);
  }
  return actual;
}

export function parseOllamaVersionResponse(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0
      || bytes.length > maximumOllamaVersionResponseBytes) {
    fail("Ollama version response is empty or exceeds its byte limit");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("Ollama version response is not valid UTF-8");
  }
  const match = responsePattern.exec(text);
  if (!match) fail("Ollama version response has an unexpected JSON shape");
  return requireCompatibleOllamaVersion(match[1]);
}

async function readBoundedResponse(path) {
  if (typeof constants.O_NOFOLLOW !== "number") {
    fail("this host cannot prove a no-follow Ollama version evidence read");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size <= 0
        || before.size > maximumOllamaVersionResponseBytes) {
      fail("Ollama version evidence is not one bounded regular file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || before.dev !== after.dev || before.ino !== after.ino
        || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) {
      fail("Ollama version evidence changed while it was being validated");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function main() {
  const [mode, value] = process.argv.slice(2);
  let version;
  if (mode === "--response" && value && process.argv.length === 4) {
    version = parseOllamaVersionResponse(await readBoundedResponse(value));
  } else if (mode === "--version" && value && process.argv.length === 4) {
    version = requireCompatibleOllamaVersion(value);
  } else {
    fail("usage: ollama-version-policy.mjs <--response file|--version value>");
  }
  process.stdout.write(`${version.rawValue}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
