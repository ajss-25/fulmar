import process from "node:process";

const maximumBytes = Number(process.argv[2]);
if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 64 * 1024 * 1024) {
  throw new Error("usage: bounded-redacted-release-stream.mjs <1024..67108864>");
}

const maximumLineBytes = Math.min(maximumBytes, 1024 * 1024);
let totalBytes = 0;
let pending = Buffer.alloc(0);
let insidePrivateKey = false;

function redact(line) {
  if (insidePrivateKey) {
    if (/-----END [A-Z ]*PRIVATE KEY-----/u.test(line)) insidePrivateKey = false;
    return "";
  }
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(line)) {
    insidePrivateKey = !/-----END [A-Z ]*PRIVATE KEY-----/u.test(line);
    return `<redacted private key material>${line.endsWith("\n") ? "\n" : ""}`;
  }
  return line
    .replace(/(authorization\s*[:=]\s*bearer\s+)[^\s"']+/giu, "$1<redacted>")
    .replace(/(x-local-harness-token\s*[:=]\s*)[^\s"']+/giu, "$1<redacted>")
    .replace(/("(?:apiKey|api_key|accessToken|access_token|authToken|auth_token|secret|password|passwd|clientSecret|client_secret)"\s*:\s*")[^"]+(")/giu, "$1<redacted>$2")
    .replace(/\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)(\s*[:=]\s*)"[^"\r\n]{1,4096}"/giu, '$1$2"<redacted>"')
    .replace(/\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)(\s*[:=]\s*)'[^'\r\n]{1,4096}'/giu, "$1$2'<redacted>'")
    .replace(/\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)(\s*[:=]\s*)[^\s,}\]"';]{3,}/giu, "$1$2<redacted>")
    .replace(/(https?:\/\/[^\s:/]+:)[^@\s]+(@)/giu, "$1<redacted>$2")
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/gu, "[REDACTED JWT]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/gu, "[REDACTED ACCESS KEY]")
    .replace(/\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b/giu, "[REDACTED TOKEN]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/giu, "[REDACTED TOKEN]")
    .replace(/\b(?:hf_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,})\b/gu, "[REDACTED API KEY]")
    .replace(/\b(?:sk|rk|api)[-_][A-Za-z0-9_-]{12,}\b/giu, "[REDACTED API KEY]")
    .replace(/\/Users\/[^/\s]+/gu, "/Users/<private>");
}

async function emit(bytes) {
  if (bytes.length > maximumLineBytes) throw new Error("release output contains an oversized line");
  const output = Buffer.from(redact(bytes.toString("utf8")), "utf8");
  if (!process.stdout.write(output)) await new Promise((resolve) => process.stdout.once("drain", resolve));
}

for await (const chunk of process.stdin) {
  totalBytes += chunk.length;
  if (totalBytes > maximumBytes) throw new Error(`release output exceeded ${maximumBytes} bytes`);
  pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
  while (true) {
    const newline = pending.indexOf(0x0a);
    if (newline < 0) break;
    const line = pending.subarray(0, newline + 1);
    pending = pending.subarray(newline + 1);
    await emit(line);
  }
  if (pending.length > maximumLineBytes) throw new Error("release output contains an oversized unterminated line");
}
if (pending.length > 0) await emit(pending);
if (insidePrivateKey) throw new Error("release output ended inside private key material");
