#!/usr/bin/env node

import { constants } from "node:fs";
import { chmod, lstat, open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const RELEASE_IDENTITY = JSON.parse(await readFile(
  new URL("../Config/ReleaseIdentity.json", import.meta.url), "utf8"
));
const EXPECTED_DSH_VERSION = RELEASE_IDENTITY.runtime.deepseekHarnessVersion;
const LOCAL_DEPENDENCIES = Object.freeze({
  "@local-harness/dsh-client-security-bridge": "1.2.1",
  "@local-harness/dsh-credentials-keychain": "1.0.8",
  "@local-harness/dsh-fs-confined": "1.0.0",
  "@local-harness/dsh-mcp-guarded": "1.0.0",
  "@local-harness/dsh-performance-profile": "1.2.0",
  "@local-harness/dsh-web-fetch-safe": "1.0.0"
});

function fail(message) {
  throw new Error(`${RELEASE_IDENTITY.productDisplayName} runtime-manifest materialization failed: ${message}`);
}

async function readRegular(path, maximumBytes = 2 * 1024 * 1024) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.size < 1n || before.size > BigInt(maximumBytes)) {
    fail(`unsafe regular file: ${path}`);
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino
        || opened.size !== before.size || opened.mtimeNs !== before.mtimeNs) {
      fail(`file changed while opening: ${path}`);
    }
    return { bytes: await handle.readFile(), mode: Number(before.mode & 0o777n) };
  } finally {
    await handle.close();
  }
}

function decode(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { fail(`${label} is not valid JSON`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is not an object`);
  return value;
}

async function main() {
  const [manifestArgument, projectArgument] = process.argv.slice(2);
  if (process.argv.length !== 4) fail("expected <copied-dsh-package.json> <project-root>");
  const manifestPath = resolve(manifestArgument);
  const projectRoot = resolve(projectArgument);
  const { bytes, mode } = await readRegular(manifestPath);
  const manifest = decode(bytes, "copied DSH manifest");
  if (manifest.name !== "@deepseek-ai/dsh" || manifest.version !== EXPECTED_DSH_VERSION
      || !manifest.dependencies || typeof manifest.dependencies !== "object"
      || Array.isArray(manifest.dependencies)) {
    fail("copied DSH manifest identity or dependency schema changed");
  }
  const existingLocal = Object.fromEntries(
    Object.entries(manifest.dependencies).filter(([name]) => name.startsWith("@local-harness/"))
  );
  const pristine = Object.keys(existingLocal).length === 1
    && existingLocal["@local-harness/dsh-credentials-keychain"] === "1.0.3";
  const alreadyMaterialized = Object.keys(existingLocal).length === Object.keys(LOCAL_DEPENDENCIES).length
    && Object.entries(LOCAL_DEPENDENCIES).every(([name, version]) => existingLocal[name] === version);
  if (!pristine && !alreadyMaterialized) {
    fail("the upstream manifest introduced an unreviewed Fulmar local dependency");
  }

  for (const [name, version] of Object.entries(LOCAL_DEPENDENCIES)) {
    const directory = name.slice("@local-harness/".length).replace(/^dsh-credentials-keychain$/u, "credentials-keychain")
      .replace(/^dsh-fs-confined$/u, "fs-confined")
      .replace(/^dsh-mcp-guarded$/u, "mcp-guarded")
      .replace(/^dsh-client-security-bridge$/u, "client-security-bridge")
      .replace(/^dsh-performance-profile$/u, "performance-profile")
      .replace(/^dsh-web-fetch-safe$/u, "web-fetch-safe");
    const source = decode(
      (await readRegular(join(projectRoot, "Resources", "DSHPlugins", directory, "package.json"), 256 * 1024)).bytes,
      `${name} source manifest`
    );
    if (source.name !== name || source.version !== version) fail(`${name} source identity changed`);
    manifest.dependencies[name] = version;
  }
  manifest.dependencies = Object.fromEntries(
    Object.entries(manifest.dependencies).sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
  );

  const destination = `${JSON.stringify(manifest, null, 2)}\n`;
  const temporary = join(dirname(manifestPath), `.${basename(manifestPath)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, destination, { mode: 0o600, flag: "wx" });
    await chmod(temporary, mode);
    await rename(temporary, manifestPath);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

await main();
