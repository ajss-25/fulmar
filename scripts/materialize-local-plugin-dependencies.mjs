#!/usr/bin/env node

import { chmod, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";

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
  // Open-first: the no-follow descriptor is opened before any shape decision,
  // its metadata is the reviewed shape, and the pathname is re-attested around
  // the read so a swapped file cannot be substituted for the reviewed inode.
  let input;
  try {
    input = await readAttestedRegularFile(path, {
      label: "runtime manifest input",
      minimumBytes: 1,
      maximumBytes,
      requireCurrentUser: false,
      requireSingleLink: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    fail(`unsafe regular file: ${path}`);
  }
  return { bytes: input.bytes, mode: Number(input.metadata.mode & 0o777n) };
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
