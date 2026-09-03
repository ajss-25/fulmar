#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";

const dshRootArgument = process.argv[2];
if (!dshRootArgument) throw new Error("packaged DSH root is required");

const dshRoot = resolve(dshRootArgument);
if (realpathSync(dshRoot) !== dshRoot) throw new Error("packaged DSH root must be canonical");

const expectedRoots = Object.freeze([
  "config/agent-presets"
]);
const removedRowIDs = Object.freeze(["tool-ralph", "tool-workflow", "workflow-worker-thread"]);
const forbiddenMarkers = Object.freeze([
  "@deepseek-ai/dsh-fs-local",
  "@deepseek-ai/dsh-tool-cordis",
  "@deepseek-ai/dsh-tool-cordis-mount",
  "@deepseek-ai/dsh-cordis-mount",
  "@deepseek-ai/dsh-workflow-worker-thread",
  "@deepseek-ai/dsh-tool-workflow",
  "@deepseek-ai/dsh-tool-ralph",
  "@deepseek-ai/dsh-code-runtime-worker-thread",
  "@deepseek-ai/dsh-tool-code"
]);
const requiredMarkers = Object.freeze([
  "@deepseek-ai/dsh-tool-bash",
  "@deepseek-ai/dsh-tool-fs",
  "@deepseek-ai/dsh-tool-subagent",
  "includeDefaultRoots: false",
  "bundledSkillDir:",
  "process.env.DSH_HOME, 'skills', 'Active'",
  "watchFollowSymlinks: false",
  "search: false",
  "fetch: true",
  "fetchTimeoutMs: 30000",
  "fetchMaxOutputChars: 200000"
]);
const expectedPreset = [
  "name: Fulmar Standard",
  "description: Sandboxed coding agent with files, shell, approved page fetch, skills, goals, plans and subagents.",
  "order: 1",
  ""
].join("\n");

function safeRelative(path) {
  const candidate = relative(dshRoot, path).split(sep).join("/");
  if (candidate === "" || candidate === ".." || candidate.startsWith("../")) {
    throw new Error("preset discovery escaped the packaged DSH root");
  }
  return candidate;
}

function assertExactEntries(path, expected) {
  const entries = readdirSync(path, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  if (JSON.stringify(names) !== JSON.stringify([...expected].sort())) {
    throw new Error(`unexpected sanitized preset entries at ${safeRelative(path)}`);
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) throw new Error(`linked sanitized preset entry at ${safeRelative(join(path, entry.name))}`);
  }
}

function readRegular(path, maximumBytes) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error(`sanitized preset file is not an independent regular file: ${safeRelative(path)}`);
  }
  if (metadata.size < 1 || metadata.size > maximumBytes) {
    throw new Error(`sanitized preset file has invalid size: ${safeRelative(path)}`);
  }
  return readFileSync(path, "utf8");
}

function verifyPresetRoot(root) {
  assertExactEntries(root, ["local-harness-policy.json", "standard"]);
  const standard = join(root, "standard");
  if (!lstatSync(standard).isDirectory()) throw new Error(`standard preset is not a directory: ${safeRelative(standard)}`);
  assertExactEntries(standard, ["agent.cordis.yml", "preset.yml"]);

  const composition = readRegular(join(standard, "agent.cordis.yml"), 256 * 1024);
  const preset = readRegular(join(standard, "preset.yml"), 16 * 1024);
  const policyText = readRegular(join(root, "local-harness-policy.json"), 16 * 1024);
  if (preset !== expectedPreset) throw new Error(`sanitized preset metadata changed at ${safeRelative(root)}`);

  for (const id of removedRowIDs) {
    if (new RegExp(`^\\s*- id:\\s*['\"]?${id}['\"]?\\s*(?:#.*)?$`, "m").test(composition)) {
      throw new Error(`unsafe preset row remained at ${safeRelative(root)}: ${id}`);
    }
  }
  for (const marker of forbiddenMarkers) {
    if (composition.includes(marker)) throw new Error(`unsafe preset capability remained at ${safeRelative(root)}: ${marker}`);
  }
  for (const marker of requiredMarkers) {
    if (!composition.includes(marker)) throw new Error(`required preset policy is missing at ${safeRelative(root)}: ${marker}`);
  }
  if ((composition.match(/^- id:[ \t]*skill-filesystem[ \t]*$/gm) ?? []).length !== 1) {
    throw new Error(`sanitized preset has an invalid skill-filesystem row count at ${safeRelative(root)}`);
  }
  const expectedWebToolRow = [
    "- id: tool-web",
    "  name: '@deepseek-ai/dsh-tool-web'",
    "  config:",
    "    search: false",
    "    fetch: true",
    "    fetchTimeoutMs: 30000",
    "    fetchMaxOutputChars: 200000",
    ""
  ].join("\n");
  const webRows = composition.match(/^- id:[ \t]*tool-web[ \t]*(?:\n(?!- id:)[^\n]*)*/gm) ?? [];
  if (webRows.length !== 1 || webRows[0].trimEnd() !== expectedWebToolRow.trimEnd()) {
    throw new Error(`sanitized preset does not expose exactly the approved fetch-only web tool at ${safeRelative(root)}`);
  }

  let policy;
  try { policy = JSON.parse(policyText); }
  catch { throw new Error(`sanitized preset policy is invalid JSON at ${safeRelative(root)}`); }
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)
      || JSON.stringify(Object.keys(policy).sort()) !== JSON.stringify(["allowedPresetIDs", "compositionSHA256", "removedRowIDs", "version"])) {
    throw new Error(`sanitized preset policy has an unexpected schema at ${safeRelative(root)}`);
  }
  if (policy.version !== 1
      || JSON.stringify(policy.allowedPresetIDs) !== JSON.stringify(["standard"])
      || JSON.stringify(policy.removedRowIDs) !== JSON.stringify(removedRowIDs)
      || policy.compositionSHA256 !== createHash("sha256").update(composition).digest("hex")) {
    throw new Error(`sanitized preset policy does not bind its composition at ${safeRelative(root)}`);
  }
  if (policyText !== `${JSON.stringify(policy, null, 2)}\n`) {
    throw new Error(`sanitized preset policy is not canonical at ${safeRelative(root)}`);
  }
  return { composition, preset, policyText };
}

const discovered = [];
const packageRoots = [];
const stack = [dshRoot];
let visited = 0;
while (stack.length > 0) {
  const directory = stack.pop();
  visited += 1;
  if (visited > 100_000) throw new Error("packaged DSH directory count exceeded the preset-verification bound");
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "package.json" && entry.isFile() && !entry.isSymbolicLink()) {
      const manifestPath = join(directory, entry.name);
      let manifest;
      try { manifest = JSON.parse(readRegular(manifestPath, 1024 * 1024)); }
      catch { throw new Error(`packaged manifest is invalid JSON at ${safeRelative(manifestPath)}`); }
      if (manifest?.name === "@deepseek-ai/dsh") {
        const relativePackage = relative(dshRoot, directory).split(sep).join("/") || ".";
        packageRoots.push(relativePackage);
      }
    }
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const child = join(directory, entry.name);
    if (entry.name === "agent-presets" && basename(directory) === "config") discovered.push(safeRelative(child));
    stack.push(child);
  }
}
discovered.sort();
packageRoots.sort();
if (JSON.stringify(discovered) !== JSON.stringify([...expectedRoots].sort())) {
  throw new Error(`packaged DSH has unexpected discoverable preset roots: ${JSON.stringify(discovered)}`);
}
if (JSON.stringify(packageRoots) !== JSON.stringify(["."])) {
  throw new Error(`packaged Runtime has unexpected @deepseek-ai/dsh package roots: ${JSON.stringify(packageRoots)}`);
}
readRegular(join(dshRoot, "lib/bin.js"), 8 * 1024 * 1024);

const verified = expectedRoots.map((path) => verifyPresetRoot(join(dshRoot, ...path.split("/"))));
process.stdout.write(`Verified one authoritative DSH package, CLI, and exact sanitized preset root.\n`);
