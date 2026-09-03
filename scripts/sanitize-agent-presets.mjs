#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2];
if (!root) throw new Error("preset root is required");

const allowed = new Set(["standard"]);
const removedRowIDs = new Set(["workflow-worker-thread", "tool-workflow", "tool-ralph"]);
const forbiddenMarkers = [
  "@deepseek-ai/dsh-fs-local",
  "@deepseek-ai/dsh-tool-cordis",
  "@deepseek-ai/dsh-tool-cordis-mount",
  "@deepseek-ai/dsh-cordis-mount",
  "@deepseek-ai/dsh-workflow-worker-thread",
  "@deepseek-ai/dsh-tool-workflow",
  "@deepseek-ai/dsh-tool-ralph",
  "@deepseek-ai/dsh-code-runtime-worker-thread",
  "@deepseek-ai/dsh-tool-code"
];

for (const name of readdirSync(root)) {
  const candidate = join(root, name);
  if (statSync(candidate).isDirectory() && !allowed.has(name)) rmSync(candidate, { recursive: true, force: true });
}

function removeRows(source) {
  const lines = source.split("\n");
  const output = [];
  for (let index = 0; index < lines.length;) {
    const match = /^(\s*)- id:\s*['"]?([^'"\s#]+)['"]?\s*(?:#.*)?$/.exec(lines[index]);
    if (!match || !removedRowIDs.has(match[2])) {
      output.push(lines[index]);
      index += 1;
      continue;
    }
    const indentation = match[1].length;
    index += 1;
    while (index < lines.length) {
      const line = lines[index];
      if (line.trim() === "" || line.trimStart().startsWith("#")) {
        index += 1;
        continue;
      }
      const leading = line.length - line.trimStart().length;
      if (leading <= indentation) break;
      index += 1;
    }
  }
  return output.join("\n").replace(/\n{3,}/g, "\n\n");
}

const standard = join(root, "standard", "agent.cordis.yml");
let composition = removeRows(readFileSync(standard, "utf8"));
function replaceSingleTopLevelRow(source, id, replacement) {
  const lines = source.split("\n");
  const rowHeader = /^- id:[ \t]*([^ \t]+)[ \t]*$/;
  const nextTopLevelRow = /^- id:/;
  const rows = lines.flatMap((line, index) => rowHeader.exec(line)?.[1] === id ? [index] : []);
  if (rows.length !== 1) throw new Error(`expected exactly one ${id} row, found ${rows.length}`);
  const start = rows[0];
  let end = start + 1;
  while (end < lines.length && !nextTopLevelRow.test(lines[end])) end += 1;
  lines.splice(start, end - start, ...replacement.split("\n"));
  return lines.join("\n");
}
const isolatedSkillRow = [
  "- id: skill-filesystem",
  "  name: '@deepseek-ai/dsh-skill-filesystem'",
  "  config:",
  "    includeDefaultRoots: false",
  "    bundledSkillDir: !!js \"process.getBuiltinModule('node:path').join(process.env.DSH_HOME, 'skills', 'Active')\"",
  "    watchFollowSymlinks: false",
  ""
].join("\n");
composition = replaceSingleTopLevelRow(composition, "skill-filesystem", isolatedSkillRow);
const approvedWebToolRow = [
  "- id: tool-web",
  "  name: '@deepseek-ai/dsh-tool-web'",
  "  config:",
  "    search: false",
  "    fetch: true",
  "    fetchTimeoutMs: 30000",
  "    fetchMaxOutputChars: 200000",
  ""
].join("\n");
composition = replaceSingleTopLevelRow(composition, "tool-web", approvedWebToolRow);
composition = composition.replace(
  "# The `web` service and its search provider stay in the host composition; only\n# the model-facing tool is per-session.",
  "# Fulmar exposes only its per-page-approved fetch tool to model-facing sessions;\n# credential-dependent general search remains absent until separately configured."
);
for (const id of removedRowIDs) {
  const remained = composition.split("\n").some((line) => /^\s*- id:\s*([^\s]+)\s*$/.exec(line)?.[1] === id);
  if (remained) throw new Error(`unsafe preset row remained: ${id}`);
}
for (const marker of forbiddenMarkers) {
  if (composition.includes(marker)) throw new Error(`unsafe preset capability remained: ${marker}`);
}
for (const required of ["@deepseek-ai/dsh-tool-bash", "@deepseek-ai/dsh-tool-fs", "@deepseek-ai/dsh-tool-subagent"]) {
  if (!composition.includes(required)) throw new Error(`required sandboxed capability is missing: ${required}`);
}
for (const required of ["includeDefaultRoots: false", "bundledSkillDir:", "process.env.DSH_HOME, 'skills', 'Active'", "watchFollowSymlinks: false", "search: false", "fetch: true", "fetchTimeoutMs: 30000", "fetchMaxOutputChars: 200000"]) {
  if (!composition.includes(required)) throw new Error(`isolated skill policy is missing: ${required}`);
}
writeFileSync(standard, composition, { mode: 0o644 });
writeFileSync(join(root, "standard", "preset.yml"), [
  "name: Fulmar Standard",
  "description: Sandboxed coding agent with files, shell, approved page fetch, skills, goals, plans and subagents.",
  "order: 1",
  ""
].join("\n"), { mode: 0o644 });

const manifest = {
  version: 1,
  allowedPresetIDs: [...allowed],
  removedRowIDs: [...removedRowIDs].sort(),
  compositionSHA256: createHash("sha256").update(composition).digest("hex")
};
writeFileSync(join(root, "local-harness-policy.json"), JSON.stringify(manifest, null, 2) + "\n", { mode: 0o644 });
