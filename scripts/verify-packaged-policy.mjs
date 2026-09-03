import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const [patchArgument, presetArgument, noticesArgument] = process.argv.slice(2);
if (!patchArgument || !presetArgument || !noticesArgument) {
  throw new Error("usage: verify-packaged-policy.mjs <LocalHarness.patch.yml> <standard-agent.cordis.yml> <THIRD_PARTY_NOTICES.md>");
}

async function boundedText(pathArgument, maximumBytes, label) {
  const path = resolve(pathArgument);
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || details.size <= 0 || details.size > maximumBytes) throw new Error(`${label} is not one bounded regular file`);
  const text = await readFile(path, "utf8");
  if (text.includes("\0") || text.includes("\r")) throw new Error(`${label} has unsafe encoding`);
  return text;
}

function requireMatch(text, expression, label) {
  if (!expression.test(text)) throw new Error(`packaged policy is missing ${label}`);
}

const patch = await boundedText(patchArgument, 1024 * 1024, "runtime patch");
const preset = await boundedText(presetArgument, 1024 * 1024, "agent preset");
const notices = await boundedText(noticesArgument, 16 * 1024 * 1024, "third-party notices");

requireMatch(notices, /^## Complete bundled npm dependency inventory$/mu, "the complete dependency heading");
const inventorySummary = /inventory contains ([0-9]+) package paths actually present[\s\S]*?; ([0-9]+) lockfile-only optional package paths are absent/u.exec(notices);
if (!inventorySummary) throw new Error("packaged notices do not declare artifact-aware present/omitted counts");
const declaredPresent = Number(inventorySummary[1]);
const dependencyRows = notices.split("\n").filter((line) => line.startsWith("| `dsh"));
if (!Number.isSafeInteger(declaredPresent) || declaredPresent <= 0 || dependencyRows.length !== declaredPresent) {
  throw new Error("packaged notices do not contain their exact declared dependency-row count");
}
if (dependencyRows.some((line) => !/`sha256:[a-f0-9]{64}`/u.test(line))) {
  throw new Error("packaged notices contain a dependency without hash-bound licence material");
}
requireMatch(notices, /auditable material inventory, not legal clearance/u, "the external legal-review warning");

const patchRequirements = [
  [/includeUserRoot: false/u, "disabled user-root inclusion"],
  [/id: credentials-keychain\s+name: '@local-harness\/dsh-credentials-keychain'/u, "Keychain credential plugin"],
  [/id: fs-sandbox\s*(?:#[^\n]*\n\s*#?[^\n]*\n?)*\s+disabled: true/u, "disabled upstream filesystem sandbox"],
  [/id: fs-confined\s+name: '@local-harness\/dsh-fs-confined'/u, "confined filesystem plugin"],
  [/id: code-runtime\s+disabled: true/u, "disabled code runtime"],
  [/id: workflow-worker-thread\s+disabled: true/u, "disabled workflow worker"],
  [/^- id: tool-workflow\n(?:  #[^\n]*\n)*  disabled: true$/mu, "disabled workflow tool"],
  [/^- id: tool-ralph\n(?:  #[^\n]*\n)*  disabled: true$/mu, "disabled Ralph tool"],
  [/id: mcp-guarded\s+name: '@local-harness\/dsh-mcp-guarded'\s+config:[\s\S]*?catalogPath: !!js process\.env\.LOCAL_HARNESS_MCP_CATALOG/u, "guarded MCP catalog"],
  [/id: client-security-bridge\s+name: '@local-harness\/dsh-client-security-bridge'/u, "client security bridge"],
  [/id: performance-profile\s+name: '@local-harness\/dsh-performance-profile'/u, "performance profile"],
  [/id: web-fetch-safe\s+name: '@local-harness\/dsh-web-fetch-safe'/u, "safe fetch plugin"],
  [/id: web-search-deepseek\s+disabled: true/u, "disabled credential-bound web search"],
  [/id: tool-web\s+config:[\s\S]*?search: false[\s\S]*?fetch: true/u, "fetch-only web tool"]
];
for (const [expression, label] of patchRequirements) requireMatch(patch, expression, label);
for (const id of ["ui-settings-general", "ui-settings-models", "ui-settings-plugin-inventory", "ui-settings-plugins", "ui-agent-preset"]) {
  requireMatch(patch, new RegExp(`id: ${id}\\s+disabled: true`, "u"), `disabled ${id}`);
}

requireMatch(preset,
  /^- id: tool-web\s+name: '@deepseek-ai\/dsh-tool-web'\s+config:\s+search: false\s+fetch: true\s+fetchTimeoutMs: 30000\s+fetchMaxOutputChars: 200000$/mu,
  "the exact standard fetch-only tool row");

process.stdout.write("Packaged DSH policy and dependency notices verified.\n");
