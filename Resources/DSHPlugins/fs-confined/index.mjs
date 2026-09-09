import { existsSync, realpathSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { pathToFileURL } from "node:url";

const runtimeRoot = process.env.LOCAL_HARNESS_RUNTIME_ROOT;
delete process.env.LOCAL_HARNESS_RUNTIME_ROOT;
delete process.env.LOCAL_HARNESS_FS_PLUGIN;
if (!runtimeRoot) throw new Error("fs-confined: reviewed runtime root is missing");

const sandboxCandidates = [
  join(runtimeRoot, "node_modules", "@deepseek-ai", "dsh-fs-sandbox", "lib", "index.js"),
  join(dirname(runtimeRoot), "dsh-fs-sandbox", "lib", "index.js")
];
const fsCandidates = [
  join(runtimeRoot, "node_modules", "@deepseek-ai", "dsh-fs", "lib", "index.js"),
  join(dirname(runtimeRoot), "dsh-fs", "lib", "index.js")
];
const sandboxModulePath = sandboxCandidates.find(existsSync);
const fsModulePath = fsCandidates.find(existsSync);
if (!sandboxModulePath || !fsModulePath) throw new Error("fs-confined: reviewed filesystem dependencies are missing");

const [{ default: SandboxedFileSystem }, { FsError }] = await Promise.all([
  import(pathToFileURL(sandboxModulePath).href),
  import(pathToFileURL(fsModulePath).href)
]);

function canonical(path) {
  try { return realpathSync.native(path); }
  catch { return realpathSync(path); }
}

function under(path, root) {
  return path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

let configuredRoots;
try {
  const decoded = JSON.parse(process.env.LOCAL_HARNESS_WORKSPACE_ROOTS ?? "[]");
  if (!Array.isArray(decoded) || decoded.length === 0 || decoded.some((value) => typeof value !== "string" || !value.startsWith("/") || value.includes("\0"))) {
    throw new Error("invalid roots");
  }
  configuredRoots = Object.freeze([...new Set(decoded.map(canonical))]);
} catch {
  throw new Error("fs-confined: approved workspace roots are missing or invalid");
}

function denied(path) {
  return new FsError(`cannot access "${path}": file access denied outside the approved workspace`, "FS_SANDBOX_DENIED");
}

/**
 * DSH's upstream filesystem sandbox fences writes only. This reviewed adapter
 * also fences path resolution, so read/stat/list/search/instruction/skill
 * consumers cannot obtain a target outside the session workspace. Every
 * existing symlink is resolved before containment is decided.
 */
class ConfinedFileSystem extends SandboxedFileSystem {
  async resolve(path, opts) {
    const cwd = opts?.cwd ?? process.cwd();
    const root = await super.resolve(".", { cwd, signal: opts?.signal });
    const approved = configuredRoots.some((allowed) => under(String(root.targetKey), allowed));
    if (!approved) throw denied(cwd);
    const target = await super.resolve(path, opts);
    if (!this.contains(root, target)) throw denied(target.displayPath);
    return target;
  }

  async lstat(path, opts, signal) {
    // Resolve first so a final symlink cannot point outside the workspace and
    // an absent target is checked through its deepest existing ancestor.
    await this.resolve(path, { cwd: opts?.cwd, signal });
    return super.lstat(path, opts, signal);
  }
}

export { ConfinedFileSystem };
export default ConfinedFileSystem;
