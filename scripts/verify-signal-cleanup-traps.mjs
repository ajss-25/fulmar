#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import { resolve, relative, extname } from "node:path";
import { pathToFileURL } from "node:url";

const SHELL_EXTENSIONS = new Set([".sh", ".zsh"]);
const SIGNAL_EXIT_CODES = new Map([
  ["HUP", "129"],
  ["1", "129"],
  ["INT", "130"],
  ["2", "130"],
  ["TERM", "143"],
  ["15", "143"]
]);
const EXIT_TARGETS = new Set(["EXIT", "0"]);

// These six occurrences are child-process fixtures whose sole purpose is to
// prove that the sandbox runner escalates after an uncooperative descendant
// ignores a signal. They are never installed as traps in the verifier shell.
const ALLOWED_ADVERSARIAL_IGNORES = new Map([
  ['\'trap "" TERM; /usr/bin/yes e | /usr/bin/tr -d "\\n" >&2\'', 1],
  ['\'(trap "" TERM; /usr/bin/yes d | /usr/bin/tr -d "\\n" >&2) & exit 0\'', 1],
  ['trap "" TERM INT HUP', 2],
  ['/bin/bash -p -c \'\\\'\'trap "" TERM INT HUP; while :; do /bin/sleep 1; done\'\\\'\' &', 1],
  ['/bin/sh -p -c \'\\\'\'trap "" TERM INT HUP; while :; do /bin/sleep 1; done\'\\\'\' &', 1]
]);

async function shellFiles(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) result.push(...await shellFiles(path));
    else if (entry.isFile() && SHELL_EXTENSIONS.has(extname(entry.name))) result.push(path);
  }
  return result.sort();
}

function parsedTrap(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("trap ")) return null;
  const rest = trimmed.slice(5).trimStart();
  if (rest.startsWith("- ") || rest === "-") return { action: "-", targets: [] };

  let action;
  let targetText;
  if (rest.startsWith("'") || rest.startsWith('"')) {
    const quote = rest[0];
    const closing = rest.lastIndexOf(quote);
    if (closing <= 0) return null;
    action = rest.slice(1, closing);
    targetText = rest.slice(closing + 1).trim();
  } else {
    const tokens = rest.split(/\s+/u);
    action = tokens.shift() ?? "";
    targetText = tokens.join(" ");
  }
  return { action, targets: targetText.split(/\s+/u).filter(Boolean) };
}

function actionInvokes(action, command, argument) {
  const tokens = action.split(/[;\s]+/u).filter(Boolean);
  return tokens.some((token, index) => token === command && tokens[index + 1] === argument);
}

function isExpectedFixtureContext(lines, index) {
  const trimmed = lines[index].trim();
  if (trimmed !== 'trap "" TERM INT HUP') return true;
  const nearby = lines.slice(Math.max(0, index - 8), index + 1).join("\n");
  return /\/bin\/(?:ba)?sh -p -c '\s*[\s\S]*trap "" TERM INT HUP$/u.test(nearby);
}

function namedFunctionBody(lines, functionName) {
  const start = lines.findIndex((line) => line.trim() === `${functionName}() {`);
  if (start < 0) return "";
  const body = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].trim() === "}") return body.join("\n");
    body.push(lines[index]);
  }
  return "";
}

export async function verifySignalCleanupTraps(repositoryRoot) {
  const scriptsRoot = resolve(repositoryRoot, "scripts");
  const failures = [];
  const observedIgnores = new Map();

  for (const path of await shellFiles(scriptsRoot)) {
    const name = relative(repositoryRoot, path);
    const lines = (await readFile(path, "utf8")).split(/\r?\n/u);
    const mappedSignals = new Set();
    let usesOnSignal = false;

    for (let index = 0; index < lines.length; index += 1) {
      const lineNumber = index + 1;
      const trimmed = lines[index].trim();
      let approvedAdversarialIgnore = false;
      if (trimmed.includes('trap ""') || trimmed.includes("trap ''")) {
        const allowed = name === "scripts/verify-sandbox-runner.sh"
          && ALLOWED_ADVERSARIAL_IGNORES.has(trimmed)
          && isExpectedFixtureContext(lines, index);
        if (!allowed) {
          failures.push(`${name}:${lineNumber}: signal-ignore trap is not an approved adversarial child fixture`);
        } else {
          approvedAdversarialIgnore = true;
          observedIgnores.set(trimmed, (observedIgnores.get(trimmed) ?? 0) + 1);
        }
      }

      if (/(?:^|[\s;(])trap\s+/u.test(lines[index]) && !trimmed.startsWith("trap ")
          && !trimmed.startsWith("#") && !approvedAdversarialIgnore) {
        failures.push(`${name}:${lineNumber}: inline trap is not structurally reviewable; place it on its own line`);
      }

      const trap = parsedTrap(lines[index]);
      if (!trap || trap.action === "-") continue;
      if (trap.action === "" && name === "scripts/verify-sandbox-runner.sh"
          && ALLOWED_ADVERSARIAL_IGNORES.has(trimmed)) continue;

      const hasExit = trap.targets.some((target) => EXIT_TARGETS.has(target));
      const signalTargets = trap.targets.filter((target) => SIGNAL_EXIT_CODES.has(target));
      if (hasExit && signalTargets.length > 0) {
        failures.push(`${name}:${lineNumber}: EXIT cleanup and direct signals share one trap and can swallow 129/130/143`);
      }
      for (const target of signalTargets) {
        const expected = SIGNAL_EXIT_CODES.get(target);
        const canonicalSignal = expected === "129" ? "HUP" : expected === "130" ? "INT" : "TERM";
        const explicitExit = actionInvokes(trap.action, "exit", expected);
        const explicitHandler = actionInvokes(trap.action, "on_signal", expected);
        if (!explicitExit && !explicitHandler) {
          failures.push(`${name}:${lineNumber}: ${canonicalSignal} trap does not deterministically exit ${expected}`);
        } else {
          usesOnSignal ||= explicitHandler;
          mappedSignals.add(canonicalSignal);
        }
      }
    }

    if (mappedSignals.size > 0) {
      for (const signal of ["HUP", "INT", "TERM"]) {
        if (!mappedSignals.has(signal)) failures.push(`${name}: explicit signal cleanup is missing ${signal}`);
      }
    }
    if (usesOnSignal) {
      const body = namedFunctionBody(lines, "on_signal");
      if (!/trap\s+-\s+(?:EXIT|0)\s+HUP\s+INT\s+TERM/u.test(body)
          || !/\bcleanup[^\n]*\|\|\s+true/u.test(body)
          || !/exit\s+"\$(?:exit_code|signal_exit)"/u.test(body)) {
        failures.push(`${name}: on_signal must disable all traps, attempt cleanup, and explicitly exit its requested status`);
      }
    }
  }

  for (const [line, expectedCount] of ALLOWED_ADVERSARIAL_IGNORES) {
    const count = observedIgnores.get(line) ?? 0;
    if (count !== expectedCount) {
      failures.push(`scripts/verify-sandbox-runner.sh: approved adversarial fixture count changed for ${JSON.stringify(line)} (${count} != ${expectedCount})`);
    }
  }

  if (failures.length > 0) throw new Error(failures.join("\n"));
  return { filesScanned: (await shellFiles(scriptsRoot)).length };
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  const root = resolve(process.argv[2] ?? process.cwd());
  try {
    const result = await verifySignalCleanupTraps(root);
    process.stdout.write(`SIGNAL_CLEANUP_TRAPS_OK files=${result.filesScanned}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
