#!/usr/bin/env node
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const expectedEntries = Object.freeze(["game.js", "index.html", "styles.css"]);
const requiredFeatures = Object.freeze([
  [/addEventListener\s*\(\s*["'`]keydown|onkeydown\s*=/iu, "keyboard controls"],
  [/score/iu, "scoring"],
  [/level/iu, "levels"],
  [/paus/iu, "pause"],
  [/restart|reset/iu, "restart"],
  [/next/iu, "next-piece display"],
  [/@media|clamp\s*\(|\b(?:vw|vh)\b|max-width|min-width|width\s*:\s*100%/iu, "responsive styling"]
]);

export async function verifyRealisticWorkspace(rootArgument) {
  if (typeof rootArgument !== "string" || rootArgument.length === 0) {
    throw new Error("A realistic workspace root is required");
  }
  const root = resolve(rootArgument);
  const entries = (await readdir(root)).sort();
  if (JSON.stringify(entries) !== JSON.stringify(expectedEntries)) {
    throw new Error(`Unexpected realistic workspace entries: ${JSON.stringify(entries)}`);
  }

  let totalBytes = 0;
  const content = {};
  for (const name of expectedEntries) {
    const target = join(root, name);
    const metadata = await lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`${name} is not a regular file`);
    }
    if (metadata.size < 64 || metadata.size > 524_288) {
      throw new Error(`${name} has implausible size ${metadata.size}`);
    }
    totalBytes += metadata.size;
    content[name] = await readFile(target, "utf8");
  }
  if (totalBytes > 1_048_576) {
    throw new Error(`Realistic fixture is too large: ${totalBytes}`);
  }

  if (!/<canvas\b/iu.test(content["index.html"])
      || !/styles\.css/iu.test(content["index.html"])
      || !/game\.js/iu.test(content["index.html"])) {
    throw new Error("The page does not connect its canvas, stylesheet, and game script");
  }

  const all = Object.values(content).join("\n");
  for (const [pattern, label] of requiredFeatures) {
    if (!pattern.test(all)) throw new Error(`Missing promised realistic feature: ${label}`);
  }
  if (/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(|https?:\/\//iu.test(all)) {
    throw new Error("Realistic fixture contains an external network dependency");
  }
  return Object.freeze({ entries: expectedEntries.length, totalBytes });
}

const executedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (executedPath === fileURLToPath(import.meta.url)) {
  await verifyRealisticWorkspace(process.argv[2]);
}
