import { lstat, readdir } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { runBoundedCommand } from "./prepare-dsh-upgrade.mjs";

const [archivePath, sourceRoot, expectedRootArgument] = process.argv.slice(2);
if (!archivePath) throw new Error("usage: verify-zip-entries.mjs <archive.zip> [source-root] [expected-archive-root]");
const releaseIdentity = JSON.parse(await readFile(
  new URL("../Config/ReleaseIdentity.json", import.meta.url), "utf8"
));
const expectedApplicationRoot = expectedRootArgument || releaseIdentity.applicationBundleName;
if (!expectedApplicationRoot || expectedApplicationRoot.includes("/") || expectedApplicationRoot === "." || expectedApplicationRoot === ".."
    || /[\x00-\x1f\x7f]/u.test(expectedApplicationRoot) || expectedApplicationRoot.length > 255) {
  throw new Error("expected archive root must be one safe path component");
}

async function unzipListing(argumentsList, maximumBytes) {
  const result = await runBoundedCommand("/usr/bin/unzip", argumentsList, {
    environment: {
      HOME: "/var/empty",
      PATH: "/usr/bin:/bin",
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8"
    },
    allowFailure: true,
    timeoutMS: 120_000,
    maximumStandardOutputBytes: maximumBytes,
    maximumStandardErrorBytes: 1024 * 1024,
    label: "release archive listing"
  });
  if (result.signal !== null || result.code !== 0) {
    throw new Error(`archive listing failed: ${result.stderr.trim().slice(-8192)}`);
  }
  return result.stdout;
}

const listing = await unzipListing(["-Z1", archivePath], 64 * 1024 * 1024);

const entries = listing.split("\n").filter(Boolean);
if (entries.length === 0) throw new Error("release archive is empty");
if (entries.length > 250_000) throw new Error("release archive exceeds the entry-count safety limit");
const normalized = new Set();
for (const entry of entries) {
  if (/[\x00-\x1f\x7f]/u.test(entry) || entry.includes("\\") || entry.startsWith("/") || entry.length > 4096) {
    throw new Error(`unsafe release archive entry: ${JSON.stringify(entry)}`);
  }
  const segments = entry.split("/").filter((segment, index, values) => !(segment === "" && index === values.length - 1));
  if (segments[0] !== expectedApplicationRoot || segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`release archive entry escapes its single app root: ${JSON.stringify(entry)}`);
  }
  const identity = segments.join("/").normalize("NFC").toLocaleLowerCase("en-US");
  if (normalized.has(identity)) throw new Error(`release archive has a duplicate normalized path: ${entry}`);
  normalized.add(identity);
}

const totals = await unzipListing(["-Z", "-t", archivePath], 1024 * 1024);
const totalsMatch = totals.match(/(?:^|\n)(\d+) files?, (\d+) bytes uncompressed, (\d+) bytes compressed:/u);
if (!totalsMatch) throw new Error("release archive totals could not be authenticated before extraction");
const archiveEntryCount = Number(totalsMatch[1]);
const archiveUncompressedBytes = BigInt(totalsMatch[2]);
if (archiveEntryCount !== entries.length) throw new Error("release archive filename inventory and central-directory totals disagree");

if (sourceRoot) {
  let sourceEntries = 0;
  let sourcePayloadBytes = 0n;
  async function inventory(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = `${directory}/${entry.name}`;
      const info = await lstat(path, { bigint: true });
      sourceEntries += 1;
      if (info.isDirectory()) await inventory(path);
      else if (info.isFile() || info.isSymbolicLink()) sourcePayloadBytes += info.size;
      else throw new Error(`source bundle contains an unsupported object before archiving: ${path}`);
    }
  }
  await inventory(sourceRoot);
  // ditto stores the app root as one directory entry; regular-file bytes and
  // symlink-target bytes account for the exact uncompressed payload.
  if (archiveEntryCount !== sourceEntries + 1 || archiveUncompressedBytes !== sourcePayloadBytes) {
    throw new Error("release archive central-directory totals do not exactly match the signed source bundle");
  }
}

process.stdout.write(`Archive path inventory verified before extraction: ${entries.length} entries and ${archiveUncompressedBytes} uncompressed bytes under one app root.\n`);
