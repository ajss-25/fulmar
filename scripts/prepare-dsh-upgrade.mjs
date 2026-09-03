import { createHash, createPublicKey, verify as verifyCryptographicSignature } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod,
  constants,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, "..");
const maximumOutputBytes = 16 * 1024 * 1024;
const terminationGraceMS = 250;
const postKillPipeDrainMS = 250;

export function validateTargetVersion(value) {
  if (typeof value !== "string"
      || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.test(value)
      || Buffer.byteLength(value, "utf8") > 128) {
    throw new Error("target must be one exact semantic version, for example 0.1.2 or 0.1.2-rc.1");
  }
  return value;
}

export function dependencyChanges(current = {}, candidate = {}) {
  const names = [...new Set([...Object.keys(current), ...Object.keys(candidate)])].sort();
  return names.flatMap((name) => {
    if (!(name in current)) return [{ name, change: "added", candidate: candidate[name] }];
    if (!(name in candidate)) return [{ name, change: "removed", current: current[name] }];
    if (current[name] !== candidate[name]) {
      return [{ name, change: "changed", current: current[name], candidate: candidate[name] }];
    }
    return [];
  });
}

export function runBoundedCommand(executable, argumentsList, {
  cwd,
  environment = {},
  allowFailure = false,
  timeoutMS = 180_000,
  maximumStandardOutputBytes = maximumOutputBytes,
  maximumStandardErrorBytes = maximumOutputBytes,
  label = "upgrade preparation command"
} = {}) {
  if (typeof executable !== "string" || !executable.startsWith("/") || executable.includes("\0")
      || !Array.isArray(argumentsList) || argumentsList.length > 4096
      || argumentsList.some((value) => typeof value !== "string" || value.includes("\0"))
      || !Number.isSafeInteger(timeoutMS) || timeoutMS < 50 || timeoutMS > 3_600_000
      || !Number.isSafeInteger(maximumStandardOutputBytes) || maximumStandardOutputBytes < 1
      || !Number.isSafeInteger(maximumStandardErrorBytes) || maximumStandardErrorBytes < 1) {
    return Promise.reject(new Error("invalid bounded child-process configuration"));
  }
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, argumentsList, {
      cwd,
      env: environment,
      // macOS gives the exact child a fresh process group. Limits can then
      // terminate its whole tree without process-name discovery or affecting
      // an unrelated npm/Node process.
      detached: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let exitResult;
    let streamsClosed = false;
    let settled = false;
    let terminating = false;
    let forceKillSent = false;
    let terminalFailure;
    let escalationTimer;
    let forcedPipeCloseTimer;
    let postExitTimer;

    const clearTimers = () => {
      clearTimeout(deadlineTimer);
      clearTimeout(escalationTimer);
      clearTimeout(forcedPipeCloseTimer);
      clearTimeout(postExitTimer);
    };
    const signalExactGroup = (signal) => {
      if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return;
      try { process.kill(-child.pid, signal); }
      catch (error) {
        if (error?.code !== "ESRCH") {
          try { child.kill(signal); } catch {}
        }
      }
    };
    const finish = () => {
      if (settled || exitResult === undefined || !streamsClosed) return;
      settled = true;
      clearTimers();
      const result = {
        code: exitResult.code,
        signal: exitResult.signal,
        stdout: Buffer.concat(stdout, stdoutBytes).toString("utf8"),
        stderr: Buffer.concat(stderr, stderrBytes).toString("utf8")
      };
      if (terminalFailure) return reject(terminalFailure);
      if (result.code !== 0 && !allowFailure) {
        const diagnostic = result.stderr.trim().slice(-8192);
        return reject(new Error(`${basename(executable)} ${argumentsList[0] ?? ""} failed (${result.code ?? result.signal}): ${diagnostic}`));
      }
      resolvePromise(result);
    };
    const scheduleForcedPipeClose = () => {
      if (forcedPipeCloseTimer !== undefined || exitResult === undefined) return;
      forcedPipeCloseTimer = setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
        streamsClosed = true;
        finish();
      }, postKillPipeDrainMS);
    };
    const beginTermination = (failure) => {
      terminalFailure ??= failure;
      if (terminating) return;
      terminating = true;
      signalExactGroup("SIGTERM");
      escalationTimer = setTimeout(() => {
        forceKillSent = true;
        signalExactGroup("SIGKILL");
        scheduleForcedPipeClose();
      }, terminationGraceMS);
    };
    const append = (chunks, currentBytes, chunk, maximum, streamName) => {
      if (terminalFailure) return currentBytes;
      if (chunk.length > maximum - currentBytes) {
        beginTermination(new Error(`${label} exceeded its ${streamName} limit`));
        return currentBytes;
      }
      chunks.push(chunk);
      return currentBytes + chunk.length;
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes = append(stdout, stdoutBytes, chunk, maximumStandardOutputBytes, "standard output");
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes = append(stderr, stderrBytes, chunk, maximumStandardErrorBytes, "standard error");
    });
    const deadlineTimer = setTimeout(() => {
      beginTermination(new Error(`${label} exceeded its time limit`));
    }, timeoutMS);
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimers();
      child.stdout.destroy();
      child.stderr.destroy();
      reject(error);
    });
    child.once("exit", (code, signal) => {
      exitResult = { code, signal };
      // `close` normally follows immediately after buffered pipe data drains.
      // If a descendant retained a pipe, waiting for `close` is unbounded even
      // though the exact child has been reaped. Treat that as a failed command,
      // stop the remaining exact group, and close our pipe ends after a second
      // bounded allowance. A setsid() descendant may survive, but cannot hang
      // this release/developer tool and receives EPIPE on its next write.
      postExitTimer = setTimeout(() => {
        if (streamsClosed) return;
        beginTermination(new Error(`${label} left descendant output streams open`));
      }, terminationGraceMS);
      if (forceKillSent) scheduleForcedPipeClose();
      finish();
    });
    child.on("close", (code, signal) => {
      exitResult ??= { code, signal };
      streamsClosed = true;
      finish();
    });
  });
}

async function boundedJSON(path, maximumBytes = 8 * 1024 * 1024) {
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.size <= 0 || details.size > maximumBytes) {
    throw new Error(`expected a bounded regular JSON file: ${path}`);
  }
  return JSON.parse(await readFile(path, "utf8"));
}

async function fileInventory(root) {
  const entries = [];
  let aggregateBytes = 0;
  async function visit(relative = "", depth = 0) {
    if (depth > 32 || entries.length > 20_000) throw new Error("candidate package tree exceeds review limits");
    const absolute = relative ? join(root, relative) : root;
    for (const child of (await readdir(absolute, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const childRelative = relative ? `${relative}/${child.name}` : child.name;
      if (childRelative === "node_modules" || childRelative.startsWith("node_modules/")) continue;
      if (child.isDirectory()) {
        await visit(childRelative, depth + 1);
        continue;
      }
      if (!child.isFile()) {
        entries.push({ path: childRelative, type: child.isSymbolicLink() ? "symlink" : "special" });
        continue;
      }
      const data = await readFile(join(root, childRelative));
      aggregateBytes += data.length;
      if (aggregateBytes > 512 * 1024 * 1024) throw new Error("candidate package files exceed review limits");
      entries.push({
        path: childRelative,
        type: "file",
        bytes: data.length,
        sha256: createHash("sha256").update(data).digest("hex")
      });
    }
  }
  await visit();
  return entries;
}

export function inventoryChanges(currentEntries, candidateEntries) {
  const current = new Map(currentEntries.map((entry) => [entry.path, entry]));
  const candidate = new Map(candidateEntries.map((entry) => [entry.path, entry]));
  return [...new Set([...current.keys(), ...candidate.keys()])].sort().flatMap((path) => {
    const before = current.get(path);
    const after = candidate.get(path);
    if (!before) return [{ path, change: "added" }];
    if (!after) return [{ path, change: "removed" }];
    if (JSON.stringify(before) !== JSON.stringify(after)) return [{ path, change: "changed" }];
    return [];
  });
}

export function validateRegistryProvenance(targetVersion, registry, lockEntry) {
  validateTargetVersion(targetVersion);
  const tarball = registry?.["dist.tarball"] ?? registry?.dist?.tarball;
  const integrity = registry?.["dist.integrity"] ?? registry?.dist?.integrity;
  const expectedTarball = `https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-${targetVersion}.tgz`;
  if (tarball !== expectedTarball) {
    throw new Error("registry returned an unexpected DSH tarball origin or version");
  }
  if (typeof integrity !== "string"
      || integrity.length > 512
      || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(integrity)) {
    throw new Error("registry returned an invalid DSH integrity value");
  }
  const encodedDigest = integrity.slice("sha512-".length);
  const decodedDigest = Buffer.from(encodedDigest, "base64");
  if (decodedDigest.length !== 64 || decodedDigest.toString("base64") !== encodedDigest) {
    throw new Error("registry returned an invalid DSH integrity value");
  }
  if (lockEntry !== undefined
      && (lockEntry?.resolved !== tarball || lockEntry?.integrity !== integrity)) {
    throw new Error("resolved DSH lock provenance does not match the reviewed registry response");
  }
  return { tarball, integrity };
}

// npm's current registry signing key is pinned in reviewed source instead of
// being fetched through the same network channel as candidate metadata. A key
// rotation is therefore an explicit source review, never an automatic trust
// update performed by this assessor.
export const reviewedNPMRegistrySigningKeys = Object.freeze([Object.freeze({
  keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
  keytype: "ecdsa-sha2-nistp256",
  scheme: "ecdsa-sha2-nistp256",
  expires: null,
  key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="
})]);

export function validateRegistrySignature(
  packageName,
  targetVersion,
  registry,
  reviewedKeys = reviewedNPMRegistrySigningKeys
) {
  validateTargetVersion(targetVersion);
  const { integrity } = validateRegistryProvenance(targetVersion, registry);
  if (packageName !== "@deepseek-ai/dsh"
      || !Array.isArray(reviewedKeys) || reviewedKeys.length < 1 || reviewedKeys.length > 16
      || !Array.isArray(registry?.["dist.signatures"])
      || registry["dist.signatures"].length < 1 || registry["dist.signatures"].length > 16) {
    throw new Error("registry did not provide one verifiable reviewed signature set");
  }
  const keys = new Map();
  for (const key of reviewedKeys) {
    if (key === null || typeof key !== "object" || Array.isArray(key)
        || typeof key.keyid !== "string" || !/^SHA256:[A-Za-z0-9+/]{43}=?$/u.test(key.keyid)
        || key.keytype !== "ecdsa-sha2-nistp256" || key.scheme !== "ecdsa-sha2-nistp256"
        || key.expires !== null || typeof key.key !== "string" || key.key.length > 512
        || keys.has(key.keyid)) {
      throw new Error("reviewed npm signing-key configuration is invalid");
    }
    const encoded = Buffer.from(key.key, "base64");
    if (encoded.length < 64 || encoded.toString("base64") !== key.key) {
      throw new Error("reviewed npm signing-key configuration is invalid");
    }
    keys.set(key.keyid, createPublicKey({ key: encoded, format: "der", type: "spki" }));
  }
  const payload = Buffer.from(`${packageName}@${targetVersion}:${integrity}`, "utf8");
  for (const signature of registry["dist.signatures"]) {
    if (signature === null || typeof signature !== "object" || Array.isArray(signature)
        || typeof signature.keyid !== "string" || typeof signature.sig !== "string"
        || signature.sig.length > 1024) continue;
    const key = keys.get(signature.keyid);
    if (!key) continue;
    const encodedSignature = Buffer.from(signature.sig, "base64");
    if (encodedSignature.length < 64 || encodedSignature.toString("base64") !== signature.sig) continue;
    if (verifyCryptographicSignature("sha256", payload, key, encodedSignature)) {
      return { keyid: signature.keyid };
    }
  }
  throw new Error("registry signature did not verify against a reviewed npm key");
}

function deepSeekCohortNameForLockPath(path) {
  if (typeof path !== "string" || path.length > 4096) return undefined;
  const match = path.match(/(?:^|\/)node_modules\/(@deepseek-ai\/dsh(?:-[^/]+)?)$/u);
  return match?.[1];
}

/// npm prerelease caret ranges can advance sibling DSH packages beyond the
/// requested root version. An upgrade review must describe one release cohort,
/// not a root package mixed with whatever sibling prerelease is newest today.
/// The provisional lock is used only to discover the bounded package-name set;
/// every discovered sibling is then forced to the exact reviewed version and a
/// fresh lock is produced from scratch.
export function exactDeepSeekCohortOverrides(lock, targetVersion) {
  validateTargetVersion(targetVersion);
  if (lock === null || typeof lock !== "object" || Array.isArray(lock)
      || lock.packages === null || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
    throw new Error("candidate lock does not contain a package map");
  }
  const names = new Set();
  for (const path of Object.keys(lock.packages)) {
    const name = deepSeekCohortNameForLockPath(path);
    if (name) names.add(name);
  }
  if (!names.has("@deepseek-ai/dsh")) {
    throw new Error("candidate lock does not contain the requested DSH root");
  }
  names.delete("@deepseek-ai/dsh");
  return Object.fromEntries([...names].sort().map((name) => [name, targetVersion]));
}

export function validateExactDeepSeekCohort(lock, targetVersion) {
  validateTargetVersion(targetVersion);
  if (lock === null || typeof lock !== "object" || Array.isArray(lock)
      || lock.packages === null || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
    throw new Error("candidate lock does not contain a package map");
  }
  const identities = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    const name = deepSeekCohortNameForLockPath(path);
    if (!name) continue;
    const version = entry?.version;
    if (version !== targetVersion) {
      throw new Error(`candidate DSH cohort drifted: ${name} resolved ${String(version)} instead of ${targetVersion}`);
    }
    identities.push(`${name}@${version}`);
  }
  if (!identities.includes(`@deepseek-ai/dsh@${targetVersion}`)) {
    throw new Error("candidate lock does not contain the exact requested DSH root");
  }
  if (new Set(identities).size !== identities.length) {
    throw new Error("candidate lock contains duplicate DSH cohort identities");
  }
  return identities.sort();
}

async function firstPartyDeepSeekInventory(nodeModulesRoot) {
  const scopeRoot = join(nodeModulesRoot, "@deepseek-ai");
  const packageNames = (await readdir(scopeRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^(?:dsh|dsh-[A-Za-z0-9._-]+)$/u.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  if (packageNames.length < 1 || packageNames.length > 1024) {
    throw new Error("candidate DSH package cohort is outside review bounds");
  }
  const entries = [];
  let aggregateBytes = 0;
  for (const unscopedName of packageNames) {
    const packageRoot = join(scopeRoot, unscopedName);
    const manifest = await boundedJSON(join(packageRoot, "package.json"));
    const expectedName = `@deepseek-ai/${unscopedName}`;
    if (manifest.name !== expectedName || typeof manifest.version !== "string"
        || manifest.version.length > 128) {
      throw new Error(`candidate contains an invalid first-party package identity: ${expectedName}`);
    }
    for (const entry of await fileInventory(packageRoot)) {
      const path = `${expectedName}/${entry.path}`;
      entries.push({ ...entry, path });
      aggregateBytes += entry.bytes ?? 0;
      if (entries.length > 200_000 || aggregateBytes > 1024 * 1024 * 1024) {
        throw new Error("candidate DSH cohort inventory exceeds review bounds");
      }
    }
  }
  return { packageNames: packageNames.map((name) => `@deepseek-ai/${name}`), entries };
}

export function sensitiveDeepSeekPackageChanges(changes) {
  if (!Array.isArray(changes)) throw new Error("DSH package changes must be an array");
  const sensitive = /^(?:@deepseek-ai\/dsh(?:-[^/]+)?)\/(?:package\.json|(?:lib|src|dist|config)\/)/u;
  return changes.filter((entry) => entry !== null && typeof entry === "object"
    && typeof entry.path === "string" && sensitive.test(entry.path));
}

export function reviewBundleDigest(files) {
  if (files === null || typeof files !== "object" || Array.isArray(files)) {
    throw new Error("review bundle must be a file map");
  }
  const names = Object.keys(files).sort();
  if (names.length < 1 || names.length > 16) throw new Error("review bundle file count is invalid");
  const hash = createHash("sha256");
  let aggregateBytes = 0;
  for (const name of names) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(name)) {
      throw new Error("review bundle contains an invalid filename");
    }
    const data = Buffer.isBuffer(files[name]) ? files[name] : Buffer.from(files[name]);
    aggregateBytes += data.length;
    if (data.length > 64 * 1024 * 1024 || aggregateBytes > 128 * 1024 * 1024) {
      throw new Error("review bundle exceeds publication bounds");
    }
    const encodedName = Buffer.from(name, "utf8");
    const header = Buffer.alloc(16);
    header.writeBigUInt64BE(BigInt(encodedName.length), 0);
    header.writeBigUInt64BE(BigInt(data.length), 8);
    hash.update(header).update(encodedName).update(data);
  }
  return hash.digest("hex");
}

async function pathDetailsOrUndefined(path) {
  try { return await lstat(path); }
  catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

async function syncDirectory(path) {
  const descriptor = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await descriptor.sync(); }
  finally { await descriptor.close(); }
}

async function verifyPublishedReviewBundle(directory, files) {
  const details = await lstat(directory);
  if (!details.isDirectory() || details.isSymbolicLink() || details.uid !== process.getuid()
      || (details.mode & 0o7777) !== 0o700) {
    throw new Error("published review directory is not an exact private directory");
  }
  const expectedNames = Object.keys(files).sort();
  const actualNames = (await readdir(directory)).sort();
  if (JSON.stringify(expectedNames) !== JSON.stringify(actualNames)) {
    throw new Error("published review directory has an unexpected file set");
  }
  for (const name of expectedNames) {
    const path = join(directory, name);
    const fileDetails = await lstat(path);
    if (!fileDetails.isFile() || fileDetails.isSymbolicLink() || fileDetails.uid !== process.getuid()
        || fileDetails.nlink !== 1 || (fileDetails.mode & 0o7777) !== 0o600) {
      throw new Error("published review file metadata is invalid");
    }
    const expected = Buffer.isBuffer(files[name]) ? files[name] : Buffer.from(files[name]);
    const actual = await readFile(path);
    if (actual.length !== expected.length || !actual.equals(expected)) {
      throw new Error("published review file bytes do not match the immutable observation");
    }
  }
}

export async function publishReviewBundle(outputParent, observationDigest, files) {
  if (typeof outputParent !== "string" || !outputParent.startsWith("/")
      || !/^[a-f0-9]{64}$/u.test(observationDigest)) {
    throw new Error("review publication target is invalid");
  }
  const computedDigest = reviewBundleDigest(files);
  if (computedDigest !== observationDigest) throw new Error("review observation digest does not match its files");
  await mkdir(outputParent, { recursive: true, mode: 0o700 });
  const parentDetails = await lstat(outputParent);
  const canonicalParent = await realpath(outputParent);
  if (!parentDetails.isDirectory() || parentDetails.isSymbolicLink()
      || parentDetails.uid !== process.getuid() || (parentDetails.mode & 0o7777) !== 0o700) {
    throw new Error("review publication parent is not an exact private directory");
  }

  const destination = join(canonicalParent, observationDigest);
  if (await pathDetailsOrUndefined(destination)) {
    await verifyPublishedReviewBundle(destination, files);
    return { directory: destination, alreadyPublished: true };
  }
  const claim = join(canonicalParent, `.${observationDigest}.publishing`);
  let claimDescriptor;
  let staging;
  try {
    claimDescriptor = await open(
      claim,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
    await claimDescriptor.writeFile(`${process.pid}\n`, "utf8");
    await claimDescriptor.sync();
    await claimDescriptor.close();
    claimDescriptor = undefined;
    await syncDirectory(canonicalParent);

    staging = await mkdtemp(join(canonicalParent, ".review-staging-"));
    await chmod(staging, 0o700);
    for (const name of Object.keys(files).sort()) {
      const data = Buffer.isBuffer(files[name]) ? files[name] : Buffer.from(files[name]);
      const descriptor = await open(
        join(staging, name),
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600
      );
      try {
        await descriptor.writeFile(data);
        await descriptor.sync();
      } finally {
        await descriptor.close();
      }
    }
    await syncDirectory(staging);
    if (await pathDetailsOrUndefined(destination)) {
      throw new Error("review destination appeared during immutable publication");
    }
    await rename(staging, destination);
    staging = undefined;
    await syncDirectory(canonicalParent);
    await verifyPublishedReviewBundle(destination, files);
    await rm(claim);
    await syncDirectory(canonicalParent);
    return { directory: destination, alreadyPublished: false };
  } finally {
    if (claimDescriptor) await claimDescriptor.close().catch(() => {});
    if (staging) await rm(staging, { recursive: true, force: true }).catch(() => {});
  }
}

export function markdown(report) {
  const rows = report.rootDependencyChanges.length
    ? report.rootDependencyChanges.map((entry) => `| \`${entry.name}\` | ${entry.change} | \`${entry.current ?? "—"}\` | \`${entry.candidate ?? "—"}\` |`).join("\n")
    : "| — | unchanged | — | — |";
  const blockers = report.blockers.map((item) => `- ${item}`).join("\n");
  const renderedSensitiveChanges = report.sensitivePackageChanges.slice(0, 200);
  const sensitive = renderedSensitiveChanges.length
    ? renderedSensitiveChanges.map((entry) => `- ${entry.change}: \`${entry.path}\``).join("\n")
      + (report.sensitivePackageChanges.length > renderedSensitiveChanges.length
        ? `\n- … ${report.sensitivePackageChanges.length - renderedSensitiveChanges.length} additional sensitive changes are retained in review.json.`
        : "")
    : "- No sensitive root-package file changes detected.";
  const registryTarball = report.registry?.["dist.tarball"] ?? report.registry?.dist?.tarball;
  const registryIntegrity = report.registry?.["dist.integrity"] ?? report.registry?.dist?.integrity;
  return `# DeepSeek Harness upgrade review: ${report.currentVersion} → ${report.targetVersion}

Generated: ${report.generatedAt}

This report prepares a candidate; it never alters VendorRuntime or the installed app.

## Promotion status

**Not promoted.** A candidate may be promoted only after the privacy patch review,
runtime inventory regeneration, full release qualification, cloned-state migration,
and rollback exercise are complete.

${blockers}

## Registry provenance

- Tarball: ${registryTarball ?? "unavailable"}
- Integrity: \`${registryIntegrity ?? "unavailable"}\`
- Resolved lock integrity: \`${report.lockIntegrity ?? "unavailable"}\`

## Root dependency changes

| Package | Change | Current | Candidate |
| --- | --- | --- | --- |
${rows}

## Sensitive DSH package changes

${sensitive}

## Review facts

- Resolved production packages: ${report.resolvedProductionPackages}
- Exact-version DeepSeek cohort packages: ${report.resolvedDeepSeekCohortPackages}
- Reviewed first-party package trees: ${report.reviewedFirstPartyPackageTrees}
- First-party file changes: ${report.packageChanges.length}
- Local MCP peer contract matches candidate: ${report.localMCPPeerContractMatches}
- DeepSeek adapter still contains forbidden stable-ID/session headers: ${report.candidateContainsForbiddenDeepSeekHeaders}
- npm audit vulnerabilities: ${report.audit.totalVulnerabilities ?? "unknown"}

## Required next gate

Follow \`docs/UPSTREAM_DSH_UPGRADES.md\`. Do not edit the live app or copy this
candidate into VendorRuntime by hand.
`;
}

async function main() {
  const argumentsList = process.argv.slice(2);
  if (argumentsList.includes("--help") || argumentsList.length === 0) {
    process.stdout.write("Usage: node scripts/prepare-dsh-upgrade.mjs <exact-version>\n\nStages an upstream DSH release with lifecycle scripts disabled and writes a bounded compatibility/provenance report. It does not promote or install the candidate.\n");
    return;
  }
  if (argumentsList.length !== 1) throw new Error("provide exactly one target version");
  const targetVersion = validateTargetVersion(argumentsList[0]);
  const identity = await boundedJSON(join(projectRoot, "Config/ReleaseIdentity.json"));
  const currentVersion = identity.runtime.deepseekHarnessVersion;
  if (targetVersion === currentVersion) throw new Error("target is already the reviewed DSH version");

  const nodeRoot = join(projectRoot, `VendorRuntime/node-v${identity.runtime.nodeVersion}-darwin-arm64`);
  const node = join(nodeRoot, "bin/node");
  const npmCLI = join(nodeRoot, "lib/node_modules/npm/bin/npm-cli.js");
  const stage = await mkdtemp(join(tmpdir(), "fulmar-dsh-upgrade."));
  try {
    const commandHome = join(stage, "home");
    const commandCache = join(stage, "cache");
    const commandTemp = join(stage, "tmp");
    await Promise.all([
      mkdir(commandHome, { mode: 0o700 }),
      mkdir(commandCache, { mode: 0o700 }),
      mkdir(commandTemp, { mode: 0o700 })
    ]);
    const npmEnvironment = {
      HOME: commandHome,
      TMPDIR: commandTemp,
      PATH: `${dirname(node)}:/usr/bin:/bin`,
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8",
      npm_config_cache: commandCache,
      npm_config_ignore_scripts: "true",
      npm_config_update_notifier: "false",
      npm_config_fund: "false",
      npm_config_registry: "https://registry.npmjs.org/"
    };
    await writeFile(join(stage, "package.json"), JSON.stringify({
      name: "fulmar-dsh-upgrade-candidate",
      private: true,
      version: "0.0.0",
      dependencies: { "@deepseek-ai/dsh": targetVersion }
    }, null, 2) + "\n", { mode: 0o600 });

    const view = await runBoundedCommand(node, [npmCLI, "view", `@deepseek-ai/dsh@${targetVersion}`, "dist.integrity", "dist.tarball", "dist.signatures", "--json"], { cwd: stage, environment: npmEnvironment });
    const registry = JSON.parse(view.stdout);
    validateRegistryProvenance(targetVersion, registry);
    const registrySignature = validateRegistrySignature("@deepseek-ai/dsh", targetVersion, registry);
    await runBoundedCommand(node, [npmCLI, "install", "--ignore-scripts", "--package-lock=true", "--audit=false", "--fund=false"], { cwd: stage, environment: npmEnvironment, timeoutMS: 600_000 });

    const provisionalLock = await boundedJSON(join(stage, "package-lock.json"), 64 * 1024 * 1024);
    const cohortOverrides = exactDeepSeekCohortOverrides(provisionalLock, targetVersion);
    await writeFile(join(stage, "package.json"), JSON.stringify({
      name: "fulmar-dsh-upgrade-candidate",
      private: true,
      version: "0.0.0",
      dependencies: { "@deepseek-ai/dsh": targetVersion },
      overrides: cohortOverrides
    }, null, 2) + "\n", { mode: 0o600 });
    await Promise.all([
      rm(join(stage, "node_modules"), { recursive: true, force: true }),
      rm(join(stage, "package-lock.json"), { force: true })
    ]);
    await runBoundedCommand(node, [npmCLI, "install", "--ignore-scripts", "--package-lock=true", "--audit=false", "--fund=false"], { cwd: stage, environment: npmEnvironment, timeoutMS: 600_000 });

    const candidateRoot = join(stage, "node_modules/@deepseek-ai/dsh");
    const [currentPackage, candidatePackage, lock, localMCPPackage] = await Promise.all([
      boundedJSON(join(projectRoot, "VendorRuntime/node_modules/@deepseek-ai/dsh/package.json")),
      boundedJSON(join(candidateRoot, "package.json")),
      boundedJSON(join(stage, "package-lock.json"), 64 * 1024 * 1024),
      boundedJSON(join(projectRoot, "Resources/DSHPlugins/mcp-guarded/package.json"))
    ]);
    if (candidatePackage.name !== "@deepseek-ai/dsh" || candidatePackage.version !== targetVersion) {
      throw new Error("npm resolved a different DSH package identity than requested");
    }
    const exactCohort = validateExactDeepSeekCohort(lock, targetVersion);

    const [currentInventory, candidateInventory] = await Promise.all([
      firstPartyDeepSeekInventory(join(projectRoot, "VendorRuntime/node_modules")),
      firstPartyDeepSeekInventory(join(stage, "node_modules"))
    ]);
    const packageChanges = inventoryChanges(currentInventory.entries, candidateInventory.entries);
    const sensitivePackageChanges = sensitiveDeepSeekPackageChanges(packageChanges);

    const candidateMCP = await boundedJSON(join(stage, "node_modules/@deepseek-ai/dsh-mcp-client/package.json"));
    const candidateCredentials = await boundedJSON(join(stage, "node_modules/@deepseek-ai/dsh-credentials/package.json"));
    const candidateSchemastery = await boundedJSON(join(stage, "node_modules/@deepseek-ai/schemastery/package.json"));
    const expectedPeers = {
      "@deepseek-ai/dsh-credentials": candidateCredentials.version,
      "@deepseek-ai/dsh-mcp-client": candidateMCP.version,
      "@deepseek-ai/schemastery": candidateSchemastery.version
    };
    const localMCPPeerContractMatches = JSON.stringify(localMCPPackage.peerDependencies) === JSON.stringify(expectedPeers);

    const deepSeekAdapterRoot = join(stage, "node_modules/@deepseek-ai/dsh-llm-deepseek");
    const adapterFiles = await fileInventory(deepSeekAdapterRoot);
    let forbiddenHeaders = false;
    for (const entry of adapterFiles.filter((item) => item.type === "file" && item.bytes <= 8 * 1024 * 1024)) {
      const text = await readFile(join(deepSeekAdapterRoot, entry.path), "utf8").catch(() => "");
      if (/x-deepseek-harness-(?:user-id|session-id)|\.anonymous-user-id/u.test(text)) forbiddenHeaders = true;
    }

    const auditRun = await runBoundedCommand(node, [npmCLI, "audit", "--omit=dev", "--json"], { cwd: stage, environment: npmEnvironment, allowFailure: true, timeoutMS: 300_000 });
    let audit = {};
    try { audit = JSON.parse(auditRun.stdout); } catch { audit = { parseError: true }; }
    const lockEntry = lock.packages?.["node_modules/@deepseek-ai/dsh"] ?? {};
    validateRegistryProvenance(targetVersion, registry, lockEntry);
    const blockers = [
      "The vendored DeepSeek privacy patch must be reapplied or explicitly retired after source review.",
      "The complete candidate dependency tree must be audited, inventoried, signed and SBOM-bound.",
      "All native, JS, provider, RPC, sandbox, migration, realistic-agent and rollback qualification gates must pass."
    ];
    if (!localMCPPeerContractMatches) blockers.unshift("The local guarded-MCP peer contract must be updated and requalified for the candidate package versions.");
    if (forbiddenHeaders) blockers.unshift("The upstream DeepSeek adapter still contains stable identifier/session header behavior removed by Fulmar's privacy patch.");

    const lockBytes = await readFile(join(stage, "package-lock.json"));
    const cohortLockSHA256 = createHash("sha256").update(lockBytes).digest("hex");
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      currentVersion,
      targetVersion,
      cohortLockSHA256,
      registry,
      registrySignature,
      lockIntegrity: lockEntry.integrity,
      lockResolved: lockEntry.resolved,
      rootDependencyChanges: dependencyChanges(currentPackage.dependencies, candidatePackage.dependencies),
      packageChanges,
      sensitivePackageChanges,
      resolvedProductionPackages: Object.keys(lock.packages ?? {}).filter((name) => name.startsWith("node_modules/")).length,
      resolvedDeepSeekCohortPackages: exactCohort.length,
      reviewedFirstPartyPackageTrees: candidateInventory.packageNames.length,
      localMCPPeerContractMatches,
      expectedLocalMCPPeers: expectedPeers,
      candidateContainsForbiddenDeepSeekHeaders: forbiddenHeaders,
      audit: {
        commandExitCode: auditRun.code,
        totalVulnerabilities: audit.metadata?.vulnerabilities?.total,
        vulnerabilities: audit.metadata?.vulnerabilities,
        parseError: audit.parseError ?? false
      },
      blockers,
      promotionReady: false
    };
    const files = {
      "review.json": Buffer.from(JSON.stringify(report, null, 2) + "\n"),
      "review.md": Buffer.from(markdown(report)),
      "registry.json": Buffer.from(JSON.stringify(registry, null, 2) + "\n"),
      "candidate-package-lock.json": lockBytes,
      "candidate-dsh-package.json": Buffer.from(JSON.stringify(candidatePackage, null, 2) + "\n")
    };
    const observationDigest = reviewBundleDigest(files);
    const publication = await publishReviewBundle(
      join(projectRoot, "build/dsh-upgrades", targetVersion, cohortLockSHA256),
      observationDigest,
      files
    );
    process.stdout.write(`Prepared DSH ${targetVersion} for review only.\nReport: ${join(publication.directory, "review.md")}\nNo source, VendorRuntime, or installed app was changed.\n`);
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
