import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { runBoundedCommand } from "./prepare-dsh-upgrade.mjs";

const [packagePath, lockPath, npmCLIPath, destination] = process.argv.slice(2);
if (!packagePath || !lockPath || !npmCLIPath || !destination) {
  throw new Error("usage: audit-dependencies.mjs <package.json> <package-lock.json> <npm-cli.js> <summary.json>");
}
const node = process.execPath;
// The audit subprocess intentionally changes into an isolated temporary
// project. Resolve the bundled npm entrypoint before that cwd transition;
// otherwise a repository-relative path is interpreted beneath the temporary
// directory and npm never starts.
const npmCLI = resolve(npmCLIPath);
const registry = process.env.NPM_CONFIG_REGISTRY ?? "https://registry.npmjs.org/";
const registryURL = new URL(registry);
if (registryURL.username || registryURL.password || registryURL.search || registryURL.hash
    || (registryURL.protocol !== "https:" && !(registryURL.protocol === "http:" && ["127.0.0.1", "::1", "localhost"].includes(registryURL.hostname)))) {
  throw new Error("dependency audit registry must be credential-free HTTPS or a literal loopback test endpoint");
}
const root = await mkdtemp(join(tmpdir(), "local-harness-npm-audit-"));
try {
  const packageBytes = await readFile(packagePath);
  const lockBytes = await readFile(lockPath);
  await writeFile(join(root, "package.json"), packageBytes, { mode: 0o600 });
  await writeFile(join(root, "package-lock.json"), lockBytes, { mode: 0o600 });
  await mkdir(join(root, "home"), { mode: 0o700 });
  await mkdir(join(root, "cache"), { mode: 0o700 });

  const result = await runBoundedCommand(
    node,
    [npmCLI, "audit", "--omit=dev", "--package-lock-only", "--json"],
    {
      cwd: root,
      environment: {
        HOME: join(root, "home"),
        PATH: "/usr/bin:/bin",
        npm_config_cache: join(root, "cache"),
        npm_config_update_notifier: "false",
        npm_config_fund: "false",
        NPM_CONFIG_REGISTRY: registryURL.href
      },
      allowFailure: true,
      timeoutMS: 120_000,
      maximumStandardOutputBytes: 32 * 1024 * 1024,
      maximumStandardErrorBytes: 32 * 1024 * 1024,
      label: "production dependency audit"
    }
  );
  if (result.signal !== null) throw new Error("production dependency audit timed out or exceeded its output limit");
  let report;
  try { report = JSON.parse(result.stdout); }
  catch { throw new Error("npm audit did not return a JSON report"); }
  if (report.error !== undefined || report.auditReportVersion !== 2 || typeof report.metadata?.vulnerabilities?.total !== "number") {
    throw new Error("npm audit could not produce a complete v2 vulnerability report");
  }
  const npmPackage = JSON.parse(await readFile(resolve(dirname(npmCLI), "../package.json"), "utf8"));
  const unresolved = Object.entries(report.vulnerabilities ?? {}).map(([name, value]) => ({
    name,
    severity: value.severity,
    direct: value.isDirect === true,
    range: value.range
  })).sort((left, right) => left.name.localeCompare(right.name));
  const summary = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    productionOnly: true,
    packageLockSHA256: createHash("sha256").update(lockBytes).digest("hex"),
    nodeVersion: process.version,
    npmVersion: npmPackage.version,
    registry: registryURL.href,
    auditReportVersion: report.auditReportVersion,
    vulnerabilities: report.metadata.vulnerabilities,
    unresolved
  };
  const destinationPath = resolve(destination);
  await mkdir(dirname(destinationPath), { recursive: true, mode: 0o755 });
  const temporary = join(dirname(destinationPath), `.${basename(destinationPath)}.${process.pid}.tmp`);
  await writeFile(temporary, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  await chmod(temporary, 0o644);
  await rename(temporary, destinationPath);
  if (summary.vulnerabilities.total !== 0 || unresolved.length !== 0 || result.code !== 0) {
    throw new Error(`production dependency audit found ${summary.vulnerabilities.total} unresolved vulnerabilities`);
  }
  process.stdout.write(`Production dependency audit passed with zero findings using npm ${summary.npmVersion}.\n`);
} finally {
  await rm(root, { recursive: true, force: true });
}
