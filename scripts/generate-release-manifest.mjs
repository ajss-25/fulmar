import { createReadStream } from "node:fs";
import { chmod, lstat, readFile, rename, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";

const [archivePath, infoPath, destination, symbolsArchivePath, vendorInventoryPath, unsignedInventoryPath, signablesPath, runtimeInventoryPath, sourceInputInventoryPath, staticSecuritySummaryPath, toolchainInventoryPath] = process.argv.slice(2);
if (!archivePath || !infoPath || !destination || !symbolsArchivePath || !vendorInventoryPath || !unsignedInventoryPath || !signablesPath || !runtimeInventoryPath || !sourceInputInventoryPath || !staticSecuritySummaryPath || !toolchainInventoryPath) {
  throw new Error("usage: generate-release-manifest.mjs <archive> <Info.plist.json> <destination> <symbols-archive> <vendor-inventory> <unsigned-runtime-inventory> <runtime-signables> <runtime-inventory> <source-build-input-inventory> <static-security-summary> <toolchain-inventory>");
}
const info = JSON.parse(await readFile(infoPath, "utf8"));
const releaseIdentity = JSON.parse(await readFile(
  new URL("../Config/ReleaseIdentity.json", import.meta.url), "utf8"
));
const details = await lstat(archivePath);
if (!details.isFile() || details.isSymbolicLink() || details.size <= 0 || details.size > 8 * 1024 * 1024 * 1024
    || basename(archivePath) !== releaseIdentity.releaseArchiveName) {
  throw new Error("release archive must be the expected non-empty regular zip file within the release size limit");
}
if (info.CFBundleDisplayName !== releaseIdentity.productDisplayName
    || info.CFBundleName !== releaseIdentity.productDisplayName
    || info.CFBundleIdentifier !== releaseIdentity.bundleIdentifier
    || info.CFBundleShortVersionString !== releaseIdentity.appVersion
    || Number(info.CFBundleVersion) !== releaseIdentity.appBuild
    || info.LSMinimumSystemVersion !== releaseIdentity.minimumMacOS
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(info.CFBundleShortVersionString ?? "")
    || !/^\d+$/.test(String(info.CFBundleVersion ?? ""))
    || !/^\d+\.\d+$/.test(info.LSMinimumSystemVersion ?? "")) {
  throw new Error("Info.plist release identity is incomplete or invalid");
}
const archiveHash = createHash("sha256");
for await (const chunk of createReadStream(archivePath)) archiveHash.update(chunk);

async function artifactDescriptor(path, expectedName, maximumBytes = 64 * 1024 * 1024) {
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1 || details.size <= 0
      || details.size > maximumBytes || basename(path) !== expectedName) {
    throw new Error(`release inventory must be the expected bounded regular file: ${expectedName}`);
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return { file: expectedName, bytes: details.size, sha256: hash.digest("hex") };
}

const manifest = {
  schemaVersion: 6,
  product: releaseIdentity.productDisplayName,
  bundleIdentifier: releaseIdentity.bundleIdentifier,
  version: info.CFBundleShortVersionString,
  build: Number(info.CFBundleVersion),
  archive: releaseIdentity.releaseArchiveName,
  archiveBytes: details.size,
  sha256: archiveHash.digest("hex"),
  symbols: await artifactDescriptor(symbolsArchivePath, releaseIdentity.symbolsArchiveName, 256 * 1024 * 1024),
  minimumMacOS: info.LSMinimumSystemVersion,
  runtime: {
    node: releaseIdentity.runtime.nodeVersion,
    deepseekHarness: releaseIdentity.runtime.deepseekHarnessVersion
  },
  inventories: {
    vendor: await artifactDescriptor(vendorInventoryPath, "VendorRuntime.inventory.json"),
    unsignedRuntime: await artifactDescriptor(unsignedInventoryPath, "runtime-unsigned-inventory.json"),
    runtimeSignables: await artifactDescriptor(signablesPath, "runtime-signables.json"),
    assembledRuntime: await artifactDescriptor(runtimeInventoryPath, "runtime-release-inventory.json"),
    buildInputs: await artifactDescriptor(sourceInputInventoryPath, "source-build-inputs.json"),
    staticSecurity: await artifactDescriptor(staticSecuritySummaryPath, "static-security-summary.json", 512 * 1024),
    toolchain: await artifactDescriptor(toolchainInventoryPath, "toolchain-inventory.json")
  }
};
const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.tmp`);
await writeFile(temporary, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600, flag: "wx" });
await chmod(temporary, 0o644);
await rename(temporary, destination);
