import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { basename } from "node:path";

const [manifestPath, archivePath, infoJSONPath, symbolsArchivePath, vendorInventoryPath, unsignedInventoryPath, signablesPath, runtimeInventoryPath, sourceInputInventoryPath, staticSecuritySummaryPath, toolchainInventoryPath] = process.argv.slice(2);
if (!manifestPath || !archivePath || !infoJSONPath || !symbolsArchivePath || !vendorInventoryPath || !unsignedInventoryPath || !signablesPath || !runtimeInventoryPath || !sourceInputInventoryPath || !staticSecuritySummaryPath || !toolchainInventoryPath) {
  throw new Error("usage: verify-release-manifest.mjs <manifest> <archive> <info-json> <symbols-archive> <vendor-inventory> <unsigned-runtime-inventory> <runtime-signables> <runtime-inventory> <source-build-input-inventory> <static-security-summary> <toolchain-inventory>");
}
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const releaseIdentity = JSON.parse(await readFile(
  new URL("../Config/ReleaseIdentity.json", import.meta.url), "utf8"
));
const archiveInfo = await lstat(archivePath);
if (!archiveInfo.isFile() || archiveInfo.isSymbolicLink() || archiveInfo.size <= 0
    || archiveInfo.size > 8 * 1024 * 1024 * 1024 || basename(archivePath) !== releaseIdentity.releaseArchiveName) {
  throw new Error("release archive is not the expected bounded regular zip file");
}
const info = JSON.parse(await readFile(infoJSONPath, "utf8"));
if (info.CFBundleDisplayName !== releaseIdentity.productDisplayName
    || info.CFBundleName !== releaseIdentity.productDisplayName
    || info.CFBundleIdentifier !== releaseIdentity.bundleIdentifier
    || info.CFBundleShortVersionString !== releaseIdentity.appVersion
    || Number(info.CFBundleVersion) !== releaseIdentity.appBuild
    || info.LSMinimumSystemVersion !== releaseIdentity.minimumMacOS) {
  throw new Error("Info.plist does not match the reviewed release identity");
}
const archiveHash = createHash("sha256");
for await (const chunk of createReadStream(archivePath)) archiveHash.update(chunk);

async function artifactDescriptor(path, expectedName, maximumBytes = 64 * 1024 * 1024) {
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1 || details.size <= 0
      || details.size > maximumBytes || basename(path) !== expectedName) {
    throw new Error(`release inventory is not the expected bounded regular file: ${expectedName}`);
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return { file: expectedName, bytes: details.size, sha256: hash.digest("hex") };
}

const expected = {
  schemaVersion: 6,
  product: releaseIdentity.productDisplayName,
  bundleIdentifier: info.CFBundleIdentifier,
  version: info.CFBundleShortVersionString,
  build: Number(info.CFBundleVersion),
  archive: releaseIdentity.releaseArchiveName,
  archiveBytes: archiveInfo.size,
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
if (JSON.stringify(manifest) !== JSON.stringify(expected)) throw new Error("release manifest does not exactly describe the archive and Info.plist");
process.stdout.write(`Release manifest verified for ${expected.version} (${expected.build}), ${expected.archiveBytes} bytes, ${expected.sha256}.\n`);
