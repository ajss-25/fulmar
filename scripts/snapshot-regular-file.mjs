import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open, rm } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { consumeAttestedRegularFile, withAttestedDirectories } from "./attested-regular-file.mjs";

const [sourcePath, destinationPath, maximumBytesText = String(8 * 1024 * 1024 * 1024)] = process.argv.slice(2);
if (!sourcePath || !destinationPath || !isAbsolute(sourcePath) || !isAbsolute(destinationPath)) {
  throw new Error("usage: snapshot-regular-file.mjs <absolute-source> <absolute-new-destination> [maximum-bytes]");
}
if (resolve(sourcePath) === resolve(destinationPath)) throw new Error("source and destination must differ");
if (!/^[1-9][0-9]*$/u.test(maximumBytesText)) throw new Error("maximum-bytes must be a positive integer");
const maximumBytes = BigInt(maximumBytesText);

const destinationFlags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL
  | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0);

let destination;
let completed = false;
try {
  if (maximumBytes > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("maximum-bytes exceeds the safe reader limit");
  const receipt = await withAttestedDirectories([dirname(sourcePath), dirname(destinationPath)], {
    label: "snapshot parent directory",
    allowContentMutation: true,
    requireCurrentUser: true
  }, async () => {
  destination = await open(destinationPath, destinationFlags, 0o600);
  const digest = createHash("sha256");
  let writeOffset = 0;
  const source = await consumeAttestedRegularFile(sourcePath, {
    label: "snapshot source",
    minimumBytes: 0,
    maximumBytes: Number(maximumBytes),
    requireCurrentUser: true,
    requireSingleLink: true
  }, async (chunk) => {
    digest.update(chunk);
    let written = 0;
    while (written < chunk.length) {
      const result = await destination.write(chunk, written, chunk.length - written, writeOffset + written);
      if (result.bytesWritten <= 0) throw new Error("snapshot destination stopped accepting bytes");
      written += result.bytesWritten;
    }
    writeOffset += chunk.length;
  });
  await destination.sync();
  const copied = await destination.stat({ bigint: true });
  if (!copied.isFile() || copied.nlink !== 1n || copied.size !== source.metadata.size || (copied.mode & 0o777n) !== 0o600n) {
    throw new Error("snapshot destination did not retain the required private regular-file shape");
  }
  return {
    schemaVersion: 1,
    bytes: source.bytes,
    sha256: digest.digest("hex")
  };
  });
  completed = true;
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
} finally {
  await destination?.close().catch(() => {});
  if (!completed) await rm(destinationPath, { force: true }).catch(() => {});
}
