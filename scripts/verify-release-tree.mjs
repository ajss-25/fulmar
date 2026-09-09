import { lstat, readdir, readlink } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { sha256AttestedRegularFile, withAttestedDirectory } from "./attested-regular-file.mjs";

const [sourceRootArgument, extractedRootArgument] = process.argv.slice(2);
if (!sourceRootArgument || !extractedRootArgument) throw new Error("usage: verify-release-tree.mjs <source-app> <extracted-app>");
const sourceRoot = resolve(sourceRootArgument);
const extractedRoot = resolve(extractedRootArgument);

async function inventory(root) {
  const result = new Map();
  const identities = new Set();
  async function visit(directory, prefix = "") {
    return withAttestedDirectory(directory, {
      label: prefix ? `bundle directory ${prefix}` : "bundle root directory",
      requireCurrentUser: true
    }, async ({ metadata: directoryMetadata }) => {
      const entries = await readdir(directory, { withFileTypes: true });
      entries.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of entries) {
        const path = `${directory}/${entry.name}`;
        const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
        const identity = relativePath.normalize("NFC").toLocaleLowerCase("en-US");
        if (identities.has(identity)) throw new Error(`bundle contains duplicate normalized path: ${relativePath}`);
        identities.add(identity);
        const info = await lstat(path);
        if (info.isDirectory()) {
          const childMetadata = await visit(path, relativePath);
          result.set(relativePath, {
            type: "directory",
            mode: Number(childMetadata.mode & 0o7777n)
          });
        } else if (info.isFile()) {
          const file = await sha256AttestedRegularFile(path, {
            label: `bundle regular file ${relativePath}`,
            minimumBytes: 0,
            maximumBytes: 8 * 1024 * 1024 * 1024,
            requireCurrentUser: true,
            requireSingleLink: true
          });
          result.set(relativePath, {
            type: "file",
            mode: Number(file.metadata.mode & 0o7777n),
            bytes: file.bytes,
            sha256: file.sha256
          });
        } else if (info.isSymbolicLink()) {
          const target = await readlink(path);
          if (target.startsWith("/")) throw new Error(`bundle contains absolute symlink: ${relativePath}`);
          const resolvedTarget = resolve(directory, target);
          const escape = relative(root, resolvedTarget);
          if (escape === ".." || escape.startsWith(`..${sep}`) || resolve(root, escape) !== resolvedTarget) {
            throw new Error(`bundle symlink escapes app root: ${relativePath}`);
          }
          // Archive extraction applies the caller's umask to symlink mode bits on
          // macOS even though those bits do not govern access through a symbolic
          // link. Bind the entry type, exact relative target, and containment;
          // continue binding modes for every regular file and directory.
          result.set(relativePath, { type: "symlink", target });
        } else {
          throw new Error(`bundle contains unsupported filesystem object: ${relativePath}`);
        }
      }
      return directoryMetadata;
    });
  }
  await visit(root);
  return result;
}

const source = await inventory(sourceRoot);
const extracted = await inventory(extractedRoot);
if (source.size !== extracted.size) throw new Error(`archive tree count mismatch: source ${source.size}, extracted ${extracted.size}`);
for (const [path, expected] of source) {
  const actual = extracted.get(path);
  if (actual === undefined || JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`archive extraction differs from signed source bundle at ${path}`);
  }
}
process.stdout.write(`Archive extraction matches ${source.size} source bundle entries byte-for-byte, by type, mode, and symlink target.\n`);
