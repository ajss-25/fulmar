import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

async function swiftFiles(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await swiftFiles(path));
    else if (entry.isFile() && entry.name.endsWith(".swift")) result.push(path);
  }
  return result;
}

test("every Darwin directory entry decoder is record-length bounded", async () => {
  const root = join(process.cwd(), "Sources");
  const occurrences = [];
  for (const path of await swiftFiles(root)) {
    const source = await readFile(path, "utf8");
    if (source.includes("pointee.d_namlen")) occurrences.push(relative(process.cwd(), path));
    assert.doesNotMatch(source, /withUnsafeBytes\s*\(\s*of:[^\n]*d_name/u);
    assert.doesNotMatch(source, /withUnsafePointer\s*\(\s*to:\s*(?!&)[^\n]*d_name/u);
  }

  assert.deepEqual(occurrences.sort(), [
    "Sources/CredentialSecurity/CredentialTransaction.swift",
    "Sources/LocalHarness/DarwinDirectoryEntry.swift",
    "Sources/PrivateInstallCoordinator/PrivateInstallCoordinator.swift",
    "Sources/SandboxPolicy/SandboxInvocation.swift"
  ]);

  for (const path of occurrences) {
    const source = await readFile(join(process.cwd(), path), "utf8");
    assert.match(source, /pointee\.d_namlen/u);
    assert.match(source, /pointee\.d_reclen/u);
    assert.match(source, /MemoryLayout<dirent>\.offset\(of: \\dirent\.d_name\)/u);
    assert.match(source, /UnsafeRawPointer\(entry\)\.advanced\(by: nameOffset\)/u);
  }
});
