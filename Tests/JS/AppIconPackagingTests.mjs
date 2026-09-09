import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const verifier = join(process.cwd(), "scripts", "verify-app-icon.mjs");
const master = join(process.cwd(), "Resources", "FulmarAppIcon.png");
const representations = [
  ["icp4", 16],
  ["icp5", 32],
  ["icp6", 64],
  ["ic07", 128],
  ["ic08", 256],
  ["ic09", 512],
  ["ic10", 1024]
];

const crcTable = new Uint32Array(256);
for (let index = 0; index < crcTable.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  }
  crcTable[index] = value >>> 0;
}

function crc32(data) {
  let value = 0xffffffff;
  for (const byte of data) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function pngChunk(type, payload) {
  const typeBytes = Buffer.from(type, "ascii");
  const header = Buffer.alloc(8);
  header.writeUInt32BE(payload.length, 0);
  typeBytes.copy(header, 4);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBytes, payload])), 0);
  return Buffer.concat([header, payload, checksum]);
}

function structuralPNG(width, height) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  const imageData = Buffer.from([0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", header),
    pngChunk("IDAT", imageData),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

function icns(overrides = new Map()) {
  const entries = representations.map(([type, expectedSize]) => {
    const size = overrides.get(type) ?? expectedSize;
    const payload = structuralPNG(size, size);
    const entryHeader = Buffer.alloc(8);
    entryHeader.write(type, 0, 4, "ascii");
    entryHeader.writeUInt32BE(payload.length + 8, 4);
    return Buffer.concat([entryHeader, payload]);
  });
  const body = Buffer.concat(entries);
  const header = Buffer.alloc(8);
  header.write("icns", 0, 4, "ascii");
  header.writeUInt32BE(body.length + 8, 4);
  return Buffer.concat([header, body]);
}

test("release icon verifier accepts the complete exact representation set and reviewed master", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-app-icon-"));
  try {
    const icon = join(root, "AppIcon.icns");
    await writeFile(icon, icns(), { mode: 0o600 });
    const result = await execFileAsync(process.execPath, [verifier, icon, master]);
    assert.match(result.stdout, /passed structural and pixel-dimension verification/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("release icon verifier rejects a wrong pixel representation and corrupt container length", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-app-icon-hostile-"));
  try {
    const wrongPixels = join(root, "wrong-pixels.icns");
    await writeFile(wrongPixels, icns(new Map([["ic10", 512]])), { mode: 0o600 });
    await assert.rejects(
      execFileAsync(process.execPath, [verifier, wrongPixels]),
      /ic10 is 512x512; expected 1024x1024/u
    );

    const corruptLength = icns();
    corruptLength.writeUInt32BE(corruptLength.length - 1, 4);
    const corrupt = join(root, "corrupt-length.icns");
    await writeFile(corrupt, corruptLength, { mode: 0o600 });
    await assert.rejects(
      execFileAsync(process.execPath, [verifier, corrupt]),
      /declared length does not match/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("both candidate assembly and final release verification enforce the packaged icon", async () => {
  const [build, release] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8")
  ]);
  assert.match(
    build,
    /verify-app-icon\.mjs" \\\n+  "\$RESOURCES_DIR\/AppIcon\.icns" "\$MASTER_ICON"/u
  );
  assert.match(
    release,
    /verify-app-icon\.mjs" \\\n+  "\$APP_DIR\/Contents\/Resources\/AppIcon\.icns" "\$PROJECT_DIR\/Resources\/FulmarAppIcon\.png"/u
  );
});
