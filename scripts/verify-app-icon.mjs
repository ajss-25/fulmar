#!/usr/bin/env node

import path from "node:path";
import { readAttestedRegularFileSync } from "./attested-regular-file.mjs";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const ICNS_ENTRIES = new Map([
  ["icp4", 16],
  ["icp5", 32],
  ["icp6", 64],
  ["ic07", 128],
  ["ic08", 256],
  ["ic09", 512],
  ["ic10", 1024]
]);
const MAX_ICON_BYTES = 32 * 1024 * 1024;

const fail = (message) => {
  throw new Error(`Fulmar app icon verification failed: ${message}`);
};

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

function readRegularFile(filePath, label) {
  const absolute = path.resolve(filePath);
  let artifact;
  try {
    artifact = readAttestedRegularFileSync(absolute, {
      label,
      minimumBytes: 1,
      maximumBytes: MAX_ICON_BYTES,
      requireCurrentUser: true,
      requireSingleLink: true
    });
  } catch {
    fail(`${label} is not a safe independent regular file`);
  }
  return { absolute: artifact.path, data: artifact.bytes };
}

function validatePNG(data, label) {
  if (data.length < 45 || !data.subarray(0, 8).equals(PNG_SIGNATURE)) {
    fail(`${label} is not a PNG image`);
  }

  let offset = 8;
  let width;
  let height;
  let chunks = 0;
  let sawImageData = false;
  let sawEnd = false;
  while (offset < data.length) {
    if (data.length - offset < 12) fail(`${label} has a truncated PNG chunk header`);
    const length = data.readUInt32BE(offset);
    const chunkEnd = offset + 12 + length;
    if (chunkEnd > data.length) fail(`${label} has a PNG chunk outside the file`);
    const typeBytes = data.subarray(offset + 4, offset + 8);
    const type = typeBytes.toString("ascii");
    if (!/^[A-Za-z]{4}$/u.test(type)) fail(`${label} has an invalid PNG chunk type`);
    const payload = data.subarray(offset + 8, offset + 8 + length);
    const expectedCRC = data.readUInt32BE(offset + 8 + length);
    const actualCRC = crc32(Buffer.concat([typeBytes, payload]));
    if (actualCRC !== expectedCRC) fail(`${label} has an invalid ${type} checksum`);

    if (chunks === 0 && type !== "IHDR") fail(`${label} does not begin with IHDR`);
    if (type === "IHDR") {
      if (chunks !== 0 || length !== 13 || width !== undefined) fail(`${label} has an invalid IHDR`);
      width = payload.readUInt32BE(0);
      height = payload.readUInt32BE(4);
      if (width === 0 || height === 0) fail(`${label} has empty dimensions`);
      if (payload[10] !== 0 || payload[11] !== 0 || ![0, 1].includes(payload[12])) {
        fail(`${label} uses an unsupported PNG encoding`);
      }
    } else if (type === "IDAT") {
      if (sawEnd) fail(`${label} contains image data after IEND`);
      sawImageData = true;
    } else if (type === "IEND") {
      if (length !== 0 || !sawImageData) fail(`${label} has an invalid IEND`);
      sawEnd = true;
      if (chunkEnd !== data.length) fail(`${label} has bytes after IEND`);
    }
    chunks += 1;
    offset = chunkEnd;
  }
  if (width === undefined || height === undefined || !sawEnd) fail(`${label} is incomplete`);
  return { width, height };
}

function verifyICNS(filePath) {
  const { absolute, data } = readRegularFile(filePath, "AppIcon.icns");
  if (data.length < 8 || data.toString("ascii", 0, 4) !== "icns") fail("the ICNS header is missing");
  if (data.readUInt32BE(4) !== data.length) fail("the ICNS declared length does not match its bytes");

  const found = new Set();
  let offset = 8;
  while (offset < data.length) {
    if (data.length - offset < 8) fail("an ICNS entry header is truncated");
    const type = data.toString("ascii", offset, offset + 4);
    const length = data.readUInt32BE(offset + 4);
    if (length < 8 || offset + length > data.length) fail(`${type || "unknown"} has an invalid ICNS length`);
    if (!ICNS_ENTRIES.has(type)) fail(`unexpected ICNS entry ${type}`);
    if (found.has(type)) fail(`duplicate ICNS entry ${type}`);
    const expectedSize = ICNS_ENTRIES.get(type);
    const dimensions = validatePNG(data.subarray(offset + 8, offset + length), `${type} payload`);
    if (dimensions.width !== expectedSize || dimensions.height !== expectedSize) {
      fail(`${type} is ${dimensions.width}x${dimensions.height}; expected ${expectedSize}x${expectedSize}`);
    }
    found.add(type);
    offset += length;
  }
  if (offset !== data.length || found.size !== ICNS_ENTRIES.size) fail("the required ICNS representation set is incomplete");
  for (const type of ICNS_ENTRIES.keys()) {
    if (!found.has(type)) fail(`required ICNS entry ${type} is missing`);
  }
  return absolute;
}

function verifyMaster(filePath) {
  const { absolute, data } = readRegularFile(filePath, "reviewed icon master");
  const { width, height } = validatePNG(data, "reviewed icon master");
  if (width !== height || width < 1024) fail(`reviewed icon master is ${width}x${height}; expected a square of at least 1024px`);
  return absolute;
}

try {
  const [, , iconPath, masterPath] = process.argv;
  if (!iconPath || process.argv.length > 4) {
    fail("usage: verify-app-icon.mjs <AppIcon.icns> [reviewed-master.png]");
  }
  const verifiedIcon = verifyICNS(iconPath);
  if (masterPath) verifyMaster(masterPath);
  process.stdout.write(`Fulmar app icon passed structural and pixel-dimension verification: ${verifiedIcon}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
