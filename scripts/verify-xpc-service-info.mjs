#!/usr/bin/env node

import { readFileSync } from "node:fs";

const [identityPath, migrationInfoPath, brokerInfoPath] = process.argv.slice(2);
if (!identityPath || !migrationInfoPath || !brokerInfoPath || process.argv.length !== 5) {
  process.stderr.write(
    "usage: verify-xpc-service-info.mjs <ReleaseIdentity.json> <migration-info.json> <broker-info.json>\n"
  );
  process.exit(64);
}

function fail(message) {
  process.stderr.write(`Credential XPC Info.plist verification failed: ${message}\n`);
  process.exit(1);
}

function rejectDuplicateJSONKeys(text, label) {
  let offset = 0;
  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  };
  const parseString = () => {
    if (text[offset] !== '"') fail(`${label} is not canonical JSON`);
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      if (text[offset] === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail(`${label} contains an invalid JSON string`);
        }
      }
      if (text[offset] === "\\") {
        offset += 2;
      } else {
        offset += 1;
      }
    }
    fail(`${label} contains an unterminated JSON string`);
  };
  const parseValue = () => {
    skipWhitespace();
    if (text[offset] === "{") {
      offset += 1;
      skipWhitespace();
      const keys = new Set();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      while (offset < text.length) {
        const key = parseString();
        if (keys.has(key)) fail(`${label} contains duplicate dictionary key ${key}`);
        keys.add(key);
        skipWhitespace();
        if (text[offset] !== ":") fail(`${label} is not canonical JSON`);
        offset += 1;
        parseValue();
        skipWhitespace();
        if (text[offset] === "}") {
          offset += 1;
          return;
        }
        if (text[offset] !== ",") fail(`${label} is not canonical JSON`);
        offset += 1;
        skipWhitespace();
      }
      fail(`${label} contains an unterminated JSON dictionary`);
    }
    if (text[offset] === "[") {
      offset += 1;
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      while (offset < text.length) {
        parseValue();
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return;
        }
        if (text[offset] !== ",") fail(`${label} is not canonical JSON`);
        offset += 1;
      }
      fail(`${label} contains an unterminated JSON array`);
    }
    if (text[offset] === '"') {
      parseString();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return;
      }
    }
    const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/uy;
    number.lastIndex = offset;
    const match = number.exec(text);
    if (!match) fail(`${label} contains an invalid JSON value`);
    offset = number.lastIndex;
  };
  parseValue();
  skipWhitespace();
  if (offset !== text.length) fail(`${label} contains trailing non-JSON data`);
}

function loadObject(path, label) {
  let value;
  try {
    const text = readFileSync(path, "utf8");
    rejectDuplicateJSONKeys(text, label);
    value = JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} is not a dictionary`);
  }
  return value;
}

function assertExactValue(actual, expected, label) {
  if (expected !== null && typeof expected === "object") {
    if (actual === null || typeof actual !== "object" || Array.isArray(actual)) {
      fail(`${label} is not the reviewed dictionary`);
    }
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
      const unexpected = actualKeys.filter((key) => !expectedKeys.includes(key));
      const missing = expectedKeys.filter((key) => !actualKeys.includes(key));
      const details = [
        unexpected.length > 0 ? `unexpected keys ${unexpected.join(", ")}` : "",
        missing.length > 0 ? `missing keys ${missing.join(", ")}` : ""
      ].filter(Boolean).join("; ");
      fail(`${label} has a non-reviewed key set${details ? ` (${details})` : ""}`);
    }
    for (const key of expectedKeys) {
      assertExactValue(actual[key], expected[key], `${label}.${key}`);
    }
    return;
  }
  if (actual !== expected || typeof actual !== typeof expected) {
    fail(`${label} does not match the reviewed value`);
  }
}

const identity = loadObject(identityPath, "release identity");
if (identity.schemaVersion !== 1
    || typeof identity.bundleIdentifier !== "string"
    || typeof identity.appVersion !== "string"
    || !Number.isSafeInteger(identity.appBuild)
    || typeof identity.minimumMacOS !== "string") {
  fail("release identity is incomplete or unsupported");
}

const common = {
  CFBundleDevelopmentRegion: "en",
  CFBundleInfoDictionaryVersion: "6.0",
  CFBundlePackageType: "XPC!",
  CFBundleShortVersionString: identity.appVersion,
  CFBundleVersion: String(identity.appBuild),
  LSMinimumSystemVersion: identity.minimumMacOS,
  XPCService: {
    // User-Keychain access requires the caller's security session; omission
    // creates a separate session even when the caller unlocked its Keychain.
    JoinExistingSession: true,
    ServiceType: "Application"
  }
};

const expectedMigration = {
  ...common,
  CFBundleDisplayName: "Fulmar Credential Migration Service",
  CFBundleExecutable: "LocalHarnessCredentialMigrationService",
  CFBundleIdentifier: `${identity.bundleIdentifier}.credential-helper`,
  CFBundleName: "Fulmar Credential Migration Service"
};
const expectedBroker = {
  ...common,
  CFBundleDisplayName: "Fulmar Credential Broker Service",
  CFBundleExecutable: "LocalHarnessCredentialBrokerService",
  CFBundleIdentifier: `${identity.bundleIdentifier}.credential-broker`,
  CFBundleName: "Fulmar Credential Broker Service"
};

assertExactValue(
  loadObject(migrationInfoPath, "credential migration XPC Info.plist"),
  expectedMigration,
  "credential migration XPC Info.plist"
);
assertExactValue(
  loadObject(brokerInfoPath, "credential broker XPC Info.plist"),
  expectedBroker,
  "credential broker XPC Info.plist"
);

process.stdout.write(
  "Credential XPC Info.plist verification passed: exact top-level and XPCService dictionaries.\n"
);
