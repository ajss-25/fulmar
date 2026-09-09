import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const project = process.cwd();
const policyScript = join(project, "scripts", "first-party-license-policy.mjs");
const licenseBytes = Buffer.from("Owner-selected fixture licence terms.\n", "utf8");
const licenseSHA256 = createHash("sha256").update(licenseBytes).digest("hex");

function metadata(overrides = {}) {
  return {
    schemaVersion: 1,
    licenseFile: "LICENSE",
    spdxExpression: "MIT OR Apache-2.0",
    displayName: "Fixture licence",
    licenseSHA256,
    ...overrides
  };
}

async function fixture({ selected = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "fulmar-first-party-license."));
  const resources = join(root, "bundle", "Fulmar.app", "Contents", "Resources");
  await mkdir(join(root, "Config"), { recursive: true, mode: 0o700 });
  await mkdir(resources, { recursive: true, mode: 0o700 });
  if (selected) {
    await writeFile(join(root, "LICENSE"), licenseBytes, { mode: 0o600 });
    await writeFile(
      join(root, "Config", "ProjectLicense.json"),
      `${JSON.stringify(metadata(), null, 2)}\n`,
      { mode: 0o600 }
    );
  }
  return { root, resources, bundledLicense: join(resources, "LICENSE") };
}

function run(action, value, { requireSelected = false, env = {} } = {}) {
  const argumentsList = [policyScript, action, value.root];
  if (action !== "state") argumentsList.push(value.bundledLicense);
  if (requireSelected) argumentsList.push("--require-selected");
  return spawnSync(process.execPath, argumentsList, {
    cwd: project,
    encoding: "utf8",
    timeout: 10_000,
    env: { ...process.env, ...env }
  });
}

function assertRejected(result, pattern) {
  assert.notEqual(result.status, 0, result.stdout);
  assert.match(`${result.stdout}\n${result.stderr}`, pattern);
}

test("the only licence-free state is an explicit private build with both policy files absent", async () => {
  const value = await fixture();
  try {
    let result = run("state", value);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { state: "unlicensed-private" });

    result = run("bundle", value);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { state: "unlicensed-private" });

    result = run("verify-bundle", value);
    assert.equal(result.status, 0, result.stderr);

    assertRejected(run("state", value, { requireSelected: true }), /public distribution requires owner-selected LICENSE/u);
    assertRejected(run("verify-bundle", value, { requireSelected: true }), /public distribution requires owner-selected LICENSE/u);

    await writeFile(value.bundledLicense, "injected terms\n", { mode: 0o600 });
    assertRejected(run("verify-bundle", value), /must not bundle first-party LICENSE bytes/u);
  } finally {
    await rm(value.root, { recursive: true, force: true });
  }
});

test("a valid selected policy is copied byte-for-byte and verified without exposing licence contents", async () => {
  const value = await fixture({ selected: true });
  try {
    let result = run("state", value, { requireSelected: true });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      state: "selected",
      licenseFile: "LICENSE",
      licenseSHA256,
      spdxExpression: "MIT OR Apache-2.0",
      displayName: "Fixture licence"
    });
    assert.doesNotMatch(result.stdout, /Owner-selected fixture/u);

    result = run("bundle", value);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(await readFile(value.bundledLicense), licenseBytes);
    result = run("verify-bundle", value, { requireSelected: true });
    assert.equal(result.status, 0, result.stderr);

    assertRejected(run("bundle", value), /refusing to replace a pre-existing bundled/u);
    await writeFile(value.bundledLicense, "mutated terms\n", { mode: 0o600 });
    assertRejected(run("verify-bundle", value), /does not match the owner-selected source bytes/u);
  } finally {
    await rm(value.root, { recursive: true, force: true });
  }
});

test("partial source states always fail, including when environment variables claim an override", async () => {
  for (const present of ["LICENSE", "metadata"]) {
    const value = await fixture();
    try {
      if (present === "LICENSE") {
        await writeFile(join(value.root, "LICENSE"), licenseBytes, { mode: 0o600 });
      } else {
        await writeFile(
          join(value.root, "Config", "ProjectLicense.json"),
          `${JSON.stringify(metadata(), null, 2)}\n`,
          { mode: 0o600 }
        );
      }
      const result = run("state", value, {
        env: {
          FULMAR_LICENSE_PATH: "/tmp/ignored",
          LOCAL_HARNESS_ALLOW_UNLICENSED_PUBLIC_RELEASE: "1"
        }
      });
      assertRejected(result, /must either both exist or both be absent/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }
});

test("project, Config, and bundle Resources directories must remain real and owner-controlled", async () => {
  const mutations = [
    async (value) => { await chmod(value.root, 0o722); },
    async (value) => { await chmod(join(value.root, "Config"), 0o722); },
    async (value) => {
      const source = join(value.root, "Config");
      const target = join(value.root, "Config.real");
      await rm(source, { recursive: true });
      await mkdir(target, { mode: 0o700 });
      await writeFile(join(target, "ProjectLicense.json"), `${JSON.stringify(metadata())}\n`, { mode: 0o600 });
      await symlink("Config.real", source);
    }
  ];
  for (const mutate of mutations) {
    const value = await fixture({ selected: true });
    try {
      await mutate(value);
      assertRejected(run("state", value), /owner-controlled directory/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }

  const value = await fixture({ selected: true });
  try {
    await chmod(value.resources, 0o722);
    assertRejected(run("bundle", value), /app Resources directory must be a real owner-controlled directory/u);
  } finally {
    await rm(value.root, { recursive: true, force: true });
  }
});

test("linked, nonregular, writable, empty, invalid-UTF8, and oversized licence sources fail closed", async () => {
  const cases = [
    async (value) => {
      await rm(join(value.root, "LICENSE"));
      await symlink("terms.txt", join(value.root, "LICENSE"));
      await writeFile(join(value.root, "terms.txt"), licenseBytes, { mode: 0o600 });
    },
    async (value) => {
      await link(join(value.root, "LICENSE"), join(value.root, "LICENSE.link"));
    },
    async (value) => { await chmod(join(value.root, "LICENSE"), 0o622); },
    async (value) => {
      await rm(join(value.root, "LICENSE"));
      await mkdir(join(value.root, "LICENSE"), { mode: 0o700 });
    },
    async (value) => { await writeFile(join(value.root, "LICENSE"), "", { mode: 0o600 }); },
    async (value) => { await writeFile(join(value.root, "LICENSE"), Buffer.from([0xff]), { mode: 0o600 }); },
    async (value) => { await writeFile(join(value.root, "LICENSE"), Buffer.alloc(1024 * 1024 + 1, 0x61), { mode: 0o600 }); }
  ];
  for (const [index, mutate] of cases.entries()) {
    const value = await fixture({ selected: true });
    try {
      await mutate(value);
      assertRejected(run("state", value), /regular|links|empty|UTF-8|byte|SHA-256/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
    assert.ok(index >= 0);
  }
});

test("linked, nonregular, writable, invalid-UTF8, and oversized metadata fail closed", async () => {
  const metadataPath = (value) => join(value.root, "Config", "ProjectLicense.json");
  const cases = [
    async (value) => {
      await rm(metadataPath(value));
      await symlink("metadata.json", metadataPath(value));
      await writeFile(join(value.root, "Config", "metadata.json"), `${JSON.stringify(metadata())}\n`, { mode: 0o600 });
    },
    async (value) => { await link(metadataPath(value), join(value.root, "Config", "metadata.link")); },
    async (value) => { await chmod(metadataPath(value), 0o622); },
    async (value) => {
      await rm(metadataPath(value));
      await mkdir(metadataPath(value), { mode: 0o700 });
    },
    async (value) => { await writeFile(metadataPath(value), Buffer.from([0xff]), { mode: 0o600 }); },
    async (value) => { await writeFile(metadataPath(value), Buffer.alloc(16 * 1024 + 1, 0x20), { mode: 0o600 }); }
  ];
  for (const mutate of cases) {
    const value = await fixture({ selected: true });
    try {
      await mutate(value);
      assertRejected(run("state", value), /regular|links|UTF-8|byte/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }
});

test("the bounded v1 metadata schema rejects malformed, duplicate, extra, mistyped, and digest-drifted fields", async () => {
  const documents = [
    "not JSON\n",
    '{"schemaVersion":1,"schemaVersion":1,"licenseFile":"LICENSE","spdxExpression":"MIT","displayName":"Fixture","licenseSHA256":"' + licenseSHA256 + '"}\n',
    `${JSON.stringify({ ...metadata(), extra: true })}\n`,
    `${JSON.stringify(metadata({ schemaVersion: 2 }))}\n`,
    `${JSON.stringify(metadata({ licenseFile: "COPYING" }))}\n`,
    `${JSON.stringify(metadata({ licenseSHA256: "0".repeat(64) }))}\n`,
    `${JSON.stringify(metadata({ licenseSHA256: licenseSHA256.toUpperCase() }))}\n`,
    `${JSON.stringify(metadata({ displayName: 7 }))}\n`,
    `${JSON.stringify(metadata({ displayName: " leading" }))}\n`,
    `${JSON.stringify(metadata({ displayName: "bad\nname" }))}\n`,
    `${JSON.stringify(metadata({ displayName: "x".repeat(129) }))}\n`
  ];
  for (const document of documents) {
    const value = await fixture({ selected: true });
    try {
      await writeFile(join(value.root, "Config", "ProjectLicense.json"), document, { mode: 0o600 });
      assertRejected(run("state", value), /JSON|duplicate|schema|SHA-256|display name/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }
});

test("the SPDX expression parser accepts bounded compound terms and rejects hostile or incomplete grammar", async () => {
  const accepted = [
    "MIT",
    "Apache-2.0 WITH LLVM-exception",
    "MIT OR Apache-2.0",
    "(MIT OR Apache-2.0) AND LicenseRef-Owner-Exception",
    "DocumentRef-Owner:LicenseRef-Private-Terms"
  ];
  for (const expression of accepted) {
    const value = await fixture({ selected: true });
    try {
      await writeFile(
        join(value.root, "Config", "ProjectLicense.json"),
        `${JSON.stringify(metadata({ spdxExpression: expression }), null, 2)}\n`,
        { mode: 0o600 }
      );
      const result = run("state", value);
      assert.equal(result.status, 0, `${expression}: ${result.stderr}`);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }

  const rejected = [
    "",
    " MIT",
    "MIT ",
    "MIT AND",
    "OR MIT",
    "MIT WITH",
    "(MIT OR Apache-2.0",
    "(MIT OR Apache-2.0) WITH LLVM-exception",
    "MIT; rm -rf /",
    "MIT\nOR Apache-2.0",
    "Definitely-Not-A-License",
    "MIT WITH Definitely-Not-An-Exception",
    "LicenseRef-",
    "DocumentRef-Owner:MIT",
    "x".repeat(257)
  ];
  for (const expression of rejected) {
    const value = await fixture({ selected: true });
    try {
      await writeFile(
        join(value.root, "Config", "ProjectLicense.json"),
        `${JSON.stringify(metadata({ spdxExpression: expression }))}\n`,
        { mode: 0o600 }
      );
      assertRejected(run("state", value), /SPDX expression|SPDX identifier/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }
});

test("bundled licence verification rejects missing, linked, hard-linked, and replaced app bytes", async () => {
  const mutations = [
    async () => {},
    async (value) => {
      await symlink(join(value.root, "LICENSE"), value.bundledLicense);
    },
    async (value) => {
      await writeFile(value.bundledLicense, licenseBytes, { mode: 0o600 });
      await link(value.bundledLicense, join(value.resources, "LICENSE.link"));
    },
    async (value) => { await writeFile(value.bundledLicense, "replaced\n", { mode: 0o600 }); }
  ];
  for (const mutate of mutations) {
    const value = await fixture({ selected: true });
    try {
      await mutate(value);
      assertRejected(run("verify-bundle", value), /missing|regular|links|does not match/u);
    } finally {
      await rm(value.root, { recursive: true, force: true });
    }
  }
});
