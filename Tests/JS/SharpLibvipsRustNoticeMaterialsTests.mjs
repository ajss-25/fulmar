// Pure tests for Config/SharpLibvipsRustNoticeMaterials.json: the version-bound
// notice material (or precise unresolved record) for every crate in
// Config/SharpLibvipsRustProvenance.json whose archive carries no licence text.
// The validator below runs over the real tree and over mutated private copies
// so that missing or drifted bytes and misattributed origins are caught. No
// network, no crate archives, no legal conclusion.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { loadManifest, loadRustNoticeMaterials } from "../../scripts/prepare-libvips-source-materials.mjs";

const project = process.cwd();
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const RUST_PREFIX = "Resources/ThirdPartyLicenses/sharp-libvips-1.3.2/rust/";
const MATERIAL_KINDS = new Set(["external-upstream-file", "external-spdx-licence-text"]);

async function validate(root) {
  const readJSON = async (relative) => JSON.parse(await readFile(join(root, relative), "utf8"));
  const manifest = await readJSON("Config/SharpLibvipsRustNoticeMaterials.json");
  const provenance = await readJSON(manifest.crateManifest);
  assert.equal(manifest.schemaVersion, 1);
  assert.match(manifest.purpose, /not legal clearance/u);
  assert.match(manifest.purpose, /never a member of the original archive/u);
  assert.doesNotMatch(JSON.stringify(manifest), /cleared|compliant|legally (?:sufficient|satisfied)/iu);
  assert.equal(manifest.crateManifest, "Config/SharpLibvipsRustProvenance.json");

  const withoutText = provenance.items.filter((item) => item.noticeStatus === "no-licence-text-in-crate");
  const expectedIdentities = withoutText.map((item) => `${item.crateName} ${item.crateVersion}`).sort();
  const recordIdentities = manifest.records.map((record) => `${record.crateName} ${record.crateVersion}`);
  assert.deepEqual([...recordIdentities].sort(), expectedIdentities, "exactly the crates without archive licence text are covered, once each");
  assert.deepEqual(recordIdentities, [...recordIdentities].sort(), "records are in sorted order");
  assert.deepEqual([...manifest.summary.established, ...manifest.summary.unresolved].sort(), expectedIdentities);

  const boundPaths = new Set();
  for (const record of manifest.records) {
    const label = `${record.crateName} ${record.crateVersion}`;
    const item = withoutText.find((candidate) => candidate.crateName === record.crateName && candidate.crateVersion === record.crateVersion);
    assert.equal(record.crateSHA256, item.sha256, `${label} is bound to the pinned crate archive digest`);
    assert.equal(record.licenseExpression, item.licenseExpression, label);
    assert.ok(["established", "unresolved"].includes(record.status), label);
    assert.ok((manifest.summary[record.status] ?? []).includes(label), `${label} summary entry matches its status`);
    assert.ok(["cargo-vcs-info", "version-tag"].includes(record.connection.kind), label);
    assert.match(record.connection.revision, COMMIT, `${label} connection revision is a full commit`);
    assert.match(record.connection.repository, /^https:\/\/github\.com\/[^/]+\/[^/]+$/u, label);
    assert.ok(record.connection.revisionEvidence.length >= 80, `${label} connection evidence is specific`);
    assert.ok(record.connection.revisionEvidence.includes(`"${record.crateVersion}"`), `${label} connection evidence cites the exact version at the revision`);
    if (record.connection.kind === "cargo-vcs-info") {
      assert.match(record.connection.revisionEvidence, /\.cargo_vcs_info\.json \(sha256 [a-f0-9]{64}\) records git sha1 [a-f0-9]{40}/u, label);
      assert.ok(record.connection.revisionEvidence.includes(record.connection.revision), label);
      assert.match(record.connection.revisionEvidence, /byte-identical/u, `${label} archive members were compared with the revision`);
    }
    if (record.status === "established") {
      assert.ok(Array.isArray(record.materials) && record.materials.length >= 1, `${label} carries material`);
      assert.equal(record.unresolved, undefined, label);
      for (const material of record.materials) {
        assert.ok(MATERIAL_KINDS.has(material.kind), `${label} material kind is labelled external`);
        assert.ok(material.sourcePath.startsWith(RUST_PREFIX), material.sourcePath);
        assert.ok(!boundPaths.has(material.sourcePath), `${material.sourcePath} bound once`);
        boundPaths.add(material.sourcePath);
        assert.match(material.describes, /external to the archive/u, `${label} material is described as external`);
        assert.equal(material.normalization, "append-terminal-lf-v1");
        assert.match(material.sha256, SHA256); assert.match(material.upstreamSHA256, SHA256);
        const origin = new URL(material.origin);
        assert.equal(origin.protocol, "https:"); assert.equal(origin.host, "github.com"); assert.equal(origin.search, "");
        const pinned = /^\/([^/]+)\/([^/]+)\/blob\/([a-f0-9]{40})\/(.+)$/u.exec(origin.pathname);
        assert.ok(pinned, `${material.sourcePath} origin is commit-pinned`);
        if (material.kind === "external-upstream-file") {
          assert.equal(`https://github.com/${pinned[1]}/${pinned[2]}`, record.connection.repository, `${label} upstream material comes from the connected repository`);
          assert.equal(pinned[3], record.connection.revision, `${label} upstream material comes from the connected revision, not a later branch`);
        } else {
          assert.equal(`${pinned[1]}/${pinned[2]}`, "spdx/license-list-data", `${label} SPDX text origin`);
          assert.equal(pinned[4], `text/${record.licenseExpression}.txt`, `${label} SPDX text matches the licence expression`);
          assert.ok(record.archiveNotice, `${label} an SPDX text may only stand in for a licence the archive itself designates`);
        }
        const bytes = await readFile(join(root, material.sourcePath));
        assert.equal(bytes.byteLength, material.size, `${material.sourcePath} tracked bytes size`);
        assert.equal(digest(bytes), material.sha256, `${material.sourcePath} tracked bytes digest`);
        assert.equal(bytes[bytes.byteLength - 1], 0x0a, material.sourcePath);
        assert.equal(digest(bytes.subarray(0, bytes.byteLength - 1)), material.upstreamSHA256, `${material.sourcePath} equals the upstream bytes plus one LF`);
        assert.equal(bytes.byteLength - 1, material.upstreamSize, material.sourcePath);
        assert.ok(!bytes.includes(0x0d) && !bytes.includes(0x00), material.sourcePath);
        assert.match(bytes.toString("utf8"), /licen[cs]e|permission/iu, `${material.sourcePath} reads as a licence text`);
      }
      if (record.archiveNotice) {
        assert.match(record.archiveNotice.member, new RegExp(`^${record.crateName}-${record.crateVersion.replaceAll(".", "\\.")}/`, "u"));
        assert.match(record.archiveNotice.memberSHA256, SHA256);
        assert.match(record.archiveNotice.text, /^\/\* This Source Code Form is subject to the terms of the Mozilla Public\n \* License, v\. 2\.0\./u);
        assert.match(record.archiveNotice.note, /archive-contained/u);
      }
    } else {
      assert.deepEqual(record.materials, [], `${label} unresolved records bind no material`);
      assert.ok(record.unresolved.missingEvidence.length >= 80, label);
      assert.match(record.unresolved.missingEvidence, /none is asserted/u, `${label} asserts nothing it cannot show`);
      assert.ok(record.unresolved.checksPerformed.length >= 4, label);
      assert.ok(record.unresolved.checksPerformed.some(({ check }) => /tag|revision/u.test(check)), label);
      assert.ok(record.unresolved.checksPerformed.some(({ check }) => /crate archive/u.test(check)), label);
      assert.ok(typeof record.unresolved.fallbackUsed === "string" && record.unresolved.fallbackUsed.length >= 20, label);
      assert.equal(record.archiveNotice, undefined, label);
    }
  }
  const files = (await readdir(join(root, RUST_PREFIX.slice(0, -1)))).map((name) => `${RUST_PREFIX}${name}`).sort();
  assert.deepEqual(files, [...boundPaths].sort(), "every tracked Rust notice file is bound and nothing unbound is present");
  return manifest;
}

test("rust notice materials manifest binds version-bound external material or a precise unresolved record for every crate without archive licence text", async () => {
  const manifest = await validate(project);
  assert.deepEqual(manifest.summary, {
    established: ["mutants 0.0.4", "selectors 0.38.0"],
    unresolved: ["block 0.1.6", "malloc_buf 0.0.6", "objc-foundation 0.1.1", "objc_id 0.1.1"]
  });
  const mutants = manifest.records.find(({ crateName }) => crateName === "mutants");
  assert.equal(mutants.connection.revision, "14011d08c42a7cd368698fe28f77eb4cd0b65bf0");
  assert.match(await readFile(join(project, mutants.materials[0].sourcePath), "utf8"), /^MIT License\n\nCopyright \(c\) 2021 Martin Pool\n/u);
  const selectors = manifest.records.find(({ crateName }) => crateName === "selectors");
  assert.equal(selectors.connection.revision, "572ecba2d1600e7c3d490586692a209faf703baa");
  assert.match(await readFile(join(project, selectors.materials[0].sourcePath), "utf8"), /^Mozilla Public License Version 2\.0\n/u);
  for (const name of ["block", "malloc_buf", "objc-foundation", "objc_id"]) {
    const record = manifest.records.find(({ crateName }) => crateName === name);
    assert.equal(record.status, "unresolved", name);
    assert.match(record.unresolved.missingEvidence, /Steven Sheldon/u, `${name} names the only authorship evidence that exists without inventing a copyright line`);
  }
  // The original per-crate archive digests and the 29-component notices are untouched.
  const provenance = JSON.parse(await readFile(join(project, "Config", "SharpLibvipsRustProvenance.json"), "utf8"));
  assert.equal(provenance.items.filter(({ noticeStatus }) => noticeStatus === "no-licence-text-in-crate").length, 6);
  const binary = JSON.parse(await readFile(join(project, "Config", "ThirdPartyBinaryProvenance.json"), "utf8")).components[0];
  assert.equal(binary.componentNotices.length, 29);
  assert.equal(binary.obligations.find(({ id }) => id === "corresponding-source").status, "open");
  assert.equal(binary.obligations.find(({ id }) => id === "legal-clearance").status, "open");
});

async function privateCopy() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-rust-notice-materials.")));
  await mkdir(join(root, "Config"), { mode: 0o700 });
  for (const name of ["SharpLibvipsRustNoticeMaterials.json", "SharpLibvipsRustProvenance.json", "ThirdPartyBinaryProvenance.json"]) {
    await cp(join(project, "Config", name), join(root, "Config", name));
  }
  await cp(join(project, RUST_PREFIX.slice(0, -1)), join(root, RUST_PREFIX.slice(0, -1)), { recursive: true });
  const manifestPath = join(root, "Config", "SharpLibvipsRustNoticeMaterials.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  return { root, manifest, save: () => writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`) };
}

const cases = [
    {
      name: "tracked material bytes drifted",
      mutate: async ({ root }) => writeFile(join(root, RUST_PREFIX, "mutants-0.0.4-external-cargo-mutants-LICENSE"), "MIT License\n\nCopyright (c) 2021 Somebody Else\n"),
      message: /tracked bytes/u
    },
    {
      name: "tracked material missing",
      mutate: async ({ root }) => rm(join(root, RUST_PREFIX, "selectors-0.38.0-external-spdx-3.28.0-MPL-2.0.txt")),
      message: /ENOENT|no such file/u
    },
    {
      name: "material origin points at a later revision than the crate was packaged from",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "mutants");
        record.materials[0].origin = "https://github.com/sourcefrog/cargo-mutants/blob/ffffffffffffffffffffffffffffffffffffffff/LICENSE";
        await copy.save();
      },
      message: /comes from the connected revision, not a later branch/u
    },
    {
      name: "material origin points at a different repository",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "mutants");
        record.materials[0].origin = "https://github.com/someone-else/cargo-mutants/blob/14011d08c42a7cd368698fe28f77eb4cd0b65bf0/LICENSE";
        await copy.save();
      },
      message: /comes from the connected repository/u
    },
    {
      name: "material origin on a mutable branch",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "mutants");
        record.materials[0].origin = "https://github.com/sourcefrog/cargo-mutants/blob/main/LICENSE";
        await copy.save();
      },
      message: /origin is commit-pinned/u
    },
    {
      name: "SPDX text substituted for a licence the archive does not designate",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "selectors");
        delete record.archiveNotice;
        await copy.save();
      },
      message: /may only stand in for a licence the archive itself designates/u
    },
    {
      name: "SPDX text for a different licence than the crate declares",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "selectors");
        record.materials[0].origin = "https://github.com/spdx/license-list-data/blob/c4a7237ec8f4654e867546f9f409749300f1bf4c/text/MIT.txt";
        await copy.save();
      },
      message: /SPDX text matches the licence expression/u
    },
    {
      name: "material described as if it were an archive member",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "mutants");
        record.materials[0].describes = "MIT licence member of the crate archive";
        await copy.save();
      },
      message: /described as external/u
    },
    {
      name: "record bound to a different crate archive digest",
      mutate: async (copy) => {
        copy.manifest.records.find(({ crateName }) => crateName === "block").crateSHA256 = "0".repeat(64);
        await copy.save();
      },
      message: /bound to the pinned crate archive digest/u
    },
    {
      name: "unresolved record silently upgraded without material",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "block");
        record.status = "established";
        copy.manifest.summary.established.push("block 0.1.6");
        copy.manifest.summary.unresolved = copy.manifest.summary.unresolved.filter((entry) => entry !== "block 0.1.6");
        await copy.save();
      },
      message: /carries material/u
    },
    {
      name: "a crate without archive licence text dropped from the manifest",
      mutate: async (copy) => {
        copy.manifest.records = copy.manifest.records.filter(({ crateName }) => crateName !== "objc_id");
        await copy.save();
      },
      message: /exactly the crates without archive licence text are covered/u
    },
    {
      name: "unbound file under the Rust notice directory",
      mutate: async ({ root }) => writeFile(join(root, RUST_PREFIX, "stray-LICENSE"), "MIT License\n"),
      message: /nothing unbound is present/u
    },
    {
      name: "unresolved record with invented certainty",
      mutate: async (copy) => {
        const record = copy.manifest.records.find(({ crateName }) => crateName === "malloc_buf");
        record.unresolved.missingEvidence = "The MIT licence obviously applies with copyright Steven Sheldon; treat as resolved for release purposes and nothing further is needed here at all.";
        await copy.save();
      },
      message: /asserts nothing it cannot show/u
    }
];

test("missing or drifted material bytes, misattributed origins and unbound files are rejected", async (context) => {
  for (const current of cases) {
    await context.test(current.name, async () => {
      const copy = await privateCopy();
      try {
        await current.mutate(copy);
        await assert.rejects(() => validate(copy.root), current.message, current.name);
      } finally {
        await rm(copy.root, { recursive: true, force: true });
      }
    });
  }
});

// The materials tool carries its own verifier for the same manifest (used by
// acquire/verify --notice-materials, the notice generator and the delivery
// staging tool). It must accept the real tree and reject every drift above.
async function loadWithTool(root) {
  const crateManifest = await loadManifest(join(root, "Config", "SharpLibvipsRustProvenance.json"));
  return loadRustNoticeMaterials(join(root, "Config", "SharpLibvipsRustNoticeMaterials.json"), crateManifest.manifest, crateManifest.manifestPath);
}

test("the materials tool's notice-material verifier accepts the real tree and rejects the same drift as the pure validator", async (context) => {
  const loaded = await loadWithTool(project);
  assert.equal(loaded.relativePath, "Config/SharpLibvipsRustNoticeMaterials.json");
  assert.equal(loaded.sha256, digest(await readFile(join(project, "Config", "SharpLibvipsRustNoticeMaterials.json"))));
  assert.deepEqual(loaded.summary, {
    established: ["mutants 0.0.4", "selectors 0.38.0"],
    unresolved: ["block 0.1.6", "malloc_buf 0.0.6", "objc-foundation 0.1.1", "objc_id 0.1.1"]
  });
  assert.deepEqual(loaded.records.map(({ identity, status }) => `${identity}:${status}`),
    ["block 0.1.6:unresolved", "malloc_buf 0.0.6:unresolved", "mutants 0.0.4:established", "objc-foundation 0.1.1:unresolved", "objc_id 0.1.1:unresolved", "selectors 0.38.0:established"]);
  const mutants = loaded.records.find(({ crateName }) => crateName === "mutants");
  assert.equal(mutants.materials[0].kind, "external-upstream-file");
  assert.match(mutants.materials[0].text, /^MIT License\n\nCopyright \(c\) 2021 Martin Pool\n/u);
  const selectors = loaded.records.find(({ crateName }) => crateName === "selectors");
  assert.equal(selectors.archiveNotice.member, "selectors-0.38.0/lib.rs");
  assert.equal(selectors.materials[0].kind, "external-spdx-licence-text");
  assert.match(selectors.materials[0].text, /^Mozilla Public License Version 2\.0\n/u);
  for (const record of loaded.records.filter(({ status }) => status === "unresolved")) {
    assert.deepEqual(record.materials, [], record.identity);
    assert.match(record.unresolved.missingEvidence, /none is asserted/u, record.identity);
  }
  const toolMessages = {
    "tracked material bytes drifted": /tracked material (?:size|SHA-256) drifted/u,
    "tracked material missing": /ENOENT|no such file/u,
    "material origin points at a later revision than the crate was packaged from": /must come from the connected repository at the connected revision/u,
    "material origin points at a different repository": /must come from the connected repository at the connected revision/u,
    "material origin on a mutable branch": /must be pinned to one full commit/u,
    "SPDX text substituted for a licence the archive does not designate": /may only stand in for a licence the archive itself designates/u,
    "SPDX text for a different licence than the crate declares": /must be the text of the crate's own licence expression/u,
    "material described as if it were an archive member": /must be described as external to the archive/u,
    "record bound to a different crate archive digest": /not bound to the pinned crate archive digest/u,
    "unresolved record silently upgraded without material": /established record cannot carry an unresolved record|must bind one to/u,
    "a crate without archive licence text dropped from the manifest": /must cover exactly the crates without archive licence text/u,
    "unbound file under the Rust notice directory": /unbound entry beside the tracked Rust notice material/u,
    "unresolved record with invented certainty": /must assert nothing it cannot show/u
  };
  assert.deepEqual(Object.keys(toolMessages).sort(), cases.map(({ name }) => name).sort(), "every pure-validator case has a tool expectation");
  for (const current of cases) {
    await context.test(`tool: ${current.name}`, async () => {
      const copy = await privateCopy();
      try {
        await current.mutate(copy);
        await assert.rejects(() => loadWithTool(copy.root), toolMessages[current.name], current.name);
      } finally {
        await rm(copy.root, { recursive: true, force: true });
      }
    });
  }
});
