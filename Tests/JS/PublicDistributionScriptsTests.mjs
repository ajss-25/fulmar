import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { rootWatchdogChildOptions } from "./RootWatchdogChildProcess.mjs";
import { readAttestedRegularFile } from "../../scripts/attested-regular-file.mjs";

const root = process.cwd();
const verifier = join(root, "scripts", "verify-public-distribution.sh");
const preparer = join(root, "scripts", "prepare-public-release-assets.sh");
const externalEvidenceVerifier = join(root, "scripts", "verify-public-external-evidence.mjs");
const snapshotter = join(root, "scripts", "snapshot-regular-file.mjs");
const xpcInfoVerifier = join(root, "scripts", "verify-xpc-service-info.mjs");
const publicAssetPublisherSource = join(root, "Tools", "PublicAssetPublisher", "main.c");
const cleanCICandidatePolicy = process.env.FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS ?? "0";
if (!new Set(["0", "1"]).has(cleanCICandidatePolicy)) {
  throw new Error("FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS must be 0 or 1");
}
const payloadAssetNames = Object.freeze([
  "Fulmar.app.zip",
  "Fulmar.dSYMs.zip",
  "LICENSE",
  "release-manifest.json",
  "static-security-summary.json",
  "LocalHarness.sbom.cdx.json",
  "THIRD_PARTY_NOTICES.md"
]);
const checksumAssetNames = Object.freeze([
  "Fulmar.app.zip",
  "Fulmar.app.zip.sha256",
  "Fulmar.dSYMs.zip",
  "LICENSE",
  "LocalHarness.sbom.cdx.json",
  "THIRD_PARTY_NOTICES.md",
  "release-manifest.json",
  "static-security-summary.json"
]);
const packageAssetNames = Object.freeze([...checksumAssetNames, "SHA256SUMS.txt"]);
const publicExternalGateNames = Object.freeze([
  "cleanInstallCurrentMacOS",
  "cleanInstallMinimumMacOS",
  "fullGitHistoryAndSecretScan",
  "githubRepositoryControls",
  "legalAndTrademarkClearance",
  "permissionAndAccessibilityMatrix",
  "supportPrivacyAndExportReview",
  "twoVersionNotarizedUpdateRollback"
]);

async function sha(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function makePublisherStage(parent, name, marker) {
  const stage = join(parent, name);
  await mkdir(stage, { mode: 0o700 });
  await chmod(stage, 0o700);
  for (const assetName of packageAssetNames) {
    await writeFile(join(stage, assetName), `${marker}:${assetName}\n`, { mode: 0o644 });
    await chmod(join(stage, assetName), 0o644);
  }
  return stage;
}

function runChild(executable, arguments_) {
  return new Promise((resolve) => {
    const child = spawn(executable, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

async function writeSyntheticPackage(directory, {
  sidecarDigest,
  checksumName = (name) => name,
  checksumDigest = async (name) => await sha(join(directory, name))
} = {}) {
  for (const name of payloadAssetNames) await writeFile(join(directory, name), name, { mode: 0o644 });
  const archiveDigest = sidecarDigest ?? await sha(join(directory, "Fulmar.app.zip"));
  await writeFile(
    join(directory, "Fulmar.app.zip.sha256"),
    `${archiveDigest}  Fulmar.app.zip\n`,
    { mode: 0o644 }
  );
  const lines = [];
  for (const name of checksumAssetNames) {
    lines.push(`${await checksumDigest(name)}  ${checksumName(name)}`);
  }
  await writeFile(join(directory, "SHA256SUMS.txt"), `${lines.join("\n")}\n`, { mode: 0o644 });
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [...packageAssetNames].sort(),
    "synthetic fixture contains the exact nine production assets"
  );
}

function assertTargetedRejection(result, target) {
  const output = `${result.stdout}\n${result.stderr}`;
  assert.notEqual(result.status, 0);
  assert.match(output, target);
  assert.doesNotMatch(output, /must contain exactly the nine reviewed release assets/u);
  assert.doesNotMatch(output, /Public verification requires timestamped Developer ID Application/u);
}

function unavailableCandidateFixture(context, reason, required = cleanCICandidatePolicy === "1") {
  if (required) {
    assert.fail(`Clean CI requires the current candidate-dependent public-distribution test: ${reason}`);
  }
  context.skip(reason);
}

test("clean CI candidate policy fails instead of silently skipping a missing or stale release fixture", () => {
  const skipped = [];
  unavailableCandidateFixture({ skip: (reason) => skipped.push(reason) }, "fixture absent", false);
  assert.deepEqual(skipped, ["fixture absent"]);
  assert.throws(
    () => unavailableCandidateFixture({ skip: () => assert.fail("must not skip") }, "fixture stale", true),
    /Clean CI requires the current candidate-dependent public-distribution test: fixture stale/u
  );
});

test("public distribution scripts pin every Apple trust and immutable-asset gate", async () => {
  assert.equal(packageAssetNames.length, 9, "the public package has nine top-level assets");
  assert.equal(checksumAssetNames.length, 8, "SHA256SUMS authenticates the other eight assets");
  const [prepare, verify, operator, makefile, readme, guide, readiness] = await Promise.all([
    readFile(join(root, "scripts", "prepare-public-release-assets.sh"), "utf8"),
    readFile(verifier, "utf8"),
    readFile(join(root, "scripts", "run-public-release.sh"), "utf8"),
    readFile(join(root, "Makefile"), "utf8"),
    readFile(join(root, "README.md"), "utf8"),
    readFile(join(root, "docs", "PUBLIC_INSTALLATION.md"), "utf8"),
    readFile(join(root, "docs", "PUBLIC_RELEASE_READINESS.md"), "utf8")
  ]);
  assert.match(prepare, /verify-release-manifest\.mjs/u);
  assert.match(prepare, /snapshot-regular-file\.mjs/u);
  assert.match(prepare, /verify-sbom\.mjs/u);
  assert.match(prepare, /generate-third-party-notices\.mjs/u);
  assert.match(prepare, /verify-macho-compatibility\.sh/u);
  assert.match(prepare, /Fulmar\.app\.zip\.sha256/u);
  assert.match(prepare, /SHA256SUMS\.txt/u);
  assert.match(prepare, /first-party-license-policy\.mjs/u);
  assert.match(prepare, /--require-selected/u);
  assert.match(prepare, /source-build-input-inventory\.mjs/u);
  assert.match(prepare, /verify-dependency-audit\.mjs/u);
  assert.match(prepare, /verify-retained-release-evidence\.mjs/u);
  assert.match(prepare, /verify-static-security-summary\.mjs/u);
  assert.match(prepare, /static-security-summary\.json/u);
  assert.match(prepare, /"\$PUBLIC_STAGING\/LICENSE"/u);
  assert.match(prepare, /Prepared public package did not contain exactly nine assets/u);
  assert.match(prepare, /Prepared public package contains an unsafe asset/u);
  assert.match(prepare, /\.\$\{OUTPUT_NAME\}\.staging\.XXXXXX/u);
  assert.match(prepare, /fulmar-public-asset-publisher/u);
  assert.match(prepare, /EXPECTED_CANDIDATE_SHA256="\$\{4:-\}"/u);
  assert.match(prepare, /verify_expected_candidate_binding[\s\S]*archive_sha256[\s\S]*EXPECTED_CANDIDATE_SHA256/u);
  assert.equal(prepare.match(/verify_expected_candidate_binding "\$MANIFEST" "\$ARCHIVE"/gu)?.length, 2,
    "the live candidate must be bound before snapshot and immediately before publish");
  assert.match(prepare, /snapshot-regular-file\.mjs" "\$MANIFEST" "\$MANIFEST_SNAPSHOT" 1048576 >\/dev\/null\nverify_expected_candidate_binding "\$MANIFEST_SNAPSHOT" "\$ARCHIVE_SNAPSHOT"/u);
  assert.match(prepare, /"\$ATOMIC_PUBLISHER" publish "\$OUTPUT_PARENT" "\$\{PUBLIC_STAGING:t\}" "\$OUTPUT_NAME"/u);
  assert.match(prepare, /verify_expected_candidate_binding "\$MANIFEST" "\$ARCHIVE"\n"\$ATOMIC_PUBLISHER" publish/u);
  assert.ok(prepare.indexOf('"$ATOMIC_PUBLISHER" publish') > prepare.lastIndexOf("verify-retained-release-evidence.mjs"),
    "the private sibling must be published only after the final retained-evidence recheck");
  assert.doesNotMatch(prepare, /mkdir -m 0755 "\$OUTPUT"/u);
  assert.match(verify, /codesign --verify --deep --strict/u);
  assert.match(verify, /Authority=Developer ID Application:/u);
  assert.match(verify, /TeamIdentifier=/u);
  assert.match(verify, /Timestamp=/u);
  assert.match(verify, /target_details[\s\S]*flags=/u);
  assert.match(verify, /target_details[\s\S]*Timestamp=/u);
  assert.match(verify, /assert_exact_entitlements/u);
  assert.match(verify, /Resources\/LocalHarness\.entitlements/u);
  assert.match(verify, /Resources\/NodeRuntime\.entitlements/u);
  assert.match(verify, /assert_no_entitlements/u);
  assert.match(verify, /PRODUCT_BUNDLE_ID\.credential-helper/u);
  assert.match(verify, /PRODUCT_BUNDLE_ID\.scheduler-helper/u);
  assert.match(verify, /PRODUCT_BUNDLE_ID\.update-helper/u);
  assert.match(verify, /PRODUCT_BUNDLE_ID\.sandbox-runner/u);
  assert.match(verify, /PRODUCT_BUNDLE_ID\.runtime-lease/u);
  assert.match(verify, /stapler validate/u);
  assert.match(verify, /spctl --assess --type execute/u);
  assert.match(verify, /snapshot-regular-file\.mjs/u);
  assert.match(verify, /snapshot-regular-file\.mjs" \\\n+  "\$PROJECT_DIR\/build\/release-manifest\.json" "\$REVIEWED_MANIFEST"/u);
  assert.match(verify, /cmp -s "\$SNAPSHOT\/release-manifest\.json" "\$REVIEWED_MANIFEST"/u);
  assert.match(verify, /verify-sbom\.mjs/u);
  assert.match(verify, /generate-third-party-notices\.mjs/u);
  assert.match(verify, /verify-macho-compatibility\.sh/u);
  const topologyIndex = verify.indexOf("verify-zip-entries.mjs");
  const extractionIndex = verify.indexOf("ditto -x");
  assert.ok(topologyIndex >= 0 && topologyIndex < extractionIndex, "ZIP topology must be checked before extraction");
  assert.match(verify, /must contain exactly the nine reviewed release assets/u);
  assert.match(verify, /first-party-license-policy\.mjs/u);
  assert.match(verify, /source-build-input-inventory\.mjs/u);
  assert.match(verify, /verify-dependency-audit\.mjs/u);
  assert.match(verify, /verify-retained-release-evidence\.mjs/u);
  assert.match(verify, /verify-static-security-summary\.mjs/u);
  assert.match(verify, /Public package static-security evidence is not the exact locally reviewed summary/u);
  assert.match(verify, /verify-notarization-evidence\.mjs/u);
  assert.match(verify, /verify-public-external-evidence\.mjs/u);
  assert.match(verify, /public-external-evidence\.json/u);
  assert.ok(
    verify.lastIndexOf("verify-public-external-evidence.mjs")
      < verify.lastIndexOf("Public distribution verification passed"),
    "external evidence must pass before public-distribution success is published"
  );
  assert.match(verify, /verify-bundle/u);
  assert.match(verify, /"\$SNAPSHOT\/LICENSE" "\$APP\/Contents\/Resources\/LICENSE"/u);
  assert.match(verify, /shasum -a 256 -c Fulmar\.app\.zip\.sha256/u);
  assert.match(verify, /SHA256SUMS\.txt has unexpected or unsafe entries/u);
  assert.match(readme, /docs\/PUBLIC_INSTALLATION\.md/u);
  assert.match(guide, /shasum -a 256 -c Fulmar\.app\.zip\.sha256/u);
  assert.match(guide, /exact nine-asset release set/u);
  assert.match(guide, /app\.localharness\.credentials/u);
  assert.match(guide, /com\.angadjairath\.localharness\.backup-authentication/u);
  assert.match(guide, /Saved Application State\/com\.angadjairath\.localharness\.savedState/u);
  assert.match(guide, /Privacy & Security/u);
  assert.match(guide, /Login Items & Extensions/u);
  assert.match(guide, /\.ollama` is shared, Ollama-owned model storage and is \*\*never part of Fulmar/u);
  assert.match(guide, /does \*\*not\*\* automatically remove/u);
  assert.match(makefile, /^public-external-evidence-verify: frozen-candidate-check$/mu);
  assert.match(makefile, /public-external-evidence\.json/u);
  assert.match(makefile, /^public-release: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh$/mu);
  assert.match(makefile, /^public-release-finalize: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh --finalize$/mu);
  assert.match(operator, /LOCAL_HARNESS_SIGN_IDENTITY with the exact Developer ID Application certificate name/u);
  assert.match(operator, /LOCAL_HARNESS_SIGNING_KEYCHAIN with the absolute signing-Keychain path/u);
  assert.match(operator, /LOCAL_HARNESS_NOTARY_PROFILE with an Apple notarytool Keychain profile/u);
  assert.match(operator, /LOCAL_HARNESS_SIGN_TIMESTAMP:-1/u);
  assert.match(operator, /LOCAL_HARNESS_SIGN_TIMESTAMP=1/u);
  assert.match(operator, /security find-identity -v -p codesigning/u);
  assert.match(operator, /IDENTITY_MATCHES == 1/u);
  assert.match(operator, /retain-release-verification\.sh/u);
  assert.match(operator, /verify-retained-release-evidence\.mjs/u);
  assert.match(operator, /verify-notarization-evidence\.mjs/u);
  assert.match(operator, /verify-release-tree\.mjs/u);
  assert.match(operator, /xcrun stapler validate "\$archived_app"/u);
  assert.match(operator, /complete the eight manual gates[\s\S]*make public-release-finalize[\s\S]*Do not rebuild/u);
  assert.match(operator, /prepare-public-release-assets\.sh" \\\n+    "\$ARCHIVE" "\$MANIFEST" "\$PUBLIC_ASSETS" \\\n+    "\$CANDIDATE_SHA256" "\$CANDIDATE_VERSION" "\$CANDIDATE_BUILD"/u);
  assert.match(operator, /\/private\/tmp\/fulmar-public-release-test\.\*[/\s\S]*test-support\/run-public-release-test-seam\.zsh/u);
  assert.ok(operator.indexOf("run_public_build") < operator.lastIndexOf("verify_public_candidate"));
  assert.ok(operator.lastIndexOf("verify_public_candidate") < operator.lastIndexOf("verify-public-external-evidence.mjs"));
  assert.ok(operator.lastIndexOf("verify-public-external-evidence.mjs") < operator.lastIndexOf("prepare-public-release-assets.sh"));
  assert.ok(operator.lastIndexOf("prepare-public-release-assets.sh") < operator.lastIndexOf("verify-public-distribution.sh"));
  assert.doesNotMatch(operator, /(?:\bgh[ \t]+release\b|\/usr\/bin\/curl|\bupload[ \t]+[^.]*asset)/u,
    "the operator must qualify but never publish");
  assert.match(readiness, /make public-external-evidence-verify/u);
  assert.match(readiness, /cleanInstallCurrentMacOS/u);
  assert.match(readiness, /twoVersionNotarizedUpdateRollback/u);

  const temporary = await mkdtemp("/private/tmp/fulmar-public-external-evidence.");
  try {
    await chmod(temporary, 0o700);
    const evidencePath = join(temporary, "public-external-evidence.json");
    const candidateSHA = "a".repeat(64);
    const version = "9.8.7";
    const build = 987;
    const validEvidence = () => ({
      schemaVersion: 1,
      evidenceType: "fulmar-public-external-evidence",
      version,
      build,
      candidate: { sha256: candidateSHA },
      allRequiredGatesPassed: true,
      gates: Object.fromEntries(publicExternalGateNames.map((gate) => [gate, {
        status: "passed",
        evidenceSHA256: createHash("sha256").update(`evidence:${gate}`).digest("hex"),
        reference: `private-review/${gate}.json`
      }]))
    });
    const writeEvidence = async (value, mode = 0o600) => {
      await writeFile(evidencePath, `${JSON.stringify(value)}\n`, { mode });
      await chmod(evidencePath, mode);
    };
    const runEvidenceVerifier = (sha256 = candidateSHA, expectedVersion = version, expectedBuild = build) =>
      spawnSync(process.execPath, [
        externalEvidenceVerifier, evidencePath, sha256, expectedVersion, String(expectedBuild)
      ], { cwd: root, encoding: "utf8", timeout: 5_000 });

    await writeEvidence(validEvidence());
    let result = runEvidenceVerifier();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /complete and candidate-bound across all 8 external gates/u);

    // The stable contract is the default invocation and never accepts the
    // separately identifiable beta profile's evidence, however complete.
    const betaShaped = validEvidence();
    betaShaped.evidenceType = "fulmar-public-beta-external-evidence";
    await writeEvidence(betaShaped);
    result = runEvidenceVerifier();
    assert.notEqual(result.status, 0, "stable must refuse beta-typed evidence");
    assert.match(result.stderr, /belongs to another release profile; the stable profile refuses it/u);
    const profileLabelled = validEvidence();
    profileLabelled.releaseProfile = "beta";
    await writeEvidence(profileLabelled);
    result = runEvidenceVerifier();
    assert.notEqual(result.status, 0, "stable must refuse a beta-labelled record");
    assert.match(result.stderr, /belongs to another release profile/u);

    for (const missingGate of publicExternalGateNames) {
      const fixture = validEvidence();
      delete fixture.gates[missingGate];
      await writeEvidence(fixture);
      result = runEvidenceVerifier();
      assert.notEqual(result.status, 0, `missing ${missingGate} must fail closed`);
      assert.match(result.stderr, /public external evidence is incomplete/u, missingGate);
    }

    await writeEvidence(validEvidence());
    for (const [label, arguments_] of [
      ["candidate SHA", ["b".repeat(64), version, build]],
      ["version", [candidateSHA, "9.8.8", build]],
      ["build", [candidateSHA, version, build + 1]]
    ]) {
      result = runEvidenceVerifier(...arguments_);
      assert.notEqual(result.status, 0, `stale ${label} must fail closed`);
      assert.match(result.stderr, /public external evidence is stale/u, label);
    }

    for (const [label, mutate, rejection] of [
      ["non-passing gate", (value) => { value.gates.cleanInstallCurrentMacOS.status = "deferred"; }, /not closed/u],
      ["placeholder digest", (value) => { value.gates.cleanInstallCurrentMacOS.evidenceSHA256 = "0".repeat(64); }, /not closed/u],
      ["missing record field", (value) => { delete value.gates.cleanInstallCurrentMacOS.reference; }, /not closed/u],
      ["extra record field", (value) => { value.gates.cleanInstallCurrentMacOS.note = "unreviewed"; }, /not closed/u],
      ["extra top-level field", (value) => { value.unreviewed = true; }, /incomplete/u]
    ]) {
      const fixture = validEvidence();
      mutate(fixture);
      await writeEvidence(fixture);
      result = runEvidenceVerifier();
      assert.notEqual(result.status, 0, `${label} must fail closed`);
      assert.match(result.stderr, rejection, label);
    }

    await writeEvidence(validEvidence(), 0o644);
    result = runEvidenceVerifier();
    assert.notEqual(result.status, 0, "non-private evidence must fail closed");
    assert.match(result.stderr, /not owner-private/u);

    await writeEvidence(validEvidence());
    const secondLink = join(temporary, "second-link.json");
    await link(evidencePath, secondLink);
    result = runEvidenceVerifier();
    assert.notEqual(result.status, 0, "hard-linked evidence must fail closed");
    assert.match(result.stderr, /must not be hard linked/u);
    await rm(secondLink);

    await rm(evidencePath);
    result = runEvidenceVerifier();
    assert.notEqual(result.status, 0, "missing evidence must fail closed");
    assert.match(result.stderr, /public external evidence is missing/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("notarized assembly retains and validates Apple's structured receipt and issue log", async () => {
  const [build, operator] = await Promise.all([
    readFile(join(root, "scripts", "build-app.sh"), "utf8"),
    readFile(join(root, "scripts", "run-public-release.sh"), "utf8")
  ]);
  assert.match(build, /LOCAL_HARNESS_SIGN_TIMESTAMP must be 0, 1, or auto/u);
  assert.match(build, /Notarization requires LOCAL_HARNESS_SIGN_IDENTITY to select a Developer ID Application certificate/u);
  assert.match(build, /Notarized Developer ID builds cannot disable the required secure timestamp/u);
  assert.match(build, /-n "\$\{LOCAL_HARNESS_NOTARY_PROFILE:-\}"[\s\S]*SIGN_ARGS\+=\(--timestamp\)/u);
  assert.match(build, /notarytool submit[\s\S]*--wait --timeout 2h --no-progress --output-format json/u);
  assert.match(build, /notarization-submission\.json/u);
  assert.match(build, /value\.status !== "Accepted"/u);
  assert.match(build, /notarytool log "\$NOTARY_SUBMISSION_ID"/u);
  assert.match(build, /notarization-log\.json/u);
  assert.match(build, /verify-notarization-evidence\.mjs/u);
  assert.match(build, /value\.jobId !== expectedID/u);
  assert.match(build, /value\.issues === null/u);
  assert.match(build, /Array\.isArray\(value\.issues\) && value\.issues\.length === 0/u);
  const submit = build.indexOf("notarytool submit");
  const log = build.indexOf('notarytool log "$NOTARY_SUBMISSION_ID"');
  const staple = build.indexOf('stapler staple "$APP_DIR"');
  const finalArchive = build.lastIndexOf('ditto -c -k --keepParent "$APP_DIR" "$ARCHIVE_PATH"');
  assert.ok(submit >= 0 && log > submit && staple > log && finalArchive > staple);

  const unconfigured = spawnSync("/bin/zsh", ["-f", join(root, "scripts", "run-public-release.sh")], {
    cwd: root,
    encoding: "utf8",
    timeout: 5_000,
    env: {
      HOME: process.env.HOME,
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      USER: process.env.USER,
      LOGNAME: process.env.LOGNAME,
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8"
    }
  });
  assert.equal(unconfigured.status, 64);
  assert.match(unconfigured.stderr, /requires LOCAL_HARNESS_SIGN_IDENTITY/u);
  assert.doesNotMatch(unconfigured.stderr, /notarytool|codesign|stapler/u,
    "missing authority must fail before any signing or Apple network operation");
  assert.match(operator, /retain_public_candidate\(\)[\s\S]*retain-release-verification\.sh/u);
  assert.match(operator, /if \[\[ "\$MODE" == "fresh" \]\]; then[\s\S]*run_public_build\n  retain_public_candidate/u);
  assert.match(operator, /else\n\s+print "Finalizing the retained public candidate without rebuilding it\."/u);

  const stateRoot = await mkdtemp("/private/tmp/fulmar-public-release-test.");
  const copiedOperator = join(stateRoot, "scripts", "run-public-release.sh");
  const seamPath = join(stateRoot, "test-support", "run-public-release-test-seam.zsh");
  const state = join(stateRoot, "test-state");
  const actionLog = join(state, "actions.log");
  const candidateA = "a".repeat(64);
  const candidateB = "b".repeat(64);
  const testIdentity = "Developer ID Application: Fulmar State Tests (AAAAAAAAAA)";
  const seam = String.raw`TEST_STATE="$PROJECT_DIR/test-state"
ACTION_LOG="$TEST_STATE/actions.log"
log_test_action() {
  print -r -- "$1" >> "$ACTION_LOG"
}
read_key_value() {
  local path="$1" expected="$2" name value
  while IFS='=' read -r name value; do
    if [[ "$name" == "$expected" ]]; then
      print -r -- "$value"
      return 0
    fi
  done < "$path"
  return 1
}
write_test_candidate() {
  local sha256="$1"
  /bin/mkdir -p "$APP" "$BUILD_DIR"
  print -r -- "archive:$sha256" > "$ARCHIVE"
  {
    print -r -- "sha256=$sha256"
    print -r -- "version=9.8.7"
    print -r -- "build=987"
  } > "$MANIFEST"
  print -r -- accepted > "$NOTARY_SUBMISSION"
  print -r -- accepted > "$NOTARY_LOG"
  /bin/chmod 0600 "$ARCHIVE" "$MANIFEST" "$NOTARY_SUBMISSION" "$NOTARY_LOG"
}
read_candidate_field() {
  read_key_value "$MANIFEST" "$1"
}
run_reviewed_node() {
  local script="$1"
  shift
  case "\${script:t}" in
    first-party-license-policy.mjs)
      log_test_action license
      ;;
    verify-public-external-evidence.mjs)
      local evidence="$1" expected_sha="$2" expected_version="$3" expected_build="$4"
      [[ -f "$evidence" && ! -L "$evidence" \
         && "$(read_key_value "$evidence" sha256)" == "$expected_sha" \
         && "$(read_key_value "$evidence" version)" == "$expected_version" \
         && "$(read_key_value "$evidence" build)" == "$expected_build" ]] || return 1
      log_test_action evidence
      ;;
    *)
      print -u2 "Unexpected public-release test Node command: \${script:t}"
      return 1
      ;;
  esac
}
run_static_scan() {
  log_test_action static-scan
}
run_public_build() {
  log_test_action build
  write_test_candidate "\${FULMAR_TEST_CANDIDATE_A}"
}
retain_public_candidate() {
  log_test_action retain
}
verify_public_candidate() {
  [[ -d "$APP" && ! -L "$APP" && -f "$ARCHIVE" && ! -L "$ARCHIVE" \
     && -f "$MANIFEST" && ! -L "$MANIFEST" \
     && -f "$NOTARY_SUBMISSION" && ! -L "$NOTARY_SUBMISSION" \
     && -f "$NOTARY_LOG" && ! -L "$NOTARY_LOG" ]] || return 1
  read_candidate_field sha256 >/dev/null
  read_candidate_field version >/dev/null
  read_candidate_field build >/dev/null
  log_test_action verify-candidate
}
run_clean_script() {
  local script="$1"
  shift
  case "\${script:t}" in
    prepare-public-release-assets.sh)
      local expected_sha="$4" expected_version="$5" expected_build="$6"
      log_test_action prepare
      if [[ -f "$TEST_STATE/swap-before-prepare" ]]; then
        write_test_candidate "\${FULMAR_TEST_CANDIDATE_B}"
      fi
      [[ "$(read_candidate_field sha256)" == "$expected_sha" \
         && "$(read_candidate_field version)" == "$expected_version" \
         && "$(read_candidate_field build)" == "$expected_build" ]] || {
        print -u2 "Public asset preparation rejected candidate drift from the operator-bound SHA, version, or build."
        return 1
      }
      [[ ! -e "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" ]] || return 1
      /bin/mkdir -m 0700 "$PUBLIC_ASSETS"
      print -r -- "$expected_sha" > "$PUBLIC_ASSETS/candidate-sha256"
      /bin/chmod 0600 "$PUBLIC_ASSETS/candidate-sha256"
      ;;
    verify-public-distribution.sh)
      log_test_action final-verify
      [[ -d "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" \
         && "$(<"$PUBLIC_ASSETS/candidate-sha256")" == "$(read_candidate_field sha256)" ]] || return 1
      run_reviewed_node "$PROJECT_DIR/scripts/verify-public-external-evidence.mjs" \
        "$PUBLIC_EXTERNAL_EVIDENCE" "$(read_candidate_field sha256)" \
        "$(read_candidate_field version)" "$(read_candidate_field build)"
      ;;
    *)
      print -u2 "Unexpected public-release test script command: \${script:t}"
      return 1
      ;;
  esac
}
`.replaceAll("\\${", "${");
  try {
    await chmod(stateRoot, 0o700);
    await Promise.all([
      mkdir(join(stateRoot, "scripts"), { recursive: true, mode: 0o700 }),
      mkdir(join(stateRoot, "test-support"), { recursive: true, mode: 0o700 }),
      mkdir(join(stateRoot, "Config"), { recursive: true, mode: 0o700 })
    ]);
    await copyFile(join(root, "scripts", "run-public-release.sh"), copiedOperator);
    await chmod(copiedOperator, 0o700);
    await writeFile(seamPath, seam, { mode: 0o600 });
    await chmod(seamPath, 0o600);
    await writeFile(join(stateRoot, "Config", "ReleaseIdentity.json"), "{}\n", { mode: 0o600 });

    const resetState = async () => {
      await rm(state, { recursive: true, force: true });
      await mkdir(join(state, "home"), { recursive: true, mode: 0o700 });
      await writeFile(join(state, "signing.keychain"), "test-only\n", { mode: 0o600 });
      await chmod(join(state, "signing.keychain"), 0o600);
    };
    const runOperator = (arguments_ = []) => spawnSync("/bin/zsh", ["-f", copiedOperator, ...arguments_], {
      cwd: stateRoot,
      encoding: "utf8",
      timeout: 5_000,
      env: {
        HOME: join(state, "home"),
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        USER: process.env.USER,
        LOGNAME: process.env.LOGNAME,
        LANG: "en_US.UTF-8",
        LC_CTYPE: "UTF-8",
        FULMAR_PUBLIC_RELEASE_TEST_SEAM: "1",
        FULMAR_TEST_CANDIDATE_A: candidateA,
        FULMAR_TEST_CANDIDATE_B: candidateB,
        LOCAL_HARNESS_SIGN_IDENTITY: testIdentity,
        LOCAL_HARNESS_SIGNING_KEYCHAIN: join(state, "signing.keychain"),
        LOCAL_HARNESS_NOTARY_PROFILE: "fulmar-state-test",
        LOCAL_HARNESS_SIGN_TIMESTAMP: "1"
      }
    });
    const writeEvidence = async (sha256) => {
      await writeFile(
        join(state, "build", "public-external-evidence.json"),
        `sha256=${sha256}\nversion=9.8.7\nbuild=987\n`,
        { mode: 0o600 }
      );
      await chmod(join(state, "build", "public-external-evidence.json"), 0o600);
    };
    const actions = async () => (await readFile(actionLog, "utf8")).trim().split("\n").filter(Boolean);

    await resetState();
    const fresh = runOperator();
    assert.equal(fresh.status, 78, `${fresh.stdout}\n${fresh.stderr}`);
    assert.match(fresh.stderr, /intentionally paused/u);
    assert.deepEqual(await actions(), ["license", "static-scan", "build", "retain", "verify-candidate"]);
    await writeEvidence(candidateA);
    const finalized = runOperator(["--finalize"]);
    assert.equal(finalized.status, 0, finalized.stderr);
    assert.match(finalized.stdout, /without rebuilding it[\s\S]*qualification passed/u);
    assert.equal((await actions()).filter((action) => action === "build").length, 1,
      "finalize must not rebuild the retained candidate");
    assert.ok((await actions()).includes("final-verify"), "final distribution verification must execute");

    await resetState();
    assert.equal(runOperator().status, 78);
    await writeEvidence(candidateB);
    const stale = runOperator(["--finalize"]);
    assert.equal(stale.status, 78, stale.stderr);
    assert.match(stale.stderr, /belongs to another candidate/u);
    assert.ok(!(await actions()).includes("prepare"), "stale evidence must fail before asset preparation");

    await resetState();
    await mkdir(join(state, "build", "public-release-assets"), { recursive: true, mode: 0o700 });
    const preexisting = runOperator();
    assert.equal(preexisting.status, 1, preexisting.stderr);
    assert.match(preexisting.stderr, /retained public asset set already exists/u);
    assert.ok(!(await actions()).includes("build"), "pre-existing assets must stop a fresh build");

    await resetState();
    assert.equal(runOperator().status, 78);
    await writeEvidence(candidateA);
    await writeFile(join(state, "swap-before-prepare"), "swap\n", { mode: 0o600 });
    const swapped = runOperator(["--finalize"]);
    assert.equal(swapped.status, 1, swapped.stderr);
    assert.match(swapped.stderr, /rejected candidate drift/u);
    await assert.rejects(stat(join(state, "build", "public-release-assets")), { code: "ENOENT" });
    assert.ok(!(await actions()).includes("final-verify"),
      "a swapped candidate must neither publish assets nor reach final verification");
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test("credential XPC Info.plists reject every unreviewed top-level and launch dictionary key", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-xpc-info-schema-"));
  try {
    const identityPath = join(root, "Config", "ReleaseIdentity.json");
    const migrationJSON = join(temporary, "migration.json");
    const brokerJSON = join(temporary, "broker.json");
    for (const [source, destination] of [
      [join(root, "Resources", "CredentialMigrationService-Info.plist"), migrationJSON],
      [join(root, "Resources", "CredentialBrokerService-Info.plist"), brokerJSON]
    ]) {
      const converted = spawnSync("/usr/bin/plutil", ["-convert", "json", "-o", destination, source], {
        cwd: root, encoding: "utf8", timeout: 2_000
      });
      assert.equal(converted.status, 0, converted.stderr);
    }
    const accepted = spawnSync(process.execPath, [
      xpcInfoVerifier, identityPath, migrationJSON, brokerJSON
    ], { cwd: root, encoding: "utf8", timeout: 2_000 });
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /exact top-level and XPCService dictionaries/u);

    const pristineMigration = JSON.parse(await readFile(migrationJSON, "utf8"));
    const pristineBroker = JSON.parse(await readFile(brokerJSON, "utf8"));
    assert.equal(pristineMigration.XPCService.JoinExistingSession, true);
    assert.equal(pristineBroker.XPCService.JoinExistingSession, true);
    const hostileFixtures = [
      ["top-level background launch", { ...pristineMigration, LSBackgroundOnly: true }, pristineBroker, /LSBackgroundOnly/u],
      ["environment injection", pristineMigration, {
        ...pristineBroker,
        XPCService: {
          ...pristineBroker.XPCService,
          EnvironmentVariables: { DYLD_INSERT_LIBRARIES: "/private/tmp/hostile.dylib" }
        }
      }, /EnvironmentVariables/u],
      ["unreviewed run loop", {
        ...pristineMigration,
        XPCService: { ...pristineMigration.XPCService, RunLoopType: "dispatch_main" }
      }, pristineBroker, /RunLoopType/u],
      ["changed service type", {
        ...pristineMigration,
        XPCService: { ...pristineMigration.XPCService, ServiceType: "System" }
      }, pristineBroker, /ServiceType does not match the reviewed value/u]
    ];
    for (const [service, pristine] of [
      ["migration", pristineMigration], ["broker", pristineBroker]
    ]) {
      for (const [label, value] of [
        ["missing", undefined], ["disabled", false], ["string", "true"], ["number", 1]
      ]) {
        const altered = {
          ...pristine,
          XPCService: { ...pristine.XPCService, JoinExistingSession: value }
        };
        hostileFixtures.push([
          `${service} security session ${label}`,
          service === "migration" ? altered : pristineMigration,
          service === "broker" ? altered : pristineBroker,
          /JoinExistingSession/u
        ]);
      }
    }
    for (const [label, migration, broker, rejection] of hostileFixtures) {
      await writeFile(migrationJSON, `${JSON.stringify(migration)}\n`, { mode: 0o600 });
      await writeFile(brokerJSON, `${JSON.stringify(broker)}\n`, { mode: 0o600 });
      const rejected = spawnSync(process.execPath, [
        xpcInfoVerifier, identityPath, migrationJSON, brokerJSON
      ], { cwd: root, encoding: "utf8", timeout: 2_000 });
      assert.notEqual(rejected.status, 0, label);
      assert.match(rejected.stderr, rejection, label);
    }
    await writeFile(migrationJSON, `${JSON.stringify(pristineMigration)}\n`, { mode: 0o600 });
    const duplicateServiceType = JSON.stringify(pristineBroker).replace(
      '"ServiceType":"Application"',
      '"ServiceType":"Application","ServiceType":"Application"'
    );
    await writeFile(brokerJSON, `${duplicateServiceType}\n`, { mode: 0o600 });
    const duplicateRejected = spawnSync(process.execPath, [
      xpcInfoVerifier, identityPath, migrationJSON, brokerJSON
    ], { cwd: root, encoding: "utf8", timeout: 2_000 });
    assert.notEqual(duplicateRejected.status, 0);
    assert.match(duplicateRejected.stderr, /duplicate dictionary key ServiceType/u);

    const enforcementScripts = [
      "build-app.sh",
      "verify-release.sh",
      "prepare-public-release-assets.sh",
      "verify-public-distribution.sh",
      "verify-credential-migration-xpc.sh",
      "verify-credential-broker-xpc.sh"
    ];
    for (const name of enforcementScripts) {
      assert.match(await readFile(join(root, "scripts", name), "utf8"), /verify-xpc-service-info\.mjs/u, name);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("public assets publish once by exclusive durable rename and failures leave no partial final directory", async () => {
  const temporary = await mkdtemp("/private/tmp/fulmar-public-publisher.");
  const publisher = join(temporary, "publisher");
  try {
    await chmod(temporary, 0o700);
    const compiled = spawnSync("/usr/bin/xcrun", [
      "--sdk", "macosx", "clang", "-std=c17", "-Os", "-Wall", "-Wextra", "-Werror",
      "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Wformat=2",
      publicAssetPublisherSource, "-o", publisher
    ], { cwd: root, encoding: "utf8", timeout: 20_000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    await chmod(publisher, 0o700);
    const signed = spawnSync("/usr/bin/codesign", [
      "--force", "--sign", "-", "--timestamp=none", publisher
    ], { cwd: root, encoding: "utf8", timeout: 5_000 });
    assert.equal(signed.status, 0, signed.stderr);

    await makePublisherStage(temporary, ".assets.staging.success", "success");
    const published = spawnSync(publisher, [
      "publish", temporary, ".assets.staging.success", "assets"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.equal(published.status, 0, published.stderr);
    assert.deepEqual((await readdir(join(temporary, "assets"))).sort(), [...packageAssetNames].sort());
    assert.equal(await readFile(join(temporary, "assets", "LICENSE"), "utf8"), "success:LICENSE\n");

    await makePublisherStage(temporary, ".assets.staging.preexisting", "preexisting");
    await writeFile(join(temporary, "occupied"), "do not replace", { mode: 0o600 });
    const preexisting = spawnSync(publisher, [
      "publish", temporary, ".assets.staging.preexisting", "occupied"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.notEqual(preexisting.status, 0);
    assert.equal(await readFile(join(temporary, "occupied"), "utf8"), "do not replace");

    await makePublisherStage(temporary, ".assets.staging.symlink-destination", "symlink-destination");
    await symlink("missing-target", join(temporary, "destination-link"));
    const symlinkDestination = spawnSync(publisher, [
      "publish", temporary, ".assets.staging.symlink-destination", "destination-link"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.notEqual(symlinkDestination.status, 0);
    assert.equal(await readFile(join(temporary, "destination-link")).catch((error) => error.code), "ENOENT");

    await makePublisherStage(temporary, ".assets.staging.symlink-target", "symlink-stage");
    await symlink(".assets.staging.symlink-target", join(temporary, ".assets.staging.symlink"));
    const symlinkStage = spawnSync(publisher, [
      "publish", temporary, ".assets.staging.symlink", "symlink-stage-final"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.notEqual(symlinkStage.status, 0);
    await assert.rejects(stat(join(temporary, "symlink-stage-final")), { code: "ENOENT" });

    await mkdir(join(temporary, ".assets.staging.incomplete"), { mode: 0o700 });
    await chmod(join(temporary, ".assets.staging.incomplete"), 0o700);
    await writeFile(join(temporary, ".assets.staging.incomplete", "LICENSE"), "partial", { mode: 0o644 });
    await chmod(join(temporary, ".assets.staging.incomplete", "LICENSE"), 0o644);
    const incompleteIdentity = await stat(join(temporary, ".assets.staging.incomplete"), { bigint: true });
    const incomplete = spawnSync(publisher, [
      "publish", temporary, ".assets.staging.incomplete", "partial-final"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.notEqual(incomplete.status, 0);
    await assert.rejects(stat(join(temporary, "partial-final")), { code: "ENOENT" });
    const cleaned = spawnSync(publisher, [
      "cleanup", temporary, ".assets.staging.incomplete",
      incompleteIdentity.dev.toString(), incompleteIdentity.ino.toString()
    ], { encoding: "utf8", timeout: 5_000 });
    assert.equal(cleaned.status, 0, cleaned.stderr);
    await assert.rejects(stat(join(temporary, ".assets.staging.incomplete")), { code: "ENOENT" });

    const realParent = join(temporary, "real-parent");
    await mkdir(realParent, { mode: 0o700 });
    await chmod(realParent, 0o700);
    await makePublisherStage(realParent, ".assets.staging.parent-link", "parent-link");
    await symlink(realParent, join(temporary, "parent-link"));
    const parentLink = spawnSync(publisher, [
      "publish", join(temporary, "parent-link"), ".assets.staging.parent-link", "linked-final"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.notEqual(parentLink.status, 0);
    await assert.rejects(stat(join(realParent, "linked-final")), { code: "ENOENT" });

    await makePublisherStage(temporary, ".assets.staging.racer-a", "racer-a");
    await makePublisherStage(temporary, ".assets.staging.racer-b", "racer-b");
    const [racerA, racerB] = await Promise.all([
      runChild(publisher, ["publish", temporary, ".assets.staging.racer-a", "race-winner"]),
      runChild(publisher, ["publish", temporary, ".assets.staging.racer-b", "race-winner"])
    ]);
    assert.equal([racerA, racerB].filter((result) => result.status === 0).length, 1,
      `${racerA.stderr}\n${racerB.stderr}`);
    const winner = await readFile(join(temporary, "race-winner", "LICENSE"), "utf8");
    assert.ok(winner === "racer-a:LICENSE\n" || winner === "racer-b:LICENSE\n");
    assert.deepEqual((await readdir(join(temporary, "race-winner"))).sort(), [...packageAssetNames].sort());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("public asset preparation requires an exact candidate identity before packaging", () => {
  const result = spawnSync("/bin/zsh", ["-f", preparer], rootWatchdogChildOptions({
    cwd: root,
    encoding: "utf8",
    timeout: 10_000
  }));
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, /requires one explicit expected candidate SHA, version, and build/u);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Prepared the exact nine/u);
});

test("public verifier rejects the exact private candidate", async (context) => {
  const archive = join(root, "build", "Fulmar.app.zip");
  const manifest = join(root, "build", "release-manifest.json");
  const symbols = join(root, "build", "Fulmar.dSYMs.zip");
  const staticSecurity = join(root, "build", "static-security-summary.json");
  try {
    await Promise.all([stat(archive), stat(manifest), stat(symbols), stat(staticSecurity)]);
  } catch {
    unavailableCandidateFixture(context, "private release fixture is not present in this source checkout");
    return;
  }
  const [identityInput, manifestInput] = await Promise.all([
    readAttestedRegularFile(join(root, "Config", "ReleaseIdentity.json"), {
      label: "release identity fixture",
      maximumBytes: 1024 * 1024
    }),
    readAttestedRegularFile(manifest, {
      label: "private release manifest fixture",
      maximumBytes: 1024 * 1024
    })
  ]);
  const identity = JSON.parse(identityInput.bytes.toString("utf8"));
  const currentManifest = JSON.parse(manifestInput.bytes.toString("utf8"));
  if (currentManifest.version !== identity.appVersion || currentManifest.build !== identity.appBuild) {
    unavailableCandidateFixture(context, "private release fixture predates the current source release identity");
    return;
  }
  const retainedEvidence = join(
    root,
    "build",
    `release-verify-${identity.appVersion}-build${identity.appBuild}-${currentManifest.sha256}.evidence`
  );
  await assert.rejects(stat(retainedEvidence), { code: "ENOENT" });
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-negative."));
  try {
    const assets = {
      "Fulmar.app.zip": archive,
      "Fulmar.dSYMs.zip": symbols,
      "LICENSE": join(root, "LICENSE"),
      "release-manifest.json": manifest,
      "static-security-summary.json": staticSecurity,
      "LocalHarness.sbom.cdx.json": join("/private/tmp", "LocalHarnessBuild", "Fulmar.app", "Contents", "Resources", "LocalHarness.sbom.cdx.json"),
      "THIRD_PARTY_NOTICES.md": join("/private/tmp", "LocalHarnessBuild", "Fulmar.app", "Contents", "Resources", "THIRD_PARTY_NOTICES.md")
    };
    for (const [name, source] of Object.entries(assets)) await copyFile(source, join(temporary, name));
    await writeFile(
      join(temporary, "Fulmar.app.zip.sha256"),
      `${await sha(join(temporary, "Fulmar.app.zip"))}  Fulmar.app.zip\n`,
      { mode: 0o644 }
    );
    const names = checksumAssetNames;
    const sums = [];
    for (const name of names) sums.push(`${await sha(join(temporary, name))}  ${name}`);
    await writeFile(join(temporary, "SHA256SUMS.txt"), `${sums.join("\n")}\n`, { mode: 0o644 });
    const result = spawnSync("/bin/zsh", ["-f", verifier, temporary], rootWatchdogChildOptions({
      cwd: root,
      encoding: "utf8",
      timeout: 120_000
    }));
    assert.notEqual(result.status, 0, "private candidate must never pass the public gate");
    assert.match(result.stderr, /ENOENT: no such file or directory/u);
    assert.ok(result.stderr.includes(retainedEvidence), result.stderr);
    assert.match(result.stderr, /verify-retained-release-evidence\.mjs/u);
    assert.doesNotMatch(result.stderr, /release manifest|Info\.plist does not match/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("release snapshots accept one stable regular file and reject links, bounds, and replacement", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-snapshot."));
  try {
    const source = join(temporary, "source.bin");
    const destination = join(temporary, "snapshot.bin");
    await writeFile(source, "immutable release bytes", { mode: 0o600 });
    let result = spawnSync(process.execPath, [snapshotter, source, destination, "64"], {
      cwd: root,
      encoding: "utf8"
    });
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout);
    assert.equal(receipt.bytes, 23);
    assert.equal(receipt.sha256, await sha(source));
    assert.equal(await readFile(destination, "utf8"), "immutable release bytes");
    assert.equal((await stat(destination)).mode & 0o777, 0o600);

    result = spawnSync(process.execPath, [snapshotter, source, destination, "64"], { cwd: root, encoding: "utf8" });
    assert.notEqual(result.status, 0, "an existing destination must never be replaced");

    const linked = join(temporary, "hardlink.bin");
    await link(source, linked);
    result = spawnSync(process.execPath, [snapshotter, source, join(temporary, "hardlink-snapshot.bin"), "64"], {
      cwd: root,
      encoding: "utf8"
    });
    assert.notEqual(result.status, 0, "hard-linked sources must fail closed");

    const target = join(temporary, "target.bin");
    const symbolic = join(temporary, "symbolic.bin");
    await writeFile(target, "target", { mode: 0o600 });
    await symlink(target, symbolic);
    result = spawnSync(process.execPath, [snapshotter, symbolic, join(temporary, "symlink-snapshot.bin"), "64"], {
      cwd: root,
      encoding: "utf8"
    });
    assert.notEqual(result.status, 0, "symbolic-link sources must fail closed");

    result = spawnSync(process.execPath, [snapshotter, target, join(temporary, "oversize-snapshot.bin"), "2"], {
      cwd: root,
      encoding: "utf8"
    });
    assert.notEqual(result.status, 0, "oversized sources must fail closed");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("public verifier rejects checksum drift before Apple trust assessment", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-checksum."));
  try {
    await writeSyntheticPackage(temporary, {
      checksumDigest: async (name) => name === "Fulmar.app.zip"
        ? "0".repeat(64)
        : await sha(join(temporary, name))
    });
    const result = spawnSync("/bin/zsh", ["-f", verifier, temporary], rootWatchdogChildOptions({
      cwd: root, encoding: "utf8", timeout: 10_000
    }));
    assertTargetedRejection(result, /Fulmar\.app\.zip: FAILED/u);
    assert.doesNotMatch(result.stderr, /SHA256SUMS\.txt has unexpected or unsafe entries/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("public verifier rejects a forged ordinary-user sidecar even when the reviewer checksum set authenticates it", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-sidecar."));
  try {
    await writeSyntheticPackage(temporary, { sidecarDigest: "0".repeat(64) });
    const result = spawnSync("/bin/zsh", ["-f", verifier, temporary], rootWatchdogChildOptions({
      cwd: root, encoding: "utf8", timeout: 10_000
    }));
    assertTargetedRejection(result, /Fulmar\.app\.zip: FAILED/u);
    assert.doesNotMatch(result.stderr, /SHA256SUMS\.txt has unexpected or unsafe entries/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("public verifier rejects checksum path injection and extra assets", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-topology."));
  try {
    await writeSyntheticPackage(temporary, {
      checksumName: (name) => name === "Fulmar.app.zip" ? "../Fulmar.app.zip" : name
    });
    let result = spawnSync("/bin/zsh", ["-f", verifier, temporary], rootWatchdogChildOptions({
      cwd: root, encoding: "utf8", timeout: 10_000
    }));
    assertTargetedRejection(result, /SHA256SUMS\.txt has unexpected or unsafe entries/u);

    await writeSyntheticPackage(temporary);
    await writeFile(join(temporary, "unexpected.txt"), "extra", { mode: 0o644 });
    result = spawnSync("/bin/zsh", ["-f", verifier, temporary], rootWatchdogChildOptions({
      cwd: root, encoding: "utf8", timeout: 10_000
    }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must contain exactly the nine reviewed release assets/u);
    assert.doesNotMatch(result.stderr, /SHA256SUMS\.txt has unexpected or unsafe entries/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
