import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import {
  chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rm, rmdir,
  symlink, unlink, utimes, writeFile
} from "node:fs/promises";
import { closeSync, constants, existsSync, openSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

const watchdog = join(process.cwd(), "scripts", "run-with-watchdog.sh");
const watchdogInternal = join(process.cwd(), "scripts", "run-with-watchdog.pl");
const watchdogCapabilityJanitor = join(process.cwd(), "scripts", "FulmarWatchdogCapabilityJanitor.pm");
const processTreeWatchdog = join(process.cwd(), "scripts", "run-process-tree-watchdog.mjs");
const signingACLHelperSource = join(process.cwd(), "scripts", "set-signing-key-partition-list-from-fd.c");
const MiB = 1024 * 1024;
const inheritedReleaseRoot = Boolean(process.env.FULMAR_ROOT_WATCHDOG_PGID_V1);
const supervisorFixture = inheritedReleaseRoot ? test.skip : test;

const capabilityJanitorProbe = String.raw`
  use strict;
  use warnings;
  use Fcntl qw(O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
  use FulmarWatchdogCapabilityJanitor qw(janitor_capabilities);
  my ($directory, $pid_state, $group_state, $race, $maximum_entries,
      $maximum_capabilities, $maximum_locks) = @ARGV;
  my $before_unlink;
  my $scan_attempt_hook;
  if ($race eq 'replace') {
    $before_unlink = sub {
      my ($path, $bytes) = @_;
      unlink($path) or die "could not remove the janitor race fixture: $!\n";
      sysopen(my $replacement, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
          or die "could not publish the janitor race replacement: $!\n";
      syswrite($replacement, $bytes) == length($bytes)
          or die "could not write the janitor race replacement: $!\n";
      close($replacement) or die "could not close the janitor race replacement: $!\n";
      chmod(0600, $path) or die "could not protect the janitor race replacement: $!\n";
    };
  }
  if ($race eq 'directory-churn') {
    my $injected = 0;
    $scan_attempt_hook = sub {
      return if $injected++;
      my $path = "$directory/unrelated-concurrent-entry";
      sysopen(my $entry, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
          or die "could not publish the unrelated churn fixture: $!\n";
      close($entry) or die "could not close the unrelated churn fixture: $!\n";
    };
  }
  my $result = janitor_capabilities(
    allow_test_directory => 1,
    directory => $directory,
    effective_uid => $<,
    maximum_entries => $maximum_entries,
    maximum_capabilities => $maximum_capabilities,
    maximum_locks => $maximum_locks,
    minimum_age_seconds => 1,
    maximum_age_seconds => 3_600,
    maximum_elapsed_seconds => 5,
    pid_is_live => sub {
      return undef if $pid_state eq 'ambiguous';
      return $pid_state eq 'live' ? 1 : 0;
    },
    sample_group => sub {
      return undef if $group_state eq 'ambiguous';
      return { members => $group_state eq 'occupied' ? 1 : 0 };
    },
    before_unlink => $before_unlink,
    scan_attempt_hook => $scan_attempt_hook,
  );
  print join("\t", $result->{ok}, $result->{removed}, $result->{message}), "\n";
`;

function invokeCapabilityJanitor(directory, {
  pidState = "dead", groupState = "empty", race = "none",
  maximumEntries = 128, maximumCapabilities = 64, maximumLocks = 64
} = {}) {
  const result = spawnSync("/usr/bin/perl", [
    "-I", join(process.cwd(), "scripts"),
    "-e", capabilityJanitorProbe, "--", directory, pidState, groupState, race,
    String(maximumEntries), String(maximumCapabilities), String(maximumLocks)
  ], { encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const match = /^(0|1)\t([0-9]+)\t([^\n]*)\n$/u.exec(result.stdout);
  assert.ok(match, `janitor probe returned malformed output: ${result.stdout}`);
  return { ok: match[1] === "1", removed: Number(match[2]), message: match[3] };
}

function capabilityFixture(root, rootPID = 900_001, processGroup = 900_002) {
  const nonce = randomBytes(32).toString("hex");
  return {
    rootPID, processGroup, nonce,
    path: join(root, `fulmar-watchdog-capability.${rootPID}.${nonce}`),
    bytes: `${rootPID}\n${processGroup}\n${nonce}\n`
  };
}

async function publishCapabilityFixture(fixture, {
  ageSeconds = 60, mode = 0o600, bytes = fixture.bytes
} = {}) {
  await writeFile(fixture.path, bytes, { flag: "wx", mode });
  await chmod(fixture.path, mode);
  const timestamp = new Date(Date.now() - ageSeconds * 1_000);
  await utimes(fixture.path, timestamp, timestamp);
}

test("watchdog capability janitor runs only for a fresh root and removes dead empty records", async () => {
  const source = await readFile(watchdogInternal, "utf8");
  const markerGuard = source.indexOf("if ($has_any_root_marker) {");
  const ancestorGuard = source.indexOf("bounded_inspector_status('detect-root'", markerGuard);
  const nestingGuard = source.indexOf("if ($watchdog_depth > 0 && !$inherit_root)", ancestorGuard);
  const janitorGuard = source.indexOf("if (!$inherit_root) {", nestingGuard);
  const janitorCall = source.indexOf("janitor_capabilities(", janitorGuard);
  const inheritedBranch = source.indexOf("if ($inherit_root) {", janitorCall);
  assert.ok(markerGuard >= 0 && ancestorGuard > markerGuard && nestingGuard > ancestorGuard
    && janitorGuard > nestingGuard && janitorCall > janitorGuard && inheritedBranch > janitorCall,
  "stale-capability recovery escaped the attested fresh-root startup path");
  assert.match(source.slice(janitorGuard, inheritedBranch),
    /sample_group => sub \{ process_group_sample\(\$_\[0\]\) \}/u,
    "fresh-root recovery does not use the existing bounded process-group sample");

  const helperSource = await readFile(watchdogCapabilityJanitor, "utf8");
  assert.match(helperSource,
    /_read_attested_file\(\$path[\s\S]*?_safe_lock_references\([\s\S]*?sample_group[\s\S]*?_safe_lock_references\([\s\S]*?_read_attested_file\(\$path/u,
    "capability recovery lost an attestation, safe-lock proof, group sample, or final reattestation");
  assert.match(helperSource, /same-user race to the syscall-sized path-unlink window/u,
    "the unavoidable final conditional-unlink residual is no longer explicit");

  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-empty-"));
  try {
    assert.deepEqual(invokeCapabilityJanitor(root), { ok: true, removed: 0, message: "" });
    const fixture = capabilityFixture(root);
    await publishCapabilityFixture(fixture);
    assert.deepEqual(invokeCapabilityJanitor(root), { ok: true, removed: 1, message: "" });
    await assert.rejects(lstat(fixture.path), { code: "ENOENT" });
    const churnFixture = capabilityFixture(root, 900_003, 900_004);
    await publishCapabilityFixture(churnFixture);
    assert.deepEqual(invokeCapabilityJanitor(root, { race: "directory-churn" }),
      { ok: true, removed: 1, message: "" },
      "one unrelated temporary-directory mutation defeated bounded retry");
    await assert.rejects(lstat(churnFixture.path), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true });
  }
});

test("watchdog capability janitor retains live occupied young and ambiguous records", async () => {
  for (const scenario of [
    { name: "live", invoke: { pidState: "live" }, ageSeconds: 60, ok: true },
    { name: "occupied", invoke: { groupState: "occupied" }, ageSeconds: 60, ok: true },
    { name: "young", invoke: {}, ageSeconds: 0, ok: true },
    { name: "ambiguous PID", invoke: { pidState: "ambiguous" }, ageSeconds: 60, ok: false },
    { name: "ambiguous group", invoke: { groupState: "ambiguous" }, ageSeconds: 60, ok: false },
    { name: "too old", invoke: {}, ageSeconds: 7_200, ok: false }
  ]) {
    const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-state-"));
    try {
      const fixture = capabilityFixture(root);
      await publishCapabilityFixture(fixture, { ageSeconds: scenario.ageSeconds });
      const result = invokeCapabilityJanitor(root, scenario.invoke);
      assert.equal(result.ok, scenario.ok, `${scenario.name} returned an unsafe status`);
      assert.equal(result.removed, 0, `${scenario.name} capability was removed`);
      assert.equal((await readFile(fixture.path, "utf8")), fixture.bytes,
        `${scenario.name} capability changed`);
    } finally {
      await rm(root, { recursive: true });
    }
  }
});

test("watchdog capability janitor never removes a safe lock owner reference", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-reference-"));
  try {
    const fixture = capabilityFixture(root);
    await publishCapabilityFixture(fixture);
    const lock = join(root, `fulmar-janitor-${randomBytes(4).toString("hex")}.lock`);
    await mkdir(lock, { mode: 0o700 });
    await chmod(lock, 0o700);
    const owner = `${fixture.rootPID}\n${fixture.processGroup}\n${fixture.path}\n${fixture.nonce}\n`;
    const ownerPath = join(lock, "owner.pid");
    await writeFile(ownerPath, owner, { flag: "wx", mode: 0o600 });
    await chmod(ownerPath, 0o600);

    assert.deepEqual(invokeCapabilityJanitor(root), { ok: true, removed: 0, message: "" });
    assert.equal(await readFile(fixture.path, "utf8"), fixture.bytes);
    assert.equal(await readFile(ownerPath, "utf8"), owner);

    await chmod(lock, 0o755);
    assert.equal(invokeCapabilityJanitor(root).ok, false,
      "a permissive lock directory was not treated as an ambiguous reference");
    await chmod(lock, 0o700);
    await chmod(ownerPath, 0o644);
    assert.equal(invokeCapabilityJanitor(root).ok, false,
      "a permissive owner record was not treated as an ambiguous reference");
    await chmod(ownerPath, 0o600);
    const ownerLink = join(lock, "owner.link");
    await link(ownerPath, ownerLink);
    assert.equal(invokeCapabilityJanitor(root).ok, false,
      "a linked owner record was not treated as an ambiguous reference");
    await unlink(ownerLink);
    await writeFile(ownerPath, "malformed-owner\n", { flag: "w", mode: 0o600 });
    assert.equal(invokeCapabilityJanitor(root).ok, false,
      "a malformed owner record was not treated as an ambiguous reference");
    await lstat(fixture.path);
  } finally {
    await rm(root, { recursive: true });
  }
});

test("watchdog capability janitor rejects linked permissive and malformed records", async () => {
  for (const scenario of ["linked", "symlink", "permissive", "malformed"]) {
    const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-unsafe-"));
    try {
      const fixture = capabilityFixture(root);
      if (scenario === "linked") {
        const original = join(root, "linked-source");
        await writeFile(original, fixture.bytes, { flag: "wx", mode: 0o600 });
        await chmod(original, 0o600);
        await link(original, fixture.path);
        const timestamp = new Date(Date.now() - 60_000);
        await utimes(fixture.path, timestamp, timestamp);
      } else if (scenario === "symlink") {
        const target = join(root, "symlink-target");
        await writeFile(target, fixture.bytes, { flag: "wx", mode: 0o600 });
        await symlink(target, fixture.path);
      } else if (scenario === "permissive") {
        await publishCapabilityFixture(fixture, { mode: 0o644 });
      } else {
        await publishCapabilityFixture(fixture, { bytes: "malformed\n".repeat(8) });
      }
      const result = invokeCapabilityJanitor(root);
      assert.equal(result.ok, false, `${scenario} capability was accepted`);
      assert.equal(result.removed, 0, `${scenario} capability was removed`);
      await lstat(fixture.path);
    } finally {
      await rm(root, { recursive: true });
    }
  }
});

test("watchdog capability janitor rejects an inode replacement at the unlink boundary", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-race-"));
  try {
    const fixture = capabilityFixture(root);
    await publishCapabilityFixture(fixture);
    const before = await lstat(fixture.path);
    const result = invokeCapabilityJanitor(root, { race: "replace" });
    const after = await lstat(fixture.path);
    assert.equal(result.ok, false);
    assert.equal(result.removed, 0);
    assert.notEqual(after.ino, before.ino, "race fixture did not replace the capability inode");
    assert.equal(await readFile(fixture.path, "utf8"), fixture.bytes,
      "changed capability was removed or rewritten");
  } finally {
    await rm(root, { recursive: true });
  }
});

test("watchdog capability janitor fails closed at every scan bound", async () => {
  for (const scenario of ["entries", "capabilities", "locks"]) {
    const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-janitor-bound-"));
    try {
      const options = {};
      if (scenario === "entries") {
        for (const name of ["one", "two", "three"]) await writeFile(join(root, name), "x");
        options.maximumEntries = 2;
      } else if (scenario === "capabilities") {
        for (let index = 0; index < 3; index += 1) {
          const fixture = capabilityFixture(root, 910_000 + index, 920_000 + index);
          await publishCapabilityFixture(fixture, { ageSeconds: 0 });
        }
        options.maximumCapabilities = 2;
      } else {
        for (const name of ["one.lock", "two.lock", "three.lock"]) {
          await writeFile(join(root, name), "x");
        }
        options.maximumLocks = 2;
      }
      const result = invokeCapabilityJanitor(root, options);
      assert.equal(result.ok, false, `${scenario} bound did not fail closed`);
      assert.equal(result.removed, 0, `${scenario} bound removed a record`);
    } finally {
      await rm(root, { recursive: true });
    }
  }
});

function run(args, options = {}) {
  return spawnSync(watchdog, [
    "--seconds", "10",
    "--max-rss-bytes", String(64 * MiB),
    "--rss-grace-seconds", "1",
    "--emergency-rss-bytes", String(256 * MiB),
    "--label", "watchdog fixture",
    "--",
    ...args
  ], { encoding: "utf8", timeout: 15_000, ...options });
}

async function waitForPID(path) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const pid = Number((await readFile(path, "utf8")).trim());
      if (Number.isSafeInteger(pid) && pid > 1) return pid;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for PID fixture ${path}`);
}

async function assertNoLockOwnerReferences(capability) {
  const names = await readdir("/private/tmp");
  assert.ok(names.length <= 16_384, "private temporary root has an unsafe entry count");
  const lockNames = names.filter((name) => /^[A-Za-z0-9._-]{1,160}\.lock$/u.test(name));
  assert.ok(lockNames.length <= 2_048, "private temporary root has too many lock candidates");
  for (const name of lockNames) {
    const directory = join("/private/tmp", name);
    let directoryDetails;
    try { directoryDetails = await lstat(directory); } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!directoryDetails.isDirectory() || directoryDetails.isSymbolicLink()
        || directoryDetails.uid !== process.getuid()) continue;
    let handle;
    try {
      handle = await open(join(directory, "owner.pid"), constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    try {
      const details = await handle.stat();
      assert.equal(details.isFile(), true, `${name} has an unsafe owner record`);
      assert.equal(details.nlink, 1, `${name} has a linked owner record`);
      assert.equal(details.uid, process.getuid(), `${name} owner record changed owner`);
      assert.equal(details.mode & 0o777, 0o600, `${name} owner record is not private`);
      assert.ok(details.size >= 1 && details.size <= 1024, `${name} owner record has an unsafe size`);
      const ownerBytes = await handle.readFile();
      assert.equal(ownerBytes.length, details.size, `${name} owner record changed while reading`);
      assert.equal(ownerBytes.toString("utf8").split("\n").includes(capability), false,
        `${name} still references the retained test capability`);
    } finally { await handle.close(); }
  }
}

async function assertNoPerlReferenceArtifacts(directory = process.cwd()) {
  const entries = await readdir(directory);
  const artifacts = entries.filter((entry) => /^HASH\(0x[0-9a-f]+\)$/u.test(entry));
  assert.deepEqual(artifacts, [],
    "a Perl reference string was used as a filesystem path");
}

function assertAbsentProcessTarget(target, label) {
  assert.ok(Number.isSafeInteger(target) && Math.abs(target) > 1,
    `${label} is not a safe process target`);
  try { process.kill(target, 0); } catch (error) {
    assert.equal(error?.code, "ESRCH", `${label} could not be proven dead`);
    return;
  }
  assert.fail(`${label} is still live`);
}

async function waitForAbsentProcessTarget(target, label) {
  assert.ok(Number.isSafeInteger(target) && Math.abs(target) > 1,
    `${label} is not a safe process target`);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { process.kill(target, 0); } catch (error) {
      if (error?.code === "ESRCH") return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(`${label} did not become absent within its bounded cleanup window`);
}

async function readFixtureCapabilityPath(path) {
  const capability = await readFile(path, "utf8");
  assert.match(capability,
    /^\/private\/tmp\/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64}$/u,
    "fixture did not publish an exact watchdog capability path");
  return capability;
}

async function readFixtureCapabilityPathIfPresent(path) {
  try { return await readFixtureCapabilityPath(path); } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

test("watchdog secret backing objects are anonymous before the first secret byte exists", async () => {
  const source = await readFile(watchdogInternal, "utf8");
  const start = source.indexOf("sub install_private_secret_descriptor {");
  const end = source.indexOf("\n}\n\nmy $signing_password", start);
  assert.ok(start >= 0 && end > start, "private-secret installer could not be isolated");
  const installer = source.slice(start, end);
  const unlinkIndex = installer.indexOf("unlink($path)");
  const frameIndex = installer.indexOf('my $frame = "$value\\n";');
  const writeIndex = installer.indexOf("syswrite($handle, $frame)");
  assert.ok(unlinkIndex >= 0 && frameIndex > unlinkIndex && writeIndex > frameIndex,
    "a watchdog secret may exist before its backing path is unlinked");
  assert.match(installer,
    /my @unpublished = stat\(\$handle\);[\s\S]*?\$unpublished\[3\] == 0[\s\S]*?\$unpublished\[7\] == 0/u,
    "the anonymous empty descriptor is not attested before publication");
});

test("the signing-secret reader accepts its exact byte boundary and rejects malformed descriptors", async () => {
  const root = await mkdtemp("/private/tmp/fulmar-signing-reader-");
  const helper = join(root, "signing-reader-probe");
  try {
    const compile = spawnSync("/usr/bin/xcrun", [
      "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
      "-DFULMAR_TEST_SECRET_READER=1", signingACLHelperSource, "-lutil", "-o", helper
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(compile.status, 0, compile.stderr || compile.error?.message);

    async function invoke(bytes, { linked = false, mode = 0o600 } = {}) {
      const path = join(root, `secret-${randomBytes(8).toString("hex")}`);
      await writeFile(path, bytes, { mode });
      await chmod(path, mode);
      const descriptor = openSync(path, constants.O_RDONLY);
      if (!linked) await unlink(path);
      const stdio = Array(197).fill("ignore");
      stdio[196] = descriptor;
      const result = spawnSync(helper, [], {
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", FULMAR_SIGNING_SECRET_FD_V1: "196" },
        stdio,
        timeout: 3_000
      });
      closeSync(descriptor);
      if (linked) await unlink(path);
      return result;
    }

    for (const length of [0, 1, 512]) {
      const result = await invoke(Buffer.from(`${"q".repeat(length)}\n`, "utf8"));
      assert.equal(result.status, 0, `bounded reader rejected ${length} bytes`);
      assert.equal(result.signal, null, `bounded reader hung at ${length} bytes`);
    }
    for (const length of [513, 514]) {
      const result = await invoke(Buffer.from(`${"q".repeat(length)}\n`, "utf8"));
      assert.equal(result.status, 1, `bounded reader accepted ${length} bytes`);
      assert.equal(result.signal, null, `bounded reader hung at ${length} bytes`);
    }
    for (const malformed of [
      { bytes: Buffer.alloc(0) },
      { bytes: Buffer.from("missing-frame-terminator", "utf8") },
      { bytes: Buffer.from("two\nframes\n", "utf8") },
      { bytes: Buffer.from([0x61, 0x00, 0x0a]) },
      { bytes: Buffer.from("linked\n", "utf8"), linked: true },
      { bytes: Buffer.from("wrong-mode\n", "utf8"), mode: 0o640 }
    ]) {
      const result = await invoke(malformed.bytes, malformed);
      assert.equal(result.status, 1, "bounded reader accepted a malformed descriptor");
      assert.equal(result.signal, null, "bounded reader hung on malformed input");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the zsh secret-closing wrapper preserves argv and closes FD 196", async () => {
  const root = await mkdtemp("/private/tmp/fulmar-zsh-fd-close-");
  const secretPath = join(root, "secret");
  try {
    assert.equal(existsSync(join(process.cwd(), "196")), false,
      "a stale top-level 196 artifact exists before the regression probe");
    await writeFile(secretPath, "private-test-frame\n", { mode: 0o600 });
    const descriptor = openSync(secretPath, constants.O_RDONLY);
    await unlink(secretPath);
    const stdio = Array(197).fill("ignore");
    stdio[1] = "pipe";
    stdio[2] = "pipe";
    stdio[196] = descriptor;
    const result = spawnSync("/bin/zsh", ["-f", "-c", String.raw`
      set -eu
      SIGNING_SECRET_FD=196
      run_without_signing_secret() {
        if [[ "$SIGNING_SECRET_FD" == 196 ]]; then
          "$@" {SIGNING_SECRET_FD}<&-
        else
          "$@"
        fi
      }
      run_without_signing_secret /usr/bin/perl -MFcntl=F_GETFD -e '
        exit 91 unless @ARGV == 2 && $ARGV[0] eq "first" && $ARGV[1] eq "two words";
        my $flags = fcntl(196, F_GETFD, 0);
        exit 92 if defined($flags);
        print "ARGV_EXACT_FD_CLOSED\n";
      ' first "two words"
    `, "fulmar-zsh-fd-close"], { cwd: root, stdio, encoding: "utf8", timeout: 3_000 });
    closeSync(descriptor);
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    assert.equal(result.stdout, "ARGV_EXACT_FD_CLOSED\n");
    assert.equal(existsSync(join(root, "196")), false,
      "the descriptor redirection created a literal 196 artifact");
    assert.equal(existsSync(join(process.cwd(), "196")), false,
      "the descriptor redirection created a top-level 196 artifact");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("watchdog secret boundaries and malformed inherited markers fail closed", {
  skip: inheritedReleaseRoot
}, async () => {
  const probe = String.raw`
    use strict; use warnings; use Fcntl qw(:mode);
    exit 81 unless @ARGV == 3 && $ARGV[1] eq 'first' && $ARGV[2] eq 'two words';
    exit 82 if exists($ENV{LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD});
    exit 83 unless ($ENV{FULMAR_SIGNING_SECRET_FD_V1} // '') eq '196';
    open(my $secret, '<&=196') or exit 84;
    my @details = stat($secret);
    exit 85 unless @details && S_ISREG($details[2]) && $details[3] == 0
      && $details[4] == $< && ($details[2] & 0777) == 0600;
    my $bytes = ''; while (length($bytes) <= 513) {
      my $chunk = ''; my $count = sysread($secret, $chunk, 514 - length($bytes));
      exit 86 unless defined($count); last if $count == 0; $bytes .= $chunk;
    }
    close($secret); my $expected = 0 + $ARGV[0];
    exit 87 unless length($bytes) == $expected + 1 && $bytes =~ /\n\z/
      && substr($bytes, 0, -1) !~ /[\r\n\0]/;
    print "$expected\n";
  `;
  for (const length of [0, 1, 512]) {
    const secret = length === 0 ? "" : `V${"q".repeat(length - 1)}`;
    const result = run(["/usr/bin/perl", "-e", probe, String(length), "first", "two words"], {
      env: { ...process.env, LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: secret }
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    assert.equal(result.stdout, `${length}\n`);
    if (secret.length > 0) {
      assert.equal(result.stdout.includes(secret) || result.stderr.includes(secret), false,
        "a bounded signing secret appeared in watchdog output");
    }
  }

  const root = await mkdtemp("/private/tmp/fulmar-secret-reject-");
  try {
    for (const length of [513, 514]) {
      const secret = `W${"r".repeat(length - 1)}`;
      const sentinel = join(root, `executed-${length}`);
      const result = run(["/usr/bin/touch", sentinel], {
        env: { ...process.env, LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: secret }
      });
      assert.equal(result.status, 126, result.stderr || result.error?.message);
      assert.equal(existsSync(sentinel), false, `oversized ${length}-byte secret reached the command`);
      assert.equal(result.stdout.includes(secret) || result.stderr.includes(secret), false,
        "an oversized signing secret appeared in watchdog output");
    }
    const sentinel = join(root, "malformed-marker-executed");
    const malformed = run(["/usr/bin/touch", sentinel], {
      env: { ...process.env, FULMAR_SIGNING_SECRET_FD_V1: "196" }
    });
    assert.equal(malformed.status, 126, malformed.stderr || malformed.error?.message);
    assert.equal(existsSync(sentinel), false, "a malformed inherited descriptor reached the command");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("watchdog secrets are absent from argv, environments, listings, logs, and relay parents", {
  skip: inheritedReleaseRoot
}, async () => {
  await assertNoPerlReferenceArtifacts();
  const root = await mkdtemp("/private/tmp/fulmar-secret-exposure-");
  const reportPath = join(root, "report.json");
  const readyPath = join(root, "ready");
  const signingSecret = `sign-${randomBytes(24).toString("hex")}`;
  const authSecret = `auth-${randomBytes(24).toString("hex")}`;
  const childProbe = String.raw`
    use strict; use warnings; use JSON::PP; use Fcntl qw(:mode O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
    my ($report_path, $ready, @safe_args) = @ARGV;
    my ($fixture_root) = defined($report_path)
      ? ($report_path =~ m{\A(/private/tmp/fulmar-secret-exposure-[A-Za-z0-9]{6})/report\.json\z})
      : ();
    exit 70 unless defined($fixture_root) && defined($ready) && $ready eq "$fixture_root/ready";
    exit 71 unless @safe_args == 2 && $safe_args[0] eq 'alpha' && $safe_args[1] eq 'two words';
    my %lengths;
    for my $entry (['signing', 196, 'FULMAR_SIGNING_SECRET_FD_V1'], ['auth', 195, 'FULMAR_AUTH_TOKEN_FD_V1']) {
      my ($name, $fd, $marker) = @$entry; exit 72 unless ($ENV{$marker} // '') eq "$fd";
      open(my $handle, "<&=$fd") or exit 73; my @details = stat($handle);
      exit 74 unless @details && S_ISREG($details[2]) && $details[3] == 0
        && $details[4] == $< && ($details[2] & 0777) == 0600;
      my $bytes = ''; while (length($bytes) <= 4097) {
        my $chunk = ''; my $count = sysread($handle, $chunk, 4098 - length($bytes));
        exit 75 unless defined($count); last if $count == 0; $bytes .= $chunk;
      }
      close($handle); exit 76 unless $bytes =~ /\n\z/ && ($bytes =~ tr/\n//) == 1;
      $lengths{$name} = length($bytes) - 1;
    }
    my $report = {
      pid => $$, ppid => getppid(), args => \@safe_args,
      signingLength => $lengths{signing}, authLength => $lengths{auth},
      directSigning => exists($ENV{LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD}),
      directAuth => exists($ENV{LOCAL_HARNESS_AUTH_TOKEN})
    };
    my $report_bytes = JSON::PP->new->canonical->encode($report);
    sysopen(my $out, $report_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or exit 77;
    my @report_details = stat($out);
    exit 78 unless @report_details && S_ISREG($report_details[2]) && $report_details[3] == 1
      && $report_details[4] == $< && ($report_details[2] & 0777) == 0600 && $report_details[7] == 0;
    exit 79 unless syswrite($out, $report_bytes) == length($report_bytes) && close($out);
    sysopen(my $ready_handle, $ready, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or exit 80;
    exit 81 unless syswrite($ready_handle, "ready\n") == 6 && close($ready_handle);
    select(undef, undef, undef, 2.0);
  `;
  const supervisor = spawn(watchdog, [
    "--seconds", "8", "--max-rss-bytes", String(128 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
    "--label", "secret exposure fixture", "--", "/usr/bin/perl", "-e", childProbe,
    reportPath, readyPath, "alpha", "two words"
  ], {
    env: {
      ...process.env,
      LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: signingSecret,
      LOCAL_HARNESS_AUTH_TOKEN: authSecret
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  supervisor.stdout.on("data", (chunk) => { if (stdout.length < 65_536) stdout += chunk; });
  supervisor.stderr.on("data", (chunk) => { if (stderr.length < 65_536) stderr += chunk; });
  const exited = new Promise((resolve) => supervisor.once("exit", (code, signal) => resolve({ code, signal })));
  try {
    for (let attempt = 0; attempt < 150 && !existsSync(readyPath); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(existsSync(readyPath), true, stderr || "secret probe did not become ready");
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    assert.deepEqual(report.args, ["alpha", "two words"]);
    assert.equal(Boolean(report.directSigning), false);
    assert.equal(Boolean(report.directAuth), false);
    assert.equal(report.signingLength, signingSecret.length);
    assert.equal(report.authLength, authSecret.length);

    const processTable = spawnSync("/bin/ps", ["-axo", "pid=,ppid=,command="], {
      encoding: "utf8", timeout: 2_000
    });
    assert.equal(processTable.status, 0, processTable.stderr || processTable.error?.message);
    assert.equal(processTable.stdout.includes(signingSecret) || processTable.stdout.includes(authSecret), false,
      "a private secret appeared in the broad process command listing");
    for (const pid of [supervisor.pid, report.ppid, report.pid]) {
      const environment = spawnSync("/bin/ps", ["eww", "-p", String(pid)], {
        encoding: "utf8", timeout: 2_000
      });
      assert.equal(environment.stdout.includes(signingSecret) || environment.stdout.includes(authSecret), false,
        "a private secret appeared in a live process environment listing");
      const descriptors = spawnSync("/usr/sbin/lsof", ["-a", "-p", String(pid), "-d", "195,196", "-Ff"], {
        encoding: "utf8", timeout: 2_000
      });
      assert.doesNotMatch(descriptors.stdout, /^f(?:195|196)$/mu,
        "a relay parent or completed consumer retained a secret descriptor");
    }
    const outcome = await exited;
    assert.deepEqual(outcome, { code: 0, signal: null }, stderr);
    assert.equal(stdout.includes(signingSecret) || stdout.includes(authSecret)
      || stderr.includes(signingSecret) || stderr.includes(authSecret), false,
    "a private secret appeared in the watchdog transcript");
    await assertNoPerlReferenceArtifacts();
  } finally {
    try { process.kill(supervisor.pid, "SIGTERM"); } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
    await rm(root, { recursive: true, force: true });
    await assertNoPerlReferenceArtifacts();
  }
});

test("nested inherited watchdogs relay each private descriptor exactly once", {
  skip: inheritedReleaseRoot
}, () => {
  const signingSecret = `nested-sign-${randomBytes(16).toString("hex")}`;
  const authSecret = `nested-auth-${randomBytes(16).toString("hex")}`;
  const probe = String.raw`
    use strict; use warnings;
    exit 61 if exists($ENV{LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD}) || exists($ENV{LOCAL_HARNESS_AUTH_TOKEN});
    exit 62 unless @ARGV == 2 && $ARGV[0] eq 'nested' && $ARGV[1] eq 'two words';
    my @lengths; for my $fd (195, 196) {
      open(my $handle, "<&=$fd") or exit 63; local $/; my $bytes = <$handle>; close($handle);
      exit 64 unless defined($bytes) && $bytes =~ /\n\z/ && ($bytes =~ tr/\n//) == 1;
      push(@lengths, length($bytes) - 1);
    }
    print join(':', @lengths), "\n";
  `;
  const result = run([
    watchdog, "--inherit-root", "--seconds", "5", "--max-rss-bytes", String(128 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
    "--label", "nested secret fixture", "--", "/usr/bin/perl", "-e", probe, "nested", "two words"
  ], {
    env: {
      ...process.env,
      LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: signingSecret,
      LOCAL_HARNESS_AUTH_TOKEN: authSecret
    }
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.equal(result.stdout, `${authSecret.length}:${signingSecret.length}\n`);
  assert.equal(result.stdout.includes(signingSecret) || result.stdout.includes(authSecret)
    || result.stderr.includes(signingSecret) || result.stderr.includes(authSecret), false,
  "a nested private secret appeared in output");
});

async function attestRetainedCapability(path) {
  const match = /^\/private\/tmp\/fulmar-watchdog-capability\.([0-9]+)\.([a-f0-9]{64})$/u.exec(path);
  assert.ok(match, "retained test capability has an unsafe path");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let details;
  let bytes;
  try {
    details = await handle.stat();
    assert.equal(details.isFile(), true);
    assert.equal(details.nlink, 1);
    assert.equal(details.uid, process.getuid());
    assert.equal(details.mode & 0o777, 0o600);
    assert.ok(details.size >= 70 && details.size <= 128);
    bytes = await handle.readFile();
    const after = await handle.stat();
    assert.deepEqual([after.dev, after.ino, after.size], [details.dev, details.ino, details.size]);
  } finally { await handle.close(); }
  assert.equal(bytes.length, details.size);
  const payload = /^([0-9]+)\n([0-9]+)\n([a-f0-9]{64})\n$/u.exec(bytes.toString("utf8"));
  assert.ok(payload, "retained test capability has invalid bytes");
  const rootPID = Number(payload[1]);
  const processGroup = Number(payload[2]);
  assert.ok(Number.isSafeInteger(rootPID) && rootPID > 1);
  assert.ok(Number.isSafeInteger(processGroup) && processGroup > 1);
  assert.equal(rootPID, Number(match[1]));
  assert.equal(payload[3], match[2]);
  return { details, rootPID, processGroup, nonce: payload[3] };
}

async function unlinkAttestedFile(path, details, label) {
  const current = await lstat(path);
  assert.equal(current.isFile(), true, `${label} changed type before exact removal`);
  assert.equal(current.isSymbolicLink(), false, `${label} became a symbolic link`);
  assert.deepEqual(
    [current.dev, current.ino, current.uid, current.mode & 0o777, current.nlink, current.size],
    [details.dev, details.ino, details.uid, details.mode & 0o777, details.nlink, details.size],
    `${label} identity changed before exact removal`
  );
  await unlink(path);
  await assert.rejects(lstat(path), { code: "ENOENT" });
}

async function removeAttestedRetainedCapability(path) {
  let attestation;
  try { attestation = await attestRetainedCapability(path); } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  const { details, rootPID, processGroup } = attestation;
  assertAbsentProcessTarget(rootPID, "retained watchdog root");
  assertAbsentProcessTarget(-processGroup, "retained watchdog process group");
  await assertNoLockOwnerReferences(path);
  await unlinkAttestedFile(path, details, "retained capability");
}

async function capturePrivateFixtureRoot(root, prefix) {
  assert.equal(dirname(root), tmpdir(), "fixture root escaped the active private temporary directory");
  const name = basename(root);
  assert.equal(name.slice(0, prefix.length), prefix);
  assert.match(name.slice(prefix.length), /^[A-Za-z0-9]{6}$/u);
  const details = await lstat(root);
  assert.equal(details.isDirectory(), true);
  assert.equal(details.isSymbolicLink(), false);
  assert.equal(details.uid, process.getuid());
  assert.equal(details.mode & 0o777, 0o700);
  return Object.freeze({
    dev: details.dev, ino: details.ino, uid: details.uid, mode: details.mode & 0o777
  });
}

async function removeAttestedFixtureRoot(root, prefix, identity) {
  assert.equal(dirname(root), tmpdir(), "fixture root moved outside the active private temporary directory");
  const name = basename(root);
  assert.equal(name.slice(0, prefix.length), prefix);
  assert.match(name.slice(prefix.length), /^[A-Za-z0-9]{6}$/u);
  const current = await lstat(root);
  assert.equal(current.isDirectory(), true);
  assert.equal(current.isSymbolicLink(), false);
  assert.deepEqual(
    [current.dev, current.ino, current.uid, current.mode & 0o777],
    [identity.dev, identity.ino, identity.uid, identity.mode],
    "fixture root identity changed before exact removal"
  );
  await rm(root, { recursive: true });
  await assert.rejects(lstat(root), { code: "ENOENT" });
}

async function finishFailureSafeCleanup(originalError, cleanup) {
  let cleanupError;
  try { await cleanup(); } catch (error) { cleanupError = error; }
  if (originalError && cleanupError) {
    throw new AggregateError([originalError, cleanupError],
      "watchdog fixture and its exact cleanup both failed", { cause: originalError });
  }
  if (cleanupError) throw cleanupError;
  if (originalError) throw originalError;
}

async function waitForChildExit(child, timeoutMilliseconds) {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise((resolve) => {
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, timeoutMilliseconds);
    child.once("exit", onExit);
  });
}

async function gracefullyStopSupervisor(child, label) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { process.kill(child.pid, "SIGTERM"); } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  if (await waitForChildExit(child, 15_000)) return;
  try { process.kill(child.pid, "SIGKILL"); } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  const killed = await waitForChildExit(child, 5_000);
  assert.equal(killed, true, `${label} did not exit after its last-resort KILL`);
  throw new Error(`${label} required a last-resort KILL before exact fixture cleanup`);
}

async function readFixturePIDIfPresent(path, label) {
  let bytes;
  try { bytes = await readFile(path, "utf8"); } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
  assert.match(bytes, /^[0-9]+$/u, `${label} PID record has invalid bytes`);
  const pid = Number(bytes);
  assert.ok(Number.isSafeInteger(pid) && pid > 1, `${label} PID record is invalid`);
  return pid;
}

async function killAndWaitForChild(child, label) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { process.kill(child.pid, "SIGKILL"); } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  assert.equal(await waitForChildExit(child, 5_000), true,
    `${label} did not exit within its bounded cleanup window`);
}

async function publishFixtureRelease(path) {
  const bytes = "FULMAR_WATCHDOG_TEST_RELEASE_V1\n";
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  const details = await lstat(path);
  assert.equal(details.isFile(), true, "fixture release marker changed type");
  assert.equal(details.isSymbolicLink(), false, "fixture release marker became a symbolic link");
  assert.equal(details.nlink, 1, "fixture release marker has an unsafe link count");
  assert.equal(details.uid, process.getuid(), "fixture release marker changed owner");
  assert.equal(details.mode & 0o777, 0o600, "fixture release marker is not private");
  assert.equal(details.size, Buffer.byteLength(bytes), "fixture release marker has unexpected bytes");
  assert.equal(await readFile(path, "utf8"), bytes);
}

function assertRetainedLockIdentity(path, details, expectedNonce, expectedLinks) {
  const match = /^\/private\/tmp\/fulmar-watchdog-retained-([0-9]+)-([A-Za-z0-9]{6})\.lock$/u.exec(path);
  assert.ok(match, "retained test lock has an unsafe path");
  assert.equal(Number(match[1]), process.pid, "retained test lock is owned by another test process");
  assert.equal(match[2], expectedNonce, "retained test lock does not match its fixture root");
  assert.equal(details.isDirectory(), true, "retained test lock changed type");
  assert.equal(details.isSymbolicLink(), false, "retained test lock became a symbolic link");
  assert.equal(details.uid, process.getuid(), "retained test lock changed owner");
  assert.equal(details.mode & 0o777, 0o700, "retained test lock is not private");
  assert.equal(details.nlink, expectedLinks, "retained test lock has an unsafe link count");
}

async function removeAttestedRetainedLock(lock, expectedCapability, fixtureNonce) {
  let lockDetails;
  try { lockDetails = await lstat(lock); } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    if (expectedCapability) await removeAttestedRetainedCapability(expectedCapability);
    return;
  }
  assertRetainedLockIdentity(lock, lockDetails, fixtureNonce, 3);
  assert.deepEqual(await readdir(lock), ["owner.pid"],
    "retained test lock contains unexpected entries");

  const ownerPath = join(lock, "owner.pid");
  const ownerHandle = await open(ownerPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let ownerDetails;
  let ownerBytes;
  try {
    ownerDetails = await ownerHandle.stat();
    assert.equal(ownerDetails.isFile(), true, "retained lock owner changed type");
    assert.equal(ownerDetails.nlink, 1, "retained lock owner has an unsafe link count");
    assert.equal(ownerDetails.uid, process.getuid(), "retained lock owner changed owner");
    assert.equal(ownerDetails.mode & 0o777, 0o600, "retained lock owner is not private");
    assert.ok(ownerDetails.size >= 72 && ownerDetails.size <= 1024,
      "retained lock owner has an unsafe size");
    ownerBytes = await ownerHandle.readFile();
    const ownerAfter = await ownerHandle.stat();
    assert.deepEqual([ownerAfter.dev, ownerAfter.ino, ownerAfter.size],
      [ownerDetails.dev, ownerDetails.ino, ownerDetails.size],
      "retained lock owner changed while reading");
  } finally { await ownerHandle.close(); }
  assert.equal(ownerBytes.length, ownerDetails.size);
  const ownerPayload = /^([0-9]+)\n([0-9]+)\n(\/private\/tmp\/fulmar-watchdog-capability\.([0-9]+)\.([a-f0-9]{64}))\n([a-f0-9]{64})\n$/u
    .exec(ownerBytes.toString("utf8"));
  assert.ok(ownerPayload, "retained lock owner has invalid bytes");
  const rootPID = Number(ownerPayload[1]);
  const processGroup = Number(ownerPayload[2]);
  const capability = ownerPayload[3];
  const capabilityPID = Number(ownerPayload[4]);
  const capabilityNonce = ownerPayload[5];
  const ownerNonce = ownerPayload[6];
  assert.ok(Number.isSafeInteger(rootPID) && rootPID > 1);
  assert.ok(Number.isSafeInteger(processGroup) && processGroup > 1);
  assert.equal(capabilityPID, rootPID, "retained capability filename changed root PID");
  assert.equal(ownerNonce, capabilityNonce, "retained lock and capability nonce differ");
  if (expectedCapability) assert.equal(capability, expectedCapability,
    "retained lock references a different capability");

  const capabilityAttestation = await attestRetainedCapability(capability);
  assert.equal(capabilityAttestation.rootPID, rootPID,
    "retained capability changed root PID");
  assert.equal(capabilityAttestation.processGroup, processGroup,
    "retained capability changed process group");
  assert.equal(capabilityAttestation.nonce, ownerNonce,
    "retained capability changed nonce");
  assertAbsentProcessTarget(rootPID, "retained lock watchdog root");
  assertAbsentProcessTarget(-processGroup, "retained lock watchdog process group");

  const lockBeforeCapabilityRemoval = await lstat(lock);
  assertRetainedLockIdentity(lock, lockBeforeCapabilityRemoval, fixtureNonce, 3);
  assert.deepEqual(
    [lockBeforeCapabilityRemoval.dev, lockBeforeCapabilityRemoval.ino,
      lockBeforeCapabilityRemoval.uid, lockBeforeCapabilityRemoval.mode & 0o777,
      lockBeforeCapabilityRemoval.nlink],
    [lockDetails.dev, lockDetails.ino, lockDetails.uid, lockDetails.mode & 0o777,
      lockDetails.nlink],
    "retained test lock identity changed before capability removal"
  );
  await unlinkAttestedFile(capability, capabilityAttestation.details, "retained lock capability");
  await unlinkAttestedFile(ownerPath, ownerDetails, "retained lock owner");
  assert.deepEqual(await readdir(lock), [], "retained test lock is not empty after owner removal");

  const lockBeforeRemoval = await lstat(lock);
  assertRetainedLockIdentity(lock, lockBeforeRemoval, fixtureNonce, 2);
  assert.deepEqual(
    [lockBeforeRemoval.dev, lockBeforeRemoval.ino, lockBeforeRemoval.uid,
      lockBeforeRemoval.mode & 0o777],
    [lockDetails.dev, lockDetails.ino, lockDetails.uid,
      lockDetails.mode & 0o777],
    "retained test lock identity changed before exact removal"
  );
  await rmdir(lock);
  await assert.rejects(lstat(lock), { code: "ENOENT" });
}

supervisorFixture("watchdog preserves an ordinary command status", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-status-"));
  const capabilityFile = join(root, "capability-path.txt");
  let capability;
  let bodyError;
  try {
    const result = run([
      "/usr/bin/perl", "-e",
      "open(my $fh,'>',$ARGV[0]) or die $!; " +
        "print $fh $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($fh); exit 7",
      capabilityFile
    ]);
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 7, result.stderr);
    capability = await readFixtureCapabilityPath(capabilityFile);
    await assert.rejects(lstat(capability), { code: "ENOENT" });
  } catch (error) {
    bodyError = error;
  }
  await finishFailureSafeCleanup(bodyError, async () => {
    capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
    if (capability) await removeAttestedRetainedCapability(capability);
    await rm(root, { recursive: true, force: true });
  });
});

supervisorFixture("fixed capability and drain-proof descriptors survive inherited descriptor pressure", () => {
  const opened = [];
  try {
    while (opened.length < 220) opened.push(openSync("/dev/null", "r"));
    const highest = Math.max(...opened);
    const stdio = Array(highest + 1).fill("ignore");
    stdio[1] = "pipe";
    stdio[2] = "pipe";
    for (const descriptor of opened) stdio[descriptor] = descriptor;
    const result = spawnSync(watchdog, [
      "--seconds", "5", "--max-rss-bytes", String(256 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(512 * MiB),
      "--label", "descriptor pressure fixture", "--", "/usr/bin/true"
    ], { stdio, encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    for (const descriptor of opened) closeSync(descriptor);
  }
});

supervisorFixture("the public launcher strips hostile language and shell preload hooks", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-hostile-entry."));
  const perlRoot = join(root, "perl");
  const perlModuleRoot = join(perlRoot, "Hostile");
  const perlMarker = join(root, "perl.marker");
  const nodeMarker = join(root, "node.marker");
  const shellMarker = join(root, "shell.marker");
  const zshMarker = join(root, "zsh.marker");
  const nodeLoader = join(root, "hostile-loader.cjs");
  const shellHook = join(root, "hostile-shell-hook.sh");
  try {
    await mkdir(perlModuleRoot, { recursive: true, mode: 0o700 });
    await writeFile(join(perlModuleRoot, "Watchdog.pm"),
      `package Hostile::Watchdog; BEGIN { open(my $fh, ">>", ${JSON.stringify(perlMarker)}); print $fh "loaded\\n"; close($fh); } 1;\n`,
      { mode: 0o600 });
    await writeFile(nodeLoader,
      `require("node:fs").appendFileSync(${JSON.stringify(nodeMarker)}, "loaded\\n");\n`,
      { mode: 0o600 });
    await writeFile(shellHook, `echo loaded >> ${JSON.stringify(shellMarker)}\n`, { mode: 0o600 });
    await writeFile(join(root, ".zshenv"), `echo loaded >> ${JSON.stringify(zshMarker)}\n`, { mode: 0o600 });
    const hostile = {
      ...process.env,
      HOME: "/Users/forbidden-live-home",
      USER: "forbidden-user",
      PERL5OPT: "-MHostile::Watchdog",
      PERL5LIB: perlRoot,
      NODE_OPTIONS: `--require=${nodeLoader}`,
      NODE_PATH: join(root, "hostile-node-path"),
      ENV: shellHook,
      BASH_ENV: shellHook,
      ZDOTDIR: root,
      DYLD_INSERT_LIBRARIES: join(root, "hostile.dylib"),
      "BASH_FUNC_fulmar_hostile%%": `() { echo loaded >> ${shellMarker}; }`
    };
    const forbiddenCheck = "for my $key (qw(PERL5OPT PERL5LIB NODE_OPTIONS NODE_PATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES)) { exit 91 if exists $ENV{$key}; } exit 0";
    const direct = run(["/usr/bin/perl", "-e", forbiddenCheck], { env: hostile });
    assert.equal(direct.status, 0, direct.stderr || direct.error?.message);

    const nested = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(128 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--label", "hostile nested launcher fixture", "--",
      "/usr/bin/env",
      `PERL5OPT=${hostile.PERL5OPT}`, `PERL5LIB=${hostile.PERL5LIB}`,
      `NODE_OPTIONS=${hostile.NODE_OPTIONS}`, `NODE_PATH=${hostile.NODE_PATH}`,
      `ENV=${hostile.ENV}`, `BASH_ENV=${hostile.BASH_ENV}`, `ZDOTDIR=${hostile.ZDOTDIR}`,
      `DYLD_INSERT_LIBRARIES=${hostile.DYLD_INSERT_LIBRARIES}`,
      watchdog, "--inherit-root",
      "--seconds", "5", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(128 * MiB),
      "--label", "clean inherited launcher fixture", "--", "/usr/bin/perl", "-e", forbiddenCheck
    ], { encoding: "utf8", timeout: 15_000 });
    assert.equal(nested.status, 0, nested.stderr || nested.error?.message);
    for (const marker of [perlMarker, nodeMarker, shellMarker, zshMarker]) {
      assert.equal(existsSync(marker), false, `hostile preload created ${marker}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("the cross-session self-test monitor preserves status and drains a TERM-resistant session", async () => {
  const ordinary = spawnSync(process.execPath, [processTreeWatchdog,
    "--seconds", "5", "--max-rss-bytes", String(256 * MiB),
    "--emergency-rss-bytes", String(512 * MiB), "--label", "tree ordinary fixture", "--",
    "/usr/bin/perl", "-e", "exit 7"
  ], { encoding: "utf8", timeout: 8_000 });
  assert.equal(ordinary.error, undefined, ordinary.error?.message);
  assert.equal(ordinary.status, 7, ordinary.stderr);

  const root = await mkdtemp(join(tmpdir(), "fulmar-tree-watchdog-"));
  const pidFile = join(root, "descendant.pid");
  const unrelated = spawn("/bin/sleep", ["20"], { stdio: "ignore" });
  try {
    const result = spawnSync(process.execPath, [processTreeWatchdog,
      "--seconds", "1", "--max-rss-bytes", String(256 * MiB),
      "--emergency-rss-bytes", String(512 * MiB), "--label", "tree timeout fixture", "--",
      "/usr/bin/perl", "-MPOSIX", "-e",
      "POSIX::setsid(); $SIG{TERM}='IGNORE'; my $pid=fork(); die $! unless defined $pid; " +
        "if($pid==0){$SIG{TERM}='IGNORE';sleep 30;exit 0} " +
        "open(my $fh,'>',$ARGV[0]) or die $!; print $fh $pid; close($fh); sleep 30", pidFile
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 124, result.stderr);
    const descendant = Number((await readFile(pidFile, "utf8")).trim());
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
    assert.equal(process.kill(unrelated.pid, 0), true);
  } finally {
    unrelated.kill("SIGKILL");
    await new Promise((resolve) => unrelated.once("exit", resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test("watchdog source contains no blocking reap fallback", async () => {
  const [source, treeSource, fixtureSource] = await Promise.all([
    readFile(watchdogInternal, "utf8"),
    readFile(processTreeWatchdog, "utf8"),
    readFile(new URL(import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(source, /waitpid\([^,\n]+,\s*0\s*\)/u);
  assert.match(treeSource, /FULMAR_COMMAND_START_V1:\$\{commandBarrierNonce\}/u);
  assert.match(treeSource, /await establishChildIdentity\(\)/u);
  assert.match(treeSource, /childExit !== undefined && childIdentityActive/u);
  assert.match(treeSource, /a retired test-runner PID reappeared while supervised/u);
  assert.doesNotMatch(treeSource, /if \(!childIdentity && root\) childIdentity/u);
  assert.ok(
    treeSource.indexOf("await establishChildIdentity()") < treeSource.indexOf("while (terminationCode === undefined)"),
    "the command identity barrier must complete before any exit/RSS/drain accounting"
  );
  const forbiddenFixturePIDHelper = new RegExp(
    ["function killAndWaitFor", "FixturePID"].join(""), "u"
  );
  assert.doesNotMatch(fixtureSource, forbiddenFixturePIDHelper);
  assert.doesNotMatch(fixtureSource,
    /process\.kill\((?:escaped|escapedPID|descendant),\s*["']SIGKILL["']/u,
    "test teardown must not signal a stale numeric descendant PID");
  const fixtureReleaseMarker = ["FULMAR_WATCHDOG_TEST_", "RELEASE_V1"].join("");
  const publishStart = fixtureSource.indexOf("async function publishFixtureRelease(");
  const publishEnd = fixtureSource.indexOf("\n}\n", publishStart);
  assert.ok(publishStart >= 0 && publishEnd > publishStart);
  assert.equal(fixtureSource.slice(publishStart, publishEnd).includes(fixtureReleaseMarker), true);
  assert.equal(fixtureSource.split(fixtureReleaseMarker).length - 1, 1);
  assert.match(fixtureSource,
    /publishFixtureRelease\(releaseFile\)[\s\S]*waitForAbsentProcessTarget\(escapedPID/u);
});

test("watchdog process-table parser fails closed on malformed or unterminated rows", () => {
  const modulePath = join(process.cwd(), "scripts");
  const probe = `
use strict; use warnings;
use FulmarWatchdogSample qw(parse_process_group_sample);
my $valid = parse_process_group_sample(" 42 10\\n 7 3\\n", 42);
exit 10 unless defined($valid) && $valid->{members} == 1 && $valid->{rss_bytes} == 10240;
for my $hostile ("", " 42 10\\nmalformed\\n", " 42 10", "\\n", "42 -1\\n", "42 10 extra\\n") {
  exit 11 if defined(parse_process_group_sample($hostile, 42));
}
exit 0;
`;
  const result = spawnSync("/usr/bin/perl", ["-I", modulePath, "-e", probe], {
    encoding: "utf8", timeout: 5_000
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
});

test("the shared process inspector is bounded and rejects empty or malformed process tables", async () => {
  const fixtureRoot = await mkdtemp("/private/tmp/fulmar-process-inspector-test.");
  const inspector = join(fixtureRoot, "bounded-process-group-inspector.mjs");
  const psFixture = join(fixtureRoot, "fixture-ps.zsh");
  const pidFile = join(fixtureRoot, "fixture.pid");
  await copyFile(join(process.cwd(), "scripts", "bounded-process-group-inspector.mjs"), inspector);
  const runInspector = (fixture, extraEnvironment = {}) => spawnSync(process.execPath, [
    inspector, "count", "4242"
  ], {
    encoding: "utf8",
    timeout: 4_000,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      FULMAR_PROCESS_INSPECTOR_TEST_ONLY_V1: "1",
      FULMAR_PROCESS_INSPECTOR_TEST_PS_V1: psFixture,
      ...extraEnvironment
    }
  });
  try {
    await writeFile(psFixture, "#!/bin/zsh\nprint -r -- '1 0 1'\nprint -r -- '42 1 4242'\n", { mode: 0o700 });
    let result = runInspector(psFixture);
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "1\n");

    await writeFile(psFixture, "#!/bin/zsh\nexit 0\n", { mode: 0o700 });
    result = runInspector(psFixture);
    assert.notEqual(result.status, 0, "an empty successful ps response must fail closed");

    await writeFile(psFixture, "#!/bin/zsh\nprint -rn -- 'malformed'\n", { mode: 0o700 });
    result = runInspector(psFixture);
    assert.notEqual(result.status, 0, "a malformed unterminated ps response must fail closed");

    await writeFile(psFixture, `#!/bin/zsh\nprint -r -- $$ > ${JSON.stringify(pidFile)}\nexec /bin/sleep 30\n`, { mode: 0o700 });
    await chmod(psFixture, 0o700);
    const started = Date.now();
    result = runInspector(psFixture, { FULMAR_PROCESS_INSPECTOR_TEST_HOLD_CLOSE_V1: "1" });
    assert.equal(result.error, undefined, result.error?.message);
    assert.notEqual(result.status, 0);
    assert.ok(Date.now() - started < 3_000, "the independent hard-fail timer must bound a missing close event");
    const fixturePID = Number((await readFile(pidFile, "utf8")).trim());
    assert.ok(Number.isSafeInteger(fixturePID) && fixturePID > 1);
    assert.throws(() => process.kill(fixturePID, 0), { code: "ESRCH" });

    const productionSeam = spawnSync(process.execPath, [
      join(process.cwd(), "scripts", "bounded-process-group-inspector.mjs"), "count", "4242"
    ], {
      encoding: "utf8",
      timeout: 2_000,
      env: {
        FULMAR_PROCESS_INSPECTOR_TEST_ONLY_V1: "1",
        FULMAR_PROCESS_INSPECTOR_TEST_PS_V1: psFixture
      }
    });
    assert.notEqual(productionSeam.status, 0, "the production inspector must reject test injection");
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("every direct shared-inspector caller propagates inspection failure", async () => {
  const [lock, supervisor] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "root-group-lock.zsh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "supervised-process-group.zsh"), "utf8")
  ]);
  assert.match(lock, /member_count="\$\("\$node" "\$inspector" count[^\n]+\)" \|\| return 1/u);
  assert.match(supervisor, /fulmar_process_inspector count "\$group_id"/u);
  assert.match(supervisor, /members="\$\(fulmar_process_group_member_count "\$group_id"\)" \|\| return 1/u);
  assert.match(supervisor, /fulmar_process_inspector pid-in-group[^\n]+>\/dev\/null/u);
});

supervisorFixture("a transient descendant RSS spike inside the grace window is allowed", () => {
  const result = run([
    "/bin/sh", "-p", "-c",
    "/usr/bin/perl -e '$x=\"x\" x (96*1024*1024); select undef,undef,undef,0.25' & wait; sleep 2"
  ]);
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
});

supervisorFixture("sustained allocation terminates the exact supervised group", () => {
  const result = run([
    "/usr/bin/perl", "-e", "$x=\"x\" x (96*1024*1024); sleep 10"
  ]);
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 125, result.stderr);
  assert.match(result.stderr, /remained above its aggregate RSS limit/u);
});

supervisorFixture("aggregate RSS includes descendants rather than only the leader", () => {
  const result = run([
    "/bin/sh", "-p", "-c",
    "/usr/bin/perl -e '$x=\"x\" x (40*1024*1024); sleep 10' & " +
      "/usr/bin/perl -e '$x=\"x\" x (40*1024*1024); sleep 10' & wait"
  ]);
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 125, result.stderr);
});

supervisorFixture("a leader that exits with an orphaned descendant fails closed and drains it", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-orphan-"));
  const pidFile = join(root, "descendant.pid");
  const capabilityFile = join(root, "capability-path.txt");
  let capability;
  let bodyError;
  try {
    const result = run([
      "/usr/bin/perl", "-e",
      "open(my $cap, '>', $ARGV[1]) or die $!; " +
        "print $cap $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($cap); " +
        "my $pid=fork(); die $! unless defined $pid; if($pid==0){sleep 30; exit 0} " +
        "open(my $fh, '>', $ARGV[0]) or die $!; print $fh $pid; close($fh); " +
        "select undef,undef,undef,0.8; exit 0",
      pidFile, capabilityFile
    ]);
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.match(result.stderr, /descendants were still running/u);
    const descendant = Number((await readFile(pidFile, "utf8")).trim());
    assert.ok(Number.isSafeInteger(descendant) && descendant > 1);
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
    capability = await readFixtureCapabilityPath(capabilityFile);
    await assert.rejects(lstat(capability), { code: "ENOENT" });
  } catch (error) {
    bodyError = error;
  }
  await finishFailureSafeCleanup(bodyError, async () => {
    capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
    if (capability) await removeAttestedRetainedCapability(capability);
    await rm(root, { recursive: true, force: true });
  });
});

supervisorFixture("an observed descendant that changes session cannot escape cleanup after its leader exits", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-setsid-escape-"));
  const pidFile = join(root, "escaped.pid");
  try {
    const result = run([
      "/usr/bin/perl", "-MPOSIX", "-e",
      "my $pid=fork(); die $! unless defined $pid; " +
        "if($pid==0){select undef,undef,undef,0.3; POSIX::setsid(); $SIG{TERM}='IGNORE'; " +
        "open(my $fh,'>',$ARGV[0]) or die $!; print $fh $$; close($fh); sleep 30; exit 0} " +
        "select undef,undef,undef,0.8; exit 0",
      pidFile
    ]);
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.match(result.stderr, /tracked descendants were still running/u);
    const escaped = Number((await readFile(pidFile, "utf8")).trim());
    assert.ok(Number.isSafeInteger(escaped) && escaped > 1);
    assert.throws(() => process.kill(escaped, 0), { code: "ESRCH" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("a timed-out observed session-changing descendant is killed before status 124 is published", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-setsid-timeout-"));
  const pidFile = join(root, "escaped.pid");
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "1", "--max-rss-bytes", String(256 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(512 * MiB),
      "--label", "setsid timeout fixture", "--", "/usr/bin/perl", "-MPOSIX", "-e",
      "my $pid=fork(); die $! unless defined $pid; " +
        "if($pid==0){select undef,undef,undef,0.3; POSIX::setsid(); $SIG{TERM}='IGNORE'; " +
        "open(my $fh,'>',$ARGV[0]) or die $!; print $fh $$; close($fh); sleep 30; exit 0} " +
        "sleep 30",
      pidFile
    ], { encoding: "utf8", timeout: 12_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 124, result.stderr);
    const escaped = Number((await readFile(pidFile, "utf8")).trim());
    assert.ok(Number.isSafeInteger(escaped) && escaped > 1);
    assert.throws(() => process.kill(escaped, 0), { code: "ESRCH" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("an external signal lets the tree owner drain an observed session-changing descendant", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-setsid-signal-"));
  const pidFile = join(root, "escaped.pid");
  const capabilityFile = join(root, "capability-path.txt");
  const supervisor = spawn(watchdog, [
    "--seconds", "20", "--max-rss-bytes", String(256 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(512 * MiB),
    "--label", "setsid signal fixture", "--", "/usr/bin/perl", "-MPOSIX", "-e",
    "open(my $cap,'>',$ARGV[1]) or die $!; " +
      "print $cap $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($cap); " +
      "my $pid=fork(); die $! unless defined $pid; " +
      "if($pid==0){select undef,undef,undef,0.3; POSIX::setsid(); $SIG{TERM}='IGNORE'; " +
      "open(my $fh,'>',$ARGV[0]) or die $!; print $fh $$; close($fh); sleep 30; exit 0} " +
      "sleep 30",
    pidFile, capabilityFile
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  let escaped;
  let escapedProvenAbsent = false;
  let capability;
  let bodyError;
  supervisor.stderr.setEncoding("utf8");
  supervisor.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    escaped = await waitForPID(pidFile);
    process.kill(supervisor.pid, "SIGTERM");
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("setsid signal fixture did not exit")), 15_000);
      supervisor.once("exit", (code, signal) => {
        clearTimeout(timer);
        resolve({ code, signal });
      });
    });
    assert.deepEqual(result, { code: 143, signal: null }, stderr);
    assert.throws(() => process.kill(escaped, 0), { code: "ESRCH" });
    escapedProvenAbsent = true;
    capability = await readFixtureCapabilityPath(capabilityFile);
    await assert.rejects(lstat(capability), { code: "ENOENT" });
  } catch (error) {
    bodyError = error;
  }
  await finishFailureSafeCleanup(bodyError, async () => {
    let supervisorCleanupError;
    try { await gracefullyStopSupervisor(supervisor, "setsid signal fixture"); } catch (error) {
      supervisorCleanupError = error;
    }
    await finishFailureSafeCleanup(supervisorCleanupError, async () => {
      escaped ??= await readFixturePIDIfPresent(pidFile, "setsid signal escaped descendant");
      if (supervisorCleanupError && !escaped) {
        throw new Error("setsid signal cleanup cannot prove its escaped descendant absent");
      }
      if (escaped && !escapedProvenAbsent) {
        await waitForAbsentProcessTarget(escaped, "setsid signal escaped descendant");
        escapedProvenAbsent = true;
      }
      capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
      if (capability) {
        await removeAttestedRetainedCapability(capability);
        await assert.rejects(lstat(capability), { code: "ENOENT" });
      }
      await rm(root, { recursive: true, force: true });
    });
  });
});

supervisorFixture("memory enforcement never kills an unrelated process", async () => {
  const unrelated = spawn("/bin/sleep", ["20"], { stdio: "ignore" });
  try {
    assert.ok(Number.isSafeInteger(unrelated.pid) && unrelated.pid > 1);
    const result = run([
      "/usr/bin/perl", "-e", "$x=\"x\" x (96*1024*1024); sleep 10"
    ]);
    assert.equal(result.status, 125, result.stderr);
    assert.equal(process.kill(unrelated.pid, 0), true);
  } finally {
    unrelated.kill("SIGKILL");
    await new Promise((resolve) => unrelated.once("exit", resolve));
  }
});

supervisorFixture("wall timeout returns 124 and drains descendants", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-timeout-"));
  const pidFile = join(root, "descendant.pid");
  const capabilityFile = join(root, "capability-path.txt");
  let capability;
  let bodyError;
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "1",
      "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1",
      "--emergency-rss-bytes", String(256 * MiB),
      "--label", "timeout fixture",
      "--", "/usr/bin/perl", "-e",
      "open(my $cap,'>',$ARGV[1]) or die $!; " +
        "print $cap $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($cap); " +
        "my $pid=fork(); die $! unless defined $pid; if($pid==0){sleep 30; exit 0} " +
        "open(my $fh, '>', $ARGV[0]) or die $!; print $fh $pid; close($fh); sleep 30",
      pidFile, capabilityFile
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 124, result.stderr);
    assert.match(result.stderr, /exceeded its 1-second wall limit/u);
    const descendant = Number((await readFile(pidFile, "utf8")).trim());
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
    capability = await readFixtureCapabilityPath(capabilityFile);
    await assert.rejects(lstat(capability), { code: "ENOENT" });
  } catch (error) {
    bodyError = error;
  }
  await finishFailureSafeCleanup(bodyError, async () => {
    capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
    if (capability) await removeAttestedRetainedCapability(capability);
    await rm(root, { recursive: true, force: true });
  });
});

supervisorFixture("wall timeout escalates to KILL and drains TERM-ignoring descendants", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-hostile-timeout-"));
  const pidFile = join(root, "descendant.pid");
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "1",
      "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1",
      "--emergency-rss-bytes", String(256 * MiB),
      "--label", "hostile timeout fixture",
      "--", "/usr/bin/perl", "-e",
      "$SIG{TERM}='IGNORE'; my $pid=fork(); die $! unless defined $pid; " +
        "if($pid==0){$SIG{TERM}='IGNORE'; sleep 30; exit 0} " +
        "open(my $fh, '>', $ARGV[0]) or die $!; print $fh $pid; close($fh); sleep 30",
      pidFile
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 124, result.stderr);
    const descendant = Number((await readFile(pidFile, "utf8")).trim());
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const [signal, expectedCode] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]]) {
  supervisorFixture(`external ${signal} is forwarded to the exact child group only`, async () => {
    const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-signal-"));
    const pidFile = join(root, "descendant.pid");
    const capabilityFile = join(root, "capability-path.txt");
    let capability;
    let descendant;
    let descendantProvenAbsent = false;
    let bodyError;
    const unrelated = spawn("/bin/sleep", ["20"], { stdio: "ignore" });
    const supervisor = spawn(watchdog, [
      "--seconds", "20",
      "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1",
      "--emergency-rss-bytes", String(256 * MiB),
      "--label", "signal fixture",
      "--", "/usr/bin/perl", "-e",
      "open(my $cap,'>',$ARGV[1]) or die $!; " +
        "print $cap $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($cap); " +
        "my $pid=fork(); die $! unless defined $pid; if($pid==0){sleep 30; exit 0} " +
        "open(my $fh, '>', $ARGV[0]) or die $!; print $fh $pid; close($fh); sleep 30",
      pidFile, capabilityFile
    ], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    supervisor.stderr.setEncoding("utf8");
    supervisor.stderr.on("data", (chunk) => { stderr += chunk; });
    try {
      descendant = await waitForPID(pidFile);
      process.kill(supervisor.pid, signal);
      const status = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("signal fixture did not exit")), 10_000);
        supervisor.once("exit", (code, childSignal) => {
          clearTimeout(timer);
          resolve({ code, signal: childSignal });
        });
      });
      assert.deepEqual(status, { code: expectedCode, signal: null }, stderr);
      assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
      descendantProvenAbsent = true;
      assert.equal(process.kill(unrelated.pid, 0), true);
      capability = await readFixtureCapabilityPath(capabilityFile);
      await assert.rejects(lstat(capability), { code: "ENOENT" });
    } catch (error) {
      bodyError = error;
    }
    await finishFailureSafeCleanup(bodyError, async () => {
      let supervisorCleanupError;
      try { await gracefullyStopSupervisor(supervisor, `${signal} signal fixture`); } catch (error) {
        supervisorCleanupError = error;
      }
      await finishFailureSafeCleanup(supervisorCleanupError, async () => {
        await killAndWaitForChild(unrelated, `${signal} unrelated sentinel`);
        descendant ??= await readFixturePIDIfPresent(pidFile, `${signal} signal descendant`);
        if (supervisorCleanupError && !descendant) {
          throw new Error(`${signal} cleanup cannot prove its fixture descendant absent`);
        }
        if (descendant && !descendantProvenAbsent) {
          await waitForAbsentProcessTarget(descendant, `${signal} signal descendant`);
          descendantProvenAbsent = true;
        }
        capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
        if (capability) {
          await removeAttestedRetainedCapability(capability);
          await assert.rejects(lstat(capability), { code: "ENOENT" });
        }
        await rm(root, { recursive: true, force: true });
      });
    });
  });
}

supervisorFixture("nested watchdog composition is rejected before a separately supervised command can escape", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-nested-"));
  const pidFile = join(root, "nested-descendant.pid");
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "10",
      "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1",
      "--emergency-rss-bytes", String(256 * MiB),
      "--label", "outer fixture",
      "--", watchdog,
      "--seconds", "20",
      "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1",
      "--emergency-rss-bytes", String(256 * MiB),
      "--label", "inner fixture",
      "--", "/usr/bin/perl", "-e",
      "$SIG{TERM}='IGNORE'; open(my $fh, '>', $ARGV[0]) or die $!; " +
        "print $fh $$; close($fh); sleep 30",
      pidFile
    ], { encoding: "utf8", timeout: 5_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.match(result.stderr, /refused unsafe nested watchdog composition/u);
    await assert.rejects(readFile(pidFile), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("stripping every marker and closing the capability FD cannot create a second root", () => {
  const nestedArguments = [
    "--seconds", "5", "--max-rss-bytes", String(64 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
    "--label", "stripped nested fixture", "--", "/usr/bin/true"
  ];
  const result = run([
    "/usr/bin/perl", "-MPOSIX", "-e",
    "POSIX::close(198); delete @ENV{qw(FULMAR_INTERNAL_WATCHDOG_DEPTH " +
      "FULMAR_ROOT_WATCHDOG_PGID_V1 FULMAR_ROOT_WATCHDOG_PID_V1 " +
      "FULMAR_ROOT_WATCHDOG_CAPABILITY_V1 FULMAR_ROOT_WATCHDOG_NONCE_V1 " +
      "FULMAR_ROOT_WATCHDOG_FD_V1)}; exec @ARGV or die $!",
    watchdog, ...nestedArguments
  ]);
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 126, result.stderr);
  assert.match(result.stderr, /stripped or ambiguous ancestor root-watchdog capability/u);
});

supervisorFixture("an inherited logical stage enforces its wall deadline without creating a session", () => {
  const result = run([
    watchdog, "--inherit-root",
    "--seconds", "1", "--max-rss-bytes", String(256 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
    "--label", "logical timeout fixture", "--", "/bin/sleep", "20"
  ]);
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 124, result.stderr);
  assert.match(result.stderr, /exceeded its 1-second inherited watchdog/u);
});

supervisorFixture("an inherited logical stage enforces a tighter aggregate RSS profile", () => {
  const result = spawnSync(watchdog, [
    "--seconds", "10", "--max-rss-bytes", String(512 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(768 * MiB),
    "--label", "outer logical RSS fixture", "--", watchdog, "--inherit-root",
    "--seconds", "10", "--max-rss-bytes", String(64 * MiB),
    "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(128 * MiB),
    "--label", "logical RSS fixture", "--", "/usr/bin/perl", "-e",
    "$x=\"x\" x (160*1024*1024); sleep 20"
  ], { encoding: "utf8", timeout: 15_000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 125, result.stderr);
  assert.match(result.stderr, /stage emergency limit|stage limit/u);
});

supervisorFixture("a supervisor-owned lock is removed only after descendant drain", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-lock-"));
  const pidFile = join(root, "descendant.pid");
  const lock = `/private/tmp/fulmar-watchdog-lock-${process.pid}-${Date.now()}.lock`;
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--lock-dir", lock, "--lock-wait-seconds", "0",
      "--label", "lock drain fixture", "--", "/usr/bin/perl", "-e",
      "my $pid=fork(); die $! unless defined $pid; if($pid==0){$SIG{TERM}='IGNORE';sleep 30;exit 0}" +
        "open(my $fh,'>',$ARGV[0]) or die $!; print $fh $pid; close($fh); " +
        "select undef,undef,undef,0.8; exit 0", pidFile
    ], { encoding: "utf8", timeout: 12_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    const descendant = Number((await readFile(pidFile, "utf8")).trim());
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });
    await assert.rejects(readFile(join(lock, "owner.pid")), { code: "ENOENT" });
  } finally {
    await rm(lock, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("an ownerless pre-existing lock fails closed after one bounded publication window", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-ownerless-lock-"));
  const lock = `/private/tmp/fulmar-watchdog-ownerless-${process.pid}-${Date.now()}.lock`;
  try {
    const preparation = spawnSync("/bin/mkdir", ["-m", "0700", lock], {
      encoding: "utf8", timeout: 5_000
    });
    assert.equal(preparation.status, 0, preparation.stderr);
    const started = Date.now();
    const result = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--lock-dir", lock, "--lock-wait-seconds", "0",
      "--label", "ownerless lock fixture", "--", "/bin/true"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.ok(Date.now() - started < 3_000, "ownerless-lock rejection must remain bounded");
    assert.match(result.stderr, /could not acquire its supervisor-owned root lock/u);
  } finally {
    await rm(lock, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("cleanup failure changes the final status receipt instead of publishing a stale zero", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-receipt-"));
  const statusFile = join(root, "status.txt");
  const lock = `/private/tmp/fulmar-watchdog-receipt-${process.pid}-${Date.now()}.lock`;
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--status-file", statusFile, "--lock-dir", lock, "--lock-wait-seconds", "0",
      "--label", "receipt cleanup fixture", "--", "/bin/zsh", "-f", "-c",
      "print -r -- hostile > \"$1/owner.pid\"", "_", lock
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.equal(await readFile(statusFile, "utf8"), "126\n");
  } finally {
    await rm(lock, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

supervisorFixture("unexpected capability removal fails closed and leaves no false success receipt", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-watchdog-capability-cleanup-"));
  const statusFile = join(root, "status.txt");
  const capabilityFile = join(root, "capability-path.txt");
  try {
    const result = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--status-file", statusFile, "--label", "capability cleanup fixture", "--",
      "/bin/zsh", "-f", "-c",
      "print -rn -- \"$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1\" > \"$1\"; " +
        "/bin/rm -f -- \"$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1\"",
      "_", capabilityFile
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 126, result.stderr);
    assert.equal(await readFile(statusFile, "utf8"), "126\n");
    const capability = await readFile(capabilityFile, "utf8");
    await assert.rejects(readFile(capability), { code: "ENOENT" });
  } finally { await rm(root, { recursive: true, force: true }); }
});

supervisorFixture("missing tree-drain proof retains the lock and blocks a next contender", async () => {
  const rootPrefix = "fulmar-watchdog-retained-lock.";
  const root = await mkdtemp(join(tmpdir(), rootPrefix));
  const rootIdentity = await capturePrivateFixtureRoot(root, rootPrefix);
  const fixtureNonce = basename(root).slice(rootPrefix.length);
  const pidFile = join(root, "escaped.pid");
  const capabilityFile = join(root, "capability-path.txt");
  const releaseFile = join(root, "release-child.txt");
  const lock = `/private/tmp/fulmar-watchdog-retained-${process.pid}-${fixtureNonce}.lock`;
  let escapedPID;
  let capability;
  let bodyError;
  try {
    const first = spawnSync(watchdog, [
      "--seconds", "10", "--max-rss-bytes", String(128 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(256 * MiB),
      "--lock-dir", lock, "--lock-wait-seconds", "0",
      "--label", "missing drain proof fixture", "--",
      "/usr/bin/perl", "-MPOSIX", "-e",
      "open(my $cap,'>',$ARGV[1]) or die $!; " +
        "print $cap $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1}; close($cap); " +
        "my $pid=fork(); die $! unless defined $pid; " +
        "if($pid==0){POSIX::setsid();$SIG{TERM}='IGNORE';$SIG{INT}='IGNORE';$SIG{HUP}='IGNORE';" +
        "open(my $fh,'>',$ARGV[0]) or die $!;print $fh $$;close($fh);" +
        "for(1..600){exit 0 if -f $ARGV[2];select undef,undef,undef,0.05}exit 86} " +
        "select undef,undef,undef,1.0;kill 9,getppid();sleep 30",
      pidFile, capabilityFile, releaseFile
    ], { encoding: "utf8", timeout: 15_000 });
    assert.equal(first.status, 126, first.stderr || first.error?.message);
    escapedPID = await waitForPID(pidFile);
    assert.equal(process.kill(escapedPID, 0), true);
    const owner = (await readFile(join(lock, "owner.pid"), "utf8")).trimEnd().split("\n");
    assert.equal(owner.length, 4);
    capability = await readFixtureCapabilityPath(capabilityFile);
    assert.equal(owner[2], capability);
    assert.equal(existsSync(capability), true);

    const next = spawnSync(watchdog, [
      "--seconds", "5", "--max-rss-bytes", String(64 * MiB),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(128 * MiB),
      "--lock-dir", lock, "--lock-wait-seconds", "0",
      "--label", "retained lock next contender", "--", "/usr/bin/true"
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(next.status, 126, next.stderr || next.error?.message);
    assert.equal(existsSync(join(lock, "owner.pid")), true);
    assert.equal(existsSync(capability), true);
  } catch (error) {
    bodyError = error;
  }
  await finishFailureSafeCleanup(bodyError, async () => {
    let retainedLockExists = true;
    try { await lstat(lock); } catch (error) {
      if (error?.code === "ENOENT") retainedLockExists = false;
      else throw error;
    }
    escapedPID ??= await readFixturePIDIfPresent(pidFile, "retained-lock escaped descendant");
    if (!escapedPID) assert.equal(retainedLockExists, false,
      "a retained test lock cannot be removed without its exact escaped PID record");
    if (escapedPID) {
      let escapedIsLive = true;
      try { process.kill(escapedPID, 0); } catch (error) {
        if (error?.code === "ESRCH") escapedIsLive = false;
        else throw error;
      }
      if (escapedIsLive) await publishFixtureRelease(releaseFile);
      await waitForAbsentProcessTarget(escapedPID, "retained-lock escaped descendant");
    }
    capability ??= await readFixtureCapabilityPathIfPresent(capabilityFile);
    await removeAttestedRetainedLock(lock, capability, fixtureNonce);
    if (capability) await assert.rejects(lstat(capability), { code: "ENOENT" });
    await removeAttestedFixtureRoot(root, rootPrefix, rootIdentity);
  });

  const syntheticBodyFailure = Object.preventExtensions(new Error("synthetic fixture body failure"));
  const syntheticCleanupFailure = new Error("synthetic fixture cleanup failure");
  await assert.rejects(
    finishFailureSafeCleanup(syntheticBodyFailure, async () => { throw syntheticCleanupFailure; }),
    (error) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [syntheticBodyFailure, syntheticCleanupFailure]);
      assert.equal(error.cause, syntheticBodyFailure);
      return true;
    }
  );
});

test("release targets never wrap verification around its already bounded gates", async () => {
  const makefile = await readFile(join(process.cwd(), "Makefile"), "utf8");
  const releaseTargets = makefile.slice(makefile.indexOf("release-verify:"), makefile.indexOf("public-assets:"));
  assert.doesNotMatch(releaseTargets, /run-with-watchdog\.pl/u);
  assert.match(releaseTargets, /retain-release-verification\.sh/u);
  assert.match(releaseTargets, /verify-release-orchestrated\.sh --signing-profile private-stable --deterministic-ci/u);
});

test("release, Swift, status, and evidence call sites contain no legacy PID-only or shlock path", async () => {
  const files = [
    "scripts/root-group-lock.zsh", "scripts/release-lock.zsh", "scripts/build-app.sh",
    "scripts/run-swift-tests.sh", "scripts/verify-release.sh",
    "scripts/verify-status-item-live.sh", "scripts/retain-release-verification.sh"
  ];
  const sources = await Promise.all(files.map(async (path) => [path, await readFile(join(process.cwd(), path), "utf8")]));
  for (const [path, source] of sources) {
    assert.doesNotMatch(source, /\/usr\/bin\/shlock|lock_pid=|LOCK_OWNER=/u, path);
  }
  const rootLock = sources.find(([path]) => path.endsWith("root-group-lock.zsh"))[1];
  assert.match(rootLock, /stat -f '%z'[\s\S]*owner_size[\s\S]*-le 1024[\s\S]*existing="\$\(<"\$owner_file"\)"/u);
  assert.match(rootLock, /FULMAR_LOCK_SUCCESSOR_V1/u);
  const status = sources.find(([path]) => path.endsWith("verify-status-item-live.sh"))[1];
  assert.match(status, /source "\$PROJECT_DIR\/scripts\/release-lock\.zsh"/u);
  assert.match(status, /fulmar_acquire_release_lock "Fulmar status-item qualification"/u);
});
