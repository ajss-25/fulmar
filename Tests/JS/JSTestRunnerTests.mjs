import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import test from "node:test";
import {
  isInsideAuthenticatedRootWatchdog,
  rootWatchdogChildOptions
} from "./RootWatchdogChildProcess.mjs";

test("JavaScript test runner isolates state and rejects hostile ambient environment", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const startupRoot = mkdtempSync("/private/tmp/fulmar-hostile-zdotdir.");
  const startupMarker = join(startupRoot, "zsh-startup.marker");
  writeFileSync(join(startupRoot, ".zshenv"),
    `print -r -- loaded > ${JSON.stringify(startupMarker)}\nexit 0\n`, { mode: 0o600 });
  const sentinel = "fulmar-forbidden-ambient-value";
  const forbidden = [
    "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
    "NPM_TOKEN", "SSH_AUTH_SOCK", "HTTPS_PROXY", "NODE_OPTIONS", "NODE_PATH",
    "NODE_EXTRA_CA_CERTS", "DYLD_INSERT_LIBRARIES", "SSL_CERT_FILE", "CODEX_HOME",
    "ZDOTDIR", "ENV", "BASH_ENV"
  ];
  const probe = `
    const forbidden = ${JSON.stringify(forbidden)};
    const result = Object.fromEntries(forbidden.map((key) => [key, process.env[key] ?? null]));
    result.home = process.env.HOME;
    result.tmp = process.env.TMPDIR;
    result.xdg = process.env.XDG_CACHE_HOME;
    result.npm = process.env.NPM_CONFIG_CACHE;
    result.root = process.env.LOCAL_HARNESS_JS_TEST_ISOLATION_ROOT;
    result.node = process.env.LOCAL_HARNESS_TEST_NODE;
    process.stdout.write(JSON.stringify(result));
  `;
  const hostileEnvironment = { ...process.env };
  for (const key of forbidden) hostileEnvironment[key] = sentinel;
  hostileEnvironment.HOME = "/Users/forbidden-live-home";
  hostileEnvironment.TMPDIR = "/private/tmp/forbidden-live-temp";
  hostileEnvironment.ZDOTDIR = startupRoot;

  try {
    // Invoke the real executable entry point. Going through `/bin/zsh script`
    // would bypass its privileged `-f` shebang and make this regression lie.
    const result = spawnSync(runner, ["-e", probe], rootWatchdogChildOptions({
      cwd: process.cwd(),
      env: hostileEnvironment,
      encoding: "utf8",
      timeout: 20_000
    }));
    assert.equal(result.status, 0, result.stderr);
    assert.equal(existsSync(startupMarker), false, "hostile .zshenv ran before the clean watchdog root");
    const observed = JSON.parse(result.stdout);
    for (const key of forbidden) assert.equal(observed[key], null, key);
    assert.match(observed.root, /^\/tmp\/fulmar-js-tests\.[A-Za-z0-9]+$/u);
    assert.equal(observed.home, `${observed.root}/home`);
    assert.equal(observed.tmp, `${observed.root}/tmp/`);
    assert.equal(observed.xdg, `${observed.root}/cache/xdg`);
    assert.equal(observed.npm, `${observed.root}/cache/npm`);
    assert.match(observed.node, /\/VendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node$/u);
    assert.equal(existsSync(observed.root), false, "runner must remove its private state root");
  } finally {
    rmSync(startupRoot, { recursive: true, force: true });
  }
});

test("ordinary child fixtures must explicitly preserve the authenticated root descriptor", {
  skip: !isInsideAuthenticatedRootWatchdog && "requires the bounded aggregate JavaScript root"
}, () => {
  const probe = 'source "$1"; fulmar_root_watchdog_state';
  const helper = join(process.cwd(), "scripts", "watchdog-root.zsh");
  const dropped = spawnSync("/bin/zsh", ["-f", "-c", probe, "fixture", helper], {
    cwd: process.cwd(), encoding: "utf8", timeout: 5_000
  });
  assert.notEqual(dropped.status, 0, "Node must not implicitly leak the capability descriptor");
  const preserved = spawnSync("/bin/zsh", ["-f", "-c", probe, "fixture", helper],
    rootWatchdogChildOptions({
      cwd: process.cwd(),
      env: {
        ...process.env,
        PROJECT_DIR: "/private/tmp/hostile-caller-project",
        NODE_OPTIONS: "--require=/private/tmp/hostile-watchdog-loader.cjs",
        NODE_PATH: "/private/tmp/hostile-watchdog-modules",
        PERL5OPT: "-MHostile::Watchdog",
        PERL5LIB: "/private/tmp/hostile-watchdog-perl"
      },
      encoding: "utf8",
      timeout: 5_000
    }));
  assert.equal(preserved.status, 0, preserved.stderr);
});

test("aggregate JavaScript test mode owns every topology-changing Node option", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const runnerSource = readFileSync(runner, "utf8");
  assert.match(runnerSource, /operand_count == full_test_count/u);
  assert.match(runnerSource, /seen_test_operands\[\$full_test_file\]/u);
  assert.doesNotMatch(runnerSource, /requested_test_files|\(@k\)seen_test_operands/u);
  const conflicts = [
    ["--test", "--experimental-test-isolation=process"],
    ["--test", "--experimental-test-isolation", "process"],
    ["--test", "--test-concurrency=2"],
    ["--test", "--test-concurrency", "2"],
    ["--test", "--no-test"],
    ["--test-only"],
    ["--test", "--test-name-pattern=fixture"],
    ["--test", "--test-shard=1/2"],
    ["--test", "--import", "/private/tmp/hostile-loader.mjs"],
    ["--test", "--eval", "process.exit(0)"],
    ["--test", "--"]
  ];
  for (const argumentsList of conflicts) {
    const result = spawnSync("/bin/zsh", ["-f", runner, ...argumentsList], rootWatchdogChildOptions({
      cwd: process.cwd(), encoding: "utf8", timeout: 10_000
    }));
    assert.equal(result.status, 64, `${argumentsList.join(" ")}\n${result.stderr}`);
    assert.match(result.stderr, /run-js-tests\.sh (?:owns JavaScript test isolation and concurrency|rejects JavaScript test-runner negation options|does not accept caller-owned JavaScript test options|accepts only reviewed test-file operands)/u);
  }
});

test("aggregate JavaScript test mode rejects discovery, duplicate, and partial operands", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const root = mkdtempSync(join(process.env.TMPDIR ?? "/private/tmp/", "fulmar-js-runner-operands."));
  const first = join(root, "first.mjs");
  const second = join(root, "second.mjs");
  try {
    writeFileSync(first, 'import test from "node:test"; test("first", () => {});\n', { mode: 0o600 });
    writeFileSync(second, 'import test from "node:test"; test("second", () => { throw new Error("must not be omitted"); });\n', { mode: 0o600 });
    for (const argumentsList of [
      ["--test"],
      ["--test", first, first],
      ["--test", "--no-test", first, second]
    ]) {
      const result = spawnSync(runner, argumentsList, rootWatchdogChildOptions({
        cwd: process.cwd(), encoding: "utf8", timeout: 10_000
      }));
      assert.equal(result.status, 64, `${argumentsList.join(" ")}\n${result.stderr}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("canonical --test=true completes one exact machine-accounted run", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const root = mkdtempSync(join(process.env.TMPDIR ?? "/private/tmp/", "fulmar-js-runner-true."));
  const fixture = join(root, "fixture.mjs");
  try {
    writeFileSync(fixture, 'import test from "node:test"; test("canonical true fixture", () => {});\n', { mode: 0o600 });
    const result = spawnSync(runner, ["--test=true", fixture], rootWatchdogChildOptions({
      cwd: process.cwd(), encoding: "utf8", timeout: 20_000
    }));
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /JavaScript event accounting passed: 1 exact tests, 0 intentional skips\./u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a test process that exits early cannot create a false-green JavaScript gate", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const root = mkdtempSync(join(process.env.TMPDIR ?? "/private/tmp/", "fulmar-js-runner-exit."));
  const fixture = join(root, "fixture.mjs");
  try {
    writeFileSync(fixture, "process.exit(0);\n", { mode: 0o600 });
    const result = spawnSync(runner, ["--test", fixture], rootWatchdogChildOptions({
      cwd: process.cwd(), encoding: "utf8", timeout: 20_000
    }));
    assert.equal(result.status, 126, result.stderr || result.stdout);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("private-root cleanup failure overrides an otherwise successful Node exit", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const probe = `
    const { mkdirSync, renameSync } = require("node:fs");
    const root = process.env.LOCAL_HARNESS_JS_TEST_ISOLATION_ROOT;
    renameSync(root, root + ".moved");
    mkdirSync(root, { mode: 0o700 });
    process.stdout.write(root);
  `;
  const result = spawnSync(runner, ["-e", probe], rootWatchdogChildOptions({
    cwd: process.cwd(), encoding: "utf8", timeout: 20_000
  }));
  const root = result.stdout.trim();
  try {
    assert.equal(result.status, 126, result.stderr || result.stdout);
    assert.match(root, /^\/tmp\/fulmar-js-tests\.[A-Za-z0-9]+$/u);
    assert.match(result.stderr, /could not remove its attested private isolation root/u);
  } finally {
    if (root.startsWith("/tmp/fulmar-js-tests.")) {
      rmSync(root, { recursive: true, force: true });
      rmSync(`${root}.moved`, { recursive: true, force: true });
    }
  }
});

test("aggregate JavaScript files execute serially in one authenticated process", () => {
  const runner = join(process.cwd(), "scripts", "run-js-tests.sh");
  const fixtureRoot = mkdtempSync(join(process.env.TMPDIR ?? "/private/tmp/", "fulmar-js-order."));
  const first = join(fixtureRoot, "01-first.test.mjs");
  const second = join(fixtureRoot, "02-second.test.mjs");
  const symbol = "fulmar.aggregate.serial.fixture";
  try {
    writeFileSync(first, `
      import assert from "node:assert/strict";
      import test from "node:test";
      test("first aggregate fixture", () => {
        const key = Symbol.for(${JSON.stringify(symbol)});
        assert.equal(globalThis[key], undefined);
        globalThis[key] = "first-completed";
      });
    `, { mode: 0o600 });
    writeFileSync(second, `
      import assert from "node:assert/strict";
      import test from "node:test";
      test("second aggregate fixture", () => {
        const key = Symbol.for(${JSON.stringify(symbol)});
        assert.equal(globalThis[key], "first-completed");
        delete globalThis[key];
      });
    `, { mode: 0o600 });
    const result = spawnSync("/bin/zsh", ["-f", runner, "--test", first, second], rootWatchdogChildOptions({
      cwd: process.cwd(), encoding: "utf8", timeout: 20_000
    }));
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /JavaScript event accounting passed: 2 exact tests, 0 intentional skips\./u);
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
