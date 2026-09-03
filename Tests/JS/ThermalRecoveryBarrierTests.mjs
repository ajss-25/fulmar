import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const project = new URL("../..", import.meta.url).pathname.replace(/\/$/u, "");
const barrier = join(project, "scripts", "wait-for-thermal-recovery.sh");
const compiler = join(project, "scripts", "compile-thermal-recovery-probe.sh");
const fixtureAuthorization = "enabled-by-behavioral-test";
let testRoot;
let probe;

before(async () => {
  testRoot = await mkdtemp(join(tmpdir(), "fulmar-thermal-probe-tests-"));
  probe = join(testRoot, "thermal-recovery-probe");
  const compiled = spawnSync("/bin/zsh", ["-f", compiler, probe], {
    cwd: project,
    encoding: "utf8",
    timeout: 120_000
  });
  assert.equal(compiled.error, undefined, compiled.error?.message);
  assert.equal(compiled.status, 0, compiled.stderr);
});

after(async () => {
  if (testRoot) await rm(testRoot, { recursive: true, force: true });
});

function runScenario(scenario, stage = "project") {
  return spawnSync("/bin/bash", ["-p", barrier, "--test-probe", probe, scenario, stage], {
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1: fixtureAuthorization
    }
  });
}

function reportedProbePIDs(output) {
  return [...output.matchAll(/^TEST_PROBE_PID=([0-9]+)$/gmu)].map((match) => Number(match[1]));
}

function runNativeSupervisor(scenario, index = 0) {
  return spawnSync(probe, ["--test-supervise-sample", scenario, String(index)], {
    encoding: "utf8",
    timeout: 5_000
  });
}

function assertPIDGone(pid) {
  assert.throws(
    () => process.kill(pid, 0),
    (error) => error?.code === "ESRCH",
    `probe child ${pid} survived cleanup`
  );
}

test("native supervisor returns normal and invalid sample payloads and reaps each exact child", () => {
  const normal = runNativeSupervisor("nominal");
  assert.equal(normal.error, undefined, normal.error?.message);
  assert.equal(normal.status, 0, normal.stderr);
  assert.match(normal.stdout, /^fulmar-thermal-sample-v1 1000000 0 [0-9]+\n$/u);
  for (const pid of reportedProbePIDs(normal.stderr)) assertPIDGone(pid);

  const invalid = runNativeSupervisor("invalid", 60);
  assert.equal(invalid.status, 0, invalid.stderr);
  assert.match(invalid.stdout, /^fulmar-thermal-sample-v1 1120000 not-a-thermal-state [0-9]+\n$/u);
  for (const pid of reportedProbePIDs(invalid.stderr)) assertPIDGone(pid);
});

test("native watchdog bounds and reaps both running and stopped children", () => {
  for (const scenario of ["hung-once", "stopped-once"]) {
    const started = performance.now();
    const result = runNativeSupervisor(scenario, 1);
    const duration = performance.now() - started;
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 124, result.stderr);
    assert.match(result.stderr, /exceeded its one-second watchdog/u);
    assert.ok(duration < 4_000, `${scenario} watchdog exceeded its bound: ${duration}ms`);
    const pids = reportedProbePIDs(result.stderr);
    assert.equal(pids.length, 1, result.stderr);
    for (const pid of pids) assertPIDGone(pid);
  }
});

test("native supervisor preserves HUP, INT, and TERM statuses after reaping its exact child", async () => {
  for (const [signal, expectedCode] of [["SIGHUP", 129], ["SIGINT", 130], ["SIGTERM", 143]]) {
    const child = spawn(probe, ["--test-supervise-sample", "hung-once", "1"], {
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stderr = "";
    let probePID;
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      const [reported] = reportedProbePIDs(stderr);
      if (reported && probePID === undefined) {
        probePID = reported;
        child.kill(signal);
      }
    });
    const completion = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`${signal} supervisor cleanup timed out; stderr=${stderr}`));
      }, 5_000);
      child.once("close", (code, closeSignal) => {
        clearTimeout(timer);
        resolve({ code, signal: closeSignal });
      });
    });
    assert.ok(probePID, `${signal} did not report its exact child; stderr=${stderr}`);
    assert.deepEqual(completion, { code: expectedCode, signal: null });
    assertPIDGone(probePID);
  }
});

test("nominal recovery requires the full 120-second idle period", () => {
  const result = runScenario("nominal", "app-owned-generation");
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /proved 120s idle with 120s continuously nominal/u);
});

test("non-nominal and invalid readings each reset the uninterrupted nominal proof", () => {
  for (const [scenario, stage] of [["reset", "bash"], ["invalid", "filesystem"]]) {
    const result = runScenario(scenario, stage);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`after ${stage} proved 182s idle with 60s continuously nominal`, "u"));
  }
});

test("forward and backward wall-clock changes cannot alter monotonic recovery", () => {
  for (const scenario of ["wall-forward", "wall-backward"]) {
    const result = runScenario(scenario);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /proved 120s idle with 120s continuously nominal/u);
  }
});

test("a backward monotonic reading is infrastructure failure, while a proven deadline is deferral", () => {
  const backwards = runScenario("monotonic-backward");
  assert.equal(backwards.status, 1);
  assert.match(backwards.stderr, /monotonic probe moved backwards/u);

  const timeout = runScenario("timeout");
  assert.equal(timeout.status, 75);
  assert.match(timeout.stderr, /could not prove 60s continuously nominal within 600s/u);
});

test("a hung thermal probe is killed, reaped, treated as invalid, and recovery continues", () => {
  const result = runScenario("hung-once");
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /exceeded its one-second watchdog/u);
  assert.match(result.stdout, /proved 120s idle with 116s continuously nominal/u);
  for (const pid of reportedProbePIDs(result.stderr)) assertPIDGone(pid);
});

test("a stopped thermal probe stays tracked, is force-cleaned within the watchdog bound, and recovery continues", () => {
  const started = performance.now();
  const result = runScenario("stopped-once");
  const duration = performance.now() - started;
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /exceeded its one-second watchdog/u);
  assert.match(result.stdout, /proved 120s idle with [0-9]+s continuously nominal/u);
  assert.ok(duration < 10_000, `stopped-probe cleanup exceeded its bound: ${duration}ms`);
  for (const pid of reportedProbePIDs(result.stderr)) assertPIDGone(pid);
});

test("test probe mode is double-explicit, suppresses startup injection, and cannot be selected by the live release path", async () => {
  const shellEnvironment = join(testRoot, "hostile-bash-environment.sh");
  const environmentMarker = join(testRoot, "bash-environment-executed");
  const functionMarker = join(testRoot, "exported-function-executed");
  await writeFile(
    shellEnvironment,
    'printf injected > "$FULMAR_BASH_ENV_MARKER"\nfulmar_injected\n',
    { mode: 0o600 }
  );
  const hostileShell = {
    BASH_ENV: shellEnvironment,
    ENV: shellEnvironment,
    FULMAR_BASH_ENV_MARKER: environmentMarker,
    FULMAR_EXPORTED_FUNCTION_MARKER: functionMarker,
    "BASH_FUNC_fulmar_injected%%":
      '() { printf injected > "$FULMAR_EXPORTED_FUNCTION_MARKER"; }'
  };
  const unauthorized = spawnSync("/bin/bash", ["-p", barrier, "--test-probe", probe, "nominal", "project"], {
    encoding: "utf8",
    timeout: 5_000,
    env: { ...process.env, ...hostileShell, FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1: "wrong" }
  });
  assert.equal(unauthorized.status, 64);
  assert.match(unauthorized.stderr, /requires explicit authorization/u);

  const liveWithMarker = spawnSync("/bin/bash", ["-p", barrier, "--live", probe, "project"], {
    encoding: "utf8",
    timeout: 5_000,
    env: {
      ...process.env,
      ...hostileShell,
      FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1: fixtureAuthorization
    }
  });
  assert.equal(liveWithMarker.status, 64);
  assert.match(liveWithMarker.stderr, /rejects test-probe authorization/u);
  assert.equal(existsSync(environmentMarker), false, "the thermal barrier sourced hostile BASH_ENV bytes");
  assert.equal(existsSync(functionMarker), false, "the thermal barrier imported a hostile Bash function");
});

test("release sequencing compiles one monotonic probe and cools after every real workload", async () => {
  const [release, route, generation, policy, nativeProbe, nativeSupervisor] = await Promise.all([
    readFile(join(project, "scripts", "verify-release.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-dsh-qwen-route.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-app-owned-ollama-generation.sh"), "utf8"),
    readFile(barrier, "utf8"),
    readFile(join(project, "Tools", "ThermalRecoveryProbe", "main.swift"), "utf8"),
    readFile(join(project, "Tools", "ThermalRecoveryProbe", "supervisor.c"), "utf8")
  ]);
  const orderedCommands = [
    'compile-thermal-recovery-probe.sh" "$THERMAL_RECOVERY_PROBE"',
    'verify-app-owned-ollama-generation.sh" "$APP_DIR"',
    '--live "$THERMAL_RECOVERY_PROBE" app-owned-generation',
    'verify-dsh-qwen-route.sh" "$APP_DIR" bash',
    '--live "$THERMAL_RECOVERY_PROBE" bash',
    'verify-dsh-qwen-route.sh" "$APP_DIR" filesystem',
    '--live "$THERMAL_RECOVERY_PROBE" filesystem',
    'verify-dsh-qwen-route.sh" "$APP_DIR" project',
    '--live "$THERMAL_RECOVERY_PROBE" project'
  ];
  let cursor = -1;
  for (const command of orderedCommands) {
    const next = release.indexOf(command, cursor + 1);
    assert.ok(next > cursor, `missing or misordered release command: ${command}`);
    cursor = next;
  }
  assert.equal((release.match(/wait-for-thermal-recovery\.sh/gu) ?? []).length, 4);
  assert.equal(
    (release.match(/\/bin\/bash -p "\$PROJECT_DIR\/scripts\/wait-for-thermal-recovery\.sh"/gu) ?? []).length,
    4
  );
  assert.equal((release.match(/-u FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1/gu) ?? []).length, 4);
  assert.match(nativeProbe, /mach_continuous_time\(\)/u);
  assert.match(nativeProbe, /ProcessInfo\.processInfo\.thermalState/u);
  assert.match(nativeSupervisor, /posix_spawn\(/u);
  assert.match(nativeSupervisor, /mach_continuous_time\(\)/u);
  assert.match(nativeSupervisor, /waitpid\(child, status, WNOHANG\)/u);
  assert.match(nativeSupervisor, /kill\(child, SIGTERM\)/u);
  assert.match(nativeSupervisor, /kill\(child, SIGKILL\)/u);
  assert.match(nativeSupervisor, /volatile sig_atomic_t received_signal/u);
  assert.match(policy, /MINIMUM_IDLE_MILLISECONDS=120000/u);
  assert.match(policy, /^#!\/bin\/bash -p\n/u);
  assert.match(policy, /STABLE_NOMINAL_MILLISECONDS=60000/u);
  assert.match(policy, /SAMPLE_INTERVAL_SECONDS=2/u);
  assert.match(policy, /MAXIMUM_WAIT_MILLISECONDS=600000/u);
  assert.match(policy, /trap cleanup EXIT/u);
  assert.match(policy, /run_probe --supervise-sample/u);
  assert.match(policy, /run_probe --supervise-monotonic/u);
  assert.doesNotMatch(policy, /jobs -p|jobs -pr|PROBE_JOB_SPEC|probe_job_is_|builtin kill|wait "\$pid"/u);
  assert.doesNotMatch(policy, /\bSECONDS\b|\/bin\/date|\/usr\/bin\/date/u);

  for (const gate of [route, generation]) {
    assert.match(gate, /THERMAL_ADMISSION_SAMPLES=5/u);
    assert.match(gate, /THERMAL_ADMISSION_INTERVAL_SECONDS=2/u);
    assert.match(gate, /if \[\[ "\$thermal_state" -ge 1 \]\]; then/u);
    assert.match(gate, /exit 75/u);
  }
  assert.doesNotMatch(release, /verify-dsh-qwen-route\.sh[^\n]*(?:\|\||&&|set \+e)/u);
  assert.doesNotMatch(release, /verify-app-owned-ollama-generation\.sh[^\n]*(?:\|\||&&|set \+e)/u);
});
