import { existsSync, realpathSync, writeFileSync } from "node:fs";
import {
  createNativeTelemetryLockTransaction,
  createPerformanceTelemetryRecorder
} from "../../Resources/DSHPlugins/performance-profile/index.mjs";

const [helper, applicationSupport, telemetryFile, readyFile, releaseFile, stage] = process.argv.slice(2);
if (![helper, applicationSupport, telemetryFile, readyFile, releaseFile].every(
  (value) => typeof value === "string" && value.length > 0
) || !new Set(["after-load", "before-rename"]).has(stage)) {
  throw new Error("expected helper, telemetry paths, synchronization paths, and a valid pause stage");
}

const pause = async () => {
  writeFileSync(readyFile, "ready", { encoding: "utf8", flag: "wx", mode: 0o600 });
  const deadline = Date.now() + 10_000;
  while (!existsSync(releaseFile)) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for the deterministic writer release");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};

const lockTransaction = createNativeTelemetryLockTransaction(helper, applicationSupport, telemetryFile);
// Foundation standardizes macOS's private temporary alias as `/var`, while
// Node's native realpath spells the same inode `/private/var`. The helper must
// receive Foundation's exact spelling and the JS file guard must receive
// Node's; both lock and mutate the same fixed filesystem nodes.
const nodeTelemetryFile = realpathSync.native(telemetryFile);
const recorder = createPerformanceTelemetryRecorder(nodeTelemetryFile, {
  now: () => 4_000_000,
  uuid: () => "12345678-1234-4abc-8def-1234567890ac",
  lockTransaction,
  ...(stage === "after-load" ? { afterLoadForTesting: pause } : { beforeRenameForTesting: pause })
});

if (recorder === undefined) throw new Error("the telemetry writer transaction was not configured");
const recorded = await recorder.record({
  schemaVersion: 1,
  id: "12345678-1234-4abc-8def-1234567890ac",
  provider: "ollama",
  model: "qwen",
  profile: "balanced",
  startedAtMilliseconds: 3_999_999,
  completedAtMilliseconds: 4_000_000,
  firstTokenAtMilliseconds: 4_000_000,
  elapsedMilliseconds: 1,
  outputTokens: 1,
  outputTokenCountSource: "providerReported",
  outcome: "completed",
  failureCategory: null
});
if (!recorded) throw new Error("the deterministic telemetry write failed");
