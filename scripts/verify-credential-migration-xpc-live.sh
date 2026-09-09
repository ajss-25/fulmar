#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-}"
[[ -n "$APP_DIR" ]] || {
  print -u2 "usage: verify-credential-migration-xpc-live.sh <canonical Fulmar.app>"
  exit 1
}
EXECUTABLE="$APP_DIR/Contents/MacOS/LocalHarness"
SERVICE_EXECUTABLE="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
PROCESS_MONITOR="$PROJECT_DIR/scripts/credential-xpc-live-process-monitor.mjs"
TIMEOUT_SECONDS=15
EXPECTED='FULMAR_CREDENTIAL_XPC_ACCEPTANCE_OK'
PROCESS_EXPECTED='FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK'

[[ -d "$APP_DIR" && ! -L "$APP_DIR" && "${APP_DIR:A}" == "$APP_DIR" \
   && -f "$EXECUTABLE" && ! -L "$EXECUTABLE" && -x "$EXECUTABLE" ]] || {
  print -u2 "Credential XPC live acceptance requires one canonical packaged app."
  exit 1
}
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration-xpc.sh" "$APP_DIR"

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-credential-xpc-live.XXXXXX)"
ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$TEMP_ROOT")"
EXPECTED_UID="$(/usr/bin/id -u)"
PID=0
MONITOR_PID=0
PHASE_DIAGNOSTIC_CLOCK=unavailable
if zmodload zsh/datetime 2>/dev/null; then
  PHASE_DIAGNOSTIC_CLOCK=ready
fi
collect_migration_phase_diagnostics() {
  # Never query on success or before the existing exact-process drain succeeds.
  [[ "${CLIENT_CONTRACT:-}" == failed && "${MONITOR_STATUS:-}" == 0 ]] || return 0
  [[ "$PHASE_DIAGNOSTIC_CLOCK" == ready ]] || {
    print -u2 'FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=unavailable'
    return 0
  }
  # This is an inherited logical stage, not a nested process-group owner.
  # The existing root owns final descendant drain. Its RSS policy is unchanged.
  # Five seconds bounds command work; existing bounded TERM/KILL reaping follows.
  # An earlier finish budget keeps either inner spawn within that outer budget.
  local -i phase_finish_ms
  phase_finish_ms=$(( EPOCHREALTIME * 1000 + 4000 ))
  "$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
    --seconds 5 --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 --label "Credential XPC phase diagnostic" -- \
    "$NODE" --input-type=module - "$PROJECT_DIR" "$TEMP_ROOT" "$ROOT_IDENTITY" \
    "$SERVICE_EXECUTABLE" "${PHASE_LOG_STARTED:-}" "${PHASE_LOG_ENDED:-}" "$phase_finish_ms" \
    2>/dev/null <<'FULMAR_MIGRATION_PHASE_DIAGNOSTIC' || \
    print -u2 'FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=unavailable'
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [project, root, rootIdentity, executable, rawStart, rawEnd, rawFinish] = process.argv.slice(2);
const unavailable = () => process.stdout.write("FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=unavailable\n");
try {
  if (!/^\d{13}$/u.test(rawFinish) || Number(rawFinish) > Date.now() + 4_000) throw 0;
  function remainingSpawnBudget(maximum) {
    const remaining = Number(rawFinish) - Date.now() - 250;
    if (!Number.isSafeInteger(remaining) || remaining < 1) throw 0;
    return Math.min(maximum, remaining);
  }
  remainingSpawnBudget(500);
  const { readAttestedRegularFileSync } = await import(pathToFileURL(join(project, "scripts/attested-regular-file.mjs")));
  const directory = lstatSync(root);
  if (!directory.isDirectory() || directory.isSymbolicLink() || realpathSync(root) !== root
      || directory.uid !== process.getuid() || (directory.mode & 0o777) !== 0o700
      || `${directory.dev}:${directory.ino}:${directory.uid}:700` !== rootIdentity) throw 0;
  function readPrivate(leaf, minimumBytes, maximumBytes) {
    const artifact = readAttestedRegularFileSync(join(root, leaf), {
      minimumBytes, maximumBytes, requireCurrentUser: true,
      requirePrivateMode: true, requireSingleLink: true, requireCanonicalPath: true
    });
    if ((artifact.metadata.mode & 0o777n) !== 0o600n) throw 0;
    return artifact.bytes;
  }
  if (readPrivate("monitor.stdout", 1, 128).toString("utf8") !== "FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK\n"
      || readPrivate("monitor.stderr", 0, 0).length !== 0
      || readPrivate("client.done", 5, 5).toString("utf8") !== "done\n") throw 0;
  const evidence = readPrivate("service.evidence", 64, 256);
  const match = /^pid=([1-9][0-9]{0,9})\nstarted=([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\ncdhash=([a-f0-9]{40,128})\n$/u.exec(evidence.toString("utf8"));
  if (!match || Number(match[1]) <= 1 || !/^\d{10}$/u.test(rawStart) || !/^\d{10}$/u.test(rawEnd)) throw 0;
  const start = Number(rawStart), end = Number(rawEnd) + 1;
  if (end <= start || end - start > 30 || end * 1_000 > Date.now() + 1_000
      || Date.now() - end * 1_000 > 30_000) throw 0;
  // ps lstart is system-local, second-resolution text. Parse it in the same
  // clean system timezone, not through an inherited TZ or a guessed UTC offset.
  const parsedStart = spawnSync("/bin/date", ["-j", "-f", "%a %b %e %T %Y", match[2], "+%s"], {
    encoding: "utf8", timeout: remainingSpawnBudget(500), killSignal: "SIGKILL", maxBuffer: 1_024,
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C" }
  });
  if (parsedStart.status !== 0 || parsedStart.signal || parsedStart.error
      || parsedStart.stderr !== "" || !/^\d{10}\n$/u.test(parsedStart.stdout)) throw 0;
  const serviceStart = Number(parsedStart.stdout.trim());
  if (serviceStart < start - 1 || serviceStart >= end) throw 0;
  const subsystem = "com.angadjairath.localharness.migration-diagnostic";
  const category = "xpc-phase";
  // Fixed candidate paths need no general predicate-language escaping. Decline
  // unusual quoting/control bytes instead of broadening the historical query.
  if (!executable.startsWith("/") || /["\\\x00-\x1f\x7f]/u.test(executable)) throw 0;
  const phases = new Set([
    "service-startup", "service-validation-entered", "service-validation-returned",
    "helper-validation-entered", "helper-validation-returned",
    "application-validation-entered", "application-validation-returned",
    "listener-resume-invoked", "listener-resume-returned", "connection-entered", "request-entered", "acceptance-entered",
    "acceptance-metadata-entered", "acceptance-metadata-returned",
    "acceptance-reply-invoked", "acceptance-reply-returned"
  ]);
  const query = spawnSync("/usr/bin/log", ["show", "--style", "json", "--color", "none", "--no-pager",
    "--start", `@${start}`, "--end", `@${end}`,
    "--predicate", `processIdentifier == ${Number(match[1])} AND processImagePath == "${executable}" AND subsystem == "${subsystem}" AND category == "${category}"`
  ], { encoding: "utf8", timeout: remainingSpawnBudget(2_000), killSignal: "SIGKILL", maxBuffer: 128 * 1_024,
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } });
  if (query.status !== 0 || query.signal || query.error || query.stderr !== ""
      || Buffer.byteLength(query.stdout ?? "") > 128 * 1_024) throw 0;
  const records = JSON.parse(query.stdout);
  if (!Array.isArray(records) || records.length > 64) throw 0;
  const selected = [];
  for (const record of records) {
    if (!record || record.eventType !== "logEvent" || record.processID !== Number(match[1])
        || record.processImagePath !== executable || record.subsystem !== subsystem
        || record.category !== category || !phases.has(record.eventMessage)
        || typeof record.timestamp !== "string"
        || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{1,9}[+-]\d{4}$/u.test(record.timestamp)) throw 0;
    const milliseconds = Date.parse(record.timestamp.replace(" ", "T"));
    if (!Number.isFinite(milliseconds) || milliseconds < Math.max(start, serviceStart) * 1_000
        || milliseconds >= end * 1_000) throw 0;
    selected.push(record.eventMessage);
  }
  // This digest binds the monitor's private evidence without disclosing it.
  // Historical log PID/path/time correlation is NOT independent CDHash or
  // process-instance attestation; PID reuse and dropped events remain possible.
  const digest = createHash("sha256").update(evidence).digest("hex");
  process.stdout.write(`FULMAR_CREDENTIAL_XPC_PHASE_EVIDENCE_SHA256=${digest}\n`);
  process.stdout.write("FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=historical-correlation-only\n");
  if (selected.length === 0) process.stdout.write("FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=no-records\n");
  for (const phase of selected) process.stdout.write(`FULMAR_CREDENTIAL_XPC_PHASE=${phase}\n`);
} catch { unavailable(); }
FULMAR_MIGRATION_PHASE_DIAGNOSTIC
}

cleanup() {
  local prior_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( PID > 1 )) && /bin/kill -0 "$PID" 2>/dev/null; then
    /bin/kill -TERM "$PID" 2>/dev/null
    /bin/sleep 0.1
    /bin/kill -KILL "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
  if (( MONITOR_PID > 1 )) && /bin/kill -0 "$MONITOR_PID" 2>/dev/null; then
    /bin/kill -TERM "$MONITOR_PID" 2>/dev/null
    /bin/sleep 0.1
    /bin/kill -KILL "$MONITOR_PID" 2>/dev/null
    wait "$MONITOR_PID" 2>/dev/null
  fi
  if [[ -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" && "${TEMP_ROOT:A}" == "$TEMP_ROOT" \
     && "$TEMP_ROOT" == /private/tmp/fulmar-credential-xpc-live.* \
     && "$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$TEMP_ROOT" 2>/dev/null)" == "$ROOT_IDENTITY" \
     && "$ROOT_IDENTITY" == *":$EXPECTED_UID:700" ]]; then
    if (( prior_status != 0 )); then
      # Secondary diagnostics run only after the original result and exact drain.
      collect_migration_phase_diagnostics || true
      # Retain fixed outcomes in the gate log before deleting private files.
      # Do not disclose arbitrary client output, process arguments or paths.
      print -u2 "Credential migration canary outcome: client_exit=${STATUS:-not-reaped}; monitor_exit=${MONITOR_STATUS:-not-reaped}; client_contract=${CLIENT_CONTRACT:-not-evaluated}."
      local diagnostic="$TEMP_ROOT/monitor.stderr"
      if [[ -f "$diagnostic" && ! -L "$diagnostic" \
         && "$(/usr/bin/stat -f '%u:%Lp:%l' "$diagnostic")" == "$EXPECTED_UID:600:1" \
         && "$(/usr/bin/stat -f '%z' "$diagnostic")" -le 512 ]]; then
        LC_ALL=C /usr/bin/sed -nE '/^Credential XPC exact-process evidence failed \((input-validation|preexisting-service-check|waiting-for-service|recording-service-identity|waiting-for-client|draining-service)\)\.$/p' "$diagnostic" >&2
      fi
    fi
    /bin/rm -rf -- "$TEMP_ROOT"
  else
    print -u2 "Credential XPC live acceptance refused unsafe temporary cleanup."
    prior_status=1
  fi
  exit "$prior_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
STDOUT_FILE="$TEMP_ROOT/stdout"
STDERR_FILE="$TEMP_ROOT/stderr"
DONE_FILE="$TEMP_ROOT/client.done"
READY_FILE="$TEMP_ROOT/monitor.ready"
EVIDENCE_FILE="$TEMP_ROOT/service.evidence"

"$NODE" "$PROCESS_MONITOR" "$SERVICE_EXECUTABLE" "$READY_FILE" "$DONE_FILE" "$EVIDENCE_FILE" \
  >"$TEMP_ROOT/monitor.stdout" 2>"$TEMP_ROOT/monitor.stderr" &
MONITOR_PID=$!
READY_STARTED=$SECONDS
while [[ ! -f "$READY_FILE" ]]; do
  /bin/kill -0 "$MONITOR_PID" 2>/dev/null || exit 1
  (( SECONDS - READY_STARTED < 3 )) || exit 1
  /bin/sleep 0.01
done
[[ ! -L "$READY_FILE" && "$(/usr/bin/stat -f '%u:%Lp:%z' "$READY_FILE")" == "$EXPECTED_UID:600:6" \
   && "$(/bin/cat "$READY_FILE")" == ready ]] || exit 1

PHASE_LOG_STARTED="${EPOCHSECONDS:-}"
"$EXECUTABLE" --credential-migration-xpc-acceptance \
  >"$STDOUT_FILE" 2>"$STDERR_FILE" &
PID=$!
STARTED=$SECONDS
while /bin/kill -0 "$PID" 2>/dev/null; do
  if (( SECONDS - STARTED >= TIMEOUT_SECONDS )); then
    /bin/kill -TERM "$PID" 2>/dev/null || true
    for _ in {1..20}; do
      /bin/kill -0 "$PID" 2>/dev/null || break
      /bin/sleep 0.05
    done
    /bin/kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    print -u2 "Credential XPC live acceptance exceeded its 15-second hard bound."
    exit 1
  fi
  /bin/sleep 0.05
done
set +e
wait "$PID"
STATUS=$?
set -e
PHASE_LOG_ENDED="${EPOCHSECONDS:-}"
PID=0
CLIENT_CONTRACT=failed
if [[ "$STATUS" == 0 && ! -s "$STDERR_FILE" \
   && "$(/bin/cat "$STDOUT_FILE")" == "$EXPECTED" ]]; then
  CLIENT_CONTRACT=satisfied
fi
( set -o noclobber; print -r -- done > "$DONE_FILE" ) || exit 1

MONITOR_STARTED=$SECONDS
while /bin/kill -0 "$MONITOR_PID" 2>/dev/null; do
  if (( SECONDS - MONITOR_STARTED >= 8 )); then
    print -u2 "Credential migration exact-process drain exceeded its hard bound."
    exit 1
  fi
  /bin/sleep 0.05
done
set +e
wait "$MONITOR_PID"
MONITOR_STATUS=$?
set -e
MONITOR_PID=0
[[ "$STATUS" == 0 && ! -s "$STDERR_FILE" \
   && "$(/bin/cat "$STDOUT_FILE")" == "$EXPECTED" ]] || {
  print -u2 "Credential XPC live acceptance failed its exact one-shot contract."
  /bin/cat "$STDERR_FILE" >&2
  exit 1
}
[[ "$MONITOR_STATUS" == 0 && ! -s "$TEMP_ROOT/monitor.stderr" \
   && "$(/bin/cat "$TEMP_ROOT/monitor.stdout")" == "$PROCESS_EXPECTED" \
   && -f "$EVIDENCE_FILE" && ! -L "$EVIDENCE_FILE" \
   && "$(/usr/bin/stat -f '%u:%Lp' "$EVIDENCE_FILE")" == "$EXPECTED_UID:600" \
   && "$(/usr/bin/wc -l < "$EVIDENCE_FILE" | /usr/bin/tr -d ' ')" == 3 \
   && "$(/usr/bin/sed -n '1p' "$EVIDENCE_FILE")" =~ '^pid=[0-9]+$' \
   && "$(/usr/bin/sed -n '3p' "$EVIDENCE_FILE")" =~ '^cdhash=[a-f0-9]{40,128}$' ]] || {
  print -u2 "Credential migration live acceptance lacked exact service identity/drain evidence."
  /bin/cat "$TEMP_ROOT/monitor.stderr" >&2
  exit 1
}

print "Credential migration live XPC acceptance passed without provider references or Keychain values."
