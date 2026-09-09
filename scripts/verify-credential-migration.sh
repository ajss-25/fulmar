#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
if [[ -n "${1-}" ]]; then
  HELPER="$1"
  CONTENTS_DIR="${HELPER:h:h}"
  NODE="$CONTENTS_DIR/Resources/Runtime/node"
  MIGRATOR="$CONTENTS_DIR/Resources/MigrateCredentials.mjs"
  YAML_MODULE="$CONTENTS_DIR/Resources/Runtime/dsh/node_modules/yaml/dist/index.js"
else
  NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
  HELPER="$PROJECT_DIR/.build/debug/LocalHarnessCredentialHelper"
  # SwiftPM publishes `.build/debug` as an architecture-specific symlink on
  # macOS. Resolve that reviewed alias once before the canonical-path guard;
  # the guard below still rejects every nonregular or further-linked binary.
  HELPER="${HELPER:A}"
  MIGRATOR="$PROJECT_DIR/Resources/MigrateCredentials.mjs"
  YAML_MODULE="$PROJECT_DIR/VendorRuntime/node_modules/yaml/dist/index.js"
fi
for executable in "$NODE" "$HELPER"; do
  [[ "$executable" == /* && "${executable:A}" == "$executable" \
     && -f "$executable" && ! -L "$executable" && -x "$executable" ]] || {
    print -u2 "Credential migration verification requires one canonical, regular candidate executable."
    exit 1
  }
done
for resource in "$MIGRATOR" "$YAML_MODULE"; do
  [[ "$resource" == /* && "${resource:A}" == "$resource" \
     && -f "$resource" && ! -L "$resource" ]] || {
    print -u2 "Credential migration verification requires canonical candidate resources."
    exit 1
  }
done
TEMP_DIR="$(mktemp -d /private/tmp/local-harness-credential-migration.XXXXXX)"
SOURCE="$TEMP_DIR/.credentials.yaml"
MIGRATION_OUTPUT="$TEMP_DIR/migration-result.json"
CANARY_SUFFIX="$(uuidgen | tr -d '-')"
REF="LOCAL_HARNESS_MIGRATION_${CANARY_SUFFIX}"
RECORD="local-harness/migration-${CANARY_SUFFIX}"
REF_VALUE="reference-canary-${CANARY_SUFFIX}"
RECORD_VALUE="record-canary-${CANARY_SUFFIX}"

cleanup() {
  "$HELPER" unset "$REF" >/dev/null 2>&1 || true
  "$HELPER" unset-record "$RECORD" >/dev/null 2>&1 || true
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

/bin/zsh -f "$PROJECT_DIR/scripts/run-js-tests.sh" --test "$PROJECT_DIR/Tests/JS/CredentialMigrationTests.mjs"

"$NODE" -e '
  const fs=require("node:fs");
  const [path,ref,record,refValue,recordValue]=process.argv.slice(1);
  const yaml=`version: 1\nrefs:\n  ${ref}: ${JSON.stringify(refValue)}\nrecords:\n  ${record}:\n    kind: api-key\n    key: ${JSON.stringify(recordValue)}\n`;
  fs.writeFileSync(path,yaml,{mode:0o600,flag:"wx"});
' "$SOURCE" "$REF" "$RECORD" "$REF_VALUE" "$RECORD_VALUE"
chmod 600 "$SOURCE"
"$NODE" -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const { spawnSync } = require("node:child_process");
  const [node, migrator, source, helper, yaml, output] = process.argv.slice(1);
  const marker = "FULMAR_CREDENTIAL_MIGRATION_LEASE_FD_V1";
  const inheritedDescriptor = 198;
  const lease = path.join(path.dirname(source), ".fulmar-credential-migration.lock");
  fs.writeFileSync(lease, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
  fs.chmodSync(lease, 0o600);
  const descriptor = fs.openSync(lease, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
  const stdio = ["ignore", "pipe", "pipe"];
  stdio.length = inheritedDescriptor + 1;
  for (let index = 3; index < inheritedDescriptor; index += 1) stdio[index] = null;
  stdio[inheritedDescriptor] = descriptor;
  let result;
  try {
    result = spawnSync(node, [migrator, source, helper, yaml], {
      env: {
        HOME: process.env.HOME,
        USER: process.env.USER,
        LOGNAME: process.env.LOGNAME,
        PATH: "/usr/bin:/bin",
        LANG: "en_US.UTF-8",
        [marker]: String(inheritedDescriptor)
      },
      stdio,
      timeout: 60_000,
      maxBuffer: 128 * 1024
    });
  } finally {
    fs.closeSync(descriptor);
  }
  if (result.error) throw result.error;
  fs.writeFileSync(output, result.stdout ?? Buffer.alloc(0), { mode: 0o600 });
  if (result.stderr?.length) process.stderr.write(result.stderr);
  if (result.status !== 0) process.exit(result.status ?? 2);
' "$NODE" "$MIGRATOR" "$SOURCE" "$HELPER" "$YAML_MODULE" "$MIGRATION_OUTPUT"
[[ -f "$MIGRATION_OUTPUT" && ! -L "$MIGRATION_OUTPUT" \
   && "$(/usr/bin/stat -f '%z' "$MIGRATION_OUTPUT")" -le 128 \
   && "$(<"$MIGRATION_OUTPUT")" == '{"references":1,"records":1}' ]]
[[ -f "$SOURCE" && ! -L "$SOURCE" \
   && "$(/usr/bin/stat -f '%Lp:%z' "$SOURCE")" == '600:0' ]]
[[ "$("$HELPER" get "$REF")" == "$REF_VALUE" ]]
[[ "$("$HELPER" get-record "$RECORD")" == "{\"kind\":\"api-key\",\"key\":\"$RECORD_VALUE\"}" ]]

echo "Credential migration verification passed: exact fd-198 lease attestation, helper isolation, transactional failure matrix, exact Keychain readback, and descriptor-bound plaintext scrubbing."
