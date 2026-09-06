#!/bin/zsh -f
set -euo pipefail

APP_DIR="${1:?Fulmar app path is required}"
INFO="$APP_DIR/Contents/Info.plist"
BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$INFO")"
EXECUTABLES=(
  "$APP_DIR:$BUNDLE_ID"
  "$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper:$BUNDLE_ID.credential-helper"
  "$APP_DIR/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc:$BUNDLE_ID.credential-helper"
  "$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc:$BUNDLE_ID.credential-helper"
  "$APP_DIR/Contents/MacOS/LocalHarnessSchedulerHelper:$BUNDLE_ID.scheduler-helper"
  "$APP_DIR/Contents/MacOS/LocalHarnessUpdateHelper:$BUNDLE_ID.update-helper"
  "$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner:$BUNDLE_ID.sandbox-runner"
  "$APP_DIR/Contents/MacOS/LocalHarnessRuntimeLease:$BUNDLE_ID.runtime-lease"
)

family=""
for specification in "${EXECUTABLES[@]}"; do
  executable="${specification%:*}"
  expected_identifier="${specification##*:}"
  details="$(codesign -dvv "$executable" 2>&1)"
  requirement="$(codesign -d -r- "$executable" 2>&1)"
  [[ "$details" != *"Signature=adhoc"* ]] || {
    print -u2 "Stable signing verification rejected an ad-hoc component: $executable"
    exit 1
  }
  [[ "$details" == *"Identifier=$expected_identifier"* ]] || {
    print -u2 "Stable signing identifier mismatch for $executable"
    exit 1
  }

  team="$(print -r -- "$details" | sed -n 's/^TeamIdentifier=//p')"
  if [[ -n "$team" && "$team" != "not set" ]]; then
    component_family="team:$team"
  else
    root_hash="$(print -r -- "$requirement" | sed -n 's/.*certificate root = H"\([0-9a-fA-F]\{40\}\)".*/\1/p')"
    [[ -n "$root_hash" ]] || {
      print -u2 "Stable signing verification could not bind the private certificate for $executable"
      exit 1
    }
    component_family="root:${root_hash:l}"
  fi
  if [[ -z "$family" ]]; then
    family="$component_family"
  elif [[ "$component_family" != "$family" ]]; then
    print -u2 "Stable signing identity changed between Fulmar components."
    exit 1
  fi
done

print -r -- "Stable signing verification passed for Fulmar and all privileged helpers ($family)."
