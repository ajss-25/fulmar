#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP="${1:-}"
SYMBOL_ROOT="${2:-}"
[[ -d "$APP" && ! -L "$APP" && -d "$SYMBOL_ROOT" && ! -L "$SYMBOL_ROOT" ]] || {
  print -u2 "usage: verify-native-symbol-privacy-adversarial.sh <Fulmar.app> <Fulmar.dSYMs>"
  exit 1
}

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-native-symbol-adversarial.XXXXXX)"
FIXTURE="$TEMP_ROOT/Fulmar.dSYMs"
cleanup() {
  local exit_code="${1:-$?}"
  case "$TEMP_ROOT" in
    /private/tmp/fulmar-native-symbol-adversarial.*) /bin/rm -rf -- "$TEMP_ROOT" ;;
    *) print -u2 "Refusing to remove an invalid adversarial-test root."; return 1 ;;
  esac
  return "$exit_code"
}
on_signal() {
  local exit_code="$1"
  trap - EXIT HUP INT TERM
  cleanup "$exit_code" || true
  exit "$exit_code"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

VERIFIER="$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh"
/bin/zsh -f "$VERIFIER" "$APP" "$SYMBOL_ROOT" >/dev/null

reset_fixture() {
  case "$FIXTURE" in
    /private/tmp/fulmar-native-symbol-adversarial.*/Fulmar.dSYMs) /bin/rm -rf -- "$FIXTURE" ;;
    *) print -u2 "Refusing to reset an invalid symbol fixture."; exit 1 ;;
  esac
  /usr/bin/ditto "$SYMBOL_ROOT" "$FIXTURE"
}

expect_rejected() {
  local label="$1"
  if /bin/zsh -f "$VERIFIER" "$APP" "$FIXTURE" >"$TEMP_ROOT/$label.out" 2>&1; then
    print -u2 "Native-symbol adversarial mutation was accepted: $label"
    exit 1
  fi
}

reset_fixture
/bin/cp "$FIXTURE/LocalHarness.dSYM/Contents/Info.plist" \
  "$FIXTURE/LocalHarness.dSYM/Contents/Resources/unreviewed.txt"
expect_rejected nested-regular-file

reset_fixture
/bin/rm -f "$FIXTURE/LocalHarness.dSYM/Contents/Info.plist"
expect_rejected missing-info-plist

reset_fixture
print -rn -- '/private/tmp/local-harness-swift-build.ATTACK/secret.swift' \
  >> "$FIXTURE/LocalHarness.dSYM/Contents/Resources/DWARF/LocalHarness"
expect_rejected appended-private-path

reset_fixture
/bin/cp "$FIXTURE/LocalHarness.dSYM/Contents/Resources/DWARF/LocalHarness" \
  "$FIXTURE/LocalHarnessCredentialHelper.dSYM/Contents/Resources/DWARF/LocalHarnessCredentialHelper"
expect_rejected swapped-dwarf

reset_fixture
/bin/ln -s /etc/passwd "$FIXTURE/LocalHarness.dSYM/Contents/Resources/unreviewed-link"
expect_rejected nested-symlink

reset_fixture
/bin/rm -rf "$FIXTURE/LocalHarnessUpdateHelper.dSYM"
expect_rejected missing-dsym

reset_fixture
/bin/cp "$FIXTURE/LocalHarness.dSYM/Contents/Info.plist" "$FIXTURE/unreviewed.txt"
expect_rejected root-extra

print "Native-symbol adversarial matrix rejected seven malformed or privacy-leaking dSYM mutations."
