#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 14400 --max-rss-bytes 34359738368 --rss-grace-seconds 15 \
    --emergency-rss-bytes 42949672960 \
    --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "Fulmar two-root reproducibility gate" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The two-root reproducibility gate inherited an invalid root-watchdog capability."
  exit 1
fi

(( $# == 0 )) || {
  print -u2 "usage: verify-two-root-reproducibility.sh"
  exit 64
}
fulmar_root_watchdog_state || {
  print -u2 "The two-root reproducibility gate lost its root-watchdog capability."
  exit 1
}

SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
INVENTORY_TOOL="$PROJECT_DIR/scripts/runtime-inventory.mjs"
REPRODUCIBILITY_TOOL="$PROJECT_DIR/scripts/unsigned-reproducibility-inventory.mjs"
VENDOR_INVENTORY="$PROJECT_DIR/VendorRuntime.inventory.json"
STATIC_SECURITY_SUMMARY="$PROJECT_DIR/build/static-security-summary.json"
REPORT="$PROJECT_DIR/build/two-root-reproducibility-summary.json"

[[ "$PROJECT_DIR" == /* && -d "$PROJECT_DIR" && ! -L "$PROJECT_DIR" \
   && "${PROJECT_DIR:A}" == "$PROJECT_DIR" \
   && -x "$NODE" && ! -L "$NODE" \
   && -f "$INVENTORY_TOOL" && ! -L "$INVENTORY_TOOL" \
   && -f "$REPRODUCIBILITY_TOOL" && ! -L "$REPRODUCIBILITY_TOOL" \
   && -f "$VENDOR_INVENTORY" && ! -L "$VENDOR_INVENTORY" \
   && -f "$STATIC_SECURITY_SUMMARY" && ! -L "$STATIC_SECURITY_SUMMARY" ]] || {
  print -u2 "The two-root reproducibility gate is missing an exact reviewed input."
  exit 1
}
[[ "$(/usr/bin/stat -f '%u' "$PROJECT_DIR")" == "$(/usr/bin/id -u)" \
   && "$(/usr/bin/stat -f '%u:%l' "$STATIC_SECURITY_SUMMARY")" == "$(/usr/bin/id -u):1" ]] || {
  print -u2 "The two-root reproducibility gate received a non-owner-controlled input."
  exit 1
}

SOURCE_TOPLEVEL="$(/usr/bin/git -C "$PROJECT_DIR" rev-parse --show-toplevel)" || {
  print -u2 "The two-root reproducibility gate requires a Git checkout."
  exit 1
}
[[ "$SOURCE_TOPLEVEL" == "$PROJECT_DIR" ]] || {
  print -u2 "The reproducibility source is not the exact Git worktree root."
  exit 1
}
SOURCE_COMMIT="$(/usr/bin/git -C "$PROJECT_DIR" rev-parse --verify 'HEAD^{commit}')" || exit 1
SOURCE_TREE="$(/usr/bin/git -C "$PROJECT_DIR" rev-parse --verify 'HEAD^{tree}')" || exit 1
[[ "${#SOURCE_COMMIT}" == 40 && "$SOURCE_COMMIT" != *[^a-f0-9]* \
   && "${#SOURCE_TREE}" == 40 && "$SOURCE_TREE" != *[^a-f0-9]* ]] || {
  print -u2 "The reproducibility source commit identity is malformed."
  exit 1
}
[[ -z "$(/usr/bin/git -C "$PROJECT_DIR" status --porcelain=v1 --untracked-files=all)" ]] || {
  print -u2 "The two-root reproducibility gate requires one clean committed source tree."
  exit 1
}
/bin/bash -p "$PROJECT_DIR/scripts/verify-tracked-index.sh" "$PROJECT_DIR"

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-two-root-repro.XXXXXX)"
TEMP_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT")" || exit 126
[[ -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" \
   && "$TEMP_ROOT_IDENTITY" == *":$(/usr/bin/id -u):Directory:700" ]] || {
  print -u2 "The two-root reproducibility isolation root is not private."
  exit 126
}

cleanup() {
  local exit_code="${1:-$?}"
  local cleanup_status=0
  if [[ -n "$TEMP_ROOT" ]]; then
    case "$TEMP_ROOT" in
      /private/tmp/fulmar-two-root-repro.??????) ;;
      *) print -u2 "Refusing to remove an invalid reproducibility root."; cleanup_status=126 ;;
    esac
    if (( cleanup_status == 0 )); then
      if [[ -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" \
         && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT" 2>/dev/null)" == "$TEMP_ROOT_IDENTITY" ]]; then
        /bin/rm -rf -- "$TEMP_ROOT" || cleanup_status=126
        [[ ! -e "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]] || cleanup_status=126
      else
        print -u2 "Refusing to remove a changed reproducibility root."
        cleanup_status=126
      fi
    fi
    (( cleanup_status == 0 )) && TEMP_ROOT=""
  fi
  (( cleanup_status == 0 )) || return "$cleanup_status"
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

GIT_HOME="$TEMP_ROOT/git-home"
CHECKOUT_A="$TEMP_ROOT/source-a"
CHECKOUT_B="$TEMP_ROOT/source-root-with-distinct-length-b"
CAPTURE_A="$TEMP_ROOT/capture-a"
CAPTURE_B="$TEMP_ROOT/capture-b"
/bin/mkdir -m 0700 "$GIT_HOME" "$CAPTURE_A" "$CAPTURE_B"

clone_exact_source() {
  local destination="$1"
  (
    umask 022
    /usr/bin/env -i \
      HOME="$GIT_HOME" PATH="$SAFE_PATH" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
      GIT_CONFIG_NOSYSTEM=1 \
      /usr/bin/git -c core.hooksPath=/dev/null clone \
        --no-hardlinks --no-tags --no-checkout --quiet "$PROJECT_DIR" "$destination"
    /usr/bin/env -i \
      HOME="$GIT_HOME" PATH="$SAFE_PATH" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
      GIT_CONFIG_NOSYSTEM=1 \
      /usr/bin/git -C "$destination" -c core.hooksPath=/dev/null \
        checkout --detach --quiet "$SOURCE_COMMIT"
  )
  [[ "$(/usr/bin/git -C "$destination" rev-parse --verify HEAD)" == "$SOURCE_COMMIT" \
     && "$(/usr/bin/git -C "$destination" rev-parse --verify 'HEAD^{tree}')" == "$SOURCE_TREE" \
     && -z "$(/usr/bin/git -C "$destination" status --porcelain=v1 --untracked-files=all)" ]] || {
    print -u2 "A reproducibility clone does not contain the exact committed tree."
    exit 1
  }
  /bin/bash -p "$destination/scripts/verify-tracked-index.sh" "$destination"
}

clone_exact_source "$CHECKOUT_A"
clone_exact_source "$CHECKOUT_B"
[[ "$CHECKOUT_A" != "$CHECKOUT_B" && "${#CHECKOUT_A}" -ne "${#CHECKOUT_B}" ]] || {
  print -u2 "The reproducibility checkouts are not meaningfully distinct."
  exit 1
}

"$NODE" "$INVENTORY_TOOL" verify \
  "$PROJECT_DIR/VendorRuntime" "$VENDOR_INVENTORY" VendorRuntime
for checkout in "$CHECKOUT_A" "$CHECKOUT_B"; do
  # Both builds deliberately consume independent copies of the same already
  # inventory-verified dependency tree. Dependency reconstruction is a separate
  # gate; this gate isolates source/scratch path effects on build products.
  /usr/bin/ditto "$PROJECT_DIR/VendorRuntime" "$checkout/VendorRuntime"
  /bin/mkdir -m 0700 "$checkout/build"
  /bin/cp "$STATIC_SECURITY_SUMMARY" "$checkout/build/static-security-summary.json"
  /bin/chmod 0644 "$checkout/build/static-security-summary.json"
  "$checkout/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node" \
    "$checkout/scripts/runtime-inventory.mjs" verify \
    "$checkout/VendorRuntime" "$checkout/VendorRuntime.inventory.json" VendorRuntime
  [[ "$(/usr/bin/git -C "$checkout" rev-parse --verify 'HEAD^{tree}')" == "$SOURCE_TREE" \
     && -z "$(/usr/bin/git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]] || {
    print -u2 "A prepared reproducibility clone changed its committed source tree."
    exit 1
  }
done

/bin/zsh -f "$CHECKOUT_A/scripts/build-app.sh" --unsigned-reproducibility-root "$CAPTURE_A"
/bin/zsh -f "$CHECKOUT_B/scripts/build-app.sh" --unsigned-reproducibility-root "$CAPTURE_B"

SCRATCH_A="$(/bin/cat "$CAPTURE_A/BuildEvidence/scratch-leaf.txt")"
SCRATCH_B="$(/bin/cat "$CAPTURE_B/BuildEvidence/scratch-leaf.txt")"
[[ "$SCRATCH_A" == local-harness-swift-build.?????? \
   && "$SCRATCH_B" == local-harness-swift-build.?????? \
   && "$SCRATCH_A" != "$SCRATCH_B" ]] || {
  print -u2 "The two compiler invocations did not prove distinct private scratch roots."
  exit 1
}

for evidence_name in \
  source-build-inputs.json \
  toolchain-inventory.json \
  runtime-unsigned-inventory.json \
  runtime-signables.json; do
  /usr/bin/cmp -s \
    "$CAPTURE_A/BuildEvidence/$evidence_name" \
    "$CAPTURE_B/BuildEvidence/$evidence_name" || {
    print -u2 "The two build roots disagree on $evidence_name."
    exit 1
  }
done

"$NODE" "$REPRODUCIBILITY_TOOL" compare-inventories \
  "$CAPTURE_A/BuildEvidence/unsigned-reproducibility-inventory.json" \
  "$CAPTURE_B/BuildEvidence/unsigned-reproducibility-inventory.json" \
  "$SOURCE_COMMIT" "$SOURCE_TREE" \
  "$REPORT"
[[ -f "$REPORT" && ! -L "$REPORT" \
   && "$(/usr/bin/stat -f '%u:%Lp:%l' "$REPORT")" == "$(/usr/bin/id -u):600:1" ]] || {
  print -u2 "The two-root reproducibility summary was not published safely."
  exit 1
}
print -r -- "Two-root reproducibility verified for committed source $SOURCE_COMMIT."
