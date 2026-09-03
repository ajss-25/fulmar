#!/bin/zsh -f

# Select an installed macOS SDK that the active Swift compiler can actually
# import. Apple may update the Command Line Tools compiler and SDK payload in
# separate stages; trusting the MacOSX.sdk symlink alone can then make even a
# valid package manifest uncompilable. An explicit SDKROOT remains supported
# for controlled CI, but it must pass the same import probe.

select_local_harness_swift_sdk() {
  local developer_root candidate existing probe_cache candidate_is_present
  typeset -a candidates
  developer_root="$(xcode-select -p)"
  probe_cache="${TMPDIR%/}/local-harness-swift-sdk-probe-cache"
  mkdir -p "$probe_cache"

  candidates=()
  if [[ -n "${SDKROOT:-}" ]]; then
    candidates+=("$SDKROOT")
  else
    candidates+=("$(xcrun --sdk macosx --show-sdk-path)")
    while IFS= read -r candidate; do
      candidate_is_present=0
      for existing in "${candidates[@]}"; do
        [[ "$existing" == "$candidate" ]] && candidate_is_present=1
      done
      (( candidate_is_present == 1 )) || candidates+=("$candidate")
    done < <(find "$developer_root/SDKs" -maxdepth 1 -type d -name 'MacOSX*.sdk' -print | sort -r)
  fi

  for candidate in "${candidates[@]}"; do
    [[ -d "$candidate" ]] || continue
    if print -r -- 'import Foundation' | env SDKROOT="$candidate" \
      swiftc -sdk "$candidate" -module-cache-path "$probe_cache" -typecheck - \
      >/dev/null 2>&1; then
      export SDKROOT="$candidate"
      return 0
    fi
  done

  echo "No installed macOS SDK is compatible with the active Swift compiler." >&2
  return 1
}

select_local_harness_swift_sdk
