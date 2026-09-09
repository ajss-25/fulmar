#!/bin/sh -p
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
EXPECTED_NODE_VERSION="v22.23.1"
PINNED_NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"

canonical_executable() {
  fulmar_candidate=$1
  case "$fulmar_candidate" in
    /*) fulmar_path=$fulmar_candidate ;;
    *) fulmar_path="$(pwd -P)/$fulmar_candidate" ;;
  esac
  fulmar_hops=0
  while [ -L "$fulmar_path" ]; do
    fulmar_hops=$((fulmar_hops + 1))
    [ "$fulmar_hops" -le 32 ] || return 1
    fulmar_link=$(/usr/bin/readlink "$fulmar_path") || return 1
    case "$fulmar_link" in
      /*) fulmar_path=$fulmar_link ;;
      *) fulmar_path="$(/usr/bin/dirname -- "$fulmar_path")/$fulmar_link" ;;
    esac
  done
  fulmar_directory=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$fulmar_path")" 2>/dev/null && pwd -P) || return 1
  fulmar_path="$fulmar_directory/$(/usr/bin/basename -- "$fulmar_path")"
  [ -f "$fulmar_path" ] && [ ! -L "$fulmar_path" ] && [ -x "$fulmar_path" ] || return 1
  printf '%s\n' "$fulmar_path"
}

if [ -f "$PINNED_NODE" ] && [ ! -L "$PINNED_NODE" ] && [ -x "$PINNED_NODE" ]; then
  NODE_SHA_KEY="nodeSHA256"
  NODE_BIN=$(canonical_executable "$PINNED_NODE") || {
    printf '%s\n' "Fulmar static scan found an unsafe bundled Node executable." >&2
    exit 1
  }
else
  case "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" in
    Linux:x86_64) NODE_SHA_KEY="nodeLinuxX64SHA256" ;;
    *)
      printf '%s\n' "Fulmar static scan has no reviewed Node provenance for this runner." >&2
      exit 1
      ;;
  esac
  NODE_CANDIDATE=$(command -v node 2>/dev/null || true)
  [ -n "$NODE_CANDIDATE" ] || {
    printf '%s\n' "Fulmar static scan requires Node 22.23.1." >&2
    exit 1
  }
  NODE_BIN=$(canonical_executable "$NODE_CANDIDATE") || {
    printf '%s\n' "Fulmar static scan found an unsafe Node executable." >&2
    exit 1
  }
fi

[ -f "$RELEASE_IDENTITY" ] && [ ! -L "$RELEASE_IDENTITY" ] || {
  printf '%s\n' "Fulmar static scan found an unsafe release identity." >&2
  exit 1
}
EXPECTED_NODE_SHA256=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/sed -nE \
  "s/^[[:space:]]*\"$NODE_SHA_KEY\": \"([a-f0-9]{64})\",?$/\\1/p" \
  "$RELEASE_IDENTITY")
case "$EXPECTED_NODE_SHA256" in
  *[!a-f0-9]*|'')
    printf '%s\n' "Fulmar static scan found an invalid Node provenance pin." >&2
    exit 1
    ;;
esac
[ "${#EXPECTED_NODE_SHA256}" -eq 64 ] || {
  printf '%s\n' "Fulmar static scan found an invalid Node provenance pin." >&2
  exit 1
}

if [ -x /usr/bin/shasum ]; then
  ACTUAL_NODE_SHA256=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/shasum -a 256 "$NODE_BIN" | /usr/bin/awk '{ print $1 }')
elif [ -x /usr/bin/sha256sum ]; then
  ACTUAL_NODE_SHA256=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/sha256sum "$NODE_BIN" | /usr/bin/awk '{ print $1 }')
else
  printf '%s\n' "Fulmar static scan cannot attest the Node executable." >&2
  exit 1
fi
[ "$ACTUAL_NODE_SHA256" = "$EXPECTED_NODE_SHA256" ] || {
  printf '%s\n' "Fulmar static scan rejected an unreviewed Node executable." >&2
  exit 1
}

SEMGREP_CANDIDATE=$(command -v semgrep 2>/dev/null || true)
[ -n "$SEMGREP_CANDIDATE" ] || {
  printf '%s\n' "Fulmar static scan requires Semgrep 1.135.0." >&2
  exit 1
}
SEMGREP_BIN=$(canonical_executable "$SEMGREP_CANDIDATE") || {
  printf '%s\n' "Fulmar static scan found an unsafe Semgrep executable." >&2
  exit 1
}

ACTUAL_NODE_VERSION=$(/usr/bin/env -i \
  PATH="$SAFE_PATH" LANG=C LC_ALL=C TMPDIR=/tmp \
  "$NODE_BIN" --version)
[ "$ACTUAL_NODE_VERSION" = "$EXPECTED_NODE_VERSION" ] || {
  printf '%s\n' "Fulmar static scan requires Node 22.23.1; found ${ACTUAL_NODE_VERSION:-unknown}." >&2
  exit 1
}

SYSTEM_TEMP=/tmp
[ ! -d /private/tmp ] || SYSTEM_TEMP=/private/tmp

# Node loader/search injection, proxies, custom trust stores, package-manager
# configuration, cloud credentials, and Semgrep authentication are deliberately
# absent before the first byte of a rule response is requested. The JavaScript
# runner independently checks the same boundary before it performs network I/O.
exec /usr/bin/env -i \
  PATH="$SAFE_PATH" \
  HOME="$SYSTEM_TEMP" \
  TMPDIR="$SYSTEM_TEMP" \
  LANG=C LC_ALL=C \
  SEMGREP_BIN="$SEMGREP_BIN" \
  "$NODE_BIN" "$PROJECT_DIR/scripts/run-static-security-scan.mjs"
