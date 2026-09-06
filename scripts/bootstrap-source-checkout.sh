#!/bin/zsh -f
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

PROJECT_DIR="${0:A:h:h}"
IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
VENDOR="$PROJECT_DIR/VendorRuntime"

[[ -f "$IDENTITY" && -f "$VENDOR/package.json" && -f "$VENDOR/package-lock.json" ]] || {
  print -u2 "Fulmar source checkout is incomplete."
  exit 1
}

/bin/zsh -f "$PROJECT_DIR/scripts/fetch-node-runtime.sh"

NODE_VERSION="$(plutil -extract runtime.nodeVersion raw -o - "$IDENTITY")"
NODE="$VENDOR/node-v${NODE_VERSION}-darwin-arm64/bin/node"
NPM="$VENDOR/node-v${NODE_VERSION}-darwin-arm64/lib/node_modules/npm/bin/npm-cli.js"

[[ -x "$NODE" && -f "$NPM" ]] || {
  print -u2 "The verified Node bootstrap is unavailable."
  exit 1
}

run_pinned_node() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C LC_ALL=C TMPDIR=/private/tmp \
    "$NODE" "$@"
}

# The bootstrap interpreter may attest npm and the rest of VendorRuntime only
# after the system SHA check in fetch-node-runtime.sh and this independently
# reviewed prefix inventory bind every file in its own distribution.
run_pinned_node "$PROJECT_DIR/scripts/runtime-inventory.mjs" verify-prefix \
  "$VENDOR/node-v${NODE_VERSION}-darwin-arm64" \
  "$PROJECT_DIR/VendorRuntime.inventory.json" \
  "node-v${NODE_VERSION}-darwin-arm64" VendorRuntime
run_pinned_node "$PROJECT_DIR/scripts/materialize-vendor-runtime.mjs" "$PROJECT_DIR" "$NPM"

run_pinned_node "$PROJECT_DIR/scripts/runtime-inventory.mjs" verify \
  "$VENDOR" "$PROJECT_DIR/VendorRuntime.inventory.json" VendorRuntime
run_pinned_node "$PROJECT_DIR/scripts/verify-source-product-contract.mjs" "$PROJECT_DIR"
run_pinned_node "$PROJECT_DIR/scripts/verify-deepseek-runtime-contract.mjs" "$PROJECT_DIR"

print "Fulmar's pinned Node and DeepSeek Harness runtime are reconstructed and verified."
