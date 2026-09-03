#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
HELPER="${1:-$PROJECT_DIR/.build/debug/LocalHarnessCredentialHelper}"
NODE="${LOCAL_HARNESS_TEST_NODE:-$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node}"

/bin/zsh -f "$PROJECT_DIR/scripts/verify-telemetry-lock-helper.sh" "$HELPER"
"$NODE" "$PROJECT_DIR/scripts/verify-credential-helper-bounds.mjs" "$HELPER"
"$NODE" "$PROJECT_DIR/scripts/verify-keychain-no-ui-transition.mjs" "$HELPER"
