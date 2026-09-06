#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
HELPER="${1:-$PROJECT_DIR/.build/debug/LocalHarnessCredentialHelper}"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"

exec "$NODE" "$PROJECT_DIR/scripts/verify-telemetry-lock-helper.mjs" "$HELPER"
