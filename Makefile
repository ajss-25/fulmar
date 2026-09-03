.PHONY: app build private-release private-install-qualified private-rollback-status private-recovery-resume private-recovery-finalize private-recovery-cancel private-recovery-reconcile private-rollback-retire build-and-smoke frozen-smoke frozen-candidate-check frozen-installed-candidate-check run clean test tracked-index-policy dsh-promotion-provenance-verify source-contract-test deepseek-contract-test static-security-scan security-test web-rpc-canary web-live-canary installed-web-live-canary sandbox-test runtime-lease-test cloned-state-security credential-test credential-crash-test dependency-audit provider-contract-test provider-matrix-test agent-route-test deep-agent-test realistic-agent-test app-owned-ollama-generation toolbar-render-macos26 status-item-compile status-item-live status-item-normal-actions status-item-headless-handoff status-item-physical-background-handoff installed-status-item-live installed-status-item-normal-actions installed-status-item-headless-handoff installed-status-item-physical-background-handoff runtime-inventory-verify runtime-inventory-test deterministic-release-verify release-verify public-release public-release-finalize public-assets public-external-evidence-verify public-distribution-verify

app: build

build: static-security-scan dsh-promotion-provenance-verify
	./scripts/run-with-watchdog.sh --seconds 7200 --max-rss-bytes 34359738368 --rss-grace-seconds 15 --emergency-rss-bytes 42949672960 --lock-dir /private/tmp/LocalHarnessBuild.lock --label "Fulmar build" -- /bin/zsh -f scripts/build-app.sh

private-release: static-security-scan dsh-promotion-provenance-verify
	@./scripts/run-with-watchdog.sh --seconds 120 --max-rss-bytes 536870912 --rss-grace-seconds 3 --emergency-rss-bytes 1073741824 --label "Fulmar signing identity" -- /bin/zsh -f scripts/create-local-signing-identity.sh >/dev/null
	LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1 LOCAL_HARNESS_SIGN_TIMESTAMP=0 ./scripts/run-with-watchdog.sh --seconds 7200 --max-rss-bytes 34359738368 --rss-grace-seconds 15 --emergency-rss-bytes 42949672960 --lock-dir /private/tmp/LocalHarnessBuild.lock --label "Fulmar private build" -- /bin/zsh -f scripts/build-app.sh

private-install-qualified:
	/bin/zsh -f scripts/install-qualified-private-candidate.sh

private-rollback-status:
	/bin/zsh -f scripts/inspect-private-install-rollback.sh

private-recovery-resume:
	/bin/zsh -f scripts/recover-private-install.sh resume

private-recovery-finalize:
	/bin/zsh -f scripts/recover-private-install.sh finalize

private-recovery-cancel:
	/bin/zsh -f scripts/recover-private-install.sh cancel

private-recovery-reconcile:
	/bin/zsh -f scripts/recover-private-install.sh reconcile

private-rollback-retire:
	/bin/zsh -f scripts/recover-private-install.sh retire

run: build
	open "/private/tmp/LocalHarnessBuild/Fulmar.app"

build-and-smoke: private-release
	$(MAKE) frozen-smoke

frozen-smoke: frozen-candidate-check
	"/private/tmp/LocalHarnessBuild/Fulmar.app/Contents/Resources/Runtime/node" scripts/verify-dsh-web-rpc-canary.mjs "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-simulated-provider-contract.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

frozen-candidate-check:
	/bin/zsh -f scripts/verify-frozen-candidate.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

frozen-installed-candidate-check: frozen-candidate-check
	/bin/zsh -f scripts/verify-frozen-candidate.sh "/Applications/Fulmar.app"

clean:
	/bin/zsh -f scripts/clean-build-outputs.sh
test:
	/bin/zsh -f scripts/run-swift-tests.sh

tracked-index-policy:
	/bin/bash -p scripts/verify-tracked-index.sh .

dsh-promotion-provenance-verify:
	VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/verify-dsh-promotion-provenance.mjs .

source-contract-test: dsh-promotion-provenance-verify
	VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/verify-source-product-contract.mjs .

deepseek-contract-test: dsh-promotion-provenance-verify
	VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/verify-deepseek-runtime-contract.mjs .

static-security-scan:
	/bin/sh -p scripts/run-static-security-scan.sh

security-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-runtime-security.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

web-rpc-canary: frozen-candidate-check
	"/private/tmp/LocalHarnessBuild/Fulmar.app/Contents/Resources/Runtime/node" scripts/verify-dsh-web-rpc-canary.mjs "/private/tmp/LocalHarnessBuild/Fulmar.app"

web-live-canary: frozen-candidate-check
	LOCAL_HARNESS_LIVE_WEB_FETCH=1 "/private/tmp/LocalHarnessBuild/Fulmar.app/Contents/Resources/Runtime/node" scripts/verify-dsh-web-rpc-canary.mjs "/private/tmp/LocalHarnessBuild/Fulmar.app"

installed-web-live-canary: frozen-installed-candidate-check
	LOCAL_HARNESS_LIVE_WEB_FETCH=1 "/Applications/Fulmar.app/Contents/Resources/Runtime/node" scripts/verify-dsh-web-rpc-canary.mjs "/Applications/Fulmar.app"

sandbox-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-sandbox-runner.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

runtime-lease-test:
	/bin/zsh -f scripts/run-bounded-swift-product-gate.sh runtime-lease

cloned-state-security: frozen-candidate-check
	/bin/zsh -f scripts/verify-cloned-state-security.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

credential-test:
	/bin/zsh -f scripts/run-bounded-swift-product-gate.sh credential

credential-crash-test:
	/bin/zsh -f scripts/verify-credential-transaction-crash.sh

dependency-audit:
	VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/audit-dependencies.mjs VendorRuntime/package.json VendorRuntime/package-lock.json VendorRuntime/node-v22.23.1-darwin-arm64/lib/node_modules/npm/bin/npm-cli.js build/dependency-audit-summary.json

provider-contract-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-simulated-provider-contract.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-simulated-provider-matrix.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

provider-matrix-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-simulated-provider-matrix.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

agent-route-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-dsh-qwen-route.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" bash
	/bin/zsh -f scripts/verify-dsh-qwen-route.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" filesystem

deep-agent-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-dsh-qwen-route.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" project

realistic-agent-test: frozen-candidate-check
	/bin/zsh -f scripts/verify-dsh-qwen-route.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" realistic

app-owned-ollama-generation: frozen-candidate-check
	/bin/zsh -f scripts/verify-app-owned-ollama-generation.sh "/private/tmp/LocalHarnessBuild/Fulmar.app"

toolbar-render-macos26:
	/bin/zsh -f scripts/verify-toolbar-render-macos26.sh

status-item-compile:
	/bin/zsh -f scripts/verify-status-item-live.sh --compile-only

status-item-live:
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" 20

status-item-normal-actions:
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" --normal-actions

status-item-headless-handoff:
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" --headless-handoff

status-item-physical-background-handoff:
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/private/tmp/LocalHarnessBuild/Fulmar.app" --physical-background-handoff

installed-status-item-live:
	test -d "/Applications/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/Applications/Fulmar.app" 20

installed-status-item-normal-actions:
	test -d "/Applications/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/Applications/Fulmar.app" --normal-actions

installed-status-item-headless-handoff:
	test -d "/Applications/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/Applications/Fulmar.app" --headless-handoff

installed-status-item-physical-background-handoff:
	test -d "/Applications/Fulmar.app"
	/bin/zsh -f scripts/verify-status-item-live.sh "/Applications/Fulmar.app" --physical-background-handoff

runtime-inventory-verify:
	VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/runtime-inventory.mjs verify VendorRuntime VendorRuntime.inventory.json VendorRuntime

runtime-inventory-test:
	/bin/zsh -f scripts/run-js-tests.sh --test Tests/JS/RuntimeInventoryTests.mjs

release-verify: dsh-promotion-provenance-verify
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1 /bin/zsh -f scripts/retain-release-verification.sh --signing-profile private-stable "/private/tmp/LocalHarnessBuild/Fulmar.app"

deterministic-release-verify: dsh-promotion-provenance-verify
	test -d "/private/tmp/LocalHarnessBuild/Fulmar.app"
	LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1 /bin/zsh -f scripts/verify-release-orchestrated.sh --signing-profile private-stable --deterministic-ci "/private/tmp/LocalHarnessBuild/Fulmar.app"

public-release: dsh-promotion-provenance-verify
	/bin/zsh -f scripts/run-public-release.sh

public-release-finalize: dsh-promotion-provenance-verify
	/bin/zsh -f scripts/run-public-release.sh --finalize

public-assets: dsh-promotion-provenance-verify
	@set -eu; \
	  candidate_sha="$$(/usr/bin/plutil -extract sha256 raw -o - build/release-manifest.json)"; \
	  version="$$(/usr/bin/plutil -extract version raw -o - build/release-manifest.json)"; \
	  build="$$(/usr/bin/plutil -extract build raw -o - build/release-manifest.json)"; \
	  /bin/zsh -f scripts/prepare-public-release-assets.sh \
	    "$(CURDIR)/build/Fulmar.app.zip" "$(CURDIR)/build/release-manifest.json" \
	    "$(CURDIR)/build/public-release-assets" "$$candidate_sha" "$$version" "$$build"

public-external-evidence-verify: frozen-candidate-check
	@set -eu; \
	  candidate_sha="$$(/usr/bin/plutil -extract sha256 raw -o - build/release-manifest.json)"; \
	  version="$$(/usr/bin/plutil -extract version raw -o - build/release-manifest.json)"; \
	  build="$$(/usr/bin/plutil -extract build raw -o - build/release-manifest.json)"; \
	  VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/verify-public-external-evidence.mjs \
	    "$(CURDIR)/build/public-external-evidence.json" "$$candidate_sha" "$$version" "$$build"

public-distribution-verify: dsh-promotion-provenance-verify
	/bin/zsh -f scripts/verify-public-distribution.sh
