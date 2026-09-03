#!/bin/bash -p
set -euo pipefail

# This gate intentionally uses only tools supplied by the hosted operating
# system. It must run before downloaded runtimes or repository build code.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT GIT_CEILING_DIRECTORIES \
  GIT_NAMESPACE GIT_REPLACE_REF_BASE
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
export GIT_OPTIONAL_LOCKS=0

ROOT="${1:-.}"
case "$ROOT" in
  /*) ;;
  *) ROOT="$PWD/$ROOT" ;;
esac
[[ -d "$ROOT" && ! -L "$ROOT" ]] || {
  echo "Tracked-index qualification requires one real source directory." >&2
  exit 2
}
ROOT="$(cd "$ROOT" && /bin/pwd -P)"

TEMP_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/fulmar-index-policy.XXXXXX")"
INDEX_RECORDS="$TEMP_ROOT/index-records"
PATH_RECORDS="$TEMP_ROOT/paths"
/bin/mkdir -m 0700 "$TEMP_ROOT/home"
cleanup() {
  local exit_code="${1:-$?}"
  case "$TEMP_ROOT" in
    */fulmar-index-policy.*) /bin/rm -rf -- "$TEMP_ROOT" ;;
    *) echo "Refusing to remove an invalid tracked-index temporary directory." >&2 ;;
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

# Isolate global Git configuration before the first repository query. Repository
# discovery itself must not inherit aliases, includes, or trust settings from the
# invoking account.
export HOME="$TEMP_ROOT/home"
export LC_ALL=C

if ! /usr/bin/git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Tracked-index qualification NOT RUN: this source tree has no Git metadata." >&2
  exit 2
fi
TOP_LEVEL="$(/usr/bin/git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)"
[[ "$TOP_LEVEL" == "$ROOT" ]] || {
  echo "Tracked-index qualification must run at the exact repository root." >&2
  exit 1
}

# Do not allow a caller's Git configuration, alternate index, object store, or
# replacement refs to change what the first-index policy examines.
INDEX_PATH="$(/usr/bin/git -C "$ROOT" rev-parse --git-path index 2>/dev/null)"
case "$INDEX_PATH" in
  /*) ;;
  *) INDEX_PATH="$ROOT/$INDEX_PATH" ;;
esac
[[ -f "$INDEX_PATH" && ! -L "$INDEX_PATH" ]] || {
  echo "Tracked-index qualification failed: the Git index is missing or linked." >&2
  exit 1
}
ALTERNATES_PATH="$(/usr/bin/git -C "$ROOT" rev-parse --git-path objects/info/alternates 2>/dev/null)"
case "$ALTERNATES_PATH" in
  /*) ;;
  *) ALTERNATES_PATH="$ROOT/$ALTERNATES_PATH" ;;
esac
[[ ! -s "$ALTERNATES_PATH" ]] || {
  echo "Tracked-index qualification failed: alternate object stores are not permitted." >&2
  exit 1
}

/usr/bin/git -C "$ROOT" ls-files --stage -z > "$INDEX_RECORDS"
[[ -s "$INDEX_RECORDS" ]] || {
  echo "Tracked-index qualification failed: the Git index is empty." >&2
  exit 1
}
: > "$PATH_RECORDS"

MAXIMUM_BLOB_BYTES=104857600
ENTRY_COUNT=0
shopt -s nocasematch
while IFS= read -r -d '' entry; do
  [[ "$entry" == *$'\t'* ]] || {
    echo "Tracked-index qualification failed: malformed index record." >&2
    exit 1
  }
  metadata="${entry%%$'\t'*}"
  path="${entry#*$'\t'}"
  if [[ ! "$metadata" =~ ^([0-7]{6})\ ([0-9a-f]{40}|[0-9a-f]{64})\ ([0-3])$ ]]; then
    echo "Tracked-index qualification failed: malformed mode/object/stage metadata." >&2
    exit 1
  fi
  mode="${BASH_REMATCH[1]}"
  object="${BASH_REMATCH[2]}"
  stage="${BASH_REMATCH[3]}"
  [[ "$stage" == "0" ]] || {
    echo "Tracked-index qualification failed: unresolved index stage for a tracked path." >&2
    exit 1
  }
  [[ "$mode" == "100644" || "$mode" == "100755" ]] || {
    echo "Tracked-index qualification failed: unsafe tracked type or mode at $path ($mode)." >&2
    exit 1
  }
  [[ -n "$path" && "$path" != /* && "$path" != *$'\n'* && "$path" != *$'\r'* \
     && "$path" != *$'\t'* && "$path" != *'\\'* && "$path" != *'//'*
     && "$path" != '.' && "$path" != '..' && "$path" != './'* \
     && "$path" != */./* && "$path" != */../* && "$path" != */.. ]] || {
    echo "Tracked-index qualification failed: unsafe tracked path spelling." >&2
    exit 1
  }

  top="${path%%/*}"
  case "$top" in
    .gitattributes|.gitignore|CHANGELOG.md|CONTRIBUTING.md|LICENSE|Makefile|Package.swift|README.md|SECURITY.md|SUPPORT.md|VendorRuntime.inventory.json)
      [[ "$path" == "$top" ]] || {
        echo "Tracked-index qualification failed: approved top-level file is used as a directory: $top" >&2
        exit 1
      }
      ;;
    .github|Config|Resources|Sources|Tests|Tools|VendorRuntime|docs|scripts)
      [[ "$path" != "$top" ]] || {
        echo "Tracked-index qualification failed: approved source directory is tracked as a file: $top" >&2
        exit 1
      }
      ;;
    .build|build|recovered-duplicates)
      echo "Tracked-index qualification failed: generated/private root is tracked: $top" >&2
      exit 1
      ;;
    *)
      echo "Tracked-index qualification failed: unapproved top-level source entry: $top" >&2
      exit 1
      ;;
  esac
  if [[ "$top" == "VendorRuntime" \
        && "$path" != "VendorRuntime/package.json" \
        && "$path" != "VendorRuntime/package-lock.json" ]]; then
    echo "Tracked-index qualification failed: generated VendorRuntime content is tracked: $path" >&2
    exit 1
  fi

  approved_executable=0
  case "$path" in
    Tests/Fixtures/CanaryCredentialHelper.sh|Tests/Fixtures/fake-credential-helper.mjs|\
    scripts/bootstrap-source-checkout.sh|scripts/create-local-signing-identity.sh|\
    scripts/prepare-public-release-assets.sh|scripts/provision-ci-signing-keychain.sh|\
    scripts/recover-private-install.sh|scripts/release-command-gate.zsh|\
    scripts/run-js-tests.sh|scripts/run-public-release.sh|scripts/run-static-security-scan.sh|scripts/run-with-watchdog.sh|\
    scripts/verify-app-owned-ollama-generation.sh|scripts/verify-cloned-state-security.sh|\
    scripts/verify-code-signature.sh|scripts/verify-credential-broker-xpc.sh|\
    scripts/verify-credential-broker-xpc-live.sh|scripts/verify-credential-helper.sh|\
    scripts/verify-credential-migration.sh|scripts/verify-credential-migration-xpc-live.sh|\
    scripts/verify-dsh-qwen-route.sh|\
    scripts/verify-dsh-web-rpc-canary.mjs|scripts/verify-macho-compatibility.sh|\
    scripts/verify-mcp-runtime-security.sh|scripts/verify-native-symbol-privacy-adversarial.sh|\
    scripts/verify-native-symbol-privacy.sh|scripts/verify-public-distribution.sh|\
    scripts/verify-release.sh|scripts/verify-runtime-lease.sh|\
    scripts/verify-simulated-provider-contract.sh|scripts/verify-stable-signing.sh|\
    scripts/verify-swiftpm-deployment-target.sh|scripts/verify-telemetry-lock-helper.mjs|\
    scripts/verify-telemetry-lock-helper.sh|scripts/verify-tracked-index.sh)
      approved_executable=1
      ;;
  esac
  if [[ "$mode" == "100755" && "$approved_executable" != "1" ]]; then
    echo "Tracked-index qualification failed: unapproved executable source mode at $path." >&2
    exit 1
  fi
  if [[ "$mode" == "100644" && "$approved_executable" == "1" ]]; then
    echo "Tracked-index qualification failed: reviewed executable source lost its executable mode at $path." >&2
    exit 1
  fi

  basename="${path##*/}"
  case "$basename" in
    .env|.env.*|.netrc|.npmrc|credentials|credentials.*|secrets|secrets.*|auth.json|token.json|id_rsa|id_dsa|id_ecdsa|id_ed25519|*.pem|*.key|*.p12|*.pfx|*.crt|*.cer|*.der|*.jks|*.keystore|*.mobileprovision|*.provisionprofile)
      echo "Tracked-index qualification failed: credential/certificate filename is tracked: $path" >&2
      exit 1
      ;;
  esac

  object_type="$(/usr/bin/git --no-replace-objects -C "$ROOT" cat-file -t "$object" 2>/dev/null || true)"
  [[ "$object_type" == "blob" ]] || {
    echo "Tracked-index qualification failed: regular-file mode does not identify a blob at $path." >&2
    exit 1
  }
  object_size="$(/usr/bin/git --no-replace-objects -C "$ROOT" cat-file -s "$object" 2>/dev/null || true)"
  [[ "$object_size" =~ ^[0-9]+$ ]] || {
    echo "Tracked-index qualification failed: blob size is unavailable for $path." >&2
    exit 1
  }
  (( object_size <= MAXIMUM_BLOB_BYTES )) || {
    echo "Tracked-index qualification failed: tracked blob exceeds 100 MiB: $path" >&2
    exit 1
  }

  /usr/bin/printf '%s\0' "$path" >> "$PATH_RECORDS"
  ENTRY_COUNT=$((ENTRY_COUNT + 1))
done < "$INDEX_RECORDS"
shopt -u nocasematch

(( ENTRY_COUNT > 0 )) || {
  echo "Tracked-index qualification failed: no stage-zero source entries were found." >&2
  exit 1
}

# APFS is commonly case-insensitive and normalizes Unicode. Detect collisions
# from the index bytes instead of relying on what the checkout filesystem could
# materialize. Invalid UTF-8 also fails closed.
/usr/bin/perl -Mstrict -Mwarnings -MEncode=decode,FB_CROAK -MUnicode::Normalize=NFC -0 -e '
  use feature "fc";
  my %seen;
  while (<>) {
    s/\0\z//;
    my $decoded = eval { decode("UTF-8", $_, FB_CROAK) };
    die "Tracked-index qualification failed: tracked path is not valid UTF-8.\n" if $@;
    my $key = fc(NFC($decoded));
    if (exists $seen{$key} && $seen{$key} ne $decoded) {
      die "Tracked-index qualification failed: case/Unicode path collision: $seen{$key} <> $decoded\n";
    }
    $seen{$key} = $decoded;
  }
' "$PATH_RECORDS"

echo "Tracked-index policy passed for $ENTRY_COUNT bounded regular source blobs. This gate does not scan Git history."
