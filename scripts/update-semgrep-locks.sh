#!/bin/bash -p
set -euo pipefail

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

PROJECT_DIR="$(cd "$(dirname "$0")/.." && /bin/pwd -P)"
MODE="${1:-}"
UV_INPUT="${2:-}"
PYTHON_INPUT="${3:-}"
[[ "$MODE" == "--check" || "$MODE" == "--update" ]] || {
  echo "usage: update-semgrep-locks.sh <--check|--update> <absolute-uv-0.11.8> <absolute-python-3.12.3>" >&2
  exit 2
}
for input_value in "$UV_INPUT" "$PYTHON_INPUT"; do
  [[ "$input_value" == /* && ${#input_value} -le 1024 && "$input_value" != *$'\n'* && "$input_value" != *$'\r'* ]] || {
    echo "Absolute uv and Python executable paths are required." >&2
    exit 2
  }
  [[ -f "$input_value" && ! -L "$input_value" && -x "$input_value" ]] || {
    echo "The uv or Python executable is unavailable or unsafe." >&2
    exit 1
  }
done

[[ "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" == "Darwin:arm64" ]] || {
  echo "Reviewed Semgrep lock regeneration requires Darwin arm64." >&2
  exit 1
}

sha256_file() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{ print $1 }'
}

MANIFEST="$PROJECT_DIR/Config/SemgrepToolchain.json"
REQUIREMENTS_INPUT="$PROJECT_DIR/Config/SemgrepRequirements.in"
for source_file in "$MANIFEST" "$REQUIREMENTS_INPUT"; do
  [[ -f "$source_file" && ! -L "$source_file" ]] || {
    echo "Semgrep lock source input is unavailable or linked." >&2
    exit 1
  }
  source_permissions="$(/usr/bin/stat -f '%Lp' "$source_file")"
  [[ "$source_permissions" =~ ^[0-7]{3,4}$ ]] || {
    echo "Could not validate source input permissions." >&2
    exit 1
  }
  case "$source_permissions" in
    *[2367][0-7]|*[0-7][2367])
      echo "Semgrep lock source input is group/world writable." >&2
      exit 1
      ;;
  esac
done

EXPECTED_UV_SHA="51f0ae3c531a124727fa39e16e8599f2e371e427822a4aa92ebf667b52548b43"
EXPECTED_PYTHON_SHA="02f1498c0eff1936ab91de7c411abf49c6f918e11628445cc6502da94d5aa15b"
EXPECTED_INPUT_SHA="0b5bee18684d658764ac9db2fdc9c8786cf28b85c90c83ddbd432e10ba66366c"
[[ "$(sha256_file "$UV_INPUT")" == "$EXPECTED_UV_SHA" ]] || {
  echo "uv does not match the reviewed 0.11.8 executable bytes." >&2
  exit 1
}
[[ "$(sha256_file "$PYTHON_INPUT")" == "$EXPECTED_PYTHON_SHA" ]] || {
  echo "Python does not match the reviewed 3.12.3 executable bytes." >&2
  exit 1
}
[[ "$(sha256_file "$REQUIREMENTS_INPUT")" == "$EXPECTED_INPUT_SHA" ]] || {
  echo "Semgrep requirements input bytes changed." >&2
  exit 1
}

TEMP_PARENT=/tmp
[[ ! -d /private/tmp ]] || TEMP_PARENT=/private/tmp
TEMPORARY="$(/usr/bin/mktemp -d "$TEMP_PARENT/fulmar-semgrep-locks.XXXXXX")"
[[ "$TEMPORARY" == "$TEMP_PARENT"/fulmar-semgrep-locks.* && -d "$TEMPORARY" && ! -L "$TEMPORARY" && -O "$TEMPORARY" ]] || {
  echo "Could not create a private Semgrep lock-generation root." >&2
  exit 1
}
/bin/chmod 700 "$TEMPORARY"
trap '/bin/rm -rf -- "$TEMPORARY"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PRIVATE_HOME="$TEMPORARY/home"
PRIVATE_TEMP="$TEMPORARY/tmp"
/bin/mkdir -m 0700 "$PRIVATE_HOME" "$PRIVATE_TEMP"

clean_uv() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
    "$UV_INPUT" --no-config --no-cache --no-python-downloads "$@"
}

clean_python() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
    "$PYTHON_INPUT" -I "$@"
}

[[ "$(clean_uv --version)" == "uv 0.11.8 (0e961dd9a 2026-04-27 aarch64-apple-darwin)" ]] || {
  echo "Expected the reviewed uv 0.11.8 build." >&2
  exit 1
}
[[ "$(clean_python --version 2>&1)" == "Python 3.12.3" ]] || {
  echo "Expected the reviewed Python 3.12.3 build." >&2
  exit 1
}
[[ "$(clean_python -m pip --version 2>&1)" == pip\ 24.0\ *"(python 3.12)" ]] || {
  echo "Expected the reviewed Python's bundled pip 24.0." >&2
  exit 1
}

compile_lock() {
  local target_platform="$1"
  local output_file="$2"
  clean_uv pip compile "$REQUIREMENTS_INPUT" \
    --output-file "$output_file" \
    --python "$PYTHON_INPUT" \
    --python-version 3.12.3 \
    --python-platform "$target_platform" \
    --only-binary=:all: \
    --generate-hashes \
    --no-annotate \
    --no-sources \
    --no-progress \
    --quiet \
    --exclude-newer 2026-09-03T00:00:00Z \
    --default-index https://pypi.org/simple \
    --keyring-provider disabled \
    --custom-compile-command '/bin/bash -p scripts/update-semgrep-locks.sh --update <absolute-uv-0.11.8> <absolute-python-3.12.3>'
}

MAC_GENERATED="$TEMPORARY/SemgrepRequirements-macos-arm64.lock"
LINUX_GENERATED="$TEMPORARY/SemgrepRequirements-linux-x64.lock"
compile_lock aarch64-apple-darwin "$MAC_GENERATED"
compile_lock x86_64-unknown-linux-gnu "$LINUX_GENERATED"

MAC_DESTINATION="$PROJECT_DIR/Config/SemgrepRequirements-macos-arm64.lock"
LINUX_DESTINATION="$PROJECT_DIR/Config/SemgrepRequirements-linux-x64.lock"
MAC_SHA="$(sha256_file "$MAC_GENERATED")"
LINUX_SHA="$(sha256_file "$LINUX_GENERATED")"

manifest_lock_hashes() {
  clean_python -c '
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as source:
    manifest = json.load(source)
print(manifest["locks"]["Darwin:arm64"]["sha256"])
print(manifest["locks"]["Linux:x86_64"]["sha256"])
' "$MANIFEST"
}

if [[ "$MODE" == "--check" ]]; then
  /usr/bin/cmp -s "$MAC_GENERATED" "$MAC_DESTINATION" || {
    echo "macOS arm64 Semgrep lock is not reproducible." >&2
    exit 1
  }
  /usr/bin/cmp -s "$LINUX_GENERATED" "$LINUX_DESTINATION" || {
    echo "Linux x64 Semgrep lock is not reproducible." >&2
    exit 1
  }
  manifest_hashes="$(manifest_lock_hashes)"
  manifest_mac_sha="$(/usr/bin/printf '%s\n' "$manifest_hashes" | /usr/bin/sed -n '1p')"
  manifest_linux_sha="$(/usr/bin/printf '%s\n' "$manifest_hashes" | /usr/bin/sed -n '2p')"
  [[ "$manifest_mac_sha" == "$MAC_SHA" && "$manifest_linux_sha" == "$LINUX_SHA" ]] || {
    echo "Semgrep lock manifest digests are stale." >&2
    exit 1
  }
  echo "Verified reproducible Semgrep dependency locks with exact uv 0.11.8 and Python 3.12.3."
  exit 0
fi

MAC_STAGED="$MAC_DESTINATION.fulmar-new"
LINUX_STAGED="$LINUX_DESTINATION.fulmar-new"
MANIFEST_STAGED="$MANIFEST.fulmar-new"
for staged_path in "$MAC_STAGED" "$LINUX_STAGED" "$MANIFEST_STAGED"; do
  [[ ! -e "$staged_path" && ! -L "$staged_path" ]] || {
    echo "Refusing to replace a pre-existing staged Semgrep lock path." >&2
    exit 1
  }
done

/bin/cp "$MAC_GENERATED" "$MAC_STAGED"
/bin/cp "$LINUX_GENERATED" "$LINUX_STAGED"
/bin/chmod 644 "$MAC_STAGED" "$LINUX_STAGED"
clean_python -c '
import hashlib, json, os, sys
manifest_path, output_path, mac_path, linux_path = sys.argv[1:]
with open(manifest_path, "r", encoding="utf-8") as source:
    manifest = json.load(source)
def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
manifest["locks"]["Darwin:arm64"]["sha256"] = digest(mac_path)
manifest["locks"]["Linux:x86_64"]["sha256"] = digest(linux_path)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
descriptor = os.open(output_path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
    json.dump(manifest, output, indent=2, ensure_ascii=True)
    output.write("\n")
' "$MANIFEST" "$MANIFEST_STAGED" "$MAC_STAGED" "$LINUX_STAGED"
/bin/chmod 644 "$MANIFEST_STAGED"

/bin/mv "$MAC_STAGED" "$MAC_DESTINATION"
/bin/mv "$LINUX_STAGED" "$LINUX_DESTINATION"
/bin/mv "$MANIFEST_STAGED" "$MANIFEST"
echo "Updated both reviewed Semgrep locks and their manifest digests."
