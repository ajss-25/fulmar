#!/bin/bash -p
set -euo pipefail

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

PROJECT_DIR="$(cd "$(dirname "$0")/.." && /bin/pwd -P)"
INSTALL_ROOT="${1:-}"
GITHUB_PATH_FILE="${2:-}"
NODE_INPUT="${3:-}"

for input_value in "$INSTALL_ROOT" "$GITHUB_PATH_FILE" "$NODE_INPUT"; do
  [[ "$input_value" == /* && ${#input_value} -le 1024 && "$input_value" != *$'\n'* && "$input_value" != *$'\r'* ]] || {
    echo "usage: install-pinned-semgrep.sh <absolute-new-install-root> <absolute-github-path-file> <absolute-node>" >&2
    exit 2
  }
done
[[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || {
  echo "Semgrep install root already exists." >&2
  exit 1
}

canonical_executable() {
  local candidate="$1"
  local resolved="$candidate"
  local hops=0
  local target directory
  while [[ -L "$resolved" ]]; do
    hops=$((hops + 1))
    [[ "$hops" -le 32 ]] || return 1
    target="$(/usr/bin/readlink "$resolved")" || return 1
    case "$target" in
      /*) resolved="$target" ;;
      *) resolved="$(/usr/bin/dirname "$resolved")/$target" ;;
    esac
  done
  directory="$(cd "$(/usr/bin/dirname "$resolved")" 2>/dev/null && /bin/pwd -P)" || return 1
  resolved="$directory/$(/usr/bin/basename "$resolved")"
  [[ -f "$resolved" && ! -L "$resolved" && -x "$resolved" ]] || return 1
  /usr/bin/printf '%s\n' "$resolved"
}

sha256_file() {
  local source_file="$1"
  if [[ -x /usr/bin/shasum ]]; then
    /usr/bin/shasum -a 256 "$source_file" | /usr/bin/awk '{ print $1 }'
  elif [[ -x /usr/bin/sha256sum ]]; then
    /usr/bin/sha256sum "$source_file" | /usr/bin/awk '{ print $1 }'
  else
    echo "No reviewed SHA-256 utility is available." >&2
    return 1
  fi
}

command_file_identity() {
  local command_file="$1"
  local identity device inode links permissions owner
  [[ -f "$command_file" && ! -L "$command_file" && -O "$command_file" ]] || return 1
  if [[ "$PLATFORM" == "Darwin:arm64" ]]; then
    identity="$(/usr/bin/stat -f '%d:%i:%l:%Lp:%u' "$command_file")" || return 1
  else
    identity="$(/usr/bin/stat -c '%d:%i:%h:%a:%u' "$command_file")" || return 1
  fi
  IFS=: read -r device inode links permissions owner <<< "$identity"
  for numeric in "$device" "$inode" "$links" "$permissions" "$owner"; do
    [[ "$numeric" =~ ^[0-9]+$ ]] || return 1
  done
  [[ "$links" == "1" && "$owner" == "$(/usr/bin/id -u)" ]] || return 1
  (( (8#$permissions & 8#022) == 0 )) || return 1
  /usr/bin/printf '%s\n' "$identity"
}

safe_archive_member() {
  local member="$1"
  local component
  [[ -n "$member" && ${#member} -le 4096 && "$member" == python/* \
    && "$member" != /* && "$member" != *\\* \
    && "$member" != *$'\r'* && "$member" != *$'\t'* ]] || return 1
  IFS=/ read -r -a components <<< "$member"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || return 1
  done
}

safe_archive_link_target() {
  local member="$1"
  local target="$2"
  local parent="${member%/*}"
  local depth component
  [[ -n "$target" && ${#target} -le 4096 && "$target" != /* && "$target" != *\\* \
    && "$target" != *$'\r'* && "$target" != *$'\t'* ]] || return 1
  IFS=/ read -r -a parent_components <<< "$parent"
  depth=${#parent_components[@]}
  [[ "$depth" -ge 1 && "${parent_components[0]}" == "python" ]] || return 1
  IFS=/ read -r -a target_components <<< "$target"
  for component in "${target_components[@]}"; do
    case "$component" in
      ''|.) ;;
      ..)
        depth=$((depth - 1))
        [[ "$depth" -ge 1 ]] || return 1
        ;;
      *) depth=$((depth + 1)) ;;
    esac
  done
}

PLATFORM="$(/usr/bin/uname -s):$(/usr/bin/uname -m)"
case "$PLATFORM" in
  Darwin:arm64) NODE_SHA_KEY="nodeSHA256" ;;
  Linux:x86_64) NODE_SHA_KEY="nodeLinuxX64SHA256" ;;
  *) echo "Semgrep's reviewed host platform is unsupported." >&2; exit 1 ;;
esac

GITHUB_PATH_IDENTITY="$(command_file_identity "$GITHUB_PATH_FILE")" || {
  echo "GitHub path command file is unsafe, linked, writable, or multiply linked." >&2
  exit 1
}

NODE="$(canonical_executable "$NODE_INPUT")" || {
  echo "Pinned Node input is unavailable or unsafe." >&2
  exit 1
}
if [[ "$PLATFORM" == "Darwin:arm64" ]]; then
  node_permissions="$(/usr/bin/stat -f '%Lp' "$NODE")"
else
  node_permissions="$(/usr/bin/stat -c '%a' "$NODE")"
fi
case "$node_permissions" in (*[!0-7]*|'') echo "Could not validate Node permissions." >&2; exit 1;; esac
(( (8#$node_permissions & 8#022) == 0 )) || {
  echo "Pinned Node executable is group/world writable." >&2
  exit 1
}

RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
[[ -f "$RELEASE_IDENTITY" && ! -L "$RELEASE_IDENTITY" ]] || {
  echo "Release identity is unavailable or linked." >&2
  exit 1
}
expected_node_sha="$(/usr/bin/sed -nE "s/^[[:space:]]*\"$NODE_SHA_KEY\": \"([a-f0-9]{64})\",?$/\\1/p" "$RELEASE_IDENTITY")"
[[ "$expected_node_sha" =~ ^[a-f0-9]{64}$ && "$(sha256_file "$NODE")" == "$expected_node_sha" ]] || {
  echo "Pinned Node executable does not match the release identity." >&2
  exit 1
}
node_version="$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$NODE" --version)"
[[ "$node_version" == "v22.23.1" ]] || {
  echo "Expected Node v22.23.1, found ${node_version:-unknown}." >&2
  exit 1
}

selection="$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  "$NODE" "$PROJECT_DIR/scripts/verify-semgrep-toolchain-lock.mjs" select "$PROJECT_DIR" "$PLATFORM")"
IFS=$'\t' read -r LOCK_REL PYTHON_URL PYTHON_BYTES PYTHON_SHA PYTHON_ENTRIES PYTHON_EXECUTABLE PYTHON_EXECUTABLE_SHA <<< "$selection"
[[ -n "$LOCK_REL" && -n "$PYTHON_URL" && "$PYTHON_BYTES" =~ ^[0-9]+$ \
  && "$PYTHON_SHA" =~ ^[a-f0-9]{64}$ && "$PYTHON_ENTRIES" =~ ^[0-9]+$ \
  && -n "$PYTHON_EXECUTABLE" && "$PYTHON_EXECUTABLE_SHA" =~ ^[a-f0-9]{64}$ ]] || {
  echo "Semgrep toolchain selection is malformed." >&2
  exit 1
}
LOCK="$PROJECT_DIR/$LOCK_REL"

/bin/mkdir -m 0700 "$INSTALL_ROOT"
PRIVATE_HOME="$INSTALL_ROOT/private-home"
PRIVATE_TEMP="$INSTALL_ROOT/private-tmp"
/bin/mkdir -m 0700 "$PRIVATE_HOME" "$PRIVATE_TEMP"
PYTHON_ARCHIVE="$INSTALL_ROOT/python-build-standalone.tar.gz"

/usr/bin/env -i \
  PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
  /usr/bin/curl --disable --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --max-redirs 3 --connect-timeout 30 --max-time 300 \
    --retry 3 --retry-all-errors --max-filesize "$PYTHON_BYTES" \
    --output "$PYTHON_ARCHIVE" "$PYTHON_URL"

/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  "$NODE" "$PROJECT_DIR/scripts/verify-semgrep-toolchain-lock.mjs" \
    verify-python-archive "$PROJECT_DIR" "$PLATFORM" "$PYTHON_ARCHIVE"

archive_entries=0
archive_members=()
while IFS= read -r archive_member; do
  safe_archive_member "$archive_member" || {
    echo "Python archive contains an unsafe member path." >&2
    exit 1
  }
  archive_members[archive_entries]="$archive_member"
  archive_entries=$((archive_entries + 1))
done < <(/usr/bin/tar -tzf "$PYTHON_ARCHIVE")
[[ "$archive_entries" == "$PYTHON_ENTRIES" ]] || {
  echo "Python archive entry count changed." >&2
  exit 1
}

verbose_index=0
while IFS= read -r verbose_member; do
  [[ "$verbose_index" -lt "$archive_entries" ]] || {
    echo "Python archive verbose topology has extra entries." >&2
    exit 1
  }
  archive_member="${archive_members[verbose_index]}"
  case "${verbose_member:0:1}" in
    -|d) ;;
    l)
      [[ "$verbose_member" == *" -> "* ]] || {
        echo "Python archive contains a malformed symbolic link." >&2
        exit 1
      }
      link_target="${verbose_member##* -> }"
      safe_archive_link_target "$archive_member" "$link_target" || {
        echo "Python archive contains an escaping symbolic-link target." >&2
        exit 1
      }
      ;;
    *)
      echo "Python archive contains an unsupported entry type." >&2
      exit 1
      ;;
  esac
  verbose_index=$((verbose_index + 1))
done < <(/usr/bin/tar -tvzf "$PYTHON_ARCHIVE")
[[ "$verbose_index" == "$archive_entries" ]] || {
  echo "Python archive verbose topology is incomplete." >&2
  exit 1
}
/usr/bin/tar --no-same-owner -xzf "$PYTHON_ARCHIVE" -C "$INSTALL_ROOT"
/bin/rm -f "$PYTHON_ARCHIVE"

PYTHON="$INSTALL_ROOT/$PYTHON_EXECUTABLE"
[[ -f "$PYTHON" && ! -L "$PYTHON" && -x "$PYTHON" \
  && "$(sha256_file "$PYTHON")" == "$PYTHON_EXECUTABLE_SHA" ]] || {
  echo "Extracted Python executable does not match the reviewed bytes." >&2
  exit 1
}
python_version="$(/usr/bin/env -i PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
  "$PYTHON" -I --version 2>&1)"
[[ "$python_version" == "Python 3.12.3" ]] || {
  echo "Expected Python 3.12.3, found ${python_version:-unknown}." >&2
  exit 1
}

VENV_ROOT="$INSTALL_ROOT/semgrep"
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
  "$PYTHON" -I -m venv "$VENV_ROOT"
VENV_PYTHON="$VENV_ROOT/bin/python"
VENV_PYTHON_REAL="$(canonical_executable "$VENV_PYTHON")" || {
  echo "Semgrep virtual environment did not produce a safe Python executable." >&2
  exit 1
}
[[ "$VENV_PYTHON_REAL" == "$PYTHON" || "$VENV_PYTHON_REAL" == "$VENV_ROOT"/* ]] || {
  echo "Semgrep virtual environment Python escaped the reviewed installation." >&2
  exit 1
}

pip_version="$(/usr/bin/env -i PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
  "$VENV_PYTHON" -I -m pip --version 2>&1)"
[[ "$pip_version" == pip\ 24.0\ *"(python 3.12)" ]] || {
  echo "Expected the reviewed Python 3.12.3 bundled pip 24.0." >&2
  exit 1
}

clean_python() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
    PIP_CONFIG_FILE=/dev/null PIP_CACHE_DIR="$INSTALL_ROOT/pip-cache" \
    PIP_KEYRING_PROVIDER=disabled PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$VENV_PYTHON" -I "$@"
}

clean_python -m pip install \
  --isolated --disable-pip-version-check --no-input --no-deps \
  --only-binary=:all: --require-hashes --timeout 30 --retries 3 \
  --index-url https://pypi.org/simple --requirement "$LOCK"
clean_python -m pip check

SEMGREP="$VENV_ROOT/bin/semgrep"
[[ -f "$SEMGREP" && ! -L "$SEMGREP" && -x "$SEMGREP" ]] || {
  echo "Hash-locked Semgrep executable is unavailable or unsafe." >&2
  exit 1
}
semgrep_version="$(/usr/bin/env -i \
  PATH=/usr/bin:/bin HOME="$PRIVATE_HOME" TMPDIR="$PRIVATE_TEMP" LANG=C LC_ALL=C \
  SEMGREP_APP_TOKEN= SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  SEMGREP_SETTINGS_FILE="$PRIVATE_TEMP/semgrep-settings.yml" \
  SEMGREP_VERSION_CACHE_PATH="$PRIVATE_TEMP/semgrep-version.json" \
  "$SEMGREP" --version 2>/dev/null)"
[[ "$semgrep_version" == "1.135.0" ]] || {
  echo "Hash-locked Semgrep reported an unexpected version." >&2
  exit 1
}

COMMAND_DIR="$INSTALL_ROOT/bin"
/bin/mkdir -m 0700 "$COMMAND_DIR"
/bin/ln -s ../semgrep/bin/semgrep "$COMMAND_DIR/semgrep"
[[ -L "$COMMAND_DIR/semgrep" && "$(canonical_executable "$COMMAND_DIR/semgrep")" == "$SEMGREP" ]] || {
  echo "Semgrep command exposure is unsafe." >&2
  exit 1
}
[[ "$(command_file_identity "$GITHUB_PATH_FILE")" == "$GITHUB_PATH_IDENTITY" ]] || {
  echo "GitHub path command file identity or protections changed during installation." >&2
  exit 1
}
/usr/bin/printf '%s\n' "$COMMAND_DIR" >> "$GITHUB_PATH_FILE"
echo "Installed content-pinned Python 3.12.3 and hash-locked Semgrep 1.135.0 for $PLATFORM."
