#!/bin/zsh -f
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

PROJECT_DIR="${0:A:h:h}"
VERSION="22.23.1"
ARCHIVE="node-v${VERSION}-darwin-arm64.tar.gz"
EXPECTED_SHA256="ef28d8fab2c0e4314522d4bb1b7173270aa3937e93b92cb7de79c112ac1fa953"
EXPECTED_EXECUTABLE_SHA256="2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d"
VENDOR="$PROJECT_DIR/VendorRuntime"
DESTINATION="$VENDOR/node-v${VERSION}-darwin-arm64"
DOWNLOAD_ROOT=""
STAGE_ROOT=""

cleanup() {
  if [[ -n "$DOWNLOAD_ROOT" && "$DOWNLOAD_ROOT" == /private/tmp/fulmar-node-bootstrap.* ]]; then
    /bin/rm -rf -- "$DOWNLOAD_ROOT"
  fi
  if [[ -n "$STAGE_ROOT" && "$STAGE_ROOT" == "$VENDOR"/.node-bootstrap.* ]]; then
    /bin/rm -rf -- "$STAGE_ROOT"
  fi
}
trap cleanup EXIT

if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
  [[ -d "$DESTINATION" && ! -L "$DESTINATION" && -x "$DESTINATION/bin/node" ]] || {
    print -u2 "The existing pinned Node runtime is incomplete or linked; use a clean checkout."
    exit 1
  }
  [[ "$(/usr/bin/shasum -a 256 "$DESTINATION/bin/node" | /usr/bin/awk '{print $1}')" == "$EXPECTED_EXECUTABLE_SHA256" ]] || {
    print -u2 "The existing pinned Node executable checksum is not reviewed; use a clean checkout."
    exit 1
  }
  [[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C "$DESTINATION/bin/node" --version)" == "v$VERSION" ]]
  exit 0
fi

DOWNLOAD_ROOT="$(mktemp -d /private/tmp/fulmar-node-bootstrap.XXXXXX)"
STAGE_ROOT="$(mktemp -d "$VENDOR/.node-bootstrap.XXXXXX")"
chmod 700 "$DOWNLOAD_ROOT" "$STAGE_ROOT"
DOWNLOAD="$DOWNLOAD_ROOT/$ARCHIVE"

/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
  /usr/bin/curl --disable --fail --silent --show-error --location \
  --noproxy '*' --proxy '' --proto '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 300 \
  "https://nodejs.org/dist/v${VERSION}/${ARCHIVE}" -o "$DOWNLOAD"
ACTUAL_SHA256="$(shasum -a 256 "$DOWNLOAD" | awk '{print $1}')"
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || {
  print -u2 "Node.js archive checksum mismatch."
  exit 1
}
tar -xzf "$DOWNLOAD" -C "$STAGE_ROOT" --no-same-owner
EXTRACTED="$STAGE_ROOT/node-v${VERSION}-darwin-arm64"
[[ -d "$EXTRACTED" && ! -L "$EXTRACTED" && -x "$EXTRACTED/bin/node" ]] || {
  print -u2 "The verified Node archive did not contain the expected runtime."
  exit 1
}
[[ "$(/usr/bin/shasum -a 256 "$EXTRACTED/bin/node" | /usr/bin/awk '{print $1}')" == "$EXPECTED_EXECUTABLE_SHA256" ]] || {
  print -u2 "The verified Node archive did not contain the reviewed executable bytes."
  exit 1
}
[[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C "$EXTRACTED/bin/node" --version)" == "v$VERSION" ]]
[[ ! -e "$DESTINATION" && ! -L "$DESTINATION" ]] || {
  print -u2 "Another process created the pinned Node runtime while bootstrapping."
  exit 1
}
/bin/mv -n "$EXTRACTED" "$DESTINATION"
[[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C "$DESTINATION/bin/node" --version)" == "v$VERSION" ]]
