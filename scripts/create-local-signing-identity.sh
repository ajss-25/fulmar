#!/bin/zsh -f
set -euo pipefail

IDENTITY_NAME="Fulmar Local Signing"
PROJECT_DIR="${0:A:h:h}"
SIGNING_KEYCHAIN="${LOCAL_HARNESS_SIGNING_KEYCHAIN:-${HOME:?A login home is required}/Library/Keychains/login.keychain-db}"
SIGNING_SECRET_FD="${FULMAR_SIGNING_SECRET_FD_V1:-}"

[[ -z "${LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD+x}" ]] || {
  print -u2 "The signing Keychain password must use the private watchdog descriptor."
  exit 1
}
[[ -z "$SIGNING_SECRET_FD" || "$SIGNING_SECRET_FD" == 196 ]] || {
  print -u2 "The signing-secret descriptor marker is malformed."
  exit 1
}

run_without_signing_secret() {
  if [[ "$SIGNING_SECRET_FD" == 196 ]]; then
    "$@" {SIGNING_SECRET_FD}<&-
  else
    "$@"
  fi
}

[[ "$SIGNING_KEYCHAIN" == /* && "$SIGNING_KEYCHAIN" != *$'\n'* \
   && "$SIGNING_KEYCHAIN" != *$'\r'* && -f "$SIGNING_KEYCHAIN" \
   && ! -L "$SIGNING_KEYCHAIN" && "${SIGNING_KEYCHAIN:A}" == "$SIGNING_KEYCHAIN" \
   && "$(/usr/bin/stat -f '%u' "$SIGNING_KEYCHAIN")" == "$(/usr/bin/id -u)" ]] || {
  print -u2 "The signing Keychain must be one owner-controlled absolute regular file."
  exit 1
}
certificate_hashes() {
  /usr/bin/security find-certificate -a -c "$IDENTITY_NAME" -Z "$SIGNING_KEYCHAIN" 2>/dev/null \
    | sed -n 's/^SHA-1 hash: //p'
}

prove_identity() {
  local hash="$1"
  local probe
  probe="$(mktemp /private/tmp/fulmar-signing-proof.XXXXXX)"
  cp /usr/bin/true "$probe"
  if ! run_without_signing_secret /usr/bin/codesign --force --options runtime --sign "$hash" --keychain "$SIGNING_KEYCHAIN" \
      --identifier com.angadjairath.fulmar.signing-proof "$probe" >/dev/null 2>&1 \
      || ! LOCAL_HARNESS_ALLOW_PRIVATE_ROOT=1 run_without_signing_secret /bin/zsh -f "$PROJECT_DIR/scripts/verify-code-signature.sh" "$probe" --strict; then
    rm -f "$probe"
    return 1
  fi
  rm -f "$probe"
}

existing="$(run_without_signing_secret certificate_hashes)"
if [[ -n "$existing" ]]; then
  existing_hashes=("${(@f)existing}")
  [[ "${#existing_hashes}" == "1" ]] || {
    print -u2 "More than one '$IDENTITY_NAME' certificate exists; refusing an ambiguous signing setup."
    exit 1
  }
  if [[ "$SIGNING_SECRET_FD" == 196 ]]; then
    # The watchdog already attested this one-shot descriptor. An existing
    # usable identity needs no password operation, so close it in this shell
    # rather than allowing a throwaway interpreter (or any later child) to
    # inherit a credential it cannot legitimately consume.
    exec {SIGNING_SECRET_FD}<&-
    unset FULMAR_SIGNING_SECRET_FD_V1
    SIGNING_SECRET_FD=""
  fi
  prove_identity "$existing" || {
    print -u2 "The '$IDENTITY_NAME' certificate has no usable private signing key."
    exit 1
  }
  print -r -- "$existing"
  exit 0
fi

OPENSSL=/usr/bin/openssl
[[ -x "$OPENSSL" ]] || { print -u2 "OpenSSL is required to create the private local identity."; exit 1; }
scratch="$(run_without_signing_secret mktemp -d /private/tmp/fulmar-local-signing.XXXXXX)"
chmod 700 "$scratch"
cleanup() {
  local exit_code="${1:-$?}"
  run_without_signing_secret chmod -R u+rwX "$scratch" 2>/dev/null || true
  run_without_signing_secret rm -rf "$scratch"
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

private_key="$scratch/private-key.pem"
import_key="$scratch/private-key-import.pem"
certificate="$scratch/certificate.pem"
partition_helper="$scratch/set-signing-key-partition-list-from-fd"

umask 077
run_without_signing_secret "$OPENSSL" req -new -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -subj "/CN=$IDENTITY_NAME/O=Fulmar Local Development" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning" \
  -keyout "$private_key" -out "$certificate" >/dev/null 2>&1
run_without_signing_secret "$OPENSSL" rsa -in "$private_key" -out "$import_key" >/dev/null 2>&1
# Import the unencrypted certificate and private-key PEM independently. Their
# containing directory is 0700 and both files are 0600; this avoids creating a
# PKCS#12 passphrase that either OpenSSL or `security import -P` would expose in
# a process argument. The imported private key is immediately non-extractable.
run_without_signing_secret /usr/bin/security import "$certificate" -k "$SIGNING_KEYCHAIN" -t cert -f x509 >/dev/null
run_without_signing_secret /usr/bin/security import "$import_key" -k "$SIGNING_KEYCHAIN" -t priv -f openssl \
  -x -T /usr/bin/codesign >/dev/null
if [[ "$SIGNING_SECRET_FD" == 196 ]]; then
  # A fresh CI Keychain has no interactive user session to approve key use.
  # A tiny native helper reads the one-shot password only from inherited FD
  # 196 and applies the same exact private-key partition ACL without placing
  # the password in argv, an environment value, or terminal input.
  run_without_signing_secret /usr/bin/xcrun clang -std=c11 -O2 -Wall -Wextra -Werror \
    "$PROJECT_DIR/scripts/set-signing-key-partition-list-from-fd.c" \
    -lutil -o "$partition_helper"
  "$partition_helper" "$SIGNING_KEYCHAIN" >/dev/null
  # The helper consumed its inherited copy, but the zsh parent still owns the
  # original seekable descriptor. Close that copy before clearing its marker;
  # otherwise certificate lookup and proof-signing children could inherit and
  # rewind the credential after the authorized operation completed.
  exec {SIGNING_SECRET_FD}<&-
  unset FULMAR_SIGNING_SECRET_FD_V1
  SIGNING_SECRET_FD=""
  /usr/bin/perl -e 'no warnings; exit(open(my $probe, "<&=196") ? 1 : 0)' || {
    print -u2 "The signing-secret descriptor remained readable after its authorized use."
    exit 1
  }
fi
created="$(run_without_signing_secret certificate_hashes)"
created_hashes=("${(@f)created}")
[[ -n "$created" && "${#created_hashes}" == "1" ]] || {
  print -u2 "The local signing identity was imported but did not resolve uniquely."
  exit 1
}
prove_identity "$created" || {
  print -u2 "The local signing identity was imported but could not sign a disposable proof."
  exit 1
}
print -r -- "$created"
