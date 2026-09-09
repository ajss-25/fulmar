#!/bin/sh -p
set -eu
unset IFS
CDPATH=
export CDPATH

fail() {
  echo "The private Swift Testing host could not be prepared: $1" >&2
  exit 126
}

[ "$#" -eq 5 ] || fail "expected source, destination, compiler, SDK, and deployment target"
host_source=$1
destination_app=$2
swiftc=$3
sdkroot=$4
minimum_macos=$5

case $host_source in /*) ;; *) fail "the host source path is not absolute" ;; esac
case $destination_app in
  /private/tmp/fulmar-swift-tests.??????/FulmarSwiftTestingHost.app) ;;
  *) fail "the destination is outside the attested Swift-test root" ;;
esac
case $swiftc in /*) ;; *) fail "the Swift compiler path is not absolute" ;; esac
case $sdkroot in /*) ;; *) fail "the SDK path is not absolute" ;; esac
case $minimum_macos in
  [1-9][0-9].[0-9]|[1-9][0-9].[0-9].[0-9]) ;;
  *) fail "the deployment target is malformed" ;;
esac

parent=${destination_app%/*}
[ -d "$parent" ] && [ ! -L "$parent" ] || fail "the destination parent is unsafe"
current_uid=$(/usr/bin/id -u) || fail "the current user could not be resolved"
[ "$(/usr/bin/stat -f '%u:%HT:%Lp' "$parent" 2>/dev/null)" = "$current_uid:Directory:700" ] \
  || fail "the destination parent identity changed"
[ ! -e "$destination_app" ] && [ ! -L "$destination_app" ] \
  || fail "the destination already exists"

[ -f "$host_source" ] && [ ! -L "$host_source" ] \
  || fail "the reviewed host source is unsafe"
source_identity=$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp:%l:%z' "$host_source" 2>/dev/null) \
  || fail "the reviewed host source identity is unreadable"
case $source_identity in
  *:"$current_uid":Regular\ File:600:1:*|*:"$current_uid":Regular\ File:644:1:*) ;;
  *) fail "the reviewed host source metadata is invalid" ;;
esac
source_sha=$(/usr/bin/shasum -a 256 "$host_source" | /usr/bin/awk '{ print $1 }') \
  || fail "the reviewed host source digest could not be read"
[ "${#source_sha}" -eq 64 ] || fail "the reviewed host source digest was malformed"
case $source_sha in *[!0-9a-f]*) fail "the reviewed host source digest was malformed" ;; esac

[ -f "$swiftc" ] && [ ! -L "$swiftc" ] && [ -x "$swiftc" ] \
  || fail "the Swift compiler is unsafe"
compiler_identity=$(/usr/bin/stat -f '%d:%i:%u:%g:%HT:%Lp:%l:%z' "$swiftc" 2>/dev/null) \
  || fail "the Swift compiler identity is unreadable"
case $compiler_identity in *:0:0:Regular\ File:755:*) ;; *) fail "the Swift compiler metadata is invalid" ;; esac
/usr/bin/codesign --verify --strict --test-requirement '=anchor apple' "$swiftc" >/dev/null 2>&1 \
  || fail "the Swift compiler is not Apple-signed"
[ -d "$sdkroot" ] || fail "the selected SDK is unsafe"

staging_app="$destination_app.staging.$$"
case $staging_app in
  /private/tmp/fulmar-swift-tests.??????/FulmarSwiftTestingHost.app.staging.[1-9][0-9]*) ;;
  *) fail "the staging app path is unsafe" ;;
esac
[ ! -e "$staging_app" ] && [ ! -L "$staging_app" ] || fail "the staging app already exists"

cleanup_staging() {
  case $staging_app in
    /private/tmp/fulmar-swift-tests.??????/FulmarSwiftTestingHost.app.staging.[1-9][0-9]*)
      if [ -e "$staging_app" ] || [ -L "$staging_app" ]; then
        /bin/rm -R -- "$staging_app" || return 126
      fi
      ;;
    *) return 126 ;;
  esac
}
on_signal() {
  signal_exit=$1
  trap - 0 HUP INT TERM
  cleanup_staging >/dev/null 2>&1 || true
  exit "$signal_exit"
}
trap 'cleanup_staging >/dev/null 2>&1 || true' 0
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

/bin/mkdir -m 0700 "$staging_app" || fail "the staging app could not be created"
/bin/mkdir -m 0700 "$staging_app/Contents" "$staging_app/Contents/MacOS" \
  || fail "the staging app contents could not be created"
plist=$staging_app/Contents/Info.plist
executable=$staging_app/Contents/MacOS/FulmarSwiftTestingHost

/usr/bin/plutil -create xml1 "$plist" || fail "the private app property list could not be created"
/usr/bin/plutil -insert CFBundleDevelopmentRegion -string en "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundleExecutable -string FulmarSwiftTestingHost "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundleIdentifier -string dev.fulmar.private.swift-testing-host "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundleName -string 'Fulmar Swift Testing Host' "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundleShortVersionString -string 1.0 "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert CFBundleVersion -string 1 "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert LSUIElement -bool true "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert NSPrincipalClass -string NSApplication "$plist" || fail "the property list is incomplete"
/usr/bin/plutil -insert NSSupportsAutomaticTermination -bool false "$plist" || fail "the property list is incomplete"
/bin/chmod 0600 "$plist" || fail "the property list mode could not be fixed"

architecture=$(/usr/bin/uname -m) || fail "the host architecture is unavailable"
case $architecture in arm64|x86_64) ;; *) fail "the host architecture is unsupported" ;; esac
"$swiftc" -parse-as-library -warnings-as-errors -O \
  -sdk "$sdkroot" -target "$architecture-apple-macosx$minimum_macos" \
  "$host_source" -o "$executable" \
  || fail "the reviewed Swift Testing host did not compile"
/bin/chmod 0700 "$executable" || fail "the compiled Swift Testing host mode could not be fixed"
[ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
  || fail "the compiled Swift Testing host is unsafe"
[ "$(/usr/bin/stat -f '%u:%HT:%Lp:%l' "$executable" 2>/dev/null)" \
   = "$current_uid:Regular File:700:1" ] \
  || fail "the compiled Swift Testing host metadata is invalid"

/usr/bin/codesign --force --sign - --timestamp=none "$staging_app" >/dev/null 2>&1 \
  || fail "the private Swift Testing app could not be signed"
/usr/bin/codesign --verify --strict "$staging_app" >/dev/null 2>&1 \
  || fail "the private Swift Testing app signature is invalid"
[ "$(/usr/bin/codesign -d --verbose=4 "$staging_app" 2>&1 | /usr/bin/awk -F= '$1 == "Identifier" { print $2 }')" \
   = dev.fulmar.private.swift-testing-host ] \
  || fail "the private Swift Testing app identity is invalid"
[ "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp:%l:%z' "$host_source" 2>/dev/null)" = "$source_identity" ] \
  && [ "$(/usr/bin/shasum -a 256 "$host_source" | /usr/bin/awk '{ print $1 }')" = "$source_sha" ] \
  || fail "the reviewed host source changed while the private app was assembled"
[ "$(/usr/bin/stat -f '%d:%i:%u:%g:%HT:%Lp:%l:%z' "$swiftc" 2>/dev/null)" = "$compiler_identity" ] \
  || fail "the Swift compiler changed while the private app was assembled"

[ "$(/usr/bin/plutil -extract CFBundlePackageType raw -o - "$plist")" = APPL ] \
  && [ "$(/usr/bin/plutil -extract LSUIElement raw -o - "$plist")" = true ] \
  && [ "$(/usr/bin/plutil -extract NSPrincipalClass raw -o - "$plist")" = NSApplication ] \
  && [ "$(/usr/bin/plutil -extract NSSupportsAutomaticTermination raw -o - "$plist")" = false ] \
  || fail "the private app property list did not round-trip exactly"

/bin/mv "$staging_app" "$destination_app" || fail "the private app could not be published atomically"
trap - 0 HUP INT TERM
printf '%s\n' "$destination_app/Contents/MacOS/FulmarSwiftTestingHost"
