#!/bin/zsh -f
set -euo pipefail

APP="${1:-}"
SYMBOL_ROOT="${2:-}"
SOURCE_PREFIX="${3:-}"
SCRATCH_PREFIX="${4:-}"
[[ -n "$APP" ]] || { print -u2 "usage: verify-native-symbol-privacy.sh <Fulmar.app> [Fulmar.dSYMs] [source-prefix] [scratch-prefix]"; exit 1; }
APP="${APP:A}"
[[ -d "$APP" && ! -L "$APP" ]] || { print -u2 "Native-symbol verification requires a real app bundle."; exit 1; }
if [[ -n "$SYMBOL_ROOT" ]]; then
  SYMBOL_ROOT="${SYMBOL_ROOT:A}"
  [[ -d "$SYMBOL_ROOT" && ! -L "$SYMBOL_ROOT" ]] || { print -u2 "Native-symbol verification requires a real symbol root."; exit 1; }
fi

typeset -a products
products=(
  LocalHarness
  LocalHarnessCredentialHelper
  LocalHarnessCredentialBrokerService
  LocalHarnessCredentialMigrationService
  LocalHarnessRuntimeLease
  LocalHarnessSandboxRunner
  LocalHarnessSchedulerHelper
  LocalHarnessUpdateHelper
)

MACOS="$APP/Contents/MacOS"
[[ -d "$MACOS" && ! -L "$MACOS" ]] || { print -u2 "Missing native executable directory."; exit 1; }
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-native-symbols.XXXXXX)"
cleanup() {
  local exit_code="${1:-$?}"
  /bin/rm -rf -- "$TEMP_ROOT"
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
typeset -a symbol_files
symbol_files=()
actual_count="$(/usr/bin/find "$MACOS" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
top_count="$(/usr/bin/find "$MACOS" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
[[ "$actual_count" == "6" && "$top_count" == "6" ]] || {
  print -u2 "The app must contain exactly the six reviewed native executables."; exit 1
}

if [[ -n "$SYMBOL_ROOT" ]]; then
  entry_count="$(/usr/bin/find "$SYMBOL_ROOT" -mindepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  total_kib="$(/usr/bin/du -sk "$SYMBOL_ROOT" | /usr/bin/awk '{ print $1 }')"
  [[ "$entry_count" -le 50000 && "$total_kib" -le 262144 ]] || {
    print -u2 "The symbol tree exceeds its entry or byte limit."; exit 1
  }
  if [[ -n "$(/usr/bin/find "$SYMBOL_ROOT" \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit)" ]]; then
    print -u2 "The symbol tree contains a link or special file."; exit 1
  fi
  symbol_file_count=0
  while IFS= read -r -d '' symbol_file; do
    (( symbol_file_count += 1 ))
    symbol_files+=("$symbol_file")
    [[ "$(/usr/bin/stat -f %l "$symbol_file")" == "1" ]] || {
      print -u2 "The symbol tree contains a hard-linked file."; exit 1
    }
  done < <(/usr/bin/find "$SYMBOL_ROOT" -type f -print0)
  (( symbol_file_count > 0 )) || { print -u2 "The symbol tree contains no regular files."; exit 1; }
fi

probe_file_pattern() {
  local mode="$1"
  local pattern="$2"
  local file="$3"
  set +e
  case "$mode" in
    extended) LC_ALL=C /usr/bin/grep -E -- "$pattern" "$file" >/dev/null ;;
    fixed) LC_ALL=C /usr/bin/grep -F -- "$pattern" "$file" >/dev/null ;;
    binary-extended) LC_ALL=C /usr/bin/grep -aE -- "$pattern" "$file" >/dev/null ;;
    binary-fixed) LC_ALL=C /usr/bin/grep -aF -- "$pattern" "$file" >/dev/null ;;
    *) set -e; print -u2 "Unsupported native-symbol scan mode."; exit 1 ;;
  esac
  local scan_status=$?
  set -e
  if (( scan_status == 0 )); then
    return 0
  elif (( scan_status == 1 )); then
    return 1
  fi
  print -u2 "Native-symbol evidence could not be scanned safely."
  exit 1
}

uuid_for() {
  /usr/bin/xcrun dwarfdump --uuid "$1" \
    | /usr/bin/awk 'NF == 4 && $1 == "UUID:" && $3 == "(arm64)" { print $2 }'
}

for product in "${products[@]}"; do
  executable="$MACOS/$product"
  if [[ "$product" == "LocalHarnessCredentialMigrationService" ]]; then
    executable="$APP/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/$product"
  elif [[ "$product" == "LocalHarnessCredentialBrokerService" ]]; then
    executable="$APP/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/MacOS/$product"
  fi
  [[ -f "$executable" && ! -L "$executable" && -x "$executable" \
     && "$(/usr/bin/stat -f %l "$executable")" == "1" ]] || {
    print -u2 "Unsafe or missing native executable: $product"; exit 1
  }
  /usr/bin/file "$executable" | /usr/bin/grep -q 'Mach-O 64-bit executable arm64' || {
    print -u2 "Unexpected native executable format: $product"; exit 1
  }
  executable_uuid="$(uuid_for "$executable")"
  [[ "$executable_uuid" =~ '^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$' ]] || {
    print -u2 "Missing or ambiguous arm64 UUID: $product"; exit 1
  }

  /usr/bin/nm -ap "$executable" > "$TEMP_ROOT/$product.nm"
  if probe_file_pattern extended ' (SO|OSO) ' "$TEMP_ROOT/$product.nm"; then
    print -u2 "Shipped native executable still contains a source/debug-map entry: $product"
    exit 1
  fi
  /usr/bin/otool -l "$executable" > "$TEMP_ROOT/$product.otool"
  if probe_file_pattern extended 'segname __DWARF|sectname __debug_' "$TEMP_ROOT/$product.otool"; then
    print -u2 "Shipped native executable still contains a DWARF section: $product"
    exit 1
  fi
  /usr/bin/strings "$executable" > "$TEMP_ROOT/$product.strings"
  for forbidden in "$SOURCE_PREFIX" "$SCRATCH_PREFIX"; do
    if [[ -n "$forbidden" ]] && probe_file_pattern fixed "$forbidden" "$TEMP_ROOT/$product.strings"; then
      print -u2 "Shipped native executable exposes a private build prefix: $product"
      exit 1
    fi
  done

  if [[ -n "$SYMBOL_ROOT" ]]; then
    symbol_bundle="$SYMBOL_ROOT/$product.dSYM"
    contents="$symbol_bundle/Contents"
    resources="$contents/Resources"
    info_plist="$contents/Info.plist"
    dwarf="$symbol_bundle/Contents/Resources/DWARF/$product"
    relocation="$resources/Relocations/aarch64/$product.yml"
    [[ -d "$symbol_bundle" && ! -L "$symbol_bundle" \
       && -d "$contents" && ! -L "$contents" \
       && -d "$resources" && ! -L "$resources" \
       && -d "$resources/DWARF" && ! -L "$resources/DWARF" \
       && -d "$resources/Relocations" && ! -L "$resources/Relocations" \
       && -d "$resources/Relocations/aarch64" && ! -L "$resources/Relocations/aarch64" \
       && -f "$info_plist" && ! -L "$info_plist" \
       && -f "$dwarf" && ! -L "$dwarf" \
       && -f "$relocation" && ! -L "$relocation" \
       && "$(/usr/bin/stat -f %l "$info_plist")" == "1" \
       && "$(/usr/bin/stat -f %l "$dwarf")" == "1" \
       && "$(/usr/bin/stat -f %l "$relocation")" == "1" ]] || {
      print -u2 "Unsafe or missing dSYM: $product"; exit 1
    }
    bundle_entries="$(/usr/bin/find "$symbol_bundle" -mindepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
    [[ "$bundle_entries" == "8" ]] || {
      print -u2 "The dSYM has an unexpected internal topology: $product"; exit 1
    }
    /usr/bin/plutil -lint "$info_plist" >/dev/null
    plist_keys="$(/usr/bin/plutil -p "$info_plist" | /usr/bin/grep -c ' => ')"
    [[ "$plist_keys" == "7" \
       && "$(/usr/bin/plutil -extract CFBundleDevelopmentRegion raw -o - "$info_plist")" == "English" \
       && "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$info_plist")" == "com.apple.xcode.dsym.$product" \
       && "$(/usr/bin/plutil -extract CFBundleInfoDictionaryVersion raw -o - "$info_plist")" == "6.0" \
       && "$(/usr/bin/plutil -extract CFBundlePackageType raw -o - "$info_plist")" == "dSYM" \
       && "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$info_plist")" == "1.0" \
       && "$(/usr/bin/plutil -extract CFBundleSignature raw -o - "$info_plist")" == "????" \
       && "$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$info_plist")" == "1" ]] || {
      print -u2 "The dSYM Info.plist is not the exact reviewed schema: $product"; exit 1
    }
    [[ "$(/usr/bin/grep -c '^binary-path:' "$relocation")" == "1" \
       && "$(/usr/bin/grep -c '^triple:' "$relocation")" == "1" ]] || {
      print -u2 "The dSYM relocation map is ambiguous: $product"; exit 1
    }
    /usr/bin/grep -Fx -- "triple:          'arm64-apple-darwin'" "$relocation" >/dev/null || {
      print -u2 "The dSYM relocation architecture is unexpected: $product"; exit 1
    }
    /usr/bin/grep -Fx -- "binary-path:     $product" "$relocation" >/dev/null || {
      print -u2 "The dSYM relocation map exposes or references an unexpected binary path: $product"; exit 1
    }
    symbol_uuid="$(uuid_for "$dwarf")"
    [[ "$symbol_uuid" == "$executable_uuid" ]] || {
      print -u2 "dSYM UUID does not match its executable: $product"; exit 1
    }
    verify_output="$TEMP_ROOT/$product.verify.out"
    verify_error="$TEMP_ROOT/$product.verify.err"
    if ! /usr/bin/xcrun dwarfdump --verify "$dwarf" >"$verify_output" 2>"$verify_error"; then
      print -u2 "The dSYM failed structural DWARF verification: $product"
      exit 1
    fi
    [[ ! -s "$verify_error" \
       && "$(/usr/bin/tail -n 1 "$verify_output")" == "No errors." ]] || {
      print -u2 "The dSYM verifier emitted a warning, error, or ambiguous result: $product"
      exit 1
    }
    if probe_file_pattern extended '(^|[^[:alpha:]])(warning|error):' "$verify_output"; then
      print -u2 "The dSYM verifier emitted a warning, error, or ambiguous result: $product"
      exit 1
    fi
    # A UUID-matched Mach-O can still be a useless symbol file. Stream the
    # complete debug information and line table through bounded predicates so
    # every public dSYM proves it contains this Swift product and line records.
    set +e
    /usr/bin/xcrun dwarfdump --debug-info "$dwarf" \
      | /usr/bin/awk -v product="$product" '
          /DW_TAG_compile_unit/ { compileUnit = 1 }
          /DW_LANG_Swift/ { swift = 1 }
          index($0, product) { productName = 1 }
          END { exit !(compileUnit && swift && productName) }
        '
    debug_info_status=("${pipestatus[@]}")
    /usr/bin/xcrun dwarfdump --debug-line "$dwarf" \
      | /usr/bin/awk '
          /^0x[[:xdigit:]]+[[:space:]]+[1-9][0-9]*[[:space:]]/ { lineRecord = 1 }
          END { exit !lineRecord }
        '
    debug_line_status=("${pipestatus[@]}")
    set -e
    [[ "${debug_info_status[1]}" == "0" && "${debug_info_status[2]}" == "0" \
       && "${debug_line_status[1]}" == "0" && "${debug_line_status[2]}" == "0" ]] || {
      print -u2 "The dSYM does not contain useful Swift symbols and line mappings: $product"
      exit 1
    }
    product_symbol_file_count=0
    for symbol_file in "${symbol_files[@]}"; do
      [[ "$symbol_file" == "$symbol_bundle"/* ]] || continue
      (( product_symbol_file_count += 1 ))
      if probe_file_pattern binary-extended \
        '/Users/|/home/|/root/|/private/tmp/|/tmp/|/var/folders/|/Volumes/|/\.build/' \
        "$symbol_file"; then
        print -u2 "dSYM exposes a non-canonical private or temporary build path: $product"
        exit 1
      fi
      for forbidden in "$SOURCE_PREFIX" "$SCRATCH_PREFIX"; do
        if [[ -n "$forbidden" ]] && probe_file_pattern binary-fixed "$forbidden" "$symbol_file"; then
          print -u2 "dSYM exposes an explicitly forbidden build prefix: $product"
          exit 1
        fi
      done
    done
    (( product_symbol_file_count > 0 )) || {
      print -u2 "The dSYM contains no regular files: $product"
      exit 1
    }
  fi
done

if [[ -n "$SYMBOL_ROOT" ]]; then
  symbol_count="$(/usr/bin/find "$SYMBOL_ROOT" -mindepth 1 -maxdepth 1 -type d -name '*.dSYM' | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  top_count="$(/usr/bin/find "$SYMBOL_ROOT" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  [[ "$symbol_count" == "${#products}" && "$top_count" == "${#products}" ]] || {
    print -u2 "The symbol root must contain exactly eight reviewed dSYM bundles."; exit 1
  }
fi

print "Native symbol privacy verified for eight arm64 executables${SYMBOL_ROOT:+ and matching dSYMs}."
