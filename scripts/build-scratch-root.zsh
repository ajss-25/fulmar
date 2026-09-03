#!/bin/zsh -f

typeset -gr FULMAR_BUILD_SCRATCH_MARKER=".fulmar-build-scratch-owner-v1"
typeset -gr FULMAR_BUILD_SCRATCH_RECORD_VERSION="FULMAR_BUILD_SCRATCH_ROOT_V1"
typeset -gr FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX="local-harness-swift-build."
typeset -gr FULMAR_BUILD_SCRATCH_MINIMUM_STALE_AGE=30
typeset -gr FULMAR_BUILD_SCRATCH_MAXIMUM_STALE_AGE=2592000
typeset -gr FULMAR_BUILD_SCRATCH_MAXIMUM_ROOTS=32

fulmar_build_scratch_namespace_is_allowed() {
  local parent="$1" prefix="$2" fixture_nonce=""
  [[ "$parent" == "/private/tmp" ]] || return 1
  if [[ "$prefix" == "$FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX" ]]; then
    return 0
  fi
  fixture_nonce="${prefix#fulmar-build-scratch-fixture.}"
  fixture_nonce="${fixture_nonce%.}"
  [[ "$prefix" == "fulmar-build-scratch-fixture.$fixture_nonce." \
     && "${#fixture_nonce}" == 32 && "$fixture_nonce" != *[^a-f0-9]* ]]
}

fulmar_build_scratch_path_is_allowed() {
  local root="$1" parent="$2" prefix="$3" name suffix
  fulmar_build_scratch_namespace_is_allowed "$parent" "$prefix" || return 1
  name="${root:t}"
  suffix="${name#$prefix}"
  [[ "$root" == "$parent/$name" && "$name" == "$prefix$suffix" \
     && "${#suffix}" == 6 && "$suffix" != *[^A-Za-z0-9]* ]]
}

fulmar_build_scratch_root_identity() {
  local root="$1"
  /usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$root" 2>/dev/null
}

fulmar_build_scratch_marker_metadata() {
  local marker="$1"
  /usr/bin/stat -f '%d:%i:%u:%HT:%Lp:%l:%z' "$marker" 2>/dev/null
}

fulmar_fsync_build_scratch_file() {
  local path="$1"
  /usr/bin/perl -MFcntl=:DEFAULT -MIO::Handle -e '
    use strict; use warnings;
    my ($path) = @ARGV;
    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or exit 126;
    my @before = stat($handle);
    exit 126 unless @before && -f $handle && $before[3] == 1;
    exit 126 unless $handle->sync;
    my @after = stat($handle);
    exit 126 unless @after && $before[0] == $after[0] && $before[1] == $after[1]
      && $before[2] == $after[2] && $before[3] == $after[3]
      && $before[4] == $after[4] && $before[7] == $after[7];
    close($handle) or exit 126;
  ' "$path"
}

fulmar_fsync_build_scratch_directory() {
  local path="$1"
  /usr/bin/perl -MFcntl=:DEFAULT -MIO::Handle -e '
    use strict; use warnings;
    my ($path) = @ARGV;
    sysopen(my $handle, $path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or exit 126;
    my @before = stat($handle);
    exit 126 unless @before && -d $handle;
    exit 126 unless $handle->sync;
    my @after = stat($handle);
    exit 126 unless @after && $before[0] == $after[0] && $before[1] == $after[1]
      && $before[2] == $after[2] && $before[4] == $after[4];
    close($handle) or exit 126;
  ' "$path"
}

fulmar_attest_new_build_scratch_root() {
  local root="$1" parent="$2" prefix="$3" expected_identity="$4" owner_pid="$5" owner_started="$6"
  local created_epoch="$7" capability_path="$8" capability_nonce="$9" watchdog_pid="${10}"
  local failure_phase="${11:-}" current_uid identity marker staging marker_metadata staging_metadata
  current_uid="$(/usr/bin/id -u)" || return 126
  fulmar_build_scratch_path_is_allowed "$root" "$parent" "$prefix" || return 126
  [[ -d "$root" && ! -L "$root" ]] || return 126
  identity="$(fulmar_build_scratch_root_identity "$root")" || return 126
  [[ "$identity" == "$expected_identity" \
     && "$identity" == *":$current_uid:Directory:700" \
     && "$owner_pid" == <-> && "$owner_pid" -gt 1 \
     && -n "$owner_started" && "$owner_started" != *$'\n'* && "$owner_started" != *$'\r'* \
     && "$created_epoch" == <-> \
     && "$capability_path" == "/private/tmp/fulmar-watchdog-capability.$watchdog_pid.$capability_nonce" \
     && "${#capability_nonce}" == 64 && "$capability_nonce" != *[^a-f0-9]* \
     && "$watchdog_pid" == <-> && "$watchdog_pid" -gt 1 \
     && ( -z "$failure_phase" || "$failure_phase" == "before-marker" \
       || "$failure_phase" == "after-marker-create" \
       || "$failure_phase" == "after-durable-publication" ) ]] || return 126

  marker="$root/$FULMAR_BUILD_SCRATCH_MARKER"
  staging="$root/$FULMAR_BUILD_SCRATCH_MARKER.staging"
  [[ ! -e "$marker" && ! -L "$marker" && ! -e "$staging" && ! -L "$staging" ]] || return 126
  [[ "$failure_phase" != "before-marker" ]] || return 125
  setopt localoptions noclobber
  print -r -- "$FULMAR_BUILD_SCRATCH_RECORD_VERSION
$owner_pid
$owner_started
$identity
$created_epoch
$capability_path
$capability_nonce
$watchdog_pid" > "$staging" || return 126
  /bin/chmod 0600 "$staging" || return 126
  staging_metadata="$(fulmar_build_scratch_marker_metadata "$staging")" || return 126
  [[ "$staging_metadata" == *":$current_uid:Regular File:600:1:"<-> \
     && "${staging_metadata##*:}" -ge 1 && "${staging_metadata##*:}" -le 2048 \
     && "$(fulmar_build_scratch_root_identity "$root")" == "$identity" ]] || return 126
  [[ "$failure_phase" != "after-marker-create" ]] || return 125
  fulmar_fsync_build_scratch_file "$staging" || return 126
  /usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or exit 126' "$staging" "$marker" || return 126
  marker_metadata="$(fulmar_build_scratch_marker_metadata "$marker")" || return 126
  [[ "$marker_metadata" == "$staging_metadata" && ! -e "$staging" && ! -L "$staging" \
     && "$(fulmar_build_scratch_root_identity "$root")" == "$identity" ]] || return 126
  fulmar_fsync_build_scratch_directory "$root" || return 126
  fulmar_fsync_build_scratch_directory "$parent" || return 126
  [[ "$(fulmar_build_scratch_root_identity "$root")" == "$identity" \
     && "$(fulmar_build_scratch_marker_metadata "$marker")" == "$marker_metadata" ]] || return 126
  [[ "$failure_phase" != "after-durable-publication" ]] || return 125
  print -r -- "$identity"
}

fulmar_remove_current_build_scratch_root() {
  local root="$1" parent="$2" prefix="$3" expected_identity="$4"
  local current_uid
  current_uid="$(/usr/bin/id -u)" || return 126
  fulmar_build_scratch_path_is_allowed "$root" "$parent" "$prefix" || return 126
  [[ -d "$root" && ! -L "$root" \
     && "$(fulmar_build_scratch_root_identity "$root")" == "$expected_identity" \
     && "$expected_identity" == *":$current_uid:Directory:700" ]] || return 126
  # This is current-run cleanup, authorized by the identity captured
  # immediately after mkdir. It deliberately works before marker publication
  # or after a staged-publication failure, but never without the exact inode.
  [[ "$(fulmar_build_scratch_root_identity "$root")" == "$expected_identity" ]] || return 126
  /bin/rm -rf -- "$root" || return 126
  [[ ! -e "$root" && ! -L "$root" ]] || return 126
}

fulmar_recover_stale_build_scratch_roots() {
  local parent="$1" prefix="$2" pattern current_uid current_epoch
  local stale_root stale_name suffix identity marker staging marker_metadata marker_size contents
  local marker_metadata_after owner_started_now stale_age
  typeset -a stale_roots fields
  fulmar_build_scratch_namespace_is_allowed "$parent" "$prefix" || return 64
  current_uid="$(/usr/bin/id -u)" || return 126
  current_epoch="$(/bin/date +%s)" || return 126
  pattern="$parent/$prefix??????"
  setopt localoptions nullglob
  stale_roots=(${~pattern}(N))
  (( ${#stale_roots[@]} <= FULMAR_BUILD_SCRATCH_MAXIMUM_ROOTS )) || {
    print -u2 "The build found too many private scratch roots for bounded recovery."
    return 126
  }

  for stale_root in "${stale_roots[@]}"; do
    fulmar_build_scratch_path_is_allowed "$stale_root" "$parent" "$prefix" || return 126
    stale_name="${stale_root:t}"
    suffix="${stale_name#$prefix}"
    [[ "${#suffix}" == 6 && "$suffix" != *[^A-Za-z0-9]* \
       && -d "$stale_root" && ! -L "$stale_root" ]] || {
      print -u2 "The build found an unsafe scratch-root candidate: $stale_root"
      return 126
    }
    identity="$(fulmar_build_scratch_root_identity "$stale_root")" || return 126
    [[ "$identity" == *":$current_uid:Directory:700" ]] || {
      print -u2 "The build found a non-private scratch-root candidate: $stale_root"
      return 126
    }

    marker="$stale_root/$FULMAR_BUILD_SCRATCH_MARKER"
    staging="$stale_root/$FULMAR_BUILD_SCRATCH_MARKER.staging"
    if [[ -e "$marker" || -L "$marker" ]]; then
      [[ ! -e "$staging" && ! -L "$staging" ]] || {
        print -u2 "The build found conflicting scratch-root publication records: $stale_root"
        return 126
      }
    elif [[ -e "$staging" || -L "$staging" ]]; then
      # A complete staged record is recoverable after a hard kill between its
      # bounded write and atomic publication. A partial/linked record still
      # fails closed under the same checks below.
      marker="$staging"
    fi
    marker_metadata="$(fulmar_build_scratch_marker_metadata "$marker")" || true
    [[ -f "$marker" && ! -L "$marker" \
       && "$marker_metadata" == *":$current_uid:Regular File:600:1:"<-> ]] || {
      print -u2 "The build found an unattested legacy scratch root requiring manual review: $stale_root"
      return 126
    }
    marker_size="${marker_metadata##*:}"
    [[ "$marker_size" == <-> && "$marker_size" -ge 1 && "$marker_size" -le 2048 ]] || return 126
    # Bound the read even if a same-user process races the marker size after
    # lstat; the inode/metadata are rechecked immediately after this read.
    contents="$(/usr/bin/head -c 2049 -- "$marker")" || return 126
    (( ${#contents} <= 2048 )) || return 126
    marker_metadata_after="$(fulmar_build_scratch_marker_metadata "$marker")" || return 126
    [[ "$marker_metadata_after" == "$marker_metadata" \
       && "$(fulmar_build_scratch_root_identity "$stale_root")" == "$identity" ]] || return 126
    fields=("${(f)contents}")
    (( ${#fields[@]} == 8 )) \
      && [[ "${fields[1]}" == "$FULMAR_BUILD_SCRATCH_RECORD_VERSION" \
         && "${fields[2]}" == <-> && "${fields[2]}" -gt 1 \
         && -n "${fields[3]}" && "${fields[3]}" != *$'\r'* \
         && "${fields[4]}" == "$identity" \
         && "${fields[5]}" == <-> && "${fields[5]}" -le "$current_epoch" \
         && "${fields[6]}" == "/private/tmp/fulmar-watchdog-capability.${fields[8]}.${fields[7]}" \
         && "${#fields[7]}" == 64 && "${fields[7]}" != *[^a-f0-9]* \
         && "${fields[8]}" == <-> && "${fields[8]}" -gt 1 ]] || {
      print -u2 "The build found malformed scratch-root attestation: $stale_root"
      return 126
    }
    [[ ! -e "${fields[6]}" && ! -L "${fields[6]}" ]] || {
      print -u2 "The build retained a scratch root whose watchdog cleanup is still active: $stale_root"
      return 75
    }
    owner_started_now="$(/bin/ps -p "${fields[2]}" -o lstart= 2>/dev/null || true)"
    if [[ -n "$owner_started_now" && "$owner_started_now" == "${fields[3]}" ]]; then
      print -u2 "The build found a live exact owner for private scratch root: $stale_root"
      return 75
    fi
    stale_age=$(( current_epoch - fields[5] ))
    (( stale_age >= FULMAR_BUILD_SCRATCH_MINIMUM_STALE_AGE \
       && stale_age <= FULMAR_BUILD_SCRATCH_MAXIMUM_STALE_AGE )) || {
      print -u2 "The build refused a scratch root outside its 30-second to 30-day recovery window: $stale_root"
      return 126
    }
    [[ "$(fulmar_build_scratch_root_identity "$stale_root")" == "$identity" \
       && "$(fulmar_build_scratch_marker_metadata "$marker")" == "$marker_metadata" ]] || return 126
    /bin/rm -rf -- "$stale_root" || return 126
    [[ ! -e "$stale_root" && ! -L "$stale_root" ]] || return 126
    print -r -- "Removed stale attested build scratch root: $stale_root"
  done
}
