#!/bin/zsh -f

source "${${(%):-%N}:A:h}/watchdog-root.zsh"
FULMAR_SAFE_RELEASE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

fulmar_require_clean_release_environment() {
  local mode="$1"
  local script="$2"
  shift 2
  [[ "$mode" == verify || "$mode" == public ]] || {
    print -u2 "Unsupported Fulmar clean-environment mode: $mode"
    return 64
  }
  if [[ "${FULMAR_CLEAN_RELEASE_MODE:-}" != "$mode" ]]; then
    [[ -z "${FULMAR_CLEAN_RELEASE_MODE:-}" ]] || {
      print -u2 "A mismatched Fulmar clean-environment marker was supplied."
      return 1
    }
    local release_home="${HOME:-}"
    local release_user="$(/usr/bin/id -un)"
    [[ "$release_home" == /* && -d "$release_home" && ! -L "$release_home" \
       && "$release_home" != *$'\n'* && "$release_home" != *$'\r'* ]] || {
      print -u2 "Release verification requires one real absolute user home."
      return 1
    }
    typeset -a clean_environment
    clean_environment=(
      "HOME=$release_home"
      "CFFIXED_USER_HOME=$release_home"
      "TMPDIR=/private/tmp/"
      "PATH=$FULMAR_SAFE_RELEASE_PATH"
      "USER=$release_user"
      "LOGNAME=$release_user"
      "LANG=en_US.UTF-8"
      "LC_CTYPE=UTF-8"
      "FULMAR_CLEAN_RELEASE_MODE=$mode"
    )
    local watchdog_state=0
    fulmar_root_watchdog_state || watchdog_state=$?
    if (( watchdog_state == 0 )); then
      clean_environment+=(
        "FULMAR_ROOT_WATCHDOG_PGID_V1=$FULMAR_ROOT_WATCHDOG_PGID_V1"
        "FULMAR_ROOT_WATCHDOG_PID_V1=$FULMAR_ROOT_WATCHDOG_PID_V1"
        "FULMAR_INTERNAL_WATCHDOG_DEPTH=$FULMAR_INTERNAL_WATCHDOG_DEPTH"
        "FULMAR_ROOT_WATCHDOG_CAPABILITY_V1=$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1"
        "FULMAR_ROOT_WATCHDOG_NONCE_V1=$FULMAR_ROOT_WATCHDOG_NONCE_V1"
        "FULMAR_ROOT_WATCHDOG_FD_V1=$FULMAR_ROOT_WATCHDOG_FD_V1"
      )
    elif (( watchdog_state == 2 )); then
      print -u2 "Release verification inherited an invalid root-watchdog attestation."
      return 1
    fi
    if [[ "$mode" == verify && -n "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-}" ]]; then
      local stable_signing="$LOCAL_HARNESS_REQUIRE_STABLE_SIGNING"
      [[ "$stable_signing" == 0 || "$stable_signing" == 1 ]] || {
        print -u2 "LOCAL_HARNESS_REQUIRE_STABLE_SIGNING must be 0 or 1."
        return 1
      }
      clean_environment+=("LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=$stable_signing")
    fi
    exec /usr/bin/env -i "${clean_environment[@]}" /bin/zsh -f "${script:A}" "$@"
  fi

  [[ "$PATH" == "$FULMAR_SAFE_RELEASE_PATH" && "$TMPDIR" == "/private/tmp/" \
     && -z "${DEVELOPER_DIR:-}" && -z "${SDKROOT:-}" \
     && -z "${NODE_OPTIONS:-}" && -z "${NODE_PATH:-}" \
     && -z "${DYLD_INSERT_LIBRARIES:-}" && -z "${DYLD_LIBRARY_PATH:-}" \
     && -z "${HTTP_PROXY:-}" && -z "${HTTPS_PROXY:-}" && -z "${ALL_PROXY:-}" \
     && -z "${SSL_CERT_FILE:-}" && -z "${SSL_CERT_DIR:-}" && -z "${CURL_CA_BUNDLE:-}" ]] || {
    print -u2 "Release verification did not enter the exact clean environment."
    return 1
  }
  local clean_watchdog_state=0
  fulmar_root_watchdog_state || clean_watchdog_state=$?
  (( clean_watchdog_state != 2 )) || {
    print -u2 "Release verification lost its root-watchdog attestation."
    return 1
  }
  local unexpected_environment
  unexpected_environment="$(/usr/bin/env \
    | /usr/bin/sed -E \
      '/^(CFFIXED_USER_HOME|FULMAR_CLEAN_RELEASE_MODE|FULMAR_INTERNAL_WATCHDOG_DEPTH|FULMAR_ROOT_WATCHDOG_CAPABILITY_V1|FULMAR_ROOT_WATCHDOG_FD_V1|FULMAR_ROOT_WATCHDOG_NONCE_V1|FULMAR_ROOT_WATCHDOG_PGID_V1|FULMAR_ROOT_WATCHDOG_PID_V1|HOME|LANG|LC_CTYPE|LOCAL_HARNESS_REQUIRE_STABLE_SIGNING|LOGNAME|OLDPWD|PATH|PWD|SHLVL|TMPDIR|USER|_)=/d; s/=.*$//')"
  [[ -z "$unexpected_environment" ]] || {
    print -u2 "Release verification inherited an unreviewed environment variable: ${unexpected_environment%%$'\n'*}"
    return 1
  }
  umask 077
}
