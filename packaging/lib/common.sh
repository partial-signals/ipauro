#!/usr/bin/env bash
# packaging/lib/common.sh — shared config for IPAuRo's macOS packaging scripts.
#
# Sourced (never executed directly) by build-app.sh, install-dev.sh,
# uninstall-dev.sh, verify.sh, and notarize.sh so the bundle identifier,
# launchd labels, paths, and team ID are defined in exactly one place.
#
# @arch:see(.yah/docs/working/W001-ipauro-plan.md)
# @arch:see(.yah/docs/architecture/A001-ipauro-architecture.md) R002-T2, R002-T6

set -euo pipefail

# --- paths (resolved relative to this file, independent of caller's cwd) ---
PKG_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${PKG_LIB_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PKG_DIR}/.." && pwd)"

# shellcheck disable=SC2034  # consumed by the scripts that source this file, not by common.sh itself
DIST_DIR="${REPO_ROOT}/dist"
APP_NAME="IPAuRo.app"
# shellcheck disable=SC2034
APP_PATH="${DIST_DIR}/${APP_NAME}"

# --- stable identifiers ---
# SOURCE OF TRUTH: crates/ipauro-proto/src/lib.rs `ids` module. That crate is
# manager-owned — packaging must not edit it. If these three literals ever
# drift from it, request the change there and update the literals below to
# match; don't just patch around a mismatch here.
# shellcheck disable=SC2034
BUNDLE_ID="io.ipauro.app"
# shellcheck disable=SC2034
CORE_AGENT_LABEL="io.ipauro.core"
# shellcheck disable=SC2034
HELPER_LABEL="io.ipauro.helper"
PROTO_SRC="${REPO_ROOT}/crates/ipauro-proto/src/lib.rs"

# assert_id_in_proto_source ID — fails loudly if ID no longer appears as a
# string literal in the manager-owned ids module, so a silent drift between
# the proto crate and the plists we bake into the bundle is caught at build
# time instead of discovered later as a mysterious SMAppService rejection.
assert_id_in_proto_source() {
  local id="$1"
  if [[ ! -f "${PROTO_SRC}" ]]; then
    echo "error: expected ${PROTO_SRC} to exist (has ipauro-proto moved?)" >&2
    exit 1
  fi
  if ! grep -qF "\"${id}\"" "${PROTO_SRC}"; then
    echo "error: identifier '${id}' not found as a string literal in ${PROTO_SRC}" >&2
    echo "       packaging/lib/common.sh has drifted from the manager-owned ids module." >&2
    echo "       Update the literals in common.sh to match; do not edit ipauro-proto." >&2
    exit 1
  fi
}

# --- team ID (overridable for forks; must match the codesign identity used) ---
IPAURO_TEAM_ID="${IPAURO_TEAM_ID:-7BW4R8G8Q6}"
export IPAURO_TEAM_ID # ipauro_proto::ids::team_id() reads this via option_env!() at COMPILE time

# --- build profile ---
IPAURO_PROFILE="${IPAURO_PROFILE:-release}"
# shellcheck disable=SC2034  # CARGO_PROFILE_FLAG is consumed by build-app.sh
case "${IPAURO_PROFILE}" in
  release) CARGO_PROFILE_FLAG="--release" ;;
  debug) CARGO_PROFILE_FLAG="" ;;
  *)
    echo "error: IPAURO_PROFILE must be 'release' or 'debug' (got '${IPAURO_PROFILE}')" >&2
    exit 1
    ;;
esac
# shellcheck disable=SC2034
TARGET_BIN_DIR="${REPO_ROOT}/target/${IPAURO_PROFILE}"

# workspace_version — reads the single `version = "..."` line under
# [workspace.package] in the root Cargo.toml (every crate inherits it via
# version.workspace = true, so there is exactly one to read).
workspace_version() {
  grep -m1 '^version[[:space:]]*=' "${REPO_ROOT}/Cargo.toml" \
    | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/'
}

# run_with_retry CMD... — cargo may be lock-contended by sibling agents
# building the same workspace concurrently; retry with backoff instead of
# failing on the first contention error.
run_with_retry() {
  local max_attempts=5 attempt=1 delay=5
  until "$@"; do
    if (( attempt >= max_attempts )); then
      echo "error: command failed after ${max_attempts} attempts: $*" >&2
      return 1
    fi
    echo "warn: attempt ${attempt}/${max_attempts} failed for: $* — retrying in ${delay}s (cargo lock contention?)" >&2
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}
