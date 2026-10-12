#!/usr/bin/env bash
#
# Control-plane CI (R009-T1) — run every hardware-free test in a Linux container.
#
# IPAuRo's data plane is macOS kernel machinery (if_bridge, pf, XPC, IOKit) and can
# only be exercised on real hardware or a macOS VM. Its *control* plane — ioreg /
# ifconfig / netstat parsing, the desired-state reconciler, the IPC protocol, mesh
# gossip/topology/routing/election — is pure logic over captured fixtures, so it
# runs anywhere. This script is the boundary between those two worlds, and it is
# written to make the boundary *fail loudly* rather than drift silently:
#
#   * The set of workspace members is read from Cargo.toml, never hardcoded. Every
#     member must appear in the classification table below. Adding a crate without
#     classifying it FAILS the run (see `classify`), so "we forgot to put the new
#     crate in CI" is not a reachable state.
#   * Each macOS-only exclusion carries its *reason* in the table. An exclusion with
#     no reason is a bug, not a policy.
#   * The container's CARGO_TARGET_DIR is a dedicated subdirectory, never the host's
#     `target/`. Linux and macOS artifacts share no fingerprints, and a concurrent
#     host `cargo build` is not blocked on our lock.
#
# Usage:
#   scripts/ci-control-plane.sh                     # run the suite in a pinned container
#   scripts/ci-control-plane.sh --native            # run the same crate set on this host
#   scripts/ci-control-plane.sh --list              # print the classification and exit
#   scripts/ci-control-plane.sh --verify-exclusions # prove each macOS-only crate really is
#
# See .yah/docs/working/W001-ipauro-plan.md §9 (test strategy) and
# .yah/docs/architecture/A002-ipauro-findings.md (the failure modes CI cannot reach).

set -euo pipefail

# Pinned by tag so two runs a month apart use the same compiler; the resolved
# digest is recorded in the run manifest so a tag re-point is visible after the
# fact. Keep in step with the toolchain the macOS job uses.
IMAGE="${IPAURO_CI_IMAGE:-rust:1.97.0-bookworm}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- classification table -----------------------------------------------------
#
# Keyed by workspace-member *path* (what Cargo.toml lists). Value is either
# `container` — hardware-free, runs in the Linux job — or `macos:<reason>`.
#
# A `macos:` entry is a statement about the crate's dependencies, not a wish. Each
# one is re-checked by `--verify-exclusions`, which proves the crate still fails to
# build on Linux; an exclusion that has silently become portable is reported so it
# can be promoted into the container job.
classify() {
  case "$1" in
    crates/ipauro-proto)  echo "container" ;;
    crates/ipauro-core)   echo "container" ;;
    crates/ipauro-cli)    echo "container" ;;
    crates/ipauro-mesh)   echo "container" ;;
    crates/ipauro-probe)  echo "container" ;;
    crates/ipauro-xpc)    echo "macos:hand-rolled FFI over Apple's C XPC API; no non-Apple implementation exists" ;;
    app/helper)           echo "macos:depends on ipauro-xpc + block2 -> objc2, which refuses to compile off Apple platforms. Its pf/bridge/DHCP rule generation is macOS-only BY DESIGN, not by accident: W002 classifies pf/ifconfig/bootpd as 'not portable, and not worth making so', and the Linux agent (R011-F2) generates nftables rules from its own executor rather than sharing this one. So this crate's tests belong on the macOS job, and there is nothing here to lift into the container." ;;
    app/ui)               echo "macos:eframe + tray-icon; a GUI client is out of scope for headless CI regardless of platform" ;;
    *)                    echo "" ;;
  esac
}

# --- workspace members, straight from the manifest ----------------------------
members() {
  sed -n '/^members = \[/,/^\]/p' Cargo.toml \
    | grep -o '"[^"]*"' \
    | tr -d '"'
}

# Package name for a member path (the -p argument cargo wants).
pkg_name() {
  grep -m1 '^name = ' "$1/Cargo.toml" | sed 's/^name = "\(.*\)"/\1/'
}

CONTAINER_PKGS=()
EXCLUDED=()
EXCLUDED_PKGS=()
UNCLASSIFIED=()

for m in $(members); do
  kind="$(classify "$m")"
  case "$kind" in
    container)  CONTAINER_PKGS+=("$(pkg_name "$m")") ;;
    macos:*)    EXCLUDED+=("$m -> ${kind#macos:}"); EXCLUDED_PKGS+=("$(pkg_name "$m")") ;;
    "")         UNCLASSIFIED+=("$m") ;;
  esac
done

if [ "${#UNCLASSIFIED[@]}" -ne 0 ]; then
  echo "FAIL: workspace member(s) missing from the control-plane CI classification:" >&2
  printf '  - %s\n' "${UNCLASSIFIED[@]}" >&2
  echo >&2
  echo "Add each to classify() in $0 as either:" >&2
  echo "  container                      — hardware-free, belongs in the Linux job" >&2
  echo "  macos:<why it cannot build>    — with the actual blocking dependency named" >&2
  exit 1
fi

print_classification() {
  echo "container-tested (${#CONTAINER_PKGS[@]}): ${CONTAINER_PKGS[*]}"
  echo "excluded (${#EXCLUDED[@]}):"
  printf '  - %s\n' "${EXCLUDED[@]}"
}

MODE="container"
for arg in "$@"; do
  case "$arg" in
    --native)             MODE="native" ;;
    --verify-exclusions)  MODE="verify-exclusions" ;;
    --list)               print_classification; exit 0 ;;
    --image=*)            IMAGE="${arg#--image=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

CARGO_ARGS=()
for p in "${CONTAINER_PKGS[@]}"; do CARGO_ARGS+=(-p "$p"); done

print_classification
echo

MANIFEST_DIR="target/ci"
mkdir -p "$MANIFEST_DIR"

if [ "$MODE" = "native" ]; then
  echo "==> native run on $(uname -s)/$(uname -m)"
  cargo test --locked "${CARGO_ARGS[@]}"
  exit 0
fi

# Exclusions rot in the direction nobody watches: a crate loses its last Apple-only
# dependency and quietly stays out of CI forever. This mode asserts the *negative*
# — each excluded crate must still fail to build on Linux. A crate that now builds
# is not a failure of the code, it is a promotion waiting to happen, so say so.
if [ "$MODE" = "verify-exclusions" ]; then
  echo "==> verifying ${#EXCLUDED_PKGS[@]} exclusions against $IMAGE"
  promotable=()
  for p in "${EXCLUDED_PKGS[@]}"; do
    if docker run --rm -v "$REPO_ROOT":/w -w /w -e CARGO_TARGET_DIR=/tmp/verify "$IMAGE" \
         cargo check --locked -p "$p" >/dev/null 2>&1; then
      echo "  PROMOTABLE  $p — builds on Linux; its exclusion reason is stale"
      promotable+=("$p")
    else
      echo "  still macOS-only  $p"
    fi
  done
  if [ "${#promotable[@]}" -ne 0 ]; then
    echo >&2
    echo "FAIL: ${#promotable[@]} crate(s) no longer need excluding: ${promotable[*]}" >&2
    echo "Move them to \`container\` in classify() so their tests actually run." >&2
    exit 1
  fi
  exit 0
fi

# Linux artifacts and cargo registry live under target/ so a `git clean` sweeps
# them, but in their own subdirectories: sharing target/debug with the host's
# macOS build would thrash fingerprints on every alternating run and make the two
# `cargo` invocations contend for one lock.
LINUX_TARGET="$REPO_ROOT/target/ci-linux"
LINUX_CARGO_HOME="$REPO_ROOT/target/ci-cargo-home"
mkdir -p "$LINUX_TARGET" "$LINUX_CARGO_HOME"

echo "==> pulling $IMAGE"
docker pull --quiet "$IMAGE" >/dev/null
IMAGE_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo "<local-only>")"

echo "==> control-plane suite in $IMAGE"
docker run --rm \
  -v "$REPO_ROOT":/w -w /w \
  -v "$LINUX_TARGET":/w/target/ci-linux \
  -v "$LINUX_CARGO_HOME":/cargo-home \
  -e CARGO_TARGET_DIR=/w/target/ci-linux \
  -e CARGO_HOME=/cargo-home \
  "$IMAGE" \
  cargo test --locked "${CARGO_ARGS[@]}"

RUSTC_VER="$(docker run --rm "$IMAGE" rustc --version)"

{
  echo "ipauro control-plane CI manifest (R009-T1)"
  echo "generated:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git rev:     $(git rev-parse HEAD)"
  echo "git dirty:   $(if [ -n "$(git status --porcelain)" ]; then echo yes; else echo no; fi)"
  echo "image:       $IMAGE"
  echo "digest:      $IMAGE_DIGEST"
  echo "rustc:       $RUSTC_VER"
  echo "crates:      ${CONTAINER_PKGS[*]}"
  echo "excluded:"
  printf '  %s\n' "${EXCLUDED[@]}"
} > "$MANIFEST_DIR/control-plane-manifest.txt"

echo
echo "==> manifest written to $MANIFEST_DIR/control-plane-manifest.txt"
