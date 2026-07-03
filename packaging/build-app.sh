#!/usr/bin/env bash
# packaging/build-app.sh — build release binaries and assemble dist/IPAuRo.app.
#
# Usage:
#   bash packaging/build-app.sh                              # full build + sign
#   SKIP_SIGN=1 bash packaging/build-app.sh                  # assemble only, no codesign (CI/dev)
#   IPAURO_PROFILE=debug bash packaging/build-app.sh         # reuse target/debug binaries (faster)
#   IPAURO_TEAM_ID=XXXXXXXXXX bash packaging/build-app.sh    # fork override (must match a keychain identity)
#
# Idempotent: dist/IPAuRo.app is removed and rebuilt from scratch every run.
#
# @arch:see(.yah/docs/working/W001-ipauro-plan.md)
# @arch:see(.yah/docs/architecture/A001-ipauro-architecture.md) R002-T2, R002-T6

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_SIGN="${SKIP_SIGN:-0}"

echo "==> IPAuRo packaging: profile=${IPAURO_PROFILE} team_id=${IPAURO_TEAM_ID} skip_sign=${SKIP_SIGN}"

# --- 0. Guard against identifier drift from the manager-owned ids module ---
assert_id_in_proto_source "${BUNDLE_ID}"
assert_id_in_proto_source "${CORE_AGENT_LABEL}"
assert_id_in_proto_source "${HELPER_LABEL}"

# --- 1. Build exactly the four binaries the bundle needs ---
echo "==> Building binaries (cargo build ${CARGO_PROFILE_FLAG:-<dev profile>})"
# shellcheck disable=SC2086  # CARGO_PROFILE_FLAG is intentionally either empty or a single flag
run_with_retry cargo build ${CARGO_PROFILE_FLAG} \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p ipauro-ui -p ipauro-core -p ipauro-helper -p ipauro-cli

for bin in ipauro-ui ipauro-core ipauro-helper ipauro; do
  if [[ ! -x "${TARGET_BIN_DIR}/${bin}" ]]; then
    echo "error: expected built binary not found: ${TARGET_BIN_DIR}/${bin}" >&2
    exit 1
  fi
done

APP_VERSION="$(workspace_version)"
if [[ -z "${APP_VERSION}" ]]; then
  echo "error: could not read workspace version from ${REPO_ROOT}/Cargo.toml" >&2
  exit 1
fi
echo "==> Workspace version: ${APP_VERSION}"

# --- 2. Assemble the bundle skeleton (clean rebuild each run) ---
echo "==> Assembling ${APP_PATH}"
rm -rf "${APP_PATH}"
mkdir -p \
  "${APP_PATH}/Contents/MacOS" \
  "${APP_PATH}/Contents/Library/LaunchDaemons" \
  "${APP_PATH}/Contents/Library/LaunchAgents"

install -m 755 "${TARGET_BIN_DIR}/ipauro-ui" "${APP_PATH}/Contents/MacOS/ipauro-ui"
install -m 755 "${TARGET_BIN_DIR}/ipauro-core" "${APP_PATH}/Contents/MacOS/ipauro-core"
install -m 755 "${TARGET_BIN_DIR}/ipauro-helper" "${APP_PATH}/Contents/MacOS/ipauro-helper"
install -m 755 "${TARGET_BIN_DIR}/ipauro" "${APP_PATH}/Contents/MacOS/ipauro"

# --- 3. Contents/Info.plist ---
INFO_PLIST="${APP_PATH}/Contents/Info.plist"
cat > "${INFO_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>${BUNDLE_ID}</string>
	<key>CFBundleName</key>
	<string>IPAuRo</string>
	<key>CFBundleDisplayName</key>
	<string>IPAuRo</string>
	<key>CFBundleExecutable</key>
	<string>ipauro-ui</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleShortVersionString</key>
	<string>${APP_VERSION}</string>
	<key>CFBundleVersion</key>
	<string>${APP_VERSION}</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSLocalNetworkUsageDescription</key>
	<string>IPAuRo builds local audio meshes and needs to see devices on your local network.</string>
</dict>
</plist>
PLIST

# --- 4. SMAppService DAEMON plist: Contents/Library/LaunchDaemons ---
# Key set verified against Apple's launchd.plist(5) reference (BundleProgram
# is documented as "only supported for plists that are installed using
# SMAppService"; MachServices registers the XPC mach service by name;
# AssociatedBundleIdentifiers ties the job to the app bundle so System
# Settings > Login Items and TCC can attribute it correctly).
HELPER_PLIST="${APP_PATH}/Contents/Library/LaunchDaemons/${HELPER_LABEL}.plist"
cat > "${HELPER_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${HELPER_LABEL}</string>
	<key>BundleProgram</key>
	<string>Contents/MacOS/ipauro-helper</string>
	<key>MachServices</key>
	<dict>
		<key>${HELPER_LABEL}</key>
		<true/>
	</dict>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>${BUNDLE_ID}</string>
	</array>
</dict>
</plist>
PLIST

# --- 5. SMAppService AGENT plist: Contents/Library/LaunchAgents ---
# No MachServices here: the core brain service is reached over the IPC unix
# socket (ipauro_proto::ipc::default_socket_path()), not an XPC mach service —
# only the helper (ids::HELPER_LABEL) is documented as a mach service name.
CORE_PLIST="${APP_PATH}/Contents/Library/LaunchAgents/${CORE_AGENT_LABEL}.plist"
cat > "${CORE_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${CORE_AGENT_LABEL}</string>
	<key>BundleProgram</key>
	<string>Contents/MacOS/ipauro-core</string>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>${BUNDLE_ID}</string>
	</array>
</dict>
</plist>
PLIST

# --- 6. Lint every plist ---
echo "==> Linting plists"
for p in "${INFO_PLIST}" "${HELPER_PLIST}" "${CORE_PLIST}"; do
  plutil -lint "${p}"
done

# --- 7. Codesign (skippable via SKIP_SIGN=1) ---
if [[ "${SKIP_SIGN}" == "1" ]]; then
  echo "==> SKIP_SIGN=1 — bundle assembled unsigned (dev/CI assembly check only; SMAppService will refuse an unsigned bundle)"
else
  echo "==> Resolving 'Developer ID Application' identity for team ${IPAURO_TEAM_ID}"
  IDENTITY_LINE="$(security find-identity -v -p codesigning 2>/dev/null \
    | grep "Developer ID Application" \
    | grep -F "(${IPAURO_TEAM_ID})" \
    | head -n1 || true)"

  if [[ -z "${IDENTITY_LINE}" ]]; then
    echo "error: no 'Developer ID Application' identity for team ${IPAURO_TEAM_ID} found in the keychain." >&2
    echo "       Available codesigning identities:" >&2
    security find-identity -v -p codesigning >&2 || true
    echo "       Fix by: setting IPAURO_TEAM_ID to a team present above, installing the right Developer ID cert, or using SKIP_SIGN=1 for an unsigned assembly check." >&2
    exit 1
  fi

  IDENTITY="$(echo "${IDENTITY_LINE}" | sed -E 's/^[[:space:]]*[0-9]+\)[[:space:]]+[0-9A-Fa-f]+[[:space:]]+"(.*)"$/\1/')"
  if [[ -z "${IDENTITY}" ]]; then
    echo "error: failed to parse identity name out of: ${IDENTITY_LINE}" >&2
    exit 1
  fi
  echo "==> Signing with identity: ${IDENTITY}"

  # Inside-out: each embedded executable individually first (these are loose
  # executables inside Contents/MacOS, not frameworks/plugins that bundle
  # signing would reach on its own), THEN the bundle. Deliberately not using
  # --deep on the bundle step — inside-out + explicit is the Apple-recommended
  # shape and --deep can silently paper over an unsigned nested binary.
  for bin in ipauro-helper ipauro-core ipauro ipauro-ui; do
    codesign --force --options runtime --timestamp \
      --sign "${IDENTITY}" "${APP_PATH}/Contents/MacOS/${bin}"
  done
  codesign --force --options runtime --timestamp \
    --sign "${IDENTITY}" "${APP_PATH}"

  echo "==> Signature summary"
  codesign -dvv "${APP_PATH}" 2>&1 | sed 's/^/    /'
fi

echo ""
echo "==> Done: ${APP_PATH}"
find "${APP_PATH}" -type f | sed "s|${DIST_DIR}/||" | sort
