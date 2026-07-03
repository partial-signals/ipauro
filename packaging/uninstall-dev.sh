#!/usr/bin/env bash
# packaging/uninstall-dev.sh — best-effort dev-machine cleanup for IPAuRo.
#
# Tears down what install-dev.sh set up: bootout the helper daemon + core
# agent from launchd, remove the installed app, and drop the PATH symlink
# IFF it points into IPAuRo.app (never touch an unrelated /usr/local/bin/ipauro).
#
# NOTE: this does not call SMAppService's unregister() — that's an in-app API
# call the running app should make before quitting/updating. This script is
# the blunt dev-cycle fallback for wiping a dev install, not a substitute for
# the app's own graceful unregister path.
#
# Usage: bash packaging/uninstall-dev.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INSTALL_PATH="/Applications/${APP_NAME}"
CLI_LINK="/usr/local/bin/ipauro"

echo "==> Booting out launchd jobs (best-effort; fine if already absent)"
launchctl bootout "system/${HELPER_LABEL}" 2>&1 | sed 's/^/    /' || true
launchctl bootout "gui/$(id -u)/${CORE_AGENT_LABEL}" 2>&1 | sed 's/^/    /' || true

if [[ -L "${CLI_LINK}" ]]; then
  LINK_TARGET="$(readlink "${CLI_LINK}")"
  if [[ "${LINK_TARGET}" == *"${APP_NAME}"* ]]; then
    echo "==> Removing PATH symlink ${CLI_LINK} -> ${LINK_TARGET}"
    rm -f "${CLI_LINK}"
  else
    echo "==> Leaving ${CLI_LINK} alone (points at ${LINK_TARGET}, not our app)"
  fi
fi

if [[ -d "${INSTALL_PATH}" ]]; then
  echo "==> Removing ${INSTALL_PATH}"
  rm -rf "${INSTALL_PATH}"
else
  echo "==> ${INSTALL_PATH} not present"
fi

cat <<EOF

==> Done (best-effort). Remaining manual step:
    System Settings > General > Login Items & Extensions may still list
    "IPAuRo" under "Allow in the Background" — remove it there if present.
    SMAppService leaves that entry until the user (or the app's own
    unregister() call) clears it; this script cannot do that from outside a
    running, registered app.
EOF
