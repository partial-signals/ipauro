#!/usr/bin/env bash
# packaging/install-dev.sh — copy dist/IPAuRo.app to /Applications for local dev.
#
# SMAppService registration (SMAppService.daemon(...).register() /
# SMAppService.agent(...).register()) happens FROM INSIDE the running app, not
# from this script — the service/UI code calls it, and the first call is what
# shows macOS's one-time approval dialog. This script's only job is to place
# the signed bundle where launchd/SMAppService expect a user-installed app
# (/Applications) and, for convenience, put the embedded CLI on PATH.
#
# Usage: bash packaging/install-dev.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INSTALL_PATH="/Applications/${APP_NAME}"
CLI_LINK="/usr/local/bin/ipauro"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "error: ${APP_PATH} not found — run packaging/build-app.sh first." >&2
  exit 1
fi

echo "==> Installing ${APP_PATH} -> ${INSTALL_PATH}"
if ! rsync -a --delete "${APP_PATH}/" "${INSTALL_PATH}/"; then
  echo "error: failed to install to ${INSTALL_PATH} — retry with: sudo bash packaging/install-dev.sh" >&2
  exit 1
fi

# The CLI binary is embedded at Contents/MacOS/ipauro specifically so it can
# be symlinked onto PATH (see packaging/build-app.sh) — do that here.
if [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
  ln -sf "${INSTALL_PATH}/Contents/MacOS/ipauro" "${CLI_LINK}"
  echo "==> Symlinked ${CLI_LINK} -> ${INSTALL_PATH}/Contents/MacOS/ipauro"
else
  echo "==> Skipped PATH symlink (/usr/local/bin missing or not writable)."
  echo "    Create it manually: sudo ln -sf \"${INSTALL_PATH}/Contents/MacOS/ipauro\" \"${CLI_LINK}\""
fi

cat <<EOF

==> Installed. Next:
    1. Launch ${INSTALL_PATH} (Finder double-click, or: open "${INSTALL_PATH}")
    2. On first run the app registers the helper daemon (${HELPER_LABEL}) and
       the core agent (${CORE_AGENT_LABEL}) via SMAppService. macOS shows a
       one-time approval dialog / a System Settings > General > Login Items &
       Extensions entry — accept it.
    3. Verify with: bash packaging/verify.sh
EOF
