#!/usr/bin/env bash
# packaging/verify.sh — sanity-check an assembled/signed dist/IPAuRo.app.
#
# Runs: a structural file-presence check, plutil -lint on every plist,
# codesign --verify --deep --strict, an spctl Gatekeeper assessment, and a
# printout of what's embedded where.
#
# Exit code is nonzero only on a STRUCTURAL problem (missing file, invalid
# plist, a SIGNED bundle whose signature doesn't verify). An UNSIGNED bundle
# failing codesign --verify, or a signed-but-unnotarized bundle failing the
# spctl assessment, are both EXPECTED states this script reports rather than
# fails on — see packaging/notarize.sh for closing the spctl gap.
#
# Usage: bash packaging/verify.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "error: ${APP_PATH} not found — run packaging/build-app.sh first." >&2
  exit 1
fi

FAIL=0
HELPER_PLIST_REL="Contents/Library/LaunchDaemons/${HELPER_LABEL}.plist"
CORE_PLIST_REL="Contents/Library/LaunchAgents/${CORE_AGENT_LABEL}.plist"

echo "==> Bundle: ${APP_PATH}"

echo ""
echo "==> Structural check: required files"
REQUIRED_FILES=(
  "Contents/Info.plist"
  "Contents/MacOS/ipauro-ui"
  "Contents/MacOS/ipauro-core"
  "Contents/MacOS/ipauro-helper"
  "Contents/MacOS/ipauro"
  "${HELPER_PLIST_REL}"
  "${CORE_PLIST_REL}"
)
for f in "${REQUIRED_FILES[@]}"; do
  if [[ -e "${APP_PATH}/${f}" ]]; then
    echo "    ok      ${f}"
  else
    echo "    MISSING ${f}"
    FAIL=1
  fi
done

echo ""
echo "==> plutil -lint"
for f in "Contents/Info.plist" "${HELPER_PLIST_REL}" "${CORE_PLIST_REL}"; do
  if [[ -e "${APP_PATH}/${f}" ]]; then
    if ! plutil -lint "${APP_PATH}/${f}"; then
      FAIL=1
    fi
  fi
done

echo ""
echo "==> Key plist values (what's embedded where)"
for f in "${HELPER_PLIST_REL}" "${CORE_PLIST_REL}"; do
  if [[ -e "${APP_PATH}/${f}" ]]; then
    echo "    ${f}:"
    plutil -p "${APP_PATH}/${f}" | sed 's/^/        /'
  fi
done

echo ""
echo "==> codesign --verify --deep --strict"
if codesign --verify --deep --strict "${APP_PATH}" 2>&1 | sed 's/^/    /'; then
  echo "    signature verified"
else
  # Disambiguate "genuinely unsigned (SKIP_SIGN)" from "we signed it and it's
  # broken". `codesign -dvv` succeeding is NOT proof our signing step ran: on
  # Apple Silicon, rustc's linker automatically ad-hoc-signs every binary
  # (flags=adhoc,linker-signed, no TeamIdentifier) so `-dvv` always succeeds
  # even on a SKIP_SIGN=1 build, and --verify then fails with a confusing
  # "code has no resources but signature indicates they must be present"
  # because that stray linker signature looks bundle-shaped to codesign's
  # heuristics. A TeamIdentifier line is the real signal that build-app.sh's
  # own `codesign --sign <Developer ID identity>` pass ran.
  if codesign -dvv "${APP_PATH}" 2>&1 | grep -q "^TeamIdentifier=" && \
     ! codesign -dvv "${APP_PATH}" 2>&1 | grep -q "^TeamIdentifier=not set"; then
    echo "    FAIL: bundle has a real TeamIdentifier signature but failed verification" >&2
    FAIL=1
  else
    echo "    note: bundle carries no real signing identity (SKIP_SIGN build, or just the toolchain's automatic ad-hoc linker signature) — not a failure, but SMAppService will refuse to register it."
  fi
fi

echo ""
echo "==> spctl -a -t exec assessment (Gatekeeper)"
if spctl -a -t exec -vv "${APP_PATH}" 2>&1 | sed 's/^/    /'; then
  echo "    accepted"
else
  echo "    note: rejected — expected for a signed-but-unnotarized (or unsigned) bundle. See packaging/notarize.sh."
fi

echo ""
echo "==> Embedded contents"
find "${APP_PATH}" -type f | sed "s|${APP_PATH}/||" | sort | sed 's/^/    /'

echo ""
if [[ "${FAIL}" -eq 1 ]]; then
  echo "==> verify.sh: FAILED (structural problem above)" >&2
  exit 1
fi
echo "==> verify.sh: OK"
