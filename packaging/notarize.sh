#!/usr/bin/env bash
# packaging/notarize.sh — DOCUMENTED STUB. Prints the notarization flow; does
# not submit anything unless explicitly told to with real credentials.
#
# Notarization needs an app-specific Apple ID credential (or API key) this
# environment does not have and should not be asked to hold. This script
# exists so the exact commands are recorded and reviewable — run it plain and
# it only prints what it would do. Nothing is submitted to Apple without
# --execute AND a NOTARY_PROFILE that already exists in the keychain.
#
# One-time setup (interactive — run this yourself, never from a script):
#   xcrun notarytool store-credentials "ipauro-notary" \
#     --apple-id "<your apple id email>" \
#     --team-id "<team id, e.g. 7BW4R8G8Q6>" \
#     --password "<app-specific password from appleid.apple.com>"
#
# Flow this script documents:
#   1. ditto-zip the signed, notarization-ready bundle (ditto, not zip(1) —
#      ditto preserves the metadata Apple's submission expects).
#   2. Submit + wait: xcrun notarytool submit ... --keychain-profile ... --wait
#   3. Staple the ticket so Gatekeeper works fully offline:
#      xcrun stapler staple dist/IPAuRo.app
#   4. Re-run packaging/verify.sh — the spctl assessment should now ACCEPT.
#
# Usage:
#   bash packaging/notarize.sh                                 # prints the flow, does nothing
#   NOTARY_PROFILE=ipauro-notary bash packaging/notarize.sh --execute

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

EXECUTE=0
for arg in "$@"; do
  case "${arg}" in
    --execute) EXECUTE=1 ;;
    *)
      echo "error: unknown argument '${arg}'" >&2
      exit 1
      ;;
  esac
done

NOTARY_PROFILE="${NOTARY_PROFILE:-}"
ZIP_PATH="${DIST_DIR}/IPAuRo.zip"

cat <<EOF
==> packaging/notarize.sh — stub. Does NOT submit anything unless invoked as:
    NOTARY_PROFILE=<keychain-profile> bash packaging/notarize.sh --execute

    Prerequisites:
      - dist/IPAuRo.app built + Developer-ID-signed (packaging/build-app.sh, no SKIP_SIGN)
      - a notarytool keychain profile already stored via
        'xcrun notarytool store-credentials' (interactive, one-time — see
        the header of this file; never scripted, never held by an agent)

    Commands this would run, in order:
      ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"
      xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "\${NOTARY_PROFILE}" --wait
      xcrun stapler staple "${APP_PATH}"
      bash packaging/verify.sh   # spctl should now accept

EOF

if [[ "${EXECUTE}" -eq 0 ]]; then
  echo "==> Dry run only (pass --execute with NOTARY_PROFILE set to actually notarize)."
  exit 0
fi

if [[ -z "${NOTARY_PROFILE}" ]]; then
  echo "error: --execute requires NOTARY_PROFILE=<keychain-profile-name>" >&2
  exit 1
fi

if [[ ! -d "${APP_PATH}" ]]; then
  echo "error: ${APP_PATH} not found — run packaging/build-app.sh first." >&2
  exit 1
fi

echo "==> Zipping ${APP_PATH} -> ${ZIP_PATH}"
ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"

echo "==> Submitting to notarytool (profile: ${NOTARY_PROFILE})"
xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait

echo "==> Stapling ticket"
xcrun stapler staple "${APP_PATH}"

echo "==> Done. Re-run: bash packaging/verify.sh to confirm spctl now accepts the bundle."
