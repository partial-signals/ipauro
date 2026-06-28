#!/bin/bash
#
# usb-link-bridge.sh — make this Mac a reliable Ableton Link relay between
# Macs connected over USB-C (hub/spoke or daisy-chain).
#
# It discovers Apple USB-NCM Ethernet interfaces via IOKit (NOT by guessing enX,
# NOT by MAC), folds them all into one L2 bridge, and gives the relay a stable
# address on the bridge. Idempotent: safe to run on a timer and on every replug.
#
# Run as root (via the launchd agent, or `sudo ./usb-link-bridge.sh`).
#
# Subnet model: relay owns BRIDGE_ADDR/BRIDGE_PREFIX. Peers get same-subnet
# addresses either from bootpd DHCP (see enable-dhcp.sh) or assigned manually.
set -euo pipefail

# ---- config -----------------------------------------------------------------
BRIDGE="${BRIDGE:-bridge90}"          # stable, high unit # to avoid Thunderbolt bridge0
BRIDGE_ADDR="${BRIDGE_ADDR:-10.69.0.1}"
BRIDGE_NETMASK="${BRIDGE_NETMASK:-255.255.255.0}"
LOG_TAG="usb-link-bridge"
# -----------------------------------------------------------------------------

log() { /usr/bin/logger -t "$LOG_TAG" "$*"; echo "[$LOG_TAG] $*"; }

# Discover USB-NCM Ethernet interfaces (the enX a USB-C-connected Mac presents).
# IOKit provenance is the only reliable identifier — see findings doc §5.
# Validate once with a Mac plugged in:  ioreg -r -c AppleUSBNCMData -w0
discover_usb_eth() {
  # HOST side of a USB-C Mac-to-Mac link (this Mac enumerates the peer). This is
  # the relay's normal role, and AppleUSBNCMData is a clean, specific signal here.
  #
  # We deliberately do NOT match AppleUSBDeviceNCMData: on a host Mac that class is
  # ALSO used by macOS's internal inter-processor NCM interfaces (the inactive
  # en1..en6), so grepping it would try to bridge internal interfaces. Device-side
  # peer detection needs the active+link-local filter in discover_device_side()
  # and is intentionally diagnostic-only, never fed to the bridge.
  {
    ioreg -r -c AppleUSBNCMData -w0 2>/dev/null
    ioreg -r -c AppleUSBECMData -w0 2>/dev/null
  } | grep -oE '\+-o en[0-9]+' | grep -oE 'en[0-9]+' | sort -u
  # NOTE: a single Mac-to-Mac link can surface TWO host-side NCM interfaces
  # (e.g. en9 live w/ link-local, en10 inert w/ no IP). Bridging the inert one is
  # harmless (it never forwards), but don't treat "2 interfaces" as "2 peers".
}

# Diagnostic only: are we the DEVICE end of a link? AppleUSBDeviceNCMData is noisy
# (internal interfaces), so require the interface to be active with a 169.254/auto
# address — the real peer link is configured, the internal ones are not.
discover_device_side() {
  for ifc in $(ioreg -r -c AppleUSBDeviceNCMData -w0 2>/dev/null \
               | grep -oE '\+-o en[0-9]+' | grep -oE 'en[0-9]+' | sort -u); do
    if ifconfig "$ifc" 2>/dev/null | grep -q 'status: active' \
       && ifconfig "$ifc" 2>/dev/null | grep -q 'inet '; then
      echo "$ifc"
    fi
  done
}

bridge_exists() { /sbin/ifconfig "$BRIDGE" >/dev/null 2>&1; }

bridge_members() {
  /sbin/ifconfig "$BRIDGE" 2>/dev/null | awk '/member:/ {print $2}'
}

ensure_bridge() {
  if ! bridge_exists; then
    log "creating $BRIDGE"
    /sbin/ifconfig "$BRIDGE" create
    # name it so it's recognizable in logs / future `networksetup` work
    /sbin/ifconfig "$BRIDGE" name "$BRIDGE" 2>/dev/null || true
  fi
}

ensure_address() {
  local have
  have="$(/sbin/ifconfig "$BRIDGE" 2>/dev/null | awk '/inet /{print $2}')"
  if [ "$have" != "$BRIDGE_ADDR" ]; then
    log "setting $BRIDGE address -> $BRIDGE_ADDR/$BRIDGE_NETMASK"
    /sbin/ifconfig "$BRIDGE" inet "$BRIDGE_ADDR" netmask "$BRIDGE_NETMASK"
  fi
}

reconcile() {
  ensure_bridge

  local want have add stale
  want="$(discover_usb_eth || true)"
  have="$(bridge_members || true)"

  if [ -z "$want" ]; then
    log "no USB-NCM interfaces present (no Mac plugged in)"
  fi

  # add newly-appeared USB interfaces
  for ifc in $want; do
    if ! printf '%s\n' $have | grep -qx "$ifc"; then
      log "adding member $ifc"
      /sbin/ifconfig "$BRIDGE" addm "$ifc" 2>/dev/null \
        && log "  ok" \
        || log "  FAILED to add $ifc (already claimed?)"
    fi
    # Strip any IPv4 the member self-assigned (e.g. 169.254.x): the address must
    # live on the bridge, not the member, or you get a split-brain subnet where
    # the member answers on link-local while the bridge serves 10.69.x.
    for a in $(/sbin/ifconfig "$ifc" 2>/dev/null | awk '/inet /{print $2}'); do
      log "  flushing member $ifc addr $a (belongs on the bridge)"
      /sbin/ifconfig "$ifc" -alias "$a" 2>/dev/null || true
    done
  done

  # drop members that are no longer USB-NCM (cable pulled / re-enumerated)
  for ifc in $have; do
    if ! printf '%s\n' $want | grep -qx "$ifc"; then
      log "removing stale member $ifc"
      /sbin/ifconfig "$BRIDGE" deletem "$ifc" 2>/dev/null || true
    fi
  done

  /sbin/ifconfig "$BRIDGE" up
  ensure_address

  # nudge peers' ARP after any topology/address change
  if command -v arping >/dev/null 2>&1; then
    arping -c1 -A -i "$BRIDGE" "$BRIDGE_ADDR" >/dev/null 2>&1 || true
  fi

  log "members now: $(bridge_members | tr '\n' ' ')"
}

# Only act when executed directly, not when sourced (so functions can be tested
# without triggering a reconcile).
[[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]] || return 0

case "${1:-reconcile}" in
  reconcile) reconcile ;;
  status)
    echo "bridge: $BRIDGE"
    /sbin/ifconfig "$BRIDGE" 2>/dev/null | grep -E 'inet |member:|status' || echo "  (not present)"
    ncm="$(discover_usb_eth | tr '\n' ' ')" || true   # empty discovery returns non-zero under pipefail
    ncm="$(echo "$ncm" | xargs)"                       # trim
    echo "discovered USB-NCM: ${ncm:-<none>}"
    # Distinguish "no cable" from "cable present but accessory not approved".
    # A peer in our IOUSB host tree with NO NCM interface => unapproved/unconfigured.
    if [ -z "$ncm" ]; then
      if ioreg -p IOUSB -w0 | grep -qi 'Mac@'; then
        echo "  ⚠️  a Mac is enumerated on USB but no NCM interface exists."
        echo "      Likely UNAPPROVED accessory. Approve on the HOST Mac:"
        echo "      System Settings > Privacy & Security > Allow accessories to connect > Always,"
        echo "      then replug with both Macs unlocked and tap Allow."
      else
        echo "  (no USB Mac hosted here. Either nothing plugged in, this Mac is the DEVICE"
        echo "   end — its IOUSB tree is empty even when linked — or the accessory is unapproved.)"
      fi
    fi
    echo "Link multicast joined here:"; netstat -gn -f inet 2>/dev/null | grep 224.76.78.75 || echo "  none"
    echo "peers (ARP on $BRIDGE):"; arp -an | grep "$BRIDGE" | grep -v 'ff:ff:ff' || echo "  none"
    ;;
  teardown)
    log "destroying $BRIDGE"
    /sbin/ifconfig "$BRIDGE" destroy 2>/dev/null || true
    ;;
  *) echo "usage: $0 {reconcile|status|teardown}"; exit 2 ;;
esac
