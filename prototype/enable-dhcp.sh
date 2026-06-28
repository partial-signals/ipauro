#!/bin/bash
#
# enable-dhcp.sh — serve DHCP on the bridge so USB-connected peers AUTO-ACQUIRE a
# same-subnet address. This is the single biggest reliability win: it eliminates
# wrong-interface mistakes, subnet splits, anpi decoys, and cross-machine MAC
# matching. Peers do nothing but plug in.
#
# Uses macOS's built-in bootpd (the same daemon Internet Sharing drives).
# Run as root.
set -euo pipefail

BRIDGE="${BRIDGE:-bridge90}"
SUBNET="${SUBNET:-10.69.0.0}"
NETMASK="${NETMASK:-255.255.255.0}"
RANGE_LO="${RANGE_LO:-10.69.0.10}"
RANGE_HI="${RANGE_HI:-10.69.0.200}"

# bootpd reads /etc/bootpd.plist. dhcp_enabled lists the interfaces to serve on;
# we serve ONLY on the bridge so we never hand out leases on Wi-Fi/Ethernet.
# detect_other_dhcp_server=1 makes it back off if a real DHCP server appears.
cat > /etc/bootpd.plist <<EOF
{
    bootp_enabled = 0;
    dhcp_enabled = ( "${BRIDGE}" );
    detect_other_dhcp_server = 1;
    reply_threshold_seconds = 0;
    use_server_config_for_dhcp_options = 1;
    Subnets = (
        {
            name = "usb-link";
            net_address = "${SUBNET}";
            net_mask = "${NETMASK}";
            net_range = ( "${RANGE_LO}", "${RANGE_HI}" );
            allocate = 1;
            lease_max = 3600;
            lease_min = 3600;
        }
    );
}
EOF
echo "[enable-dhcp] wrote /etc/bootpd.plist serving ${SUBNET}/${NETMASK} on ${BRIDGE}"

# Sanity: bootpd binds its served interfaces AT LAUNCH, so the bridge must already
# exist or bootpd silently serves nothing. Verified the hard way.
if ! /sbin/ifconfig "$BRIDGE" >/dev/null 2>&1; then
    echo "[enable-dhcp] ERROR: $BRIDGE doesn't exist yet. Run usb-link-bridge.sh reconcile first." >&2
    exit 1
fi

# Load if needed, then ALWAYS kickstart -k to force bootpd to restart and re-bind
# its interface list — covers the case where it was already running before the
# bridge existed (in which case it would otherwise keep serving the old, empty set).
launchctl load -w /System/Library/LaunchDaemons/bootps.plist 2>/dev/null || true
launchctl kickstart -k system/com.apple.bootpd 2>/dev/null \
  || launchctl kickstart -k system/com.apple.bootps 2>/dev/null || true
echo "[enable-dhcp] bootpd (re)started and bound to $BRIDGE. Peers will get ${RANGE_LO}-${RANGE_HI}."
echo "[enable-dhcp] On each peer, just make sure its USB interface is set to DHCP:"
echo "               sudo ipconfig set <usb-enX> DHCP"
echo "[enable-dhcp] disable later with:  ./enable-dhcp.sh off   (or) launchctl unload -w /System/Library/LaunchDaemons/bootps.plist"

if [ "${1:-}" = "off" ]; then
    launchctl unload -w /System/Library/LaunchDaemons/bootps.plist 2>/dev/null || true
    echo "[enable-dhcp] bootpd stopped."
fi
