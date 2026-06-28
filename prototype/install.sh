#!/bin/bash
# install.sh — install the relay script + launchd daemon. Run with sudo.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

install -m 0755 "$HERE/usb-link-bridge.sh" /usr/local/sbin/usb-link-bridge.sh
install -m 0644 "$HERE/com.leif.usb-link-bridge.plist" /Library/LaunchDaemons/com.leif.usb-link-bridge.plist
chown root:wheel /Library/LaunchDaemons/com.leif.usb-link-bridge.plist

launchctl bootout system/com.leif.usb-link-bridge 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.leif.usb-link-bridge.plist
launchctl enable system/com.leif.usb-link-bridge

echo "Installed. Watch it work:  tail -f /var/log/usb-link-bridge.log"
echo "Status:                    /usr/local/sbin/usb-link-bridge.sh status"
echo "Uninstall:                 sudo launchctl bootout system/com.leif.usb-link-bridge && sudo rm /Library/LaunchDaemons/com.leif.usb-link-bridge.plist /usr/local/sbin/usb-link-bridge.sh"
