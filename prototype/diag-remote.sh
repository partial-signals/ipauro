#!/bin/bash
# Run this ON the other Mac to report USB-NCM link state.
# Usage from THIS Mac:  ssh <other-mac> 'bash -s' < /Users/leif/ss/audio-router/prototype/diag-remote.sh
echo "==== HOST: $(scutil --get LocalHostName 2>/dev/null) / macOS $(sw_vers -productVersion) / $(uname -m) ===="

echo "-- NCM interface present? --"
ioreg -r -c AppleUSBNCMData -w0 | grep -oE '\+-o en[0-9]+' || echo "  NONE"

echo "-- USB Mac device in IOUSB host tree? --"
ioreg -p IOUSB -w0 | grep -iE 'Mac@|NCM' || echo "  NONE"

echo "-- IOUSB controllers (any device hanging off them?) --"
ioreg -p IOUSB -w0 | grep -E '\+-o' | sed -E 's/<class.*//'

echo "-- en interfaces (ether/addr/status) --"
for i in $(ifconfig -l | tr ' ' '\n' | grep -E '^en[0-9]'); do
  printf "%s: " "$i"
  ifconfig "$i" | grep -E 'ether|inet |status' | tr '\n' ' '
  echo
done

echo "-- any link-local (169.254) addresses --"
ifconfig | grep 'inet 169.254' || echo "  none"

echo "-- USB-C port / accessory-approval hints --"
ioreg -l -w0 | grep -iE '"UsbConnectType"|"PortType"|IOUSBHostDevice' | head -5 || true
echo "==== end ===="
