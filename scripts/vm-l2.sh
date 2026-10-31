#!/usr/bin/env bash
# macOS-VM L2 tier (R009-T2, W001 §9 tier 2): real if_bridge + real pf in a
# lima macOS guest, observed from outside through socket-attached segments.
#
#   ./scripts/vm-l2.sh                      # every case
#   ./scripts/vm-l2.sh --case pf-stateful-trap
#
# One-time setup (downloads the macOS IPSW, ~17 GB; ~7 min on Apple silicon):
#   brew install lima        # >= 2.1 (macOS guests)
#   limactl start --name=ipauro-vmlab --tty=false template:macos-26
#
# The harness stops/starts the instance itself (its segment NICs can only be
# attached at boot) and leaves it stopped with the NICs detached. Needs a macOS
# host: Virtualization.framework only virtualises macOS on macOS, so this is
# not a container tier and not on the Linux CI job.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Darwin ]]; then
  echo "vm-l2: needs a macOS host (Virtualization.framework)" >&2
  exit 2
fi
command -v limactl >/dev/null || { echo "vm-l2: limactl not found (brew install lima)" >&2; exit 2; }

cargo build -p ipauro-vmlab -p ipauro-helper
exec target/debug/ipauro-vmlab run --helper target/debug/ipauro-helper "$@"
