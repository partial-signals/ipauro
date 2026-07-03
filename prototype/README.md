# audio-router prototype (formerly usb-link-bridge — the validated shell PoC)

Tooling + findings for running **Ableton Link (and similar local-network audio
protocols) over pure USB-C / Thunderbolt between Macs**, instead of WiFi.

**Status (2026-06-27): core thesis PROVEN on real hardware.** A 3-node mesh —
relay + a clean MacBook Air + a corporate (CrowdStrike Falcon) MacBook Pro —
ran a single synchronized Link session over **nothing but USB-C**, surviving WiFi
being physically turned off on all three machines. See
`../.yah/docs/architecture/A002-ipauro-findings.md` for the full blow-by-blow,
including several scary conclusions that turned out to be wrong (the EDR was
innocent; the kernel-bridge "host-egress" limitation was a ghost).

## The actual goal (where this is headed)

A shippable app/library that builds arbitrary **USB/TB audio meshes**:
**N hubs + M peers**, in **daisy-chain ∪ hub-and-spoke ∪ mixtures**, with a **UI to
elect each machine as a hub (forwarder) or a peer (leaf)**. See
`../.yah/docs/architecture/A001-ipauro-architecture.md` (Thread 3) for the topology
architecture, and Thread 2 for de-`sudo`-ing it into a real app (privileged helper /
NetworkExtension) — superseded where it differs by
`../.yah/docs/working/W001-ipauro-plan.md`. The scripts here are the **executable
spec** for the data-plane that the Rust core will eventually own (spec for the
*behavior*, not the mechanism — the shipping helper uses pf anchors + selective
state kill and an in-process DHCP responder, see R005-T5 / R005-T6).

## What's proven and how the pieces fit

1. USB-C between two Macs auto-creates an Apple **USB-NCM Ethernet** interface
   (`enX`) — no driver, no config. A Mac can host **multiple** such links at once.
2. A **kernel L2 bridge** (`bridge90`) of those `enX` interfaces makes all the USB
   segments **one broadcast domain** — Link's multicast (`224.76.78.75:20808`,
   IPv6 `ff12::8080`) floods across, so every node sees every other. **The hub can
   also be a peer** (verified — critical for daisy chains).
3. All bridged nodes must share **one subnet**; the hub binds the **bridge**
   interface (e.g. `10.69.0.1`), peers take `10.69.0.x`.
4. **`pf` transport-scoping** forces an interface-unaware app onto the USB transport
   by allowing its port only on the chosen interface(s) and blocking it everywhere
   else — proven by cut-and-restore, and it survived WiFi-off.

## Scripts

| File | Role |
|------|------|
| `usb-link-bridge.sh` | Discover USB-NCM `enX` (IOKit, not enX-guessing/MAC), build/maintain the bridge, flush member IPs, address the bridge. `reconcile` / `status` / `teardown`. Idempotent. |
| `pf-prefer.sh` | Pin a UDP audio protocol (default Link `udp/20808`) to chosen interface(s); block it everywhere else. **State-flushing** (stateful-pf trap, see findings). `on <iface...>` / `off` / `status` / `verify`. |
| `enable-dhcp.sh` | Optional: serve DHCP on the bridge via `bootpd` so peers auto-acquire `10.69.0.x`. Force-kickstarts `bootpd` (it binds interfaces at launch). |
| `install.sh` + `com.leif.usb-link-bridge.plist` | Install the reconcile script as a root LaunchDaemon (runs at boot + every 15s → survives replug/reboot, no repeated sudo). |
| `diag-remote.sh` | Run on a peer (`ssh host 'bash -s' < diag-remote.sh`) to report its USB-NCM / interface / link state. |
| `baseline-unplugged.txt` | Snapshot of interfaces with nothing plugged in (diff against this to find a new USB `enX`). |

## Quick start — a hub + spokes over USB only

On the **hub** (the Mac cabled to each peer):
```sh
sudo ./usb-link-bridge.sh reconcile        # bridge all USB-NCM links -> bridge90 = 10.69.0.1
sudo ./pf-prefer.sh on bridge90            # force Link onto USB (block WiFi/AWDL/etc.)
```
On each **peer** (one USB cable to the hub):
```sh
sudo ifconfig <its-usb-enX> inet 10.69.0.N netmask 255.255.255.0   # unique N; or use DHCP
sudo bash pf-prefer.sh on <its-usb-enX>                            # force its Link onto USB
```
(Find a peer's USB `enX`: it's the interface that came up with a `169.254.x` self-assign,
or `ioreg -r -c AppleUSBNCMData -w0 | grep -oE '\+-o en[0-9]+'` when the peer is the host
end. On a Mac that's the *device* end, look for the new active `enX`.)

Then run a Link app on each; all nodes should reach the same `peers` count (full mesh) and
share tempo/phase. Turn WiFi off to confirm it's genuinely USB.

## Verify

```sh
sudo ./usb-link-bridge.sh status                                   # members, bridge addr, joins, ARP
sudo timeout 6 tcpdump -ni bridge90 'udp port 20808' \
  | grep -oE '10\.69\.0\.[0-9]+' | sort -u                         # which nodes emit Link
```
Note `tcpdump` (BPF) sees inbound packets BELOW `pf` and BELOW the macOS Local Network gate,
so "packets on the wire" ≠ "app received them" — verify with the app's peer count too.

## Gotchas the hard way (full detail in findings doc)

- **Cable quality is the #1 failure.** Charge-only / marginal USB-C cables power the peer but
  carry no data — both Macs show an empty IOUSB tree while charging. Use a known data / TB4 cable.
- **macOS has no userspace "re-enumerate USB."** If a link comes up power-only, physical
  replug is the only reliable fix (and check Privacy & Security → "Allow accessories").
- **macOS 15+ "Local Network" privacy gate.** Apps need Local Network permission to send/recv
  local multicast; **SSH/headless-launched processes are silently DENIED** and their multicast
  is dropped (packets reach the NIC, app gets nothing). Run the Link app from a GUI/granted
  context. This — not an EDR — was what blocked our corporate machine. Sonoma 14 has no gate.
- **`pf` is stateful.** Loading a block rule does NOT cut existing flows (state table is checked
  first); `pf-prefer.sh on` flushes states so the scope actually applies. "Session stayed up
  after I changed the rules" proves nothing under stateful pf.
- **Fail-safe:** never leave Link blocked if something crashes. `pf-prefer.sh` supports a TTL
  auto-restore (`--ttl <sec>`); the shipping app must tie the scope to its own lifecycle.
- **Loop safety:** discovery only ever bridges USB-NCM members — never `en0`/WiFi/Thunderbolt
  bridge. Multi-hub meshes will need spanning-tree (see A001 Thread 3).

## Config (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `BRIDGE` | `bridge90` | bridge interface name |
| `BRIDGE_ADDR` | `10.69.0.1` | hub address on the bridge |
| `BRIDGE_NETMASK` | `255.255.255.0` | |
| `SUBNET`/`RANGE_LO`/`RANGE_HI` | `10.69.0.0` / `.10` / `.200` | DHCP pool (enable-dhcp.sh) |
| `PORT` (pf-prefer) | `20808` | audio protocol UDP port |

## See also
- `../.yah/docs/architecture/A002-ipauro-findings.md` — every finding, correction, and failure
  mode (→ test cases).
- `../.yah/docs/architecture/A001-ipauro-architecture.md` — Thread 1 (3-node/EDR: solved),
  Thread 2 (de-sudo the app), Thread 3 (N-hub/M-peer topology + forwarding), and the test
  strategy.
- `../.yah/docs/working/W001-ipauro-plan.md` — the roadmap; supersedes A001 where they differ.
