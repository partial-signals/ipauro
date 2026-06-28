# IPAuRo Findings — USB Mac-to-Mac Bridging for Ableton Link

**Status:** Empirical base (hardware-validated). Each failure mode → a test case.
`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — architecture threads referenced below.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — roadmap.

Date: 2026-06-25/27
Host: this Mac (Apple Silicon, macOS 25.5 / "Darwin 25.5.0")

## 1. Goal & topology

Make **one Mac act as a relay** between two other Macs connected to it over **pure USB-C**,
so that all three participate in a single Ableton Link session (shared tempo/transport).

Two target shapes:

- **Hub/spoke** — center Mac has a USB cable to each peer; peers have no direct link to each
  other and rely on the center to forward between them. (This is what we built.)
- **Line / daisy-chain** — A–B–C where B forwards for A and C. Functionally identical to
  hub/spoke at the relay node; the relay just bridges its two USB segments.

### What actually exists on the wire

When two Macs are joined by USB-C with no other config, macOS brings up an **Apple
USB-NCM (Network Control Model) gadget**. Each connection enumerates as:

```
IOUSB
└── AppleT8142USBXHCI@02000000              (USB host controller)
    └── Mac@02100000   (idVendor 1452 Apple, Product "Mac", S/N KKXCVX7Y0G, High-Speed 480Mbps)
        ├── NCM Control@0 → AppleUSBNCMControl
        └── NCM Data@1    → AppleUSBNCMData
                            └── en9   (IOEthernetInterface)
```

Key point: **the USB link presents as an ordinary Ethernet NIC** (`enX`) with
`BROADCAST,MULTICAST` flags. Anything that works on a normal LAN works here — which is
exactly why Ableton Link works over it with zero configuration.

In this session:

- Peer A enumerated on **en9** (host-side learned MAC `c2:7a:92:b6:6d:13`)
- Peer B ("freshboi") enumerated on **en10** (host-side learned MAC `c2:7a:92:b6:6d:33`)

## 2. What we built

A kernel L2 bridge on the center Mac joining the two USB segments:

```
sudo ifconfig bridge1 create
sudo ifconfig bridge1 addm en9 addm en10
sudo ifconfig bridge1 up
# give the relay an address ON THE BRIDGE (not the member):
sudo ifconfig en9 -alias 169.254.84.1            # (initial link-local attempt)
sudo ifconfig bridge1 inet 169.254.84.1 netmask 255.255.0.0
```

Later re-addressed everything onto a stable static subnet `10.0.0.0/24`:

| Machine          | Interface        | Address     | Status at end           |
|------------------|------------------|-------------|-------------------------|
| Center (relay)   | `bridge1`        | `10.0.0.1`  | OK                      |
| Peer B (freshboi)| correct USB `en` | `10.0.0.3`  | OK, reachable           |
| Peer A           | **wrong** `en17` | `10.0.0.2`  | NOT reachable (misfiled)|

We verified the bridge forwards correctly: a `tcpdump` on `en10` showed Peer A's Link
multicast (`169.254.109.94 > 224.76.78.75.20808`) **and** the relay's own multicast arriving
on the en10 wire — proving L2 flooding between the two USB segments works.

## 3. Outcome classification

### Predictable / deterministic (a helper can rely on these)

1. **USB-C between two Macs always yields an NCM `enX` Ethernet interface.** No driver, no
   user action. Detectable in IOKit (`ioreg -p IOUSB`, look for `AppleUSBNCMData` →
   `IOEthernetInterface`) or by enumerating `enX` interfaces tied to a USB host controller.
2. **A kernel bridge (`if_bridge`) floods L2 frames, including multicast, between members.**
   This is what makes hub/spoke and line topologies work for Link. Deterministic.
3. **Ableton Link discovery is multicast (`224.76.78.75:20808` / IPv6 `ff12::8080:20808`)
   and is link-scoped** — it crosses an L2 bridge but never an L3 router. So bridging (not
   routing) is the correct and only simple approach.
4. **Link needs same-subnet unicast to actually sync.** Multicast discovers peers; the
   tempo/phase session runs unicast between peer IPs. Cross-subnet => discovery may flicker
   but sync fails. (This was the final bug: Peer A ended up on `169.254/16` while the others
   were on `10.0.0/24`.)
5. **The relay's IP must live on the bridge interface, not a member port.** Multicast group
   membership (IGMP join) follows the interface that holds the address; only the bridge
   interface spans both segments.

### Wrangle-able with software (a "bridge helper" should automate these)

1. **Bridge lifecycle.** Create bridge, add the right members, bring it up, assign a stable
   address — idempotently, and re-run on USB replug (interface indices change!).
2. **Correct interface identification.** This was the single biggest manual pain. See §5.
3. **Address/subnet assignment.** Hand out a coherent static subnet (e.g. `10.0.0.0/24`) to
   the relay and coordinate/instruct each peer to take a unique address in it.
4. **Verification.** Ping each peer, confirm both peer MACs are learned on distinct bridge
   ports, confirm `224.76.78.75` is joined on the bridge, optionally sniff for `udp/20808`
   from each peer IP to prove three-way Link presence.
5. **Persistence.** Survive reboot / replug via a `launchd` agent that re-applies the bridge.

### Genuinely hard / fragile (helper must handle defensively, not assume)

1. **Interface naming is unstable** — `enX` numbers shift on replug; you cannot hardcode.
2. **Peer-side interface identification cannot rely on the MAC the relay sees** (see §5).
3. **Link-local (`169.254`) self-assignment is non-deterministic and drops on any hiccup** —
   fine for a quick jam, unreliable for a fixed rig. Static IPs strongly preferred.
4. **macOS does not show these interfaces/bridge in System Settings → Network** (no
   SystemConfiguration "service" is created for raw `ifconfig` bridges or unconfigured NCM
   interfaces), so users can't fix it through the GUI — CLI/automation only.

## 4. Issue catalog

### General networking issues

- **Bridge vs route confusion.** People reach for Internet Sharing / routing; that breaks
  Link (multicast won't route, link-local won't route). Must be an L2 bridge.
- **Subnet coherence.** All nodes must share one IPv4 subnet for unicast Link to complete.
  Mixed `169.254/16` + `10.0.0/24` silently half-works (discovery yes, sync no).
- **Multicast membership location.** IP-on-member vs IP-on-bridge changes which port the
  IGMP join covers. Put the address on the bridge.

### macOS-specific issues

- **NCM gadget is automatic but invisible.** Works at the socket layer; absent from the
  Network UI. Diagnosis is CLI-only (`ifconfig`, `ioreg`, `arp`, `netstat -g`, `tcpdump`).
- **Host-assigned NCM MACs.** The MACs the relay's bridge learns
  (`c2:7a:92:b6:6d:13` / `...:33`) are **assigned by the relay's NCM driver to represent the
  remote ends and do NOT appear in the peer's own `ifconfig`.** MAC-matching across machines
  fails. (Major time-sink this session.)
- **`anpi*` interfaces are decoys.** Apple's internal-coprocessor interfaces also carry
  `169.254.x` link-local addresses, so naive "find the 169.254 interface" logic surfaces
  them. The USB link is always a plain `enX`, never `anpi`.
- **`sudo` over a non-TTY shell fails** (`a terminal is required to read the password`).
  Automation must use an askpass helper, a privileged launchd context, or cached credentials.
- **`ifconfig` config is not persistent** — gone on reboot/replug; needs launchd to survive.
- **Interface index churn** — `en9`/`en10`/`en17` are not stable identifiers.

### USB enumeration / approval issues (added after live retry)

- **The accessory-approval gate is a hard prerequisite.** On Apple Silicon, plugging
  two Macs together fires an "Allow accessory to connect?" prompt on the **host** side.
  Until it's approved, the device enumerates but stays **unconfigured — no NCM `enX` is
  created on *either* end.** Symptom we hit: prompt appeared, but
  `ioreg -r -c AppleUSBNCMData` was empty on both Macs. This is not automatable; a human
  must approve (or set Privacy & Security → "Allow accessories to connect" → Always, both
  Macs unlocked). The helper must *detect and report* this state, not spin.
- **`ioreg -p IOUSB` (host plane) only shows the peer when THIS Mac is the USB host.**
  USB-C negotiates data roles; whichever Mac becomes host sees the other as a `Mac@…`
  device in its IOUSB tree, while the **device-side Mac's IOUSB tree is completely empty**
  even when the link is healthy. We confirmed this by repeatedly getting an empty IOUSB
  tree on the device-side machine. Consequence: **discovery must key off the NCM interface
  (`AppleUSBNCMData`), never off the IOUSB device tree.** Both ends still get an `enX` once
  approved, so the interface is the reliable signal; the device tree is role-dependent.
- **Role is auto-negotiated and not trivially forced.** Which Mac becomes host depends on
  USB-C negotiation (initiator, power state, cable). For a relay you ideally want it to be
  host of each peer link, but you can't assume it — design for "I'm the device end" too.
- **Charge/USB2-only cables muddy diagnosis.** A marginal cable can fire the accessory
  prompt (enough detection) without bringing up a usable NCM data link. A known
  Thunderbolt/USB4 cable removes this variable. (Reboot of the peer also clears stuck
  half-approved state.)

### Verified live against a third Mac (MetrcAdmins, M1, macOS 15.7.3)

- **A charge-only / marginal USB-C cable is indistinguishable from "macOS hid the link"
  until you look at IOKit.** Symptom: prompt fired once, then nothing; BOTH Macs' IOUSB
  trees totally empty across ports, reboots, and accessory-policy changes. Swapping to a
  known-data cable brought the link up instantly. **Cable is the #1 suspect when both ends
  show an empty IOUSB tree.** A configurator should say "no USB data device on either end →
  likely charge-only cable," not imply an approval problem.
- **Host vs device discovery classes differ — confirmed:**
  - Host side (Mac that enumerates the peer): interface under `AppleUSBNCMData`.
  - Device side (Mac being hosted): `AppleUSBNCMData` = 0, but the interface is live with a
    link-local address, backed by **`AppleUSBDeviceNCMData`**. `discover_usb_eth()` must
    check both classes or it goes blind on any peer it doesn't host. (Fixed in script.)
- **The power-source Mac tended to win the USB host role.** When this Mac powered the other,
  this Mac became host (`Mac@…` appeared in its IOUSB tree, NCM `enX` came up here). Useful
  lever: to make a given Mac the relay/host, have it be the one supplying power.
- **One Mac-to-Mac link surfaced TWO host-side NCM interfaces** (`en9` live w/ link-local,
  `en10` inert w/ no IP). Don't equate interface count with peer count; the inert one is
  harmless to bridge but should not be mistaken for a second peer.
- **Link-local connectivity needs ARP convergence + interface binding.** First unbound ping
  was 100% loss; an `en9`-bound ping seconds later was 0% loss and the peer's ARP had
  resolved our MAC. Verifiers must bind to the interface (`ping -b enX`) and tolerate a
  few-second warm-up before declaring failure.

### macOS 15 "Local Network" privacy gate — the REAL blocker (Falcon was innocent)

**CORRECTION.** We initially blamed CrowdStrike Falcon on the Metrc machine for dropping Link.
That was WRONG — a classic "saw the EDR, blamed the EDR" correlation error. The actual cause:
**macOS 15 (Sequoia) Local Network privacy + launching the app over SSH.** Proven by launching
the same binary from Metrc's GUI Terminal → it immediately reached `peers 2` and joined the
3-node session over USB. Falcon never touched it.

- **macOS 15+ gates each app's local-network traffic** (multicast + local-subnet unicast)
  behind a per-app permission with a GUI prompt ("… would like to find devices on your local
  network"). Sonoma 14 and earlier have **no such gate**.
- **Processes launched over SSH / headless cannot show the prompt and are silently DENIED**,
  and macOS then drops their local multicast — packets reach the NIC/kernel (ICMP replies
  work, `tcpdump` shows them) but never reach the app socket. This is the exact
  "arrives-but-app-silent" symptom we misattributed to the EDR's NEFilterDataProvider.
- **The corroboration we ignored:** the Air that worked is **Sonoma 14.8.5 (no gate)**; Metrc
  is **Sequoia 15.7.3 (gated)**. Same binary, same network — the only difference was the OS
  version that added the permission. Launch context (GUI vs SSH) was the hidden variable.
- **Fix:** run the app in a context that holds Local Network permission — a GUI app the user
  has granted (System Settings → Privacy & Security → Local Network), or a process that
  inherits a granted parent (GUI Terminal). A **signed app that declares local-network use**
  gets the prompt normally and Just Works. Headless/SSH/cron contexts on macOS 15+ are denied.
- **Diagnostic lesson:** an unprivileged-app "local multicast received at L2 but not at the
  app" on macOS 15+ is Local Network privacy until proven otherwise — check the OS version and
  launch context BEFORE blaming an EDR you happen to see in `systemextensionsctl`. Correlation
  with a visible security agent is not causation.
- **Configurator implications:**
  - The app MUST hold Local Network permission and be GUI/agent-launched; never expect a
    headless helper to do local multicast on macOS 15+ without the grant.
  - Detect the gate: on macOS ≥15, if local multicast is joined but no peers appear while the
    link is healthy, surface "grant Local Network access (Privacy & Security)" — NOT "blocked
    by endpoint security."
  - This also reshapes the privileged-helper design (ARCHITECTURE Thread 2): the Local-Network-
    sensitive part (Link itself) must run in the user's GUI session context, while only the
    root networking ops (ifconfig/pf) go in the helper.

(Falcon footnote: it was present and active but not the cause here. Don't disable/tamper with
EDR regardless — but also don't scapegoat it. Real corporate machines CAN do local USB Link
sessions once the OS permission is granted.)

### pf transport-scoping works — but pf is STATEFUL (critical gotcha)

- **Confirmed live:** `pf` can force an interface-unaware app (Ableton Link) onto a chosen
  transport by blocking its port (`udp/20808` + multicast `224.76.78.75`/`ff12::8080`) on
  every interface except the preferred one (`block drop quick on ! <iface> proto udp ... port
  20808`). Two physical Macs, USB vs WiFi: scope to USB → stays linked; scope away from USB +
  block WiFi → drops to 0; scope back to USB → re-links. Fully deterministic.
- **THE TRAP: macOS `pf` checks the state table BEFORE the ruleset.** The default ruleset has
  `pass all flags S/SA keep state`, so flows established *before* you load a block rule get
  state-table entries and **keep flowing** — the new `block quick` only catches *new* packets,
  of which an established session has none. Symptom: rule counters climb (thousands of packets
  dropped) yet the app stays connected. We nearly shipped this as a "proof" that was actually
  the old session surviving on cached state — possibly over the very interface we thought we'd
  blocked.
- **Fix:** after loading the scoping ruleset, `pfctl -F states` to flush the state table so
  live connections re-evaluate against the new rules. Safe for SSH/TCP **iff** the ruleset's
  trailing `pass` is unrestricted (recreates state on the next packet); a `flags S/SA`-only
  pass would strand mid-stream connections. (Implemented in `pf-prefer.sh on`.)
- **Configurator implication:** any transport-preference enforcement MUST flush (or
  selectively kill) states on apply, and integration tests MUST verify by *tearing down and
  re-establishing* a session under the scope — not just observing that an already-up session
  stayed up. "Session stayed connected after we changed the rules" proves nothing under
  stateful pf.

### Kernel bridge supports HUB-AS-PEER (verified — host multicast egresses to members)

We initially feared macOS `if_bridge` floods member↔member multicast but won't egress the
host's OWN (relay-originated) multicast to members — which would mean a forwarding hub couldn't
also participate in Link (fatal for daisy chains, where every interior node is a hub-and-peer).
An early test suggested this, but it was confounded (an `en9` split-brain with a stale
`169.254` alias + Metrc's Local Network privacy gate).

**Retested clean and it WORKS:** relay + 2 spokes all bridged onto one subnet
(`10.69.0.0/24`: relay `bridge90`=.1, Metrc=.2, Air=.3), relay's `link_audio_hut` bound to the
`bridge90` interface → **all three reached `peers 2`** (full mesh). The relay's host-originated
Link multicast reached both members.

Implications for the N-hub/M-peer product (ARCHITECTURE Thread 3):
- **Daisy chains and hub-spoke can use in-kernel bridging** — hub-as-peer is free, no userspace
  forwarder required for the common case.
- Hard requirements: (1) all bridged nodes share **one subnet** (multicast floods over the
  bridge, but Link's follow-up unicast needs same-subnet peers); (2) the hub binds the
  **bridge interface**, not raw members; (3) the hub's transport-scoping `pf` rule must target
  the **bridge interface** (`on bridge90`), since that's where the hub's Link now lives.
- A userspace forwarder is still preferable for multi-hub loop control + control-plane
  integration, but it's a *choice*, no longer forced by a kernel limitation.

### Unplugging ONE USB member destroys the whole bridge (replug blast radius)

Live incident: with a 3-node mesh up (relay bridging `en9`=Metrc + `en12`=Air), unplugging and
replugging the **Air** cable **tore down the entire `bridge90`** — not just the Air's link.
Metrc dropped too, because its bridge evaporated out from under it (`en9` was orphaned, lost the
`10.69.0.1` it reached the subnet through). Interfaces did NOT renumber (`en9`–`en12` reused),
and the Air kept `10.69.0.3` — only the relay-side bridge died.

- **macOS `if_bridge` does not gracefully drop a removed member — it tears the bridge down.**
  So any member unplug = total mesh outage for that hub, until the bridge is rebuilt.
- **Recovery = rebuild the bridge (`reconcile`) + restart the hub's audio app.** The app's
  multicast socket was bound to the dead bridge interface; it must rejoin on the new one.
- **Peers surviving replug is luck** unless they use DHCP (a peer whose interface fully resets
  loses its static IP). Another vote for DHCP-on-the-bridge.
- A single hub is a **single point of failure** for its whole sub-mesh → argues for multi-hub /
  daisy-chain topologies with redundant paths + spanning tree (ARCHITECTURE Thread 3).
- **Product consequence:** the reconcile daemon is MANDATORY and must be **event-driven**
  (react to IOKit USB attach/detach, not just a 15s poll) so a member change self-heals in
  ~instant rather than leaving the mesh down. See ARCHITECTURE "Controller / desired-state
  reconciler."

### Ableton Link-specific issues

- **Ports/groups:** UDP `20808`; multicast `224.76.78.75` (IPv4) and `ff12::8080` (IPv6).
  Live binds `*:20808` on ALL interfaces simultaneously (Wi-Fi, Thunderbolt bridge, USB).
- **No per-interface selector in Live** — you can't tell Live "only sync over USB." To
  isolate, you must down the other interfaces.
- **A peer with no IP on the segment emits no Link traffic.** Confirmed via `tcpdump`: Peer B
  sent zero `udp/20808` until it had an address — the USB link was L2-alive (MAC learned) but
  Link was silent. "Has carrier" ≠ "has IP" ≠ "is syncing." A helper should check all three.
- **Stale ARP after re-addressing.** Moving the relay's IP from a member MAC to the bridge MAC
  left peers with stale ARP for the relay; Link blips until ARP refreshes. Send gratuitous
  ARP / expect a few-second reconverge after any address change.

## 5. The hard part, distilled: "which interface is the USB link?"

This consumed most of the session. A reliable helper needs a robust answer. Ranked by
reliability:

1. **IOKit provenance (best, relay side):** walk `ioreg -p IOUSB` for
   `AppleUSBNCMData → IOEthernetInterface` and read the `BSD Name` (`enX`). Unambiguous and
   tied to the physical USB device — survives renames within a boot.
2. **Traffic-based (best, peer side):** sniff which interface actually receives the relay's
   packets — `tcpdump -nei any 'udp port 20808'` and watch which `enX` carries frames from the
   relay's IP. Cannot be fooled by MAC labels or anpi.
3. **Exact link-local match:** find the `enX` holding the *specific* `169.254.x` address seen
   on the wire (not just any `169.254`, which catches `anpi`). Works until the address rolls.
4. **MAC match across machines:** DO NOT — NCM MACs are host-assigned and don't appear on the
   peer. This is the trap we hit.

## 6. Design sketch for a "Mac USB Link Bridge Helper"

A small daemon + CLI that makes a Mac a reliable Link relay in line or hub/spoke topology:

**Discovery**
- Enumerate USB-NCM interfaces via IOKit provenance (§5.1), not by `enX` guessing.
- Watch IOKit for USB attach/detach to handle replugs live.

**Bridge management (relay node)**
- Idempotently create/maintain a bridge, add every discovered USB-NCM member, bring it up.
- Assign the relay a fixed address on the **bridge** interface.
- For line topology with >2 segments, same logic — all USB members into one bridge.

**Addressing / coordination**
- Own a private subnet (e.g. `10.69.0.0/24`). Relay = `.1`.
- Hand peers addresses. Cleanest: run a tiny DHCP responder on the bridge so peers
  auto-acquire a same-subnet address (removes all manual per-peer `ifconfig` and the
  wrong-interface class of bug entirely). Fallback: a companion peer-side agent that
  self-identifies its USB `enX` via §5.2 and assigns a unique static IP.

**Verification / health (continuous)**
- Both peer MACs learned on distinct bridge ports.
- `224.76.78.75` joined on the bridge.
- Each peer reachable (ARP + ping) and on the right subnet.
- Optional: per-peer `udp/20808` presence to confirm Link is actually live, surfaced as a
  simple "3/3 peers syncing" status.

**Persistence & resilience**
- launchd agent; re-run the whole reconcile on boot and on every USB attach/detach.
- After any address change, emit gratuitous ARP and expect a short reconverge.

**Privilege handling**
- Run privileged (launchd) so it never hits the non-TTY `sudo` wall.

**Why DHCP-on-the-bridge is the single biggest win:** nearly every painful moment this
session — wrong interface (`en17`), subnet split (`169.254` vs `10.0.0`), anpi decoys,
cross-machine MAC matching — collapses if the relay simply *serves* addresses on the bridged
segment and peers acquire them automatically. Peers do nothing but plug in.

## 7. End state / open item

- Relay `10.0.0.1` and Peer B `10.0.0.3` confirmed working and mutually reachable.
- Peer A's `10.0.0.2` was assigned to the wrong interface (`en17`); its real USB `enX` (the
  one still on `169.254.109.94`) still needs the address. Once Peer A has `10.0.0.2` on the
  correct interface, all three are same-subnet and the two peers will see each other.
- Nothing further is needed on the relay; the bridge and forwarding are correct.
