<!--
@yah:ticket(R009-T3, "Failure-mode suite: each A002 finding -> named case (cable-dead, charge-only, unapproved-accessory, stateful-pf-survival, bridge-host-egress, link-local-flap, member-unplug-blast-radius) + hardware runbook")
@yah:at(2026-06-28T03:09:36Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R009)
@yah:gotcha("Two of this ticket's named cases ALREADY EXIST as VM-tier cases in crates/ipauro-vmlab (R009-T2): stateful-pf-survival = `pf-stateful-trap` + `pf-scope-forces-onto-interface`, and bridge-host-egress = `bridge-host-multicast-egress`. Run them with ./scripts/vm-l2.sh, and map them in the suite instead of re-implementing them. The VM tier canNOT reach cable-dead, charge-only, unapproved-accessory, link-local-flap (USB/configd), or member-unplug-blast-radius, because a lima socket NIC cannot be hot-removed like a USB gadget. Those are runbook or fixture cases. Also see the new A002 section 'pf states are FLOATING': a restarted Link session re-matches surviving state, so the runbook's pf step must check `pfctl -s states`, not just restart the app.")
-->

<!--
@yah:ticket(R009-T2, "macOS-VM virtual-switch L2 tests: bridge flooding, host multicast egress, pf-forces-onto-interface — ALWAYS verify by teardown-and-re-establish (stateful-pf discipline)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-10-29T22:05:30Z)
@yah:phase(P3)
@yah:parent(R009)
@yah:gotcha("Apple licensing caps macOS VMs at 2 per virtualization host — 2-node L2 behaviors virtualize fine; 4+-node meshes (R006-T5, R010-T5) belong to the hardware runbook, not this tier.")
@yah:handoff("Built crates/ipauro-vmlab + scripts/vm-l2.sh. ONE real macOS 26.4 guest (lima template:macos-26, vz) is the device under test; its two extra NICs are lima `socket:` networks whose unix sockets the harness owns (qemu stream framing, confirmed from limactl's DialQemu/qemuPacketConn symbols and by live traffic). Wire observations come from OUTSIDE the guest kernel; the other hosts are emulated peers (MAC/IP/ARP/Link-shaped beacon), so Apple's 2-VM cap never binds. The same binary runs in-guest as a Link-shaped endpoint (one socket per iface on :20808, multicast+unicast, group joined per iface). Guest NICs are found by fixed MAC: they came up as en3/en2, not en1/en2.")
@yah:handoff("pf cases drive the REAL helper PfctlExecutor via new dev-only `ipauro-helper --pf-console` (app/helper/src/pf_console.rs; refuses without IPAURO_INSECURE_DEV=1; stdin EOF clears scopes). Five named cases, 27 checks: bridge-floods-member-multicast (built AND rebuilt), bridge-host-multicast-egress, pf-stateful-trap (reproduces A002's trap on purpose, as a negative control showing the harness can see it), pf-scope-forces-onto-interface (scope under a live session, then a fresh session, idempotent anchor point, clear restores), pf-scope-on-bridge-keeps-forwarding.")
@yah:handoff("DISCOVERED + FIXED a shipped-helper bug (app/helper/src/pf.rs, R005 code, no live owner): ScopeUdp did NOT bite. flush_affected_states ran `pfctl -F states -i <iface>`, but macOS pf states are floating (`ALL udp ...`), so -i never matched them. The capture showed link-b states byte-identical before and after. Because Link is fixed-port on both ends, a restarted session re-matched the surviving state, so teardown-and-re-establish could not rescue it either. Replaced it with invalidate_scoped_states: parse `pfctl -s states` and kill the host pairs of UDP states on scoped ports, in both directions (-k is host-only on macOS). 3 parser tests use the verbatim captured lines. Shown non-vacuous: the same case failed 3 checks against the old flush. A002 gained a 'pf states are FLOATING' section, and pf.rs's 'needs bench verification' note is replaced with the VM evidence.")
@yah:handoff("Also: lima 2.1.1 SIGTRAPs in StartGraphicApplication on every non-install start of a macOS instance, so the harness sets video.display=none (Lima::ensure_headless). The lima guest has no passwordless sudo, so Lima::ensure_sudo installs a guest-only sudoers drop-in from ~/password. The pf fixture is UDP-only, because a TCP stateful pass killed lima's mid-stream SSH (exit 255). Classified ipauro-vmlab/hdmi/iec61937/spatial in ci-control-plane.sh: all were unclassified, so the container gate was red. ipauro-iroh is R003's, and @Ashguard:griffin's courier is adding it. Docs: W001 section 9, README tier table, ci.yml header.")
@yah:verify("./scripts/vm-l2.sh - 27 passed, 0 failed (3 consecutive full runs on the final code; VM left Stopped, NICs detached)")
@yah:verify("cargo test -p ipauro-vmlab -p ipauro-helper - 13 + 129 green; cargo clippy --all-targets on both clean")
@yah:verify("docker run rust:1.97.0-bookworm cargo test --locked -p ipauro-vmlab -p ipauro-iec61937 -p ipauro-hdmi -p ipauro-spatial - green on Linux")
@yah:verify("Non-vacuity: before the pf.rs fix, pf-scope-forces-onto-interface failed 3 checks (148 / 140 frames on blocked link b, pb rx=68)")
@yah:verify("shellcheck scripts/vm-l2.sh scripts/ci-control-plane.sh - clean")
@yah:gotcha("One-time setup per host: `limactl start --name=ipauro-vmlab --tty=false template:macos-26` downloads the macOS IPSW (~17 GB on Apple's CDN; install ~7 min). The harness owns the VM's start and stop, because socket NICs attach only at boot.")
@yah:gotcha("Not covered at this tier: member-unplug teardown (a socket NIC cannot be hot-removed like a USB gadget), USB-NCM enumeration, and the Local Network gate (the agent runs as root over lima SSH, which sidesteps it). These belong to R009-T3's hardware runbook.")
@yah:gotcha("Full ./scripts/ci-control-plane.sh stays red until ipauro-iroh is classified (R003's in-flight crate; their courier session:2208af46 is adding the line).")
-->

<!--
@yah:ticket(R009-T1, "Control-plane CI in containers: discovery parsing, NodeId->address, pf/rule generation, gossip dedup/partition-heal, spanning-tree — no hardware")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-07-26T22:10:13Z)
@yah:phase(P1)
@yah:parent(R009)
@yah:handoff("Built scripts/ci-control-plane.sh + .github/workflows/ci.yml (3 jobs). Container job runs the 5 hardware-free crates (proto, core, cli, mesh, probe) in a pinned rust:1.97.0-bookworm: ~180 tests, verified green end-to-end locally via docker. macOS job runs the full workspace (~350 tests, 1 hardware test #[ignore]d), also verified green locally.")
@yah:handoff("Anti-drift is the design point, in BOTH directions. The script derives workspace members from Cargo.toml (never hardcoded) and HARD-FAILS if any member is unclassified - verified by constructing a synthetic 9th member. The converse, --verify-exclusions, proves each macOS-only crate still genuinely fails to build on Linux, so an exclusion cannot rot into a silently-untested crate.")
@yah:handoff("DISCOVERED + FIXED, inside the ticket's named test areas: gossip dedup did not exist. gossip.rs documented Record.seq as 'a receiver keeps only the newest' but topology.rs folded every record unconditionally - duplicate flood arrivals re-folded, and reordered stragglers rolled the view BACKWARD. Added a per-author seq watermark plus Topology::accepts() (kept separate from apply() so a dissemination layer can decline to re-flood without paying to fold), and reordered MeshNode::apply_gossip to reject stale records BEFORE observe_epoch: PolicyEpoch ordering rejects an older epoch but cannot detect a replay carrying a current one, so that path half-adopted a record it then discarded. 5 new tests; all 5 verified to FAIL with the guards reverted, so they are not vacuous.")
@yah:handoff("Also added MeshNode::topology() and ::policy_epoch() read accessors (R003-T5 membership/status surfacing will want exactly these) and corrected ipauro-mesh's now-false 'Not wired to a real build' status line. Docs updated: W001 section 9 and README gained a test-tier table.")
@yah:verify("./scripts/ci-control-plane.sh - container suite green")
@yah:verify("./scripts/ci-control-plane.sh --verify-exclusions - all 3 exclusions still hold")
@yah:verify("./scripts/ci-control-plane.sh --list - prints the classification")
@yah:verify("cargo test --locked --workspace on macOS - full suite green (this is what the macos CI job runs)")
@yah:verify("shellcheck scripts/ci-control-plane.sh - clean")
@yah:gotcha("Lands ALONGSIDE M1, not after M5 - the rule-generator and reconciler ports (R005) should grow their CI the day they're written, per the capabilities-merge-with-a-test rule.")
@yah:gotcha("Two of the five named areas have no tests because they have no CODE yet: NodeId->address (R003-T3) and spanning-tree (R006-F1). CI is deliberately crate-scoped, not test-name-scoped, so both are picked up the day they land - no CI change is needed for them.")
@yah:gotcha("pf/rule generation is NOT container-testable and never will be. It lives in app/helper, which pulls ipauro-xpc -> block2 -> objc2 and cannot compile off Apple platforms - and W002 classifies pf/ifconfig/bootpd as 'not portable, and not worth making so' (the Linux agent, R011-F2, emits nftables from its own executor). That coverage therefore lives permanently on the macOS job. Do NOT file a ticket to lift pf into a portable crate; it contradicts canon.")
@yah:gotcha("Deliberately did NOT touch app/helper or ipauro-core/reconcile.rs - @Ashguard:eclipse (session:bc63097e) is live on R005 and owns those files. Making app/helper Linux-buildable was considered and rejected on both grounds: a peer's blast radius, and W002 saying it is pointless.")
@yah:gotcha("The container run writes to target/ci-linux and target/ci-cargo-home, never target/debug - sharing a target dir with the host macOS build would thrash fingerprints and contend for one cargo lock on this shared tree.")
@yah:gotcha("cargo fmt is a non-gating warning step on purpose: locally this repo inherits a .rustfmt.toml from the parent noisetable checkout (unstable options, a spill-specific ignore list) but would not in a standalone GH checkout, so gating on it would behave differently in the two places.")
-->

# IPAuRo Findings — USB Mac-to-Mac Bridging for Ableton Link

**Status:** Empirical base (hardware-validated). Each failure mode → a test case.
`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — architecture threads referenced below.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — roadmap.

Date: 2026-06-25/27
Host: this Mac (Apple Silicon, macOS 26.5 / Darwin 25.5.0 — macOS major = Darwin major + 1; an
earlier draft mislabeled this "macOS 25.5")

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

### Verified live against a third Mac (CorpAdmins, M1, macOS 15.7.3)

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

**CORRECTION.** We initially blamed CrowdStrike Falcon on the Corp machine for dropping Link.
That was WRONG — a classic "saw the EDR, blamed the EDR" correlation error. The actual cause:
**macOS 15 (Sequoia) Local Network privacy + launching the app over SSH.** Proven by launching
the same binary from Corp's GUI Terminal → it immediately reached `peers 2` and joined the
3-node session over USB. Falcon never touched it.

- **macOS 15+ gates each app's local-network traffic** (multicast + local-subnet unicast)
  behind a per-app permission with a GUI prompt ("… would like to find devices on your local
  network"). Sonoma 14 and earlier have **no such gate**.
- **Processes launched over SSH / headless cannot show the prompt and are silently DENIED**,
  and macOS then drops their local multicast — packets reach the NIC/kernel (ICMP replies
  work, `tcpdump` shows them) but never reach the app socket. This is the exact
  "arrives-but-app-silent" symptom we misattributed to the EDR's NEFilterDataProvider.
- **The corroboration we ignored:** the Air that worked is **Sonoma 14.8.5 (no gate)**; Corp
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

### Local Network gate — execution-context matrix, measured (R002-T8, 2026-07-25)

The section above established *that* the gate exists and that SSH loses to it. **R002-T8 measured
which execution contexts actually hold the grant**, because the 2026-07-02 brain/face split moved
the brain out of the tray app and into a launchd job — reopening the question of whether a launchd
agent can hold what a GUI app could. Instrument: `crates/ipauro-probe` (see its `RUNBOOK.md`).
Host: single Mac, **macOS 26.5.1 (25F80)**, Apple silicon, `en0` on a normal home LAN.

**Method upgrade — two observation points, not one.** The original A002 method ("BPF sees the
packet, the app doesn't") was run by eye across two terminals. `ipauro-probe check` now runs both
legs itself, against the same beacons, on Link's own group/port (`224.76.78.75:20808`): the
process's own socket, and a `/dev/bpf` tap on the egress interface. This matters because a
socket-only probe **cannot falsify its own "gate open" result** — in-kernel multicast loopback can
satisfy the socket leg while nothing leaves the machine. Verified concretely: with the tap pointed
at an off-path interface the same run reports `LOOPBACK ONLY`, which is exactly the false positive
a one-legged probe would have called success.

- **XNU routes the multicast loopback copy via `lo0`, not the egress interface.** Measured: a run
  beaconing out `en0` shows 9 beacons on an `en0` tap *and* 9 on an `lo0` tap. They are different
  copies, so a nonzero count on the egress interface is genuine transmission, not the loopback
  copy being double-counted. This is what licenses `check`'s "wire-confirmed" wording.

**The authoritative registry.** macOS records its local-network posture per code identity in
`/Library/Preferences/com.apple.networkextension.plist` — world-readable, an `NSKeyedArchiver`
archive, with `MulticastPreferenceSet` (a decision exists) and `DenyMulticast` (the decision) per
app. `ipauro-probe grants` reads it. This is the missing half of the diagnostic: behaviour alone
cannot distinguish "this context holds the grant" from "someone approved this months ago", and a
denial persists silently with no prompt ever shown again.

- **`unset` is not `denied`.** On this host **236 of 263** records have no explicit decision, and
  their traffic flows normally (VLC, Zoom, Telegram are all `unset`). Absence of a decision means
  the system has not been told otherwise — the default is allow. Any consumer of this registry
  (R007-F1) must treat `unset` and `DENIED` as different states, not fold them together.

**Identity attribution — who the grant actually attaches to.** Three shapes, measured:

| Launch shape | Registry identity |
|---|---|
| Binary run from a shell | **none of its own** — attributed to the responsible app (our shell runs went to `dev.yah`; `target/release/ipauro-probe` never got an entry) |
| Bare executable as a launchd job | its own **code-signing identifier + path** (`ipauro-probe-agent-devid` → `/private/tmp/...`) |
| Executable inside a bundle, launchd job with `AssociatedBundleIdentifiers` | the **associated bundle id**, no path (`io.ipauro.probetest`) |

The first row invalidates a whole class of test: **running the probe from Terminal or over SSH
measures Terminal's or `sshd`'s grant, not the binary's.** Those are rows about the parent app.
Only launchd jobs have an independent identity, which is precisely why the brain service's
placement had to be measured as a launchd job rather than inferred from a shell run.

**The matrix.** Every row is `ipauro-probe check --seconds 8 --iface en0`, wire-confirmed:

| Execution context | Signing | Prompt? | Registry | `check` | Verdict |
|---|---|---|---|---|---|
| Non-interactive shell (agent) | ad-hoc | none | inherits `dev.yah` (allowed) | `0` | GATE OPEN |
| User LaunchAgent, `gui/501` | ad-hoc, **never-seen path** | none | auto-recorded **allowed** | `0` | GATE OPEN |
| User LaunchAgent, `gui/501` | **Developer ID** (7BW4R8G8Q6) | none | auto-recorded **allowed** | `0` | GATE OPEN |
| User LaunchAgent, `gui/501`, binary inside a signed **app bundle**, `AssociatedBundleIdentifiers` | Developer ID | none | bundle id, `unset` | `0` | GATE OPEN |
| Root LaunchDaemon | — | **not run** (needs an operator password) | — | — | see RUNBOOK |
| Over SSH | — | **not re-run** — established denied on macOS 15 above | — | — | see RUNBOOK |

**Result: the feared failure mode did not occur.** R002-T8's premise was that "a user agent may be
denied WITHOUT ever showing a prompt." On macOS 26.5.1 a **brand-new, never-before-seen,
ad-hoc-signed LaunchAgent** got full bidirectional multicast on a real interface, wire-confirmed,
with no prompt — and the system recorded an *allow* for it unprompted. Developer ID signing and
bundle embedding changed the recorded identity but not the outcome.

**Honest limits of this run — read before relying on it:**

- **No denial was observed anywhere.** 0 of 263 records on this host are denied, so this run
  demonstrates the auto-grant path and does *not* demonstrate that the instrument detects a real
  denial on macOS 26. The negative case still rests on the macOS 15 SSH observation above. The
  wire leg's ability to report a true zero *is* independently shown (off-path tap → `0`).
- **Single host, single OS version.** The A002-era denial was on macOS 15.7.3; this is 26.5.1.
  Behaviour may have relaxed between them — do not retro-fit this result onto macOS 15 machines.
- **A managed/corporate Mac may behave differently** (MDM can preset these decisions). Re-run the
  matrix there before assuming.
- The rows above are a *user session that is already logged in*. Boot-before-login and
  fast-user-switch behaviour are untested.

**Placement decision (this is what R002-T8 was for):** the brain service **stays where it is** — an
unprivileged user LaunchAgent (`io.ipauro.core`) inside the signed app bundle, registered via
`SMAppService`, with `AssociatedBundleIdentifiers` → `io.ipauro.app`. No multicast-touching work
needs to be delegated to the UI client or to the root helper, and the fallback sketched in W001 §4
(delegate the gossip beacon / forwarder to a granted context) is **not needed** and should not be
built. `io.ipauro.app` already carries a registry entry in the `unset` (i.e. permitted) state.

**Consequence that had to be fixed, not just noted:** the grant attaches to the *code-signing
identifier*, and `codesign` derives that from the filename when not told otherwise — so
`ipauro-core` was signing as the bare, unnamespaced identifier `ipauro-core`. That is the name the
grant binds to and the name System Settings shows the user. `packaging/build-app.sh` now signs each
embedded executable with an explicit `--identifier` matching its launchd label
(`io.ipauro.core`, `io.ipauro.helper`, `io.ipauro.app.cli`), and asserts it landed. Safe with
respect to XPC caller authentication, which pins the **team ID** only
(`ipauro_proto::helper::peer_requirement`), never a signing identifier.

**First real confirmation is still owed at M2.** `ipauro-core` has not yet sent a multicast packet
(that arrives with R003-F9's air-gapped bootstrap beacon), so its registry entry is `unset` by
never having been exercised rather than by having been exercised and permitted. When R003-F9 lands,
re-run `ipauro-probe grants --filter ipauro` and confirm the decision records against
`io.ipauro.app` / `io.ipauro.core` — that is the last mile of this ticket, and it is cheap.

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

### pf states are FLOATING — a per-interface flush is a no-op, and a restart re-matches (VM tier, 2026-10-29)

Measured in a macOS 26.4 guest by `crates/ipauro-vmlab` (R009-T2), case
`pf-scope-forces-onto-interface`, with pf enabled under a stateful UDP pass (the bench condition
above — note a STOCK pf.conf has no pass rule, and pf passes unmatched packets without creating
state, so on a stock Mac the trap needs something else to have loaded a stateful rule first):

- **States carry no interface.** macOS pf's default `state-policy` is `floating`; `pfctl -s states`
  prints Link's flows as `ALL udp 10.70.2.1:20808 <- 10.70.2.2:20808`. So `pfctl -F states -i en2`
  does not touch them. The helper's first `ScopeUdp` flushed exactly that way, per interface, and
  **did not bite**: the link-b states were byte-identical before and after, the live session kept
  flowing on the blocked link, and so did a session started afterwards.
- **Teardown-and-re-establish does not rescue an unflushed table for Link.** Link is fixed-port at
  both ends (`:20808 <-> :20808`), so a restarted app produces the IDENTICAL 5-tuple and re-matches
  the surviving state, which the peer's own traffic keeps alive indefinitely. The discipline above
  still stands, but a re-established session only proves the rule if the state table was actually
  cleared — check the table, not just the restart.
- **Fix (shipped in `app/helper/src/pf.rs`):** macOS `pfctl -k` selects by host/network only (no
  port, no label), so the helper reads `pfctl -s states`, collects the host pairs of UDP states on
  scoped ports, and kills each pair in both directions. Verified in the VM: link-b states go to `[]`,
  the live session is cut, a fresh one never touches link b, `ClearScopes` restores it.
- **Scoping onto a bridge is safe.** With `ScopeUdp(20808, [bridge])`, the relay's own multicast
  still egresses every member and member↔member forwarding is unaffected (case
  `pf-scope-on-bridge-keeps-forwarding`) — the interface-unqualified `block` in the anchor does not
  catch bridged frames on the members on this kernel.

### Kernel bridge supports HUB-AS-PEER (verified — host multicast egresses to members)

We initially feared macOS `if_bridge` floods member↔member multicast but won't egress the
host's OWN (relay-originated) multicast to members — which would mean a forwarding hub couldn't
also participate in Link (fatal for daisy chains, where every interior node is a hub-and-peer).
An early test suggested this, but it was confounded (an `en9` split-brain with a stale
`169.254` alias + Corp's Local Network privacy gate).

**Retested clean and it WORKS:** relay + 2 spokes all bridged onto one subnet
(`10.69.0.0/24`: relay `bridge90`=.1, Corp=.2, Air=.3), relay's `link_audio_hut` bound to the
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

Live incident: with a 3-node mesh up (relay bridging `en9`=Corp + `en12`=Air), unplugging and
replugging the **Air** cable **tore down the entire `bridge90`** — not just the Air's link.
Corp dropped too, because its bridge evaporated out from under it (`en9` was orphaned, lost the
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

### M1 single-Mac verification (2026-07-04/05) — four reproduced findings (R005-T10)

Driving the shipped M0+M1 stack (`ipauro-core` + the `SMAppService` helper) on one Mac, with
no second machine, surfaced four failures that no unit test could have found. Each is now
handled in code with a named test, per §9 of the plan ("each failure mode → a named test case").

1. **Stale helper survives a bundle replacement.** launchd keeps the RESIDENT helper process
   alive when the `.app` is replaced, so a freshly-installed core drives the PREVIOUS build —
   observed as an M0 helper answering `bad request: unknown variant` to M1 verbs. Registration
   has to be cycled before the new binary runs. *Fix:* the core compares the helper's `Pong`
   version against its own and cycles registration on a mismatch
   (`ipauro_core::helper_link::SupervisedHelper`). **The package version cannot carry that
   signal** — it is `0.0.1` for every build of every milestone — so `packaging/lib/common.sh`
   stamps a per-run `IPAURO_BUILD_ID` that both binaries compile into `build_version()`.
   Note the deliberate cost: unregistering kills the helper, so its fail-open grace window
   restores stock networking, and the bounce can leave registration in `RequiresApproval`.
   Tests: `helper_link::tests::a_stale_helper_bounces_registration_once_not_once_per_request`.
2. **`:67` is held by launchd, not by a visible process.** The DHCP responder failed with a bare
   `binding :67: Address already in use`. Cause: **launchd socket-activates `*:67` whenever the
   `bootps` job is loaded**, so the port is held with no `bootpd` running for `lsof` to find —
   and the prototype's `enable-dhcp.sh` left it loaded with `-w` (persistently). `SO_REUSEADDR`
   does not get past it. *Fix:* the bind failure is now a diagnosis naming the holder (confirmed
   via `launchctl print system/com.apple.bootpd`) and the exact reversal,
   `sudo launchctl unload -w /System/Library/LaunchDaemons/bootps.plist` — blockage-as-first-class
   (R007's philosophy) arriving early. Tests: `dhcp::server::tests::port_in_use_*`.
3. **One refused step aborted the whole pass.** A `ServeDhcp` the helper refused (finding 2)
   ended the reconcile pass, so the pf transport scope went unapplied — even though scoping
   needs nothing whatsoever from DHCP. *Fix:* a pass now attempts every step whose prerequisites
   still hold, and reports partial convergence (`reconcile::Facet` / `blocked_by` /
   `Pass::failures`). Two dependency rules are load-bearing: anything naming the bridge waits on
   the bridge step, and `DestroyBridge` waits on the scope teardown — tearing the bridge down
   under a scope we failed to clear blocks the port EVERYWHERE (the incident above). A dead
   channel still aborts: every remaining verb would fail identically. Tests:
   `reconcile::tests::a_refused_dhcp_step_does_not_cost_us_the_transport_scope` and siblings.
4. **`HelperState` only ever went `Connected` at boot.** The snapshot read "registered (not
   connected)" while commands were flowing through the helper, because the boot ping was the one
   and only writer. *Fix:* liveness is observed on EVERY exchange (`SupervisedHelper`), including
   a helper `Err` — a refusal still proves the helper is there. A channel-level failure clears
   the cached identity, which re-arms the staleness check of finding 1 on the next reconnect;
   that is exactly the upgrade shape. Tests:
   `helper_link::tests::a_plain_successful_request_marks_the_helper_connected`,
   `integration::a_command_that_reached_the_helper_reports_it_connected`.

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

### 5.5 Verified against a quiet Mac (2026-07-25, R005-F7)

Captured on an Apple Silicon MacBook Pro with **nothing plugged in**, while porting the
ranking above into `ipauro-core::discovery`. Four things the original session inferred but
never saw directly:

- **`anpi` is a child of `AppleUSBDeviceNCMData`.** §3 called `anpi` a decoy without naming
  the mechanism; this is it. `ioreg -r -c AppleUSBDeviceNCMData` returns `anpi0`, `anpi1`
  and `anpi2` as `AppleUSBDeviceNCMPrivateEthernetInterface` nodes, interleaved with the
  real `enN` ones. Any device-side query that greps for interface names rather than the
  `+-o en[0-9]+` shape will bridge an `anpi`.
- **A quiet Mac already shows three `enN` under that class** (`en3`, `en4`, `en5` here) —
  all `status: inactive`, no `inet`, no `inet6`. §5 wrote them as "`en1`..`en6`"; the
  numbering is machine-specific and must never be hardcoded. The `active` + IPv4 narrowing
  rejects all three, which is what makes the device-side class safe to query at all.
- **`inet6` must not count as "configured".** A device-end link that has come up self-assigns
  an IPv4 (`169.254/16` absent DHCP); the internals do not. But internals frequently *do*
  carry an IPv6 link-local, so a `grep inet` that also matches `inet6` promotes every one of
  them to a link.
- **`netstat -ib` marks a DOWN interface with a trailing `*`** (`gif0*`, `stf0*`). The star is
  status, not part of the BSD name — a traffic-counter parser that keeps it files the counters
  under a name no lookup matches, and then silently reports zero traffic forever.

Implementation: `crates/ipauro-core/src/discovery.rs` carries the verbatim captures as test
fixtures, so these shapes are regression-checked without hardware; its `#[ignore]`d
`real_machine_identification_holds_its_invariants` re-checks them against a live Mac after a
macOS update.

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
