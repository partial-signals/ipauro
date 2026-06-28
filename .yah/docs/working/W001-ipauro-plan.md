<!--
@yah:relay(R007, "IPAuRo M5 — blockage UX + hardening (Local Network / EDR / firewall detection, signing)")
@yah:at(2026-06-28T02:30:24Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
@yah:depends_on(R004)
-->

<!--
@yah:relay(R006, "IPAuRo M3 — topology + spanning tree (daisy/star/mixtures, hub-loss survival)")
@yah:at(2026-06-28T02:30:19Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
@yah:depends_on(R003)
-->

<!--
@yah:relay(R005, "IPAuRo M1 — port the proven data plane (bridge + pf reconcile) into the helper")
@yah:at(2026-06-28T02:30:05Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
@yah:depends_on(R002)
-->

<!--
@yah:relay(R004, "IPAuRo M4 — multi-protocol + transport policy (registry; move a non-Link proto off WiFi)")
@yah:at(2026-06-28T02:29:47Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
@yah:depends_on(R006)
-->

<!--
@yah:relay(R003, "IPAuRo M2 — control plane (iroh): identity, gossip membership, role election, addressing")
@yah:at(2026-06-28T02:29:47Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
@yah:depends_on(R005)
-->

<!--
@yah:relay(R002, "IPAuRo M0 — privilege + lifecycle spine (Tauri ⇄ Rust ⇄ SMAppService helper, fail-open)")
@yah:at(2026-06-28T02:29:47Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
-->

# IPAuRo — Project Plan (M0–M5 roadmap)

**Status:** In-flight roadmap. Milestones tracked as tickets on the noisetable board (see [quests.md](../../quests.md)).
`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — architecture.
`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` — empirical base.

**One line:** a macOS app + privileged helper that detects available network transports and
**steers Layer-3 audio/sync protocols onto the best one** (USB-C / Thunderbolt / Ethernet over
WiFi), **bridges** machines into one domain, and **routes around blockage** (EDR, OS privacy
gates, WiFi client isolation) — for protocols that are themselves "interface-unaware" and can't
be told where to go.

Status: **core thesis de-risked on real hardware** (see `docs/FINDINGS.md`). This plan is the
handoff for a team to build the product.

---

## 1. Problem

Layer-3 audio + sync protocols — **Ableton Link**, AES67 / RTP, Dante, AVB-over-IP, NDI,
RTP-MIDI, OSC, mDNS-based discovery — share two chronic failure modes:

1. **Suboptimal routing.** They bind *all* interfaces and discover via multicast; when a Mac is
   on WiFi *and* has a wired/USB path, the protocol may use WiFi — higher jitter, contention,
   and AP-dependent multicast behavior — with **no app-level control** to prefer the good wire.
2. **Blockage.** The same traffic gets silently dropped by: corporate **EDR** network filters,
   the **macOS 15 "Local Network" privacy gate**, WiFi **client isolation**, host firewalls, or
   simply the absence of a shared subnet. The app shows "no peers" and the user has no recourse.

These apps can't be fixed (they're third-party, closed, multicast-based). The leverage is **at
the OS network layer, underneath them**: choose the transport, build the topology, scope the
traffic — without the app knowing.

## 2. What's already proven (de-risked)

Validated live across 3 Macs (incl. a CrowdStrike-managed corporate machine) — full detail in
`docs/FINDINGS.md`, working PoC in `prototype/`:

- **USB-C/TB between Macs auto-creates an Ethernet interface** (Apple USB-NCM); a Mac can host
  several at once.
- **Kernel L2 bridge** of those interfaces makes all USB segments one broadcast domain → a Link
  mesh forms across them. **A bridging hub can also be a peer** (critical for daisy chains).
- **`pf` transport-scoping** forces an interface-unaware protocol onto a chosen interface
  (allow its port there, block elsewhere). Proven by cut-and-restore; **survived WiFi being
  physically turned off** — the mesh ran on pure USB.
- **Blockage diagnosis is tractable.** The "EDR blocked it" scare was actually the **macOS 15
  Local Network privacy gate** denying an SSH-launched process; run in a granted GUI context and
  it works. Method: distinguish "packet on wire (BPF) but app never receives" → OS/EDR filter.
- **Hard gotchas mapped** (each becomes a test case): charge-only cables, accessory-approval
  gating, no userspace USB re-enumeration, stateful-`pf` (must flush states), and — biggest —
  **unplugging one bridge member destroys the whole macOS bridge** → mandates a reconciling
  controller.

## 3. Goals / non-goals

**Goals**
- Detect transports per machine; rank them by a policy (USB/TB > Ethernet > WiFi by default).
- Steer a configurable set of L3 audio protocols onto the preferred transport, transparently.
- Build arbitrary meshes: **N hubs + M peers**, daisy-chain ∪ hub-spoke ∪ mixtures; user elects
  hub vs peer per machine.
- Detect & clearly surface blockage (Local Network privacy, EDR, firewall, no-shared-subnet).
- Self-heal on plug/unplug/reboot (desired-state reconciler).
- Ship as a **user-space tray app** (Docker Desktop / OrbStack model) that returns the system
  to default when it isn't running.

**Non-goals (initial)**
- Carrying the actual audio payload (Link/PTP are clock/sync — tiny; AES67/Dante media is
  high-bandwidth and stays on the wire/bridge, not proxied by us). We route/clear paths; we are
  not an audio mixer or a DSP.
- Windows/Linux (macOS first; architecture should not preclude later).
- Replacing the protocols — we operate beneath them.

## 4. Architecture

Two planes + two processes. (Diagrams/detail in `docs/ARCHITECTURE.md`.)

### Control plane vs data plane
- **Control plane (transport-agnostic):** node identity, membership, role election, topology &
  spanning-tree, address allocation, health/blockage status. Built on **iroh** (ed25519 NodeId,
  `iroh-gossip`) so it works over any reachable path (WiFi/LAN/relay) and never deadlocks on
  bootstrap. Carries NO audio.
- **Data plane (pinned to the chosen wire):** the L2 bridge of USB/TB/Ethernet segments + the
  `pf` transport-scope (and, for multi-hub loop-safety, a forwarder). Carries the audio/sync.

### Two processes (Docker Desktop / OrbStack model)
- **User-space tray/agent app (Tauri, runs as the user, UNPRIVILEGED):** menu-bar UI + optional
  window, hub/peer election, IOKit USB attach/detach watch (needs no root), **holds the macOS
  Local Network grant** (mandatory for the audio/multicast side), desired-state brain, iroh.
- **Privileged helper (`SMAppService`, ROOT, inert):** the only persistent system component —
  the `vmnetd` analogue. Does bridge/`ifconfig`/`pfctl` **only on the app's XPC command**, does
  nothing on its own, and **fails open on XPC disconnect** (app quit/crash → restore default
  networking). One-time install auth.

### Desired-state controller (the helper's real job)
A Kubernetes-style reconcile loop driving actual → desired network state (membership,
addressing, `pf` scope, DHCP, app-rebind, spanning-tree pruning). **Event-driven** (IOKit
attach/detach, interface/address changes, control-plane updates) with a periodic poll backstop.
Idempotent + ordered (e.g. `pf` off before bridge rebuild). Forced by the live incident where a
member unplug tore down the whole bridge.

### Protocol registry + transport policy (the generalization beyond Link)
- **Protocol registry:** each managed protocol as `{name, ports, multicast groups, discovery}`
  — Link (`udp/20808`, `224.76.78.75`, `ff12::8080`); AES67/RTP ranges; Dante ports; mDNS
  (`5353`/`224.0.0.251`); etc. The `pf` scope generalizes from one port to the registry.
- **Transport policy engine:** ranks live interfaces (USB/TB > Ethernet > WiFi, user-overridable)
  and emits the per-protocol scope the helper enforces. "Pick the good wire" becomes data, not
  code.

## 5. Topology model

- **Peer:** a leaf; one link into the mesh.
- **Hub:** forwards between its links (kernel bridge by default; userspace forwarder when loop
  control / control-plane integration is needed). Hubs may also be peers (proven).
- **Daisy-chain / star / mixture:** one L2 domain, one subnet. Mixtures create loops → **spanning
  tree required** (kernel RSTP or, preferred, a control-plane tree computed by iroh from the
  known graph). Hub election is a UI toggle; the control plane recomputes the tree on change.
- **Addressing:** one subnet across the domain. Default to IPv6 link-local (`fe80::`,
  zero-config, collision-free — Link already uses it) or a ULA derived from NodeId; DHCP-on-the-
  hub for IPv4 peers so they survive replug.

## 6. Roadmap (de-risk the spine before the logic)

**M0 — Privilege + lifecycle spine (highest unknown).** Minimal Tauri + Rust + `SMAppService`
helper whose entire job is create/destroy `bridge90` over XPC, with **quit/crash → auto-destroy
(fail-open)** and the one-time install auth. Validates install/auth/XPC/lifecycle with one
trivial op. *Exit: a tray button makes a bridge appear/disappear; quitting the app removes it.*

**M1 — Port the proven data plane into the helper.** Move `prototype/`'s reconcile + `pf`-scope
logic into the Rust helper (the shell scripts are the executable spec). Single hub + spokes,
one protocol (Link), manual roles. *Exit: hub-spoke Link mesh over USB, no sudo, self-heals on
replug (M-incident fixed).*

**M2 — Control plane (iroh).** NodeId identity, gossip membership, role election in the tray UI,
NodeId→address allocation, health/blockage status surfaced. *Exit: machines auto-discover and
show in UI; elect hub/peer; addresses auto-assigned.*

**M3 — Topology + spanning tree.** Daisy chains and mixtures; control-plane spanning tree;
forwarder where bridges can't. *Exit: a 4+ node mixed mesh with a redundant link survives a hub
loss.*

**M4 — Multi-protocol + transport policy.** Protocol registry + policy engine; steer AES67/mDNS/
etc., not just Link; auto-prefer wired over WiFi. *Exit: a non-Link protocol demonstrably moved
off WiFi onto USB/Ethernet.*

**M5 — Blockage UX + hardening.** Detect & explain Local Network privacy / EDR / firewall /
no-subnet; signing + notarization; resilience + telemetry. *Exit: a blocked node shows a clear,
actionable reason instead of silent failure.*

**Later — NetworkExtension transport (Tier B).** Evaluate `NEPacketTunnelProvider` as a
no-root, no-per-interface-hack data plane (iroh owns discovery to dodge multicast-over-tunnel).
Replaces bridge+`pf` if it pans out.

## 7. Tech choices
- **Rust** core (controller, reconciler, protocol/policy engine, iroh). **Tauri** shell (tray
  UI). **`SMAppService`** privileged helper + **XPC**. **iroh** + **iroh-gossip** control plane.
  **`pf`** + **`if_bridge`** data plane now; **NetworkExtension** later. Signing/notarization
  from M0 (also helps with EDR).

## 8. Risks & open questions
- **macOS 15 Local Network privacy:** the audio side must run in a granted GUI context — never
  headless. Designed-in (tray app holds the grant); verify the helper-driven app rebind path.
- **EDR (mostly debunked):** corporate machines work once OS permission is granted; keep
  detection + "ask IT to allowlist" as the genuine-block fallback. **Never tamper with EDR.**
- **Multicast-over-tunnel:** the open question for the NE transport (M-Later); plan B is
  iroh-driven discovery + unicast.
- **Spanning tree correctness** under churn; loop safety in mixtures.
- **Bridge fragility:** member unplug destroys the bridge → controller must be event-driven and
  fast.
- **Cross-platform** later: the control plane is portable; the data plane is per-OS.
- **High-bandwidth media protocols** (Dante/AES67 media): confirm we only *clear the path* /
  bridge, not proxy the media.

## 9. Test strategy
- **Control plane → CI (containers):** discovery parsing, NodeId→address, `pf`/rule generation,
  gossip dedup/partition-heal, spanning-tree. No hardware.
- **L2/multicast behavior → macOS VMs on a virtual switch:** bridging, multicast flooding,
  `pf`-forces-onto-interface — **always verify by tear-down-and-re-establish** (an already-up
  session staying up proves nothing under stateful `pf`). No USB needed.
- **Physical/security reality → hardware runbook (un-CI-able):** USB data-role negotiation,
  cable quality, accessory approval, EDR, Local Network privacy. Bench checklist + ship
  *detection* so the field reports these, not CI.
- Each `docs/FINDINGS.md` failure mode → a named test case.

## 10. Repo contents
- `.yah/docs/working/W001-ipauro-plan.md` — this document (team handoff).
- `.yah/docs/architecture/A002-ipauro-findings.md` — every validated finding, correction, and
  failure mode (the empirical base).
- `.yah/docs/architecture/A001-ipauro-architecture.md` — detailed architecture threads (controller,
  topology, de-sudo, app lifecycle, test strategy).
- `prototype/` — the working shell PoC = executable spec for the data plane (bridge discovery +
  reconcile, `pf` transport-scope, DHCP, diag, launchd). Validated on hardware; port to Rust.
