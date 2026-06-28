# IPAuRo Architecture — control/data plane, topology, reconciler

**Status:** Design canon (pre-implementation; data plane proven on hardware via the shell `prototype/`).
`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` — empirical base.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — M0–M5 roadmap.

Companion to [A002-ipauro-findings.md](A002-ipauro-findings.md). Two concrete threads to pursue next.
Status as of 2026-06-27: relay↔Air (clean Macs) fully proven — USB-NCM link, Link
discovery/sync over USB, and `pf` transport-scoping (with state flush) all validated on
real hardware. Metrc (CrowdStrike Falcon) confirmed blocking Link at the EDR flow layer.

---

## Thread 1 — 3-node session with the "Falcon" machine — SOLVED (2026-06-27)

**RESOLVED: yes, it works.** All three Macs (relay + Air + Metrc) reached `peers 2` in a
fully-meshed Link session over USB. **Falcon was NOT the blocker** — see the corrected
findings-doc section. The real cause was **macOS 15 Local Network privacy denying the
SSH-launched hut**; launching it from Metrc's GUI Terminal (which holds the Local Network
grant) fixed it instantly. Lesson banked: Link must run in a Local-Network-permitted GUI/agent
context on macOS 15+; never blame a visible EDR before ruling out OS permission + launch
context. The experiments below are retained only as the general method for *if* a real EDR
block is ever encountered.

### (Historical) What we thought we knew
- Metrc's CrowdStrike Falcon (`NEFilterDataProvider`) **drops Link's inbound UDP at the
  socket/flow layer.** Proven: packets arrive at `en4` (tcpdump/BPF, below the filter) but the
  app never receives them; app firewall was off; kernel ICMP passes. See findings doc.
- **No client-side networking trick fixes a flow-layer EDR drop.** Bridge topology is
  irrelevant: even member↔member multicast (which floods fine) still lands on Metrc's NIC and
  is then dropped by Falcon before the app. The block is *on Metrc*, independent of how it's
  wired.
- Therefore: as-is, **Metrc cannot be an audio-transport peer.** A 3-node Link session
  including Metrc is not achievable without changing Metrc's policy.

### Experiments to run (cheap → expensive) — determine if it can EVER work without IT
1. **Signed + notarized binary.** Falcon app-control often keys on code signature / reputation.
   Build the Link app with a Developer ID signature + notarization and test on Metrc. If a
   signed binary's flows pass, signing is the unlock (and we need it anyway — see Thread 2).
   *Likely partial:* signature may satisfy app-control but a network-firewall policy can still
   block by port/destination regardless of signer.
2. **Unicast vs multicast.** Re-test whether Falcon drops only multicast (`224.76.78.75`/
   `ff12::8080`) or all `udp/20808`. If unicast survives, a discovery shim that seeds peers
   out-of-band (via the iroh control plane) and runs Link peer-to-peer on unicast *might* slip
   through. Test by sending a unicast `udp/20808` from the relay to Metrc and watching whether
   the app receives it.
3. **Outbound check.** Confirm whether Metrc can SEND Link (does the relay see Metrc's
   `udp/20808` egress?). If outbound is also blocked, even a one-way-fixed path is dead.

### Verdict / fallback design
- **The legitimate fix is organizational:** Metrc's IT allowlists the app (signature) and/or
  the port/interface in the Falcon policy. Pursue this if Metrc genuinely needs to be in the
  mesh. **Do NOT attempt to disguise/tunnel audio traffic to evade the EDR** — that's
  circumventing a corporate security control on a managed device.
- **Architectural fallback (do this regardless):** represent EDR-blocked nodes as a
  first-class state — *"in the mesh (control plane reachable) but audio-transport blocked by
  endpoint security."* The control plane (iroh, over normal allowed networking) can still see
  Metrc; the data plane can't carry its audio. The app should detect this
  (`systemextensionsctl list` for known EDR bundle IDs) and surface it instead of silently
  failing. A 2-node clean session + a visible "Metrc blocked by Falcon — ask IT to allowlist"
  is the honest, shippable behavior.

---

## Thread 2 — Building an app that isn't constantly fighting `sudo`

Every privileged op we did by hand needs root: `ifconfig` (bridge create/addm/inet),
`pfctl` (load/flush/enable), `bootpd`, plus `tcpdump`/firewall reads. A shipping app can't
prompt for `sudo` repeatedly. macOS has three sanctioned tiers — pick by how deep we go.

### Foundational (required for ALL tiers): code signing + notarization
- Developer ID signature + notarization is a prerequisite for privileged helpers and system
  extensions, and is the thing most likely to help with EDR (Thread 1). Do this first.

### Tier A — Privileged helper via `SMAppService` (smallest leap from today)
- Ship a tiny **root helper daemon** (`SMAppService.daemon`, macOS 13+; legacy `SMJobBless`).
  User authorizes **once** at install (one auth dialog); thereafter the GUI app talks to the
  helper over **XPC**, and the helper runs the exact `ifconfig`/`pfctl` logic we already wrote.
- Pros: minimal redesign — our shell logic ports almost 1:1 into the helper. No repeated sudo.
- Cons: still using kernel bridges + `pf`; helper is a root attack surface (keep its XPC API
  narrow and validated).
- **This is the recommended first migration target** — turns the working PoC into a no-sudo
  app without rethinking the networking model.

### Tier B — NetworkExtension (Apple-blessed, no root ever)
- **NEPacketTunnelProvider** (à la Tailscale/WireGuard): a system extension creates a virtual
  `utun` interface that IS the mesh transport; approved once by the user (+ MDM on managed
  Macs), runs as a background system extension, never needs sudo.
- **NEFilterDataProvider / NEAppProxyProvider:** the same primitive *Falcon* uses — could
  steer/scope the audio app's flows onto the chosen transport at the OS level (a friendlier,
  sanctioned version of our `pf` scoping).
- Pros: the "correct" macOS way; survives reboots cleanly; works on managed Macs via MDM.
- Cons: requires the `com.apple.developer.networking.networkextension` entitlement (Apple
  approval for distribution); more engineering. **The hard part: Ableton Link is multicast for
  discovery, and multicast through a `utun`/NE tunnel is awkward** — a tunnel is great for
  unicast/routed traffic but doesn't naturally carry link-scoped multicast. Would likely need
  the control plane (iroh) to handle discovery and feed Link unicast peers, sidestepping
  multicast-over-tunnel.

### Tier C — full System Extension (DriverKit/NE)
- Heavyweight, Falcon-style. Only if Tiers A/B can't express what we need. Same entitlement &
  approval burden as B, more power.

### Recommended path
1. Sign + notarize the binary (unblocks helper/extension *and* tests the Falcon theory).
2. **Tier A privileged helper** to ship the working bridge+`pf` model with one-time auth —
   fastest route to a no-sudo app.
3. Prototype **Tier B NEPacketTunnelProvider** in parallel as the long-term transport, with
   iroh owning discovery so we don't have to solve multicast-over-tunnel. If it pans out, it
   replaces the bridge+`pf` core with something that needs no root and no per-interface hacks.

### App architecture & lifecycle (decided 2026-06-27) — the Docker Desktop / OrbStack model

Shape: a **user-space agent/tray app** (Tauri), visible to the user via a menu-bar item and/or
window — **not** a hidden always-on system service, and not strictly foreground. Exactly how
Docker Desktop / OrbStack work: the *brain* (UI, control, lifecycle) is a normal user app the
user can see and quit; the only system-level component is a **thin privileged helper** that is
**inert unless the app drives it** (Docker's `vmnetd` analogue). The app **requires** the helper
because bridge/`ifconfig`/`pfctl` need root, which a user app can't have.

Split (forced by the Local-Network-privacy finding):

| User-space tray/agent app (UNPRIVILEGED, runs as the user) | `SMAppService` helper (ROOT, inert) |
|---|---|
| menu-bar/tray UI, optional window, hub/peer election | bridge create/destroy/addm |
| **holds Local Network grant** (mandatory for the Link/audio side; headless is denied) | `ifconfig` addressing |
| **IOKit USB attach/detach watch** (needs no root) | `pfctl` scope load/flush/restore |
| desired-state compute + iroh control plane | does NOTHING on its own — only on app XPC command |

- **`LSUIElement` menu-bar app** (no forced Dock presence); a window opens on demand. This *is*
  the "background but visible" the user wants — like the Docker/OrbStack whale/menu icon.
- **IOKit watch lives in the app** — the event *source* needs no root; only the *actions* do.
  Keeps the helper a narrow, auditable root executor.
- **Fail-open on XPC disconnect = the "default state when the app isn't running" requirement.**
  The helper watches its XPC connection; quitting the tray app (or a crash) invalidates it →
  helper restores stock networking (destroy bridge, `pf off`) and goes idle. The helper staying
  *installed* (launchd, like `vmnetd`) is fine — it does nothing visible without the app; it's
  not the "hidden always-on thing" to avoid. Better dead-man's-switch than `pf-prefer --ttl`.
- **Lifecycle:** tray app running → desired state enforced, mesh maintained; tray app quit →
  fail open to default. "Start at login" checkbox = `SMAppService.loginItem` → the tray app
  auto-launches at login (mesh persists from boot). One-time auth installs the helper.

### What to prototype FIRST (de-risk the spine, not the logic)
The reconcile *logic* is already de-risked (shell `reconcile` works; replug self-heal proven by
hand). The unknown is the **privilege + lifecycle spine**: Tauri ⇄ Rust ⇄ `SMAppService` helper
over XPC, install/auth, and fail-open-on-disconnect. So build a **minimal real-stack skeleton**:
a Tauri app + Rust + a helper whose entire job is "create `bridge90`" / "destroy `bridge90`" on
XPC command, with **quit/crash → auto-destroy**. One trivial op exercises the whole spine
(install, auth, XPC, lifecycle, fail-open). Then pour the proven reconcile logic + IOKit events
in with low risk. (A throwaway shell launchd IOKit-watcher would validate event-driven reconcile
cheaply but dodges the riskiest plumbing — lower value than the skeleton.)

---

## Thread 3 — General topology: N hubs, M peers, daisy-chain ∪ star ∪ mixture

Stated goal: arbitrary meshes of Macs over USB/TB — daisy chains, hub-and-spoke, and
mixtures — with a **UI to elect each node as hub (forwarder) or peer (leaf)**.

### The defining constraint: a hub is often also a peer
In a daisy chain `A—B—C`, the interior node `B` forwards between its two links AND wants to
make music. So **"a forwarding node must also participate in Link" is mandatory**, not
optional. This is exactly the macOS `if_bridge` host-multicast-egress question under test:
if the kernel bridge cannot re-emit the hub's OWN multicast back out its members, kernel
bridging is unusable for interior daisy-chain nodes → must go userspace.

### Loops → spanning tree (mandatory once "mixtures" exist)
Redundant links between hubs create L2 loops → broadcast storms. Options:
- `if_bridge` RSTP (`ifconfig bridge stp <member>`) — kernel handles it, but coarse.
- **Control-plane spanning tree:** iroh gossip already knows the full graph (roles + who's
  linked to whom), so compute a loop-free forwarding tree centrally and hand each hub its
  per-link forwarding set. Preferred — integrates with role election and is observable in UI.

### Forwarding mechanism: kernel bridge vs userspace forwarder
- **Kernel `if_bridge`:** most efficient (in-kernel), but (a) host-egress may block
  hub-as-peer (under test), (b) loop handling via STP only, (c) opaque to the control plane.
- **Userspace Link forwarder (leaning this way):** a per-hub daemon that joins the Link
  multicast group (`224.76.78.75:20808` / `ff12::8080`) on each of the hub's links and
  repeats packets between them per the control-plane spanning tree, AND injects the local
  node's own packets (solves hub-as-peer cleanly). Dedup/loop-prevention by seen-cache or
  hop-limit. **Latency is a non-issue:** Link is clock-sync metadata, not audio — tiny
  packets, and Link compensates via timestamps. This generalizes to any topology and is
  fully control-plane-driven.
- **Likely answer:** userspace forwarder as the default (works for daisy chains + mixtures +
  hub-as-peer + loop control), with kernel bridge as an optional fast-path for simple leaf
  hubs that don't need to participate.

### Role election + addressing
- UI toggle per node: Hub (run the forwarder on its links) vs Peer (leaf, no forwarding).
- iroh gossip propagates roles; control plane computes the spanning tree over hub nodes and
  pushes each hub its forwarding set; recomputes on topology change (plug/unplug).
- One L2 domain ⇒ one subnet. Use IPv6 link-local (`fe80::`, zero-config, collision-free —
  Link already speaks it) or a ULA derived from each NodeId for stable addressing.

### RESOLVED (2026-06-27): kernel bridge re-emits host multicast → hub-as-peer works
Tested clean: relay + 2 spokes bridged onto one subnet, relay bound to `bridge90` → all three
`peers 2`. So macOS `if_bridge` DOES egress the hub's own multicast to members; the earlier
"it doesn't" was a confounded observation. **Kernel bridging is viable for daisy chains and
hub-spoke** (hub-as-peer is free). The userspace forwarder remains the better choice for
multi-hub loop control + control-plane integration, but is now an optimization, not a
requirement. Requirements that hold: one subnet across all bridged nodes; hub binds the bridge
interface; the hub's transport-scoping `pf` targets the bridge interface (`on bridge90`).

---

## Controller / desired-state reconciler (the daemon's real job)

The hub daemon must be a **desired-state controller** (Kubernetes-style reconcile loop), not a
one-shot script. It continuously drives **actual** network state toward **desired** state and
self-heals on any drift. This is forced by a live incident: unplugging one USB member tore down
the entire macOS bridge and dropped every node on that hub (see findings) — only a proactive
reconciler keeps the mesh alive through plug/unplug/reboot.

**Desired state** (computed by the control plane — iroh roles + topology + spanning tree):
- which local USB-NCM interfaces should be bridge members (this hub's links)
- the bridge exists, is up, and holds the hub's address on the shared subnet
- member interfaces carry no stray IPs (addresses live on the bridge)
- transport-scoping `pf` rules target the **bridge** interface (block the audio port elsewhere)
- DHCP served on the bridge so peers auto-(re)acquire addresses
- the local audio app is bound/rejoined to the current bridge (after any rebuild)
- (multi-hub) only the spanning-tree-selected links forward; loops pruned

**Reconcile triggers (event-driven first, poll as backstop):**
- IOKit USB attach/detach notifications (the authoritative signal — a member appearing/leaving)
- interface up/down + address changes (`SCDynamicStore` / `NWPathMonitor`)
- control-plane changes (role toggled hub↔peer in UI; topology/spanning-tree update via gossip)
- periodic safety poll (e.g. 15s) as a backstop for missed events
- the shell PoC (`usb-link-bridge.sh` + the LaunchDaemon) only does the poll — the Rust
  controller must add the IOKit event watch so a member change self-heals in ~instant, not ≤15s.

**Reconcile must be idempotent + ordered.** Each pass: (1) rebuild/repair the bridge and its
membership, (2) flush stray member IPs + (re)assign the bridge address, (3) (re)load `pf` scope
for the current bridge, (4) ensure DHCP, (5) signal the audio app to rejoin the new bridge.
Order matters — pf scoped to a now-dead bridge blocks the audio port on *everything* (we hit
this: had to `pf off` before rebuilding).

**Failure-mode coverage** (each a reconcile/test case): member unplug → bridge gone → rebuild +
app-rebind; peer replug → DHCP re-lease; cable dead/charge-only → surface, don't spin;
macOS-15 Local-Network-denied → tell the user to grant; stale `pf` scope → re-target or restore.

**Safety:** the controller owns the transport-scope lifecycle — scope is applied only while the
controller is healthy and torn down on exit/crash (fail-open to normal networking, never leave
the audio protocol blocked). `pf-prefer.sh --ttl <sec>` is the shell stand-in for this.

## Cross-cutting: keep the control/data-plane split (see findings doc)
- Control plane = iroh (identity, gossip membership, EDR/health status), transport-agnostic.
- Data plane = the chosen direct transport (USB-NCM bridge today; NE tunnel later).
- The helper/extension only touches the data plane; the GUI + iroh stay unprivileged.

---

## Test strategy (captured for when the app exists)
- **Control plane → CI in containers:** discovery parsing, serial↔enX mapping, NodeId→address
  derivation, `pf`/rule *generation*, gossip dedup/partition-heal. No hardware.
- **L2/multicast behavior → macOS VMs on a virtual switch:** bridge flooding, the host-egress
  quirk, `pf`-forces-onto-interface (with **state flush** — see findings; an already-up
  session staying up proves nothing under stateful `pf`). Real macOS networking, no USB.
- **Physical/security reality → hardware runbook (un-CI-able):** USB data-role negotiation,
  cable quality, accessory approval, EDR filters. Document as a bench checklist + ship
  *detection* so the field reports these, not CI.
- Turn each findings-doc failure mode into a test case: cable-dead, charge-only,
  unapproved-accessory, EDR-filtered, bridge-host-egress, link-local-flap, stateful-pf-survival.
