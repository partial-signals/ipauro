<!--
@yah:relay(R010, "IPAuRo Protocol NAT — cross-protocol audio gateway as a queueing/routing node (1:1 / fan-in / fan-out; per-leg passthrough or transcode)")
@yah:at(2026-06-28T03:56:36Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(Q001)
@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)
@yah:depends_on(R004)
-->

<!--
@yah:relay(R009, "IPAuRo — test harness + failure-mode suite (CI containers, macOS-VM L2, A002 cases)")
@yah:at(2026-06-28T03:09:08Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)
-->

<!-- @yah:covered-by(Q001, status=open, 2026-06-27) -->

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
@yah:relay(R002, "IPAuRo M0 — privilege + lifecycle spine (brain service ⇄ SMAppService helper over XPC; IPC v0 + CLI/tray clients; fail-open)")
@yah:at(2026-06-28T02:29:47Z)
@yah:status(open)
@yah:parent(Q001)
@arch:see(.yah/docs/working/W001-ipauro-plan.md)
-->

# IPAuRo — Project Plan (M0–M5 roadmap)

> **Handoff note — read order for the implementation team.** This file (**W001**) is the primary
> source of truth and carries the bulk of the design decisions; read it first, whole. Then:
> **A001** (original architecture threads: planes, reconciler, topology — *predates several W001
> decisions; W001 supersedes where they differ*), **A002** (hardware findings — each a test case),
> **A003** (prior art, reuse map, license), **A004** (protocol taxonomy + canonical "superset"
> stream model). The board is quest **Q001** (8 relays / 55 tickets, all Open; every ticket carries
> `@yah:gotcha` notes with the *why* — read them). **Start point:** **M0 (R002)** — scaffold the
> service/helper spine around what the `prototype/` shell PoC already proved (bridge + `pf` + DHCP +
> Link-over-USB); the prototype is the executable spec, reproduce it, don't redesign it. **IPAuRo is
> protocol-blind except the termination family (R010):** through M4 it steers/bridges protocols by
> ports + multicast groups only and never parses their payloads; it first speaks protocol bytes at
> Protocol NAT and the **system-sound plugin** (§4). So `tactus`/`link-wire-rs` (the MIT clean-room
> Link/LinkAudio) is NOT on the MVP critical path — its still-unproven interop vs the reference peer
> `link_audio_hut` (R005-F8) gates **R010** (where tactus debuts as the system-sound plugin's
> LinkAudio broker), and is validated as a parallel track, before R010
> builds on it. **Scope gate for any new work:** "does this make patching any source to any
> destination feel more analog?" If not, it's out.

## The thesis — make digital audio I/O feel like an analog patchbay again

A patchbay was *perfect*: a cable from any output to any input, and it **worked** — no protocols,
no drivers, no clock domains, no discovery, no config. Fifty years of digital "progress" has been
hell by comparison: every device speaks a different protocol over a different transport with a
different clock, and "plug it in" decayed into "maybe it works." **Everything in this document —
speaking every protocol, opting ports in and out per protocol, terminating and transcoding streams,
the control plane, the mesh — exists for one reason: to hide all of that and give the patchbay
back.** The complexity is internal; the product is a cable.

The only way to make the patchbay work again is to **refuse to not speak even one protocol** —
total fluency *underneath* is what makes connectivity feel analog *on top*. We are not boiling the
ocean for its own sake; we are boiling it so the user never has to. So this is also the **discipline
against scope creep**: every feature is tested against *"does this make patching any source to any
destination feel more analog — more like it just works?"* If it doesn't serve that, it's out. The
giant pile of machinery is not the goal; the *disappearance* of the pile, from the user's seat, is.

### Why now — the AlphaFold era of software

What made "speak every protocol" absurd a decade ago was the *labor*: each protocol is a dialect
with its own discovery, framing, clock, and quirks, and hand-writing dozens of them was a career,
not a feature. **That cost has collapsed.** The same step-change that took protein folding ~10× in
a single year past what a century of human effort managed is now loose in software — with
near-infinite reference information and AI-assisted implementation, **exhaustive protocol coverage
is a choice, not a heroic effort.** There is no longer a good reason for a widget to *not* speak
every protocol humans have written and be willing to adapt it (pass / sink / fan-in / fan-out /
transcode — every verb in this doc).

This is a strategic bet with a hard architectural consequence: breadth only compounds if each new
protocol is **data in the registry + a small adapter**, never a core rewrite. **If protocol N+1
isn't roughly a day's work, the abstraction is wrong.** Rust + a declarative protocol registry + an
adapter trait (with the pass/sink/fan/transcode verbs as the interface) is how "speak everything"
stays tractable and keeps getting *cheaper* per protocol over time. The moat isn't any one
protocol — it's the compounding library of them behind one analog-feeling patch.

### License & governance — FOSS, GPLv3, never monetized

IPAuRo is **free and open-source, GPLv3-licensed, and never monetized** — a public-good utility (the
LibreOffice model). **GPL is the right call precisely because IPAuRo is an *application* — a network
widget — not a library.** Copyleft's one real downside is *library virality* (it forces anything
that links you to also be GPL); that simply doesn't apply to an app nobody embeds. Integration is by
**IPC/RPC over a socket/port** — other apps *control* IPAuRo through a documented API (see Goals),
and **IPC is not linking**, so an external controller (even a proprietary one) can drive IPAuRo
without inheriting GPL. So GPL costs adopters nothing and buys the guarantee MIT can't: **IPAuRo and
its forks stay free forever — no proprietary capture of a public good.**

This also *dissolves* the earlier reuse tension: the GPL audio engines we package (JackTrip,
zita-njbridge, SonoBus) are fully license-compatible — bundle or even link them freely. Process
separation reverts to a packaging/isolation *engineering* choice, not a legal one. **For Link the
policy is still `tactus`** (the MIT clean-room Link/LinkAudio): GPL would *permit* Ableton's GPL SDK,
but tactus exists so the commercial siblings (the noise table apps) can speak Link without catching
GPL, and IPAuRo standardizes on the same house implementation — one impl to maintain, and IPAuRo
doesn't need to speak Link at all until Protocol NAT (R010). The contribution is unchanged:
**package the fragmented landscape and make it easy.** See the prior-art doc (A003) for the reuse map.

**Status:** In-flight roadmap. Milestones tracked as tickets on the noisetable board (see [quests.md](../../quests.md)).
`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — architecture.
`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` — empirical base.
`@arch:see(.yah/docs/architecture/A003-ipauro-prior-art.md)` — predecessor analysis (NetJack/JackTrip/Dante/AES67; reuse + surpass).
`@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)` — protocol taxonomy + canonical "superset" stream model.

**One line:** a macOS app + privileged helper that detects available network transports and
**steers Layer-3 audio/sync protocols onto the best one** (USB-C / Thunderbolt / Ethernet over
WiFi), **bridges** machines into one domain, and **routes around blockage** (EDR, OS privacy
gates, WiFi client isolation) — for protocols that are themselves "interface-unaware" and can't
be told where to go.

Status: **core thesis de-risked on real hardware** (see A002-ipauro-findings.md). This plan is
the handoff for a team to build the product.

**North star — "VLC, but two-way, for a multichannel audio mesh."** VLC's gift was universality:
feed it any input protocol and it sinks to your screen (with a little transcode along the way).
IPAuRo is that idea **turned two-way and aimed at a network** — receive any audio/sync protocol,
route or translate it to any other, across a mesh of machines, in both directions. The
go-to-market wedge is **Ableton Link** (the fun, cheap, musician-friendly entry point); the far
end is **cheap hardware daisy-chaining its way into a 22.6.2 Dolby Atmos rig or a 64-node dome**.
But the positioning is deliberately humble: for serious wavefront/WFS distribution there will
always be better, purpose-built paths (FPGA). **IPAuRo is the janky, bring-your-own, DIY layer** —
accessible, hackable, good-enough — *not* a bid to beat the high end. That humility is a design
constraint, not just a disclaimer: it's *why* we bound channel counts, prefer cheap ubiquitous
transports (USB-C), and never chase throughput maximization.

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

**The core primitive is a per-port × per-protocol enrollment matrix — the control the OS hides.**
Networking long ago decided to hide as much as possible: you plug a cable in and a protocol
either works or it doesn't, and no Mac will ever offer "enable this protocol on this port" or
"prefer this port for this protocol." But that explicit, per-(interface, protocol) opt-in/opt-out
is exactly what high-performance realtime DSP + control systems need. So the product primitive is
a matrix: every `(interface, protocol)` cell is **opt-in / opt-out / auto**. "Opt WiFi out of
Link" is one cell; "opt one of two Ethernet ports out of Dante because that route goes through a
flaky hub" is another. "Prefer the good wire" is not the primitive — it's a *derived default* the
policy engine computes for `auto` cells. Suppression matters as much as preference: **Dante (and
kin) bind first-come-first-serve — given two routes to a peer they silently lock to whichever
announcement arrives first** and stay there, so you cannot fix a bad path by merely *preferring*
the good one; you must be able to *remove* the bad route from that protocol entirely. The matrix
+ `pf` scoping is how an interface-unaware protocol gets told "not here."

## 2. What's already proven (de-risked)

Validated live across 3 Macs (incl. a CrowdStrike-managed corporate machine) — full detail in
A002-ipauro-findings.md, working PoC in `prototype/`:

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
- Detect transports per machine; rank them by real bandwidth/quality (TB/USB4→Ethernet 1/2.5GbE
  > ad-hoc USB-C NCM 480M > WiFi > Bluetooth PAN by default, user-overridable).
- Steer a configurable set of L3 audio protocols onto the preferred transport, transparently.
- Build arbitrary meshes: **N hubs + M peers**, daisy-chain ∪ hub-spoke ∪ mixtures; user elects
  hub vs peer per machine.
- Detect & clearly surface blockage (Local Network privacy, EDR, firewall, no-shared-subnet).
- Self-heal on plug/unplug/reboot (desired-state reconciler).
- Ship as a **user-session service + thin UI client** (Docker Desktop / OrbStack model, brain
  split from face): the service is the product, launchd/systemd-managed; the bundled tray UI is a
  stateless client of the same IPC API external apps use. The system returns to default when the
  *service* isn't running; the UI coming and going changes nothing.
- Expose an **IPC/RPC API over a socket/port** as the **primary control surface** and the
  integration *and* extension surface: IPAuRo's own UI client speaks this same API (client/server —
  snapshot on connect + ordered event stream keeps every client in sync), so external apps
  (including closed-source) drive IPAuRo (enrollment, roles, status) exactly as our UI does, and
  exchange canonical streams (mixing apps, out-of-process protocol adapters) — without linking, so a
  proprietary app integrates and even **adds a new protocol** without catching GPL or touching the
  core. Adapters are thus **two-tier**: in-tree (GPL, joins the commons) or out-of-process (any
  license, bridges over the API). See the closed-app-with-a-new-protocol case in §4.

**Non-goals (initial)**
- Carrying the actual audio payload *in the common same-protocol case* (Link/PTP are clock/sync —
  tiny; AES67/Dante media is high-bandwidth and stays on the wire/bridge, not proxied by us). We
  route/clear paths; we are not an audio **mixer** or a creative DSP.
  - **Exception (the termination family — Protocol NAT + the system-sound plugin; see §4, §6 /
    relay R010):** a polyglot node MAY act as
    a **queueing/routing node** — propagate streams 1:1, fan-in, or fan-out, where each fan-out leg
    is independently **passthrough** (same protocol) or **transcode** (different protocol) — and
    the system-sound plugin terminates streams at this Mac's OS audio system (same machinery, the
    Mac as endpoint). That
    puts the gateway path on the media plane, but only as *format adaptation + routing*, bounded
    (~8–16 ch/iface, where even 100BASE-T has huge headroom: Dante does 48×48 there). Cost is CPU
    (transcode + clock-domain bridging), not bandwidth.
  - **Mixing is strictly out — never, not even fan-in.** "Fan-in" here means **routing/aggregating
    discrete streams onto one leg, kept channel-discrete — never summing samples.** This app does
    not mix. A *separate* app may ask this one to expose streams from the I/O in various formats and
    do its own mixing — that consumer boundary is exactly how mixing stays out of scope: we are the
    transport/format layer, the mixer is someone else's app downstream of us.
  - **Hardware-DAC round-trip.** To land divergent streams on *this* machine's DAC, IPAuRo delivers
    every stream (in whatever format) **to** the mixing app, and the mixing app either sends its mix
    **back** to IPAuRo to hit the hardware, **or** drives the DAC directly. The handoff mechanism is
    a **CoreAudio virtual device / aggregate device** (model on roc-toolkit's `roc-vad` — a virtual
    CoreAudio device with a control interface; see prior-art doc) so a DAW sees our network streams +
    the hardware DAC as one device. We are I/O + transport + format; the mix and the DAC routing are
    the consumer app's call.
- Windows/Linux (macOS first; architecture should not preclude later — the core/plugin split in
  §4 is the mechanism: cross-platform core, per-OS plugins).
- Replacing the protocols — we operate beneath them.
- **Competing with purpose-built high-end distribution** (FPGA / wavefront-synthesis rigs). IPAuRo
  is the DIY/BYO accessible layer — "VLC two-way," good-enough and hackable — not the pro-grade
  path. This bounds the whole design: cheap transports, modest channel counts, connectivity over
  throughput.

## 4. Architecture

Two planes + three tiers. (Original threads/detail in A001-ipauro-architecture.md; where they
differ, this file wins.)

### Control plane vs data plane
- **Control plane (transport-agnostic):** node identity, membership, role election, topology &
  spanning-tree, address allocation, health/blockage status. Built on **iroh** (ed25519 NodeId,
  `iroh-gossip`) so it works over any reachable path (WiFi/LAN/relay) and never deadlocks on
  bootstrap. Carries NO audio.
- **Data plane (pinned to the chosen wire):** the L2 bridge of USB/TB/Ethernet segments + the
  `pf` transport-scope (and, for multi-hub loop-safety, a forwarder). Carries the audio/sync.

### Three tiers (Docker Desktop / OrbStack model, brain split from face)
- **Brain service (runs as the user, UNPRIVILEGED, launchd/systemd-managed):** the product core.
  Desired-state brain, iroh control plane, IOKit USB attach/detach watch (needs no root), and the
  IPC server every client connects to. Lives in the user's login session so it can hold the
  **macOS Local Network grant** for its own multicast (gossip bootstrap, forwarder) — *which
  execution context can actually hold the grant (root daemon vs launchd user agent vs GUI app) is
  an M0 validation item (R002-T8)*; the fallback is delegating multicast-touching work to a
  granted context.
- **UI client (tray + transient panel, UNPRIVILEGED, stateless — egui, decided 2026-07-02):** a
  thin renderer/commander over the IPC API — hub/peer election, enrollment matrix, blockage
  status, metering. **UX model: Apple Control Center** — opened from the tray for brief
  observe-or-tweak moments, then closed; or left up as a **compact widget** (small always-on
  metering strip). Immediate mode fits exactly this shape: a closed window costs nothing, an open
  one is visibly animating meters anyway (GPU-rendered, meter telemetry straight off the socket,
  no webview boundary). Holds no state the service doesn't have; external apps connect to the
  same socket as peers of our UI. UI quit/crash never touches the mesh.
- **Privileged helper (`SMAppService`, ROOT, inert):** the only persistent system component —
  the `vmnetd` analogue. Does bridge/`ifconfig`/`pfctl` **only on the service's XPC command**,
  does nothing on its own, and **fails open on XPC disconnect** (service death → restore default
  networking; a short grace window tolerates service restart/upgrade without tearing the mesh
  down, but still fails open if no reconnect). One-time install auth. The XPC endpoint
  **authenticates its caller** (audit-token code-signature + team ID check), not just its message
  schema.

### Desired-state controller (the helper's real job)
A Kubernetes-style reconcile loop driving actual → desired network state (membership,
addressing, `pf` scope, DHCP, app-rebind, spanning-tree pruning). **Event-driven** (IOKit
attach/detach, interface/address changes, control-plane updates) with a periodic poll backstop.
Idempotent + ordered (e.g. `pf` off before bridge rebuild). Forced by the live incident where a
member unplug tore down the whole bridge.

### Protocol registry + enrollment matrix + transport policy (the generalization beyond Link)
- **Protocol registry:** each managed protocol as `{name, ports, multicast groups, discovery}`
  — Link (`udp/20808`, `224.76.78.75`, `ff12::8080`); AES67/RTP ranges; Dante ports; mDNS
  (`5353`/`224.0.0.251`); etc. The `pf` scope generalizes from one port to the registry.
- **Enrollment matrix (the source of truth):** every `(interface, protocol)` cell holds
  **opt-in / opt-out / auto**. The `pf` rule generator is just `registry × matrix → per-(iface,
  protocol) allow/block` — opting a port *out* of a protocol means block that protocol's ports +
  groups on that interface. This is the explicit per-port/per-protocol control no OS exposes, and
  it makes **suppression** a first-class operation, not just preference — required because
  **Dante & kin bind first-come-first-serve**: given two routes to a peer they silently lock to
  whichever announcement arrives first and stay there, so a bad path is only fixable by *removing*
  that route from the protocol (a matrix opt-out), never by merely preferring the good one. (Two
  routes on the *same* L2 domain — a loop — are the spanning-tree's job; the matrix is for
  per-interface route selection.)
- **Transport policy engine (the default resolver):** for every `auto` cell, computes a default
  from a bandwidth/quality ranking (not bus type): **TB/USB4→Ethernet 1G/2.5GbE > ad-hoc USB-C
  NCM 480M > WiFi > Bluetooth PAN**. Ad-hoc USB-C NCM is the *default medium* (480 Mb/s, free, every Mac
  has the port) but not the top rank — a TB/USB4→Ethernet GbE link beats it when present, and a
  hub must be able to bridge that wired link in alongside its USB segments. Any explicit opt-in/
  opt-out the user sets overrides the resolver. "Pick the good wire" becomes data, not code.
- **Extension surface — two-tier adapters over the IPC/RPC API.** A protocol adapter is either
  **in-tree** (compiled into IPAuRo, GPLv3, part of the public registry) or **out-of-process** (a
  sidecar that speaks the protocol on one side and IPAuRo's canonical stream model (A004) over the
  IPC/RPC socket on the other — any license). Worked case: *a closed-source app with its own new
  audio protocol.* It connects to IPAuRo over IPC (no GPL caught), and its novel protocol joins the
  mesh **either** by upstreaming a GPL adapter (the protocol becomes a commons everyone can speak)
  **or** by shipping a closed external adapter that bridges over the API (protocol stays the
  vendor's, interop still works). Speaking every protocol is thus *community-extensible without
  copyleft coercion* — contribute it, or bridge it closed; the patchbay grows either way.
- **IPAuRo as a public soundcard — two consumer paths.** (a) *Any* app opens IPAuRo over IPC as a
  **network-backed soundcard** — sends/receives audio as if it were hardware — while IPAuRo handles
  the mesh, transport, and protocol beneath. (b) For apps that will never integrate (Zoom, Teams,
  any video-chat client), the **system-sound plugin** presents a *virtual system audio device*
  (macOS: a CoreAudio AudioServerPlugIn — the BlackHole / roc-vad model, installed by the
  privileged helper): the user picks "IPAuRo" in the app's device list and that app's sound
  enters/leaves the IP-audio space. That is the **Dante Virtual Soundcard job, made
  protocol-plural** — system sound to/from any/all currently connected IP-audio streams, not one
  vendor's. Both paths stay a **general public capability, never app-specific** (abstract before
  specific): mixing apps, a vendor's app, video chat, and out-of-process adapters are all just
  consumers of the same surface. Apps may *depend on IPAuRo being installed* (the vmnetd/runtime
  model) and treat it as their I/O.
- **IPAuRo plugins — OS-specific endpoints on a cross-platform core.** Anything that *terminates*
  streams (the system-sound device, protocol brokers) is packaged as an **ipauro plugin**: the
  core (control plane, policy engine, IPC surface, reconciler logic) stays cross-platform, while
  plugins are OS-specific wherever they touch the OS audio stack (a CoreAudio HAL plugin has no
  Windows/Linux equivalent — WASAPI / PipeWire versions are *sibling plugins*, not ports; pure-Rust
  protocol brokers can stay portable). Plugins attach over the same IPC/canonical-stream surface as
  out-of-process adapters — the A004 two-tier model made concrete. First plugins: **tactus →
  LinkAudio** (broker system sound into the Link Audio space — tactus's first real consumer in
  IPAuRo), and, candidate, an **inferno-based Dante plugin** (R010-F8) replacing Dante Virtual
  Soundcard — inferno is Linux-only today, so its first home may be a cheap Linux node acting as
  the mesh's Dante gateway.
  **Atmos-over-HDMI object sink** (W002, evidence A005): the same plugin shape for an AVR's Dolby
  Atmos renderer, fed from ADM-OSC / canonical `Object` streams. Its encoders are portable Rust, its
  transports per-OS, and its Plan B is the same cheap-Linux-gateway-node pattern.
- **Protocol evolution — IPAuRo makes a new protocol survivable.** Two patterns fall out, and
  together they're the generative half of the product:
  - **Superset / "Link++" (no transcode):** a node speaks a backward-compatible *extension* of an
    existing protocol — e.g. a **clean-room Ableton Link** (no GPL SDK) carrying extra metadata. To
    plain-Link nodes it *is* Link; extended nodes get the bonus metadata. The canonical model's
    `metadata` + degrade rule (A004) carry it and degrade gracefully — no fork, no translation.
  - **Better-than-legacy + backward-compat NAT:** a node speaks a genuinely better protocol natively
    (Link's latency isn't great) and **leans on IPAuRo to stay Link-compatible** — Protocol NAT
    (R010) bridges the new protocol *down* to Link for the legacy ecosystem while native peers get
    full fidelity. This breaks the protocol **network-effect lock-in**: you don't have to convince
    the world to switch to ship something better — build it, and IPAuRo keeps the old world working.
    **IPAuRo turns "integrate the past" into "enable the future."**

## 5. Topology model

- **Peer:** a leaf; one link into the mesh.
- **Hub:** forwards between its links (kernel bridge by default; userspace forwarder when loop
  control / control-plane integration is needed). Hubs may also be peers (proven).
- **Heterogeneous links per hub:** a hub's member links need not be the same medium. USB-NCM and
  TB/USB4→Ethernet are both plain `enX` and join the kernel bridge directly. **WiFi and Bluetooth
  PAN are last-resort members** a hub bridges in only when no better wire reaches a node: macOS
  won't let you kernel-bridge the live WiFi NIC and Bluetooth isn't Ethernet, so both go through
  the userspace forwarder (Bluetooth = Classic BNEP PAN — macOS has no native IP-over-BLE). The
  transport policy still prefers the best wire; these tiers exist so a node that *only* has
  WiFi/Bluetooth can still reach the mesh.
- **Daisy-chain / star / mixture:** one L2 domain, one subnet. Mixtures create loops → **spanning
  tree required** (kernel RSTP or, preferred, a control-plane tree computed by iroh from the
  known graph). Hub election is a UI toggle; the control plane recomputes the tree on change.
- **Addressing (control-plane-assigned, no DHCP authority):** one subnet across the domain, but
  **nobody depends on a single node to hand out addresses.** Each IPAuRo node derives a stable
  address from its **NodeId** (IPv6 ULA `fd…::<nodeid-hash>`, or a hashed IPv4 with collision
  check) and **gossips it** — serverless, collision-free, and replug-stable because the address is
  a function of identity, not a lease. Link alone needs even less: IPv6 link-local (`fe80::`,
  zero-config, Link already speaks it) is sufficient on one bridged L2 domain; the derived ULA is
  for AES67/Dante and iroh-over-the-bridge.
  - **DHCP is an *ingestion adapter for foreign (non-IPAuRo) devices only*, not infrastructure.**
    When a naive leaf (a hardware Link box, another vendor's gear) plugs into a hub, the **control
    plane allocates** a coherent address for it (so two hubs never collide), the hub's local
    responder *delivers* exactly that address (with **no router/gateway option** — never makes the
    audio segment a default route), and the assignment is **gossiped** so the leaf becomes a
    first-class addressable member mesh-wide. If the leaf only self-assigns link-local and won't
    take a lease, the hub copes/maps it rather than depending on DHCP.
- **Sample rate — 48 kHz is the One Rate; the cascade governs only the exceptions.** IPAuRo *can*
  resample anything (R010-F4), so rate is never a hard blocker — but resampling is waste, and two
  inputs pulling different rates forces a conversion. The cleanest fix is social, not algorithmic:
  **aggressively default and evangelize 48 kHz** as the only rate human-audience audio ever needs
  (Nyquist 24 kHz is past human hearing; 48 k is already the Dante/AES67/AVB lingua franca; higher
  rates buy *production* headroom, not audible fidelity). 48 kHz is a **gossiped mesh-consensus
  value** (a sibling of NodeId addressing) — default 48 k, raisable only by lifting the **whole
  mesh together** (e.g. a deliberate 96 k session), never by letting two nodes silently diverge.
  When a rate *does* differ (legacy 44.1 gear, a raised session), the broker answers "what should I
  clock to?" by cascade: **(a) an input → match its corresponding output; (b) an output → match its
  host's hardware clock; (c) a host pulling a generic external input, or any fan-out with no single
  partner rate → the gossiped mesh rate.** (a)+(b) chain so the authoritative clock lands at the
  consuming hardware and everything upstream agrees with it. *Nominal-rate agreement ≠ drift:* even
  at a shared 48 k, crystals drift ppm apart, so R010-F4's ASRC still runs — but **near unity**
  (cheap, transparent) instead of a 2× ratio conversion. *Caveat:* 48 k suffices **only while the
  audience is human** — machine-listening / measurement / ultrasonic audiences are the lone reason
  to go higher, and they're out of IPAuRo's DIY-human-audio lane (the high-end is the FPGA non-goal).
  *Participation is by capability, never by protocol name (no type-name-sniffing):* a stream
  participates in sample-rate policy **iff it carries PCM samples** (the canonical model's `signal`
  payload). A pure-sync stream (classic tempo/phase sync — no samples) doesn't; an audio-carrying
  stream does — decided from the payload, not from whether the protocol happens to be called "Link."
- **Appliance semantics — "closed" means scoped, not traffic-exclusive.** Enrolling an interface
  in the audio mesh removes its *default route* (so it never becomes an internet path) and `pf`
  pins the **audio protocol's ports** to it (so audio can't leak to WiFi and behaves optimally) —
  but the wire stays a **normal addressable L3 entity**: it keeps a control/iroh address,
  registers itself, and remains reachable for control from nodes *not* on the audio segment. This
  is the explicit fix for the **single-port (Dante/AES67) failing** where one Ethernet port that
  carries audio goes invisible for control: here one wire carries pinned audio **and** vanilla
  control on the same L2 domain, and **iroh keeps a segment-only node addressable mesh-wide**.
  (Full cloud-*internet* egress for an otherwise-offline node — NAT through a peer that has
  internet — is the heavier piece that can come later; control reachability is near-term.)
- **A hub is a transparent control relay, never a media-only bridge.** When a node sits
  *downstream* of a hub, the hub MUST forward that node's **plain control traffic** (not just
  audio) AND **gossip the downstream node as a real next-hop-via-me**, so upstream / off-segment
  nodes get a working route to its control endpoint. Concrete failing we design against:
  **MTRX ⇄ AVB-D16 ⇄ Apple** — the AVB-D16 (Dante↔AVB *media* bridge) converts audio faithfully
  but **drops plain IP**, so the MTRX's control protocol never reaches the Apple though on a flat
  LAN they'd see each other. The bridge preserved audio and severed control. **Our own userspace
  Link forwarder must not repeat this** — a forwarder that only repeats audio multicast *is* an
  AVB-D16; it (or a parallel path) has to carry control + iroh for downstream nodes too.

## 6. Roadmap (de-risk the spine before the logic)

**M0 — Privilege + lifecycle spine (highest unknown).** Minimal brain service + `SMAppService`
helper whose entire job is create/destroy `bridge90` over XPC, with **service death → auto-destroy
(fail-open)**, the one-time install auth, and the **IPC control facet v0** (socket; snapshot +
event stream) with a CLI reference client — the tray UI client follows on the same API. Developer
ID signing is stood up **here, not M5** (`SMAppService` effectively requires it). Also at M0: map
the Local Network gate across execution contexts (R002-T8) to pin the brain's placement. The UI
client is **egui** (decided). Validates install/auth/XPC/lifecycle with one trivial op.
*Exit: an IPC command (CLI or tray button) makes a bridge appear/disappear; killing the service
removes it; restarting the UI client changes nothing.*

**M1 — Port the proven data plane into the helper.** Move `prototype/`'s reconcile + `pf`-scope
logic into the Rust helper (the shell scripts are the executable spec). Single hub + spokes,
one protocol (Link), manual roles. *Exit: hub-spoke Link mesh over USB, no sudo, self-heals on
replug (M-incident fixed).*

**M2 — Control plane (iroh).** NodeId identity, gossip membership, role election over the IPC
API (UI client renders it), NodeId→address allocation, health/blockage status surfaced,
**air-gapped LAN bootstrap** (R003-F9 — peers must find each other with no internet). *Exit:
machines auto-discover and show in UI; elect hub/peer; addresses auto-assigned.*

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

**End of roadmap — Protocol NAT (cross-protocol audio gateway). Relay R010.** Today the world is
binary: either one protocol wins ("all appliances in the kitchen match") or two devices simply
can't speak — and people give up at the first mismatch. The goal is to make a Mac that speaks
several protocols the **universal translator** so divergent single-protocol nodes form one mesh:
one machine that does [Link, AVB, Dante] connects 4 computers where the other 3 each speak only
one of those. Modeled as a **queueing/routing node** — propagate 1:1 / fan-in / fan-out, each
fan-out leg **passthrough or transcode**. **No mixing, ever** — fan-in routes discrete streams,
never sums them; a separate app may consume our format-adapted streams and mix on its own. The
**AVB-D16 is both the cautionary tale and the
existence proof**: it's a real Dante↔AVB media gateway (so the translation is shippable) that
*drops control* (so our version must preserve control + advertise the route, per R003-F6). The
easy half is packet plumbing; the **hard half is clock-domain bridging** — Link, AVB (gPTP/
802.1AS) and Dante (PTP) each run their own sync, and **PTPv1/v2/gPTP are mutually incompatible**
(the wall the whole Dante/AES67 world hits). The FOSS field already settled this: **don't try to
sync clocks — adaptively resample at the receiver** (JackTrip / zita-njbridge / SonoBus), the only
approach robust to a USB/WiFi/Bluetooth mesh with no shared PTP domain. So R010 **reuses** a proven
resampling engine (zita-njbridge / JackTrip) + a SonoBus-style adaptive jitter buffer rather than
reinventing ASRC, and uses boundary-clock sync only where a leg demands hardware PTP. See the
prior-art doc (A003): our defensible *surpass* over Jack & co. is **integration** — heterogeneous
auto-discovery (iroh), cross-family NAT, self-healing, mesh fan-out — not a better resampler.
Scoped for *connectivity across divergent systems*, not channel-count maximization: ~8–16 ch/iface,
CPU-bound not bandwidth-bound. Depends on M2 (capability gossip) + M4 (registry); sequenced after M5.

## 7. Tech choices
- **Rust** core (controller, reconciler, protocol/policy engine, iroh) as a launchd/systemd
  **service**. Thin cross-platform **UI client** over the IPC socket: **egui** (decided
  2026-07-02) — the UX is a Control-Center-style transient panel / compact metering widget, and
  immediate mode fits it exactly (GPU-rendered multi-stream meters, telemetry straight off the
  socket, no webview; closed = zero cost). Tray integration via the `tray-icon` crate family
  (egui has no native tray). *Known cost, accepted deliberately:* egui is **"less designy" out
  of the box** (stock look reads as dev-tool) but cleans up well with a real theming pass —
  custom `Style`/`Visuals` (spacing, rounding, palette), deliberate fonts, and bespoke meter
  widgets. **We commit to that pass**; a Control-Center-style surface lives on polish, so the
  stock theme is scaffolding-only, never what ships. **ipauro plugins** for stream termination
  (system-sound virtual device, protocol brokers) — OS-specific where they touch the OS audio
  stack, attached over the IPC/canonical-stream surface (§4). **`SMAppService`** privileged helper + **XPC**
  (caller-authenticated). **iroh** + **iroh-gossip** control plane. **`pf`** (anchor-based) +
  **`if_bridge`** data plane now; **NetworkExtension** later. Signing/notarization from M0 (also
  helps with EDR).

## 8. Risks & open questions
- **macOS 15 Local Network privacy:** the audio side must run in a granted context — never
  headless-SSH. With the brain now a launchd service, *which* context can hold the grant is
  unverified (a root daemon may be exempt as out-of-session; a user agent may be denied without
  ever seeing a prompt) — R002-T8 maps this empirically at M0; fallback is delegating
  multicast-touching work to a granted context. Also verify the helper-driven app rebind path.
- **pf coexistence:** the shipping helper must use a dedicated **anchor** + selective state kill
  (`pfctl -k`), never the prototype's whole-ruleset replace + global `-F states` — those clobber
  Apple's `com.apple/*` anchors and every other pf user (VPNs, firewalls). See R005-T5.
- **IPv4 hashed addressing collides at modest mesh sizes** (birthday math: ~20 nodes in a /24 is
  >50% collision odds) — needs a deterministic resolution rule and a foreign-DHCP pool disjoint
  from the hash range; the IPv6 ULA path is clean, but Dante/AES67 are IPv4-only. See R003-T3.
- **Native IP-over-Thunderbolt is unranked (open):** two TB-cabled Macs get a multi-Gb/s
  Thunderbolt Bridge with no dongle, but it *is* itself a bridge interface (bridge-in-bridge
  conflict with `bridge90` membership) — investigate whether its member links can be reclaimed,
  then place it in the transport ranking.
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
  session staying up proves nothing under stateful `pf`). No USB needed. (Apple licensing caps
  macOS VMs at 2 per host, so 4+-node integration tests — R006-T5, R010-T5 — are hardware-runbook
  tier, not VM tier.)
- **Physical/security reality → hardware runbook (un-CI-able):** USB data-role negotiation,
  cable quality, accessory approval, EDR, Local Network privacy. Bench checklist + ship
  *detection* so the field reports these, not CI.
- Each A002-ipauro-findings.md failure mode → a named test case.

## 10. Repo contents
- `.yah/docs/working/W001-ipauro-plan.md` — this document (team handoff).
- `.yah/docs/architecture/A002-ipauro-findings.md` — every validated finding, correction, and
  failure mode (the empirical base).
- `.yah/docs/architecture/A001-ipauro-architecture.md` — detailed architecture threads (controller,
  topology, de-sudo, app lifecycle, test strategy).
- `prototype/` — the working shell PoC = executable spec for the data plane (bridge discovery +
  reconcile, `pf` transport-scope, DHCP, diag, launchd). Validated on hardware; port to Rust.
