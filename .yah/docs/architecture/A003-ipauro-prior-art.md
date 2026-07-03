<!--
@yah:ticket(R005-F8, "Adopt tactus (link-wire-rs, MIT clean-room Link+LinkAudio v1) as IPAuRo's Link impl when IPAuRo first speaks Link (Protocol NAT / diagnostics) — gated on link-wire-rs M4 interop validation vs reference peer link_audio_hut")
@yah:at(2026-06-28T05:31:13Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("tactus (link-wire-rs, crates tactus-wire/tactus) is MIT clean-room Link + LinkAudio v1 (PCM i16, channel announce/request, beat-aligned), derived ONLY from link-wire-spec + CC0 vectors. RATIONALE (2026-07-02): IPAuRo is GPLv3, so the Ableton GPL SDK would be license-LEGAL — but tactus exists so the commercial siblings can speak Link without GPL, and IPAuRo standardizes on the same house impl (one implementation to maintain). NEVER vendor or link Ableton/link, LinkKit, ableton-link-rs, or rusty_link. RE-SCOPED off the MVP critical path (was P1/R005): IPAuRo is PROTOCOL-BLIND through M4 — it steers/bridges by ports+groups and never parses payloads — so it first needs to SPEAK Link at Protocol NAT (R010) (optionally earlier for read-only diagnostics). HARD GATE stands: tactus M1 passes byte-for-byte vectors, but live interop vs link_audio_hut (tactus M4) is UNPROVEN — validate as a PARALLEL TRACK (needs no IPAuRo scaffold: two Macs + the reference peer) before R010 builds on it. link_audio_hut is a GPL test peer (use, not derivation); if interop fails, the fix is a link-wire-spec issue, never reading the reference source.")
-->

<!--
@yah:ticket(R010-F8, "Evaluate inferno (unofficial Rust Dante impl, github.com/teodly/inferno) as the Dante backend of the system-sound plugin — the Dante Virtual Soundcard replacement")
@yah:at(2026-07-02T18:53:47Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("Verified 2026-07-02 from the repo: reverse-engineered Dante TX+RX in Rust; PTPv1/v2 sync (leans on an external Statime daemon — statime is already in our crate map); mDNS discovery that Dante Controller recognizes; dual-licensed GPLv3+/AGPLv3+ (license-compatible with IPAuRo); LINUX-ONLY today (x86_64/ARM64); self-described 'highly experimental', known clock collisions with NTP. Repo carries an explicit patent disclaimer: 'Dante uses technology patented by Audinate. This source code may use these patents too.' So the Dante wall (R010-T5) is PATENT risk + maturity, not spec-absence — the evaluation must cover legal posture, not just interop.")
@yah:gotcha("Packaging: an OS-specific ipauro PLUGIN over the canonical-stream surface (keeps the GPL core clean of the patent question). Being Linux-only, its first home may be a cheap Linux box / RPi acting as the mesh's DANTE GATEWAY NODE rather than the Mac itself — which the control plane already supports (capability gossip, R010-F1). Fallback stays Dante-in-AES67-mode.")
-->

<!--
@yah:ticket(R010-F6, "System-sound plugin: virtual system audio device (CoreAudio AudioServerPlugIn; BlackHole/roc-vad model) — system sound to/from any/all connected IP-audio streams (the DVS job, protocol-plural); mixing-app handoff + aggregate-device DAC round-trip")
@yah:at(2026-06-28T04:09:01Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("Model on roc-toolkit roc-vad (a macOS CoreAudio virtual device with a control interface) + BlackHole (MIT, the minimal loopback AudioServerPlugIn shell) + native CoreAudio AGGREGATE devices — don't write a CoreAudio driver from zero (A003 §3). Round-trip: IPAuRo -> streams (any format) -> mixing app -> EITHER back to IPAuRo -> hardware DAC OR the mixing app drives the DAC directly. We expose + transport + format-adapt; we never mix and we don't own the DAC routing decision.")
@yah:gotcha("GENERALIZE beyond mixing: this is IPAuRo as a public network-backed SOUNDCARD via TWO consumer paths — (a) apps that integrate open IPAuRo over IPC; (b) apps that never will (Zoom, Teams, any video chat) route through the virtual SYSTEM device: pick 'IPAuRo' in the device list and that app's sound enters/leaves the IP-audio space, BlackHole-like. Same job as Dante Virtual Soundcard but protocol-plural. Keep it a general public capability, NEVER app-specific (abstract-before-specific). Apps may depend on IPAuRo being installed (vmnetd/runtime model).")
@yah:gotcha("Packaging + sequencing: this is an OS-SPECIFIC ipauro plugin (macOS: HAL AudioServerPlugIn installed to /Library/Audio/Plug-Ins/HAL by the privileged helper + coreaudiod kickstart; WASAPI/PipeWire siblings later) attached over the canonical-stream surface. First broker: TACTUS -> LinkAudio (system sound into the Link Audio space — tactus's first real consumer in IPAuRo; interop gate R005-F8). THIN-SLICE option: system<->LinkAudio alone needs no cross-protocol NAT — it could lead R010 as its first shippable slice (killer demo: Zoom audio onto a Link mesh over USB).")
-->

<!-- @yah:covered-by(R010, status=open, 2026-06-27) -->

# IPAuRo Prior Art — networked audio transport, and how we reuse + surpass it

**Status:** Design canon (reference). Predecessor analysis for Protocol NAT (relay **R010**) and the
mixing-app boundary.
`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — architecture threads.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — roadmap (R010 = end-of-roadmap Protocol NAT).

The brief (2026-06-27): *"if we can't do better than Jack, let's go home."* So before building the
cross-protocol gateway, study the giants. The conclusion is encouraging: **the hard transport
primitives are solved and reusable; our defensible surpass is integration, not DSP.** We don't
out-resample JackTrip — we glue the FOSS world (NetJack/JackTrip/Link) to the standards world
(Dante/AES67/AVB) with a control plane none of them have.

---

## 1. The landscape splits into two camps

### FOSS / network-music-performance camp (software, peer-ish, musician-facing)

| Tool | Clock model | Transport | Killer limitation to learn from |
|---|---|---|---|
| **NetJACK1 (netone)** | master/slave, sample-accurate via Delayed Feedback Approach (DFA) | UDP, optional CELT compression for WAN | brittle |
| **NetJACK2** | same master/slave DFA; auto-discovery; slave = in-server JACK client | UDP, no compression | **cannot tolerate packet loss; LAN-only; useless on WiFi/WAN**; identical SW both ends |
| **JackTrip** | **deliberately does NOT sync** — resamples to stay aligned; tolerant of ~100 ms | **unicast only**; many channels (16–24 ch uncompressed over Internet2) | no multicast/fan-out; high-latency-tolerant by design (not low-latency) |
| **zita-njbridge** | **adaptive resampling at receiver**; sender/receiver each own sample-rate + period | UDP uni/multicast, LAN | low latency only on dedicated/lightly-loaded net |
| **SonoBus** | **adaptive jitter buffer** (auto-grows on drops, shrinks when clean) | UDP, internet-tolerant | the pragmatic loss/jitter design NetJack lacks |

### Pro / standards camp (hardware-grade, PTP-clocked, deterministic — but interop is the wall)

- **Dante** (PTPv1 by default, PTPv2 in AES67 mode), **AES67/RAVENNA** (PTPv2), **AVB** (802.1AS /
  gPTP). All deterministic *within* their domain.
- **The interop wall is the clock.** **PTPv1 and PTPv2 are not inter-compatible.** Bridging Dante↔
  AES67 needs an AES67-capable Dante device acting as a **boundary clock** straddling both PTP
  domains, with careful manual config (Master Clock on "Media profile," matching DSCP — Dante/
  RAVENNA default CS6 for PTP / EF for audio; RAVENNA lets you reconfigure DSCP at end nodes, Dante
  largely doesn't).
- **Setup is manual and fragile:** "sneakernet SDP files around the facility," hand-built clock
  structures. The standards world has determinism but **no plug-and-play heterogeneous interop** —
  exactly the gap R010 targets.

## 2. The one hard problem — clock — and who won

Every networked-audio system must reconcile that **two endpoints have independent clocks that
drift.** Two strategies exist:

1. **Synchronize the clocks** (NetJack DFA; all PTP systems). Sample-accurate, but **brittle**:
   needs homogeneous infrastructure, intolerant of loss/jitter, and across protocol families hits
   the PTPv1/v2/gPTP incompatibility wall.
2. **Don't synchronize — adaptively resample at the receiver** (JackTrip, zita-njbridge, SonoBus;
   ASRC driven by measured drift). Robust to heterogeneous clocks, loss, and jitter.

**The FOSS field overwhelmingly converged on (2), and so should we** — it is the only approach that
survives a mesh spanning USB / WiFi / Bluetooth with no shared PTP domain. **Decision for R010-F4:**
default to **receiver-side adaptive resampling** (each protocol island keeps its own clock; the
gateway ASRC-bridges between domains), and use **boundary-clock sync only where a specific protocol
leg demands hardware PTP**. Combine it with a **SonoBus-style adaptive jitter buffer** so the mesh
tolerates the lossy links NetJack cannot.

## 3. Where we REUSE (don't reinvent — the brief said "use them where possible")

- **Resampling transport engine:** **zita-njbridge** (Fons Adriaensen's high-quality ASRC) or
  **JackTrip** are proven, open-source, and solve exactly the R010-F3/F4 media-plane resampling +
  buffering. Reuse one as the engine rather than writing an ASRC + jitter buffer from scratch;
  **SonoBus** is the reference for adaptive-buffer behavior.
- **Mixing-app / DAC boundary + system-sound plugin:** **roc-toolkit `roc-vad`** is a macOS
  **CoreAudio Virtual Audio Device with a gRPC control interface** (add/remove/configure virtual
  devices on the fly), and **BlackHole** (MIT) is the minimal loopback `AudioServerPlugIn` to model
  the device shell on. Together they are the mechanism for our boundary *and* for the
  **system-sound plugin** (R010-F6): present network streams as a CoreAudio device any app —
  DAW, Zoom, Teams — consumes, and take output back to hardware. Native **CoreAudio aggregate
  devices** combine the virtual network device + the hardware DAC so the DAW sees one device.
  Reuse / model on these rather than writing a CoreAudio driver from zero. The commercial
  reference for the *job* is **Dante Virtual Soundcard** — ours is protocol-plural.
- **Dante backend candidate:** **inferno** (github.com/teodly/inferno) — unofficial,
  reverse-engineered Rust Dante TX/RX with PTPv1/v2 (via Statime) and Dante-Controller-compatible
  mDNS discovery. Dual GPLv3+/AGPLv3+, **Linux-only today, highly experimental**, and the repo
  carries an Audinate **patent** disclaimer — so it's an *evaluation* (R010-F8), packaged as an
  OS-specific ipauro plugin if adopted, never in-core. Fallback: Dante-in-AES67-mode.
- **Link** itself, **JACK**, the protocol stacks — we sit beneath/beside them, never fork them.

## 4. Where we genuinely SURPASS (the integration none of them have)

The transport is commodity; the glue is not. IPAuRo's defensible advantages over every tool above:

1. **Heterogeneous auto-discovery + addressing via the iroh control plane.** Fixes NetJack's
   "identical software both ends + manual setup" and AES67's "sneakernet SDP files." Nobody in the
   list discovers *across* protocol families.
2. **Cross-family Protocol NAT.** No tool bridges NetJack ↔ Dante ↔ AVB ↔ Link. The AVB-D16 proves
   one pair in hardware (Dante↔AVB) but drops control; we generalize it in software and preserve
   control (R003-F6).
3. **Per-port × per-protocol enrollment matrix** (R004-F6) + transport steering — the OS-level
   control none of these expose.
4. **Self-healing reconciler** over plug/unplug/reboot (R005) — NetJack/JackTrip assume a static
   topology.
5. **Mesh fan-out** — JackTrip is unicast-only; our forwarder + spanning tree distribute to many
   nodes.

**So "better than Jack" is honest:** not by out-DSP-ing it, but by being the heterogeneous,
self-healing, auto-discovering integrator that turns a pile of incompatible audio tools into one
mesh. That is the part "infinite information + modern cognition" actually buys us — synthesizing the
whole fragmented field, not inventing a better resampler.

## 5. Packaging & license (FOSS / GPLv3, never monetized)

**IPAuRo itself is GPLv3** — correct for an *application* (a network widget integrated via IPC/RPC,
not linked as a library), and it makes the reuse map trivial: **everything here is GPL-compatible.**
The value-add is **packaging the existing tools and making them easy**, not reimplementing them.

- **Permissive (compose freely, GPL-compatible):** `rubato` (MIT/Apache — the resampler/ASRC),
  `statime` (PTP), `cpal`/`coreaudio-rs` (I/O), `mdns-sd` (discovery), `roc`/`symphonia` (MPL-2.0),
  and — importantly — **`tactus` / `tactus-wire`** (the `link-wire-rs` repo: **MIT clean-room** Link
  **+ LinkAudio v1**, derived only from `link-wire-spec`). This is IPAuRo's Link(Audio) impl **in
  tree** — no Ableton GPL SDK needed at all.
- **GPL engines (compatible):** JackTrip, zita-njbridge, SonoBus — bundle or link freely since
  IPAuRo is GPL. For **Link specifically, use `tactus`, not** Ableton's GPL SDK /
  `ableton-link-rs` / `rusty_link`: GPL would *permit* the Ableton SDK, but tactus exists so the
  commercial siblings can speak Link without catching GPL, and IPAuRo standardizes on the same
  house implementation (one impl to maintain; never vendor or link the reference). The GPL
  reference binary `link_audio_hut` is used only as an *interop test peer* (use, not derivation).
- **Process separation is an *engineering* choice now, not a legal one** — use it for crash
  isolation, independent restart, and clean packaging where it helps; link in-process where that's
  simpler. License no longer forces the boundary.
- **Adopter safety:** external apps integrate over the **IPC/RPC control API** (socket/port), which
  is not linking — so a proprietary controller can drive IPAuRo without catching GPL.

## 6. Sources
- JACK NetJack FAQ — https://jackaudio.org/faq/netjack.html
- jack2 `README_NETJACK2` — https://github.com/jackaudio/jack2/blob/develop/README_NETJACK2
- JackTrip "Under the Hood" (CCRMA) — https://ccrma.stanford.edu/groups/soundwire/publications/papers/2009-caceres_chafe-ICMC-jacktrip.pdf
- zita-njbridge — https://github.com/digital-stage/zita-njbridge
- SonoBus user guide — https://www.sonobus.net/sonobus_userguide.html
- roc-vad (CoreAudio virtual device) — https://github.com/roc-streaming/roc-vad
- BlackHole (loopback AudioServerPlugIn) — https://github.com/ExistentialAudio/BlackHole
- inferno (unofficial Rust Dante impl) — https://github.com/teodly/inferno
- AES67 / Dante / RAVENNA PTP interop — https://www.ravenna-network.com/your-practical-guide-to-aes67-part-2-2/ ; https://en.wikipedia.org/wiki/AES67
- Clock drift compensation by adaptive resampling — https://www.researchgate.net/publication/275956793_Clock_Drift_Compensation_by_Adaptive_Resampling_for_Audio_Networking
