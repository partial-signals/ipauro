<!--
@yah:ticket(R010-F7, "Protocol evolution: backward-compatible supersets (clean-room Link + metadata, carried via canonical metadata/degrade) AND backward-compat NAT (a better-than-Link protocol bridged down to Link so innovators keep ecosystem compat)")
@yah:at(2026-06-28T04:37:39Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("The strategic payoff of Protocol NAT. Two modes: (A) SUPERSET / 'Link++' — a backward-compatible extension (clean-room Link, no GPL SDK, + extra metadata): plain-Link nodes see Link, extended nodes get the metadata, carried by the canonical metadata map + degrade rule (A004), NO transcode. (B) BETTER-THAN-LEGACY + backward-compat NAT — a genuinely better protocol (Link's latency isn't great) spoken natively between capable peers, bridged DOWN to Link by IPAuRo for the legacy ecosystem. (B) breaks the protocol network-effect lock-in: you don't have to convince the world to switch to ship something better. This is the generative half — IPAuRo makes a NEW protocol survivable, turning 'integrate the past' into 'enable the future'.")
-->

<!-- @yah:covered-by(R004, status=open, 2026-06-27) -->

# IPAuRo Audio-Protocol Taxonomy — the dimensions of a "superset"

**Status:** Design canon (reference). The dimensional schema behind the protocol registry (**R004-F1**)
and Protocol NAT's canonical stream model (**R010**).
`@arch:see(.yah/docs/architecture/A003-ipauro-prior-art.md)` — predecessor tools.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — thesis (patchbay) + "speak every protocol".

**Question this answers:** can IPAuRo become a *superset* of the audio-protocol space? **Yes — and
the proof is the floor:** if a protocol can transmit a signal, that signal reduces to *clocked PCM
samples with channel identity*. So a **lossless lowest-common-denominator (LCD) always exists**. A
"superset" is then well-defined: an internal **canonical stream model** that is the *union* of
representable semantics, with the LCD **guaranteed** and richer semantics (names, objects, spatial
metadata) **preserved when both ends speak them, gracefully dropped when they don't** — never the
signal. The protocol space is large but *finite and classifiable*; each protocol is one point in
the axis-space below. Classify one-by-one, map each to the canonical model, done.

---

## 1. The axes every adapter must classify

A protocol is fully described as a point across these (mostly orthogonal) dimensions:

1. **Transport** — L2 raw Ethernet (AVB/AVTP), L3 UDP unicast (AES67/RTP, Dante), L3 multicast
   (AES67, Dante flows, Link discovery), TCP (NDI), USB-NCM, QUIC (our control plane), point-to-
   point (MADI coax/fiber).
2. **Discovery / session** — multicast announce (Link), mDNS/DNS-SD (Dante, AES67), SDP files
   (AES67 — manual "sneakernet"), SAP/SIP, controller/registry (Dante DDM), none/manual (MADI).
3. **Clock / sync** — PTPv1 (Dante), PTPv2 (AES67/RAVENNA, ST2110), gPTP/802.1AS (AVB/Milan),
   Link's musical beat-clock (*not* sample-accurate), word clock, free-run + resample (JackTrip,
   zita, SonoBus), none. *(The hard axis — see A003 §2: default to resample, not sync.)*
4. **Channelization** — discrete indexed (MADI), discrete named flows (Dante), muxed-many-on-one
   (MADI 64ch/link), and the ADM trichotomy: **channel-based** ("DirectSpeakers"), **object-based**
   (each source + positional metadata, rendered late), **scene-based** (Ambisonics/HOA — a
   speaker-independent soundfield). Object/scene carry *spatial semantics a plain channel can't*.
5. **Sample format / coding** — PCM int16/24/32 + f32, sample rate 44.1k–192k+, endianness,
   packing; coded (CELT/Opus/AAC/FLAC), DSD. Most pro AoIP is uncompressed L24/L16 PCM.
6. **Packetization / framing** — samples-per-packet / frame size, RTP vs AVTP vs proprietary
   headers, one-stream-many-channels (mux) vs one-stream-per-channel (discrete).
7. **QoS / delivery** — DSCP marks (EF audio / CS6 PTP), TSN reservations (AVB SRP + credit-based
   shaper), best-effort, FEC / loss-conceal, retransmit (rare in RT), latency target (AVB <1 ms →
   Dante ~ms → JackTrip ~100 ms).
8. **Metadata / naming** — **named vs indexed** channels/devices (Dante names, AES67 indexes),
   gain/trim/mute, stream descriptions, object metadata blobs (ADM), labels; out-of-band control
   (OSC, OCA/AES70, Dante control).
9. **Directionality / topology** — source/sink subscription (Dante TX/RX), peer (Link), unicast-only
   (JackTrip) vs native multicast/fan-out, broadcast.
10. **Identity / addressing** — device IDs, NodeIds, channel GUIDs, IP/MAC, human names.

### Representative protocols across the axes (condensed)

| Protocol | Transport | Clock | Channelization | Format | Fan-out |
|---|---|---|---|---|---|
| **Ableton Link (sync)** | L3 multicast + unicast | musical beat (no samples) | n/a (tempo/phase sync) | n/a | multicast |
| **LinkAudio v1** *(carries audio!)* | Link transport | beat-time-aligned | discrete channels (announce/request) | **PCM i16** | multicast |
| **Dante** | L3 uni/multicast | PTPv1 (v2 in AES67 mode) | discrete **named** flows | L16/L24/L32 PCM | subscription |
| **AES67 / RAVENNA** | RTP/UDP uni/multicast | PTPv2 | discrete **indexed** | L16/L24 PCM | multicast |
| **AVB / Milan** | L2 AVTP + SRP/TSN | gPTP (802.1AS) | discrete (AM824/AAF) | PCM | reserved streams |
| **MADI** | point-to-point coax/fiber | embedded/word clock | **muxed** 64ch indexed | PCM | none |
| **NDI (audio)** | TCP/UDP | stream timestamps | discrete | PCM/float | unicast-ish |
| **NetJack2 / JackTrip / SonoBus** | UDP | resample/free-run | discrete | PCM (CELT in NJ1) | uni (mostly) |
| **ADM / Atmos** | file/ST2110/MPEG-H | PTP / file | **object** + **scene** + channel | PCM + metadata | render-time |
| **USB Audio Class** | USB | implicit/async feedback | discrete indexed | PCM/DSD | n/a |

## 2. The canonical stream model (the superset, concretely)

The internal representation every adapter maps to/from. This *is* the registry's data schema and
R010's interchange object:

> **Spatial roles: proposal pending (2026-10-12).** noisetable W256 (`.yah/docs/working/W256-native-spatial-scene-format.md`
> in the noisetable tree) proposes that `Object{pos,gain,t}` be *defined by* a shared MIT spatial scene schema,
> working name `orrery`. Its contents: ADM-cartesian axes, noisetable's W246 *rank*, frame-stamped last-value
> state with ramps, and sink-up capabilities. Its encodings: relay kind 9, an A118 in-cycle slot leg (noisetable→IPAuRo
> mode 3), and flowpack on the network. ADM-OSC, ADM/BW64 and the W002 HDMI carriers become edge dialects. Until it
> is ruled, treat the spatial fields below as a sketch. Note that noisetable's `@speaker` azimuth is positive-right,
> while ADM's is positive-left, so no angle should cross this boundary unlabelled.

```
CanonicalStream {
  identity:   { stream_id: Guid, name: Option<String>, origin_node: NodeId, origin_proto: ProtoId }
  signal:     { frames: PcmBlock, sample_rate: u32, sample_fmt: {i16|i24|i32|f32}, channels: u16 }
  channel_map: [ Channel {
                   index: u16,
                   name: Option<String>,                         // named vs indexed
                   role: DirectSpeaker(pos) | Object{pos,gain,t} | Ambisonic{order,comp} | Mono
                } ]                                                // ADM trichotomy, captured
  clock:      { domain: ClockId, ref: PTPv1|PTPv2|gPTP|LinkBeat|FreeRun, est_offset_ppm: f32 }
  qos:        { latency_target_ms: u16, loss_policy: Conceal|FEC|None, priority_hint: Dscp }
  metadata:   Map<String, Bytes>                                  // gain/trim, object blobs, vendor
  binding:    { iface, addr, group }                              // how it arrived / how to emit
}
```

**Adapter contract** — each protocol implements:
- `ingest(wire) -> CanonicalStream` and `emit(CanonicalStream) -> wire`
- capability flags: `speaks`, native verbs (**pass / sink / fan-in / fan-out / transcode**),
  `can_originate`, `clock_kind`.
- **Degrade rule:** when emitting to a poorer protocol, drop unsupported semantics (object → flat
  channels, named → indexed) but **never the signal** — the LCD is inviolable. When both ends share
  a semantic (object→object, named→named), preserve it end-to-end.
- **Adapter locus (two-tier):** an adapter is either **in-tree** (compiled in, GPLv3, part of the
  public registry) **or out-of-process** — a sidecar that speaks this same contract over the
  IPC/RPC socket. Out-of-process adapters may be **any license**, so a closed-source vendor can add
  a brand-new protocol (or consume streams) without touching IPAuRo's GPL core. Upstreaming an
  in-tree adapter donates the protocol to the commons; the sidecar keeps it the vendor's. Both make
  the mesh speak it.

This makes "superset" precise: the canonical model's field set is the *union*; any protocol is a
*projection* of it; translation is `ingest` into the union then `emit` as the target's projection.

## 3. Feasibility — why this is bounded, not boiling the ocean

- **The axis-space is finite** and each protocol is one classifiable point in it. There is no
  infinite regress — "infinite varieties" are combinations of a *finite* set of dimensions.
- **~80% is already on tap in the Rust ecosystem** — the wire/codec/clock labor is largely solved,
  so an adapter is mostly *wiring*, not *inventing* (this is the AlphaFold-era + crate-ecosystem
  feasibility, W001 "Why now"). Representative crates already in reach:
  - **Resampling / clock-bridge:** `rubato` (high-quality async SRC — the R010-F4 ASRC).
  - **RTP / AES67 plumbing:** `rtp`, `webrtc` stack, `gstreamer` bindings.
  - **PTP:** `statime` (pure-Rust IEEE-1588).
  - **Codecs / decode:** `symphonia` (broad decode), `opus`/`audiopus`, `flac`.
  - **CoreAudio / device I/O:** `cpal`, `coreaudio-rs` (+ roc-vad for the virtual device, A003).
  - **Discovery:** `mdns-sd`, `zeroconf`.
  - **Link:** `tactus` / `tactus-wire` — the house MIT clean-room Link+LinkAudio (never the
    Ableton SDK or `rusty_link`; rationale + interop gate in R005-F8).
- **The genuinely novel work is small and already scoped:** the canonical model (this doc), the
  clock-domain bridge (R010-F4, decided: resample), and the cross-family control plane (R003/R010) —
  *not* fifty hand-rolled stacks.
- **Honest limits (where "superset" is lossy):** object/scene → channel loses spatial metadata
  unless the sink also speaks objects; a musical-beat clock (Link) carries no samples (it's a sync
  peer, not an audio source); hard-real-time TSN guarantees can't be manufactured over best-effort
  WiFi. We surface these as *graceful degradation*, never silent signal loss.

**Verdict:** a Rust app that is a practical superset of human audio protocols is achievable — the
space is finite, the floor is guaranteed, the ecosystem supplies most parts, and the residue is the
exact integration work IPAuRo already exists to do.

## 4. Sources
- Dante / AES67 / AVB / MADI / NDI comparison — https://www.tecnare.com/article/dante-avb-madi-and-aes67-audio-network-transmission-protocols/
- RH Consulting networked-AV protocol state (Dante/NDI dominance, AVB decline) — https://audioxpress.com/news/rh-consulting-s-latest-report-on-networked-media-shows-dante-and-ndi-expanding-dominance
- AES67 RTP/PTPv2 + interop — https://en.wikipedia.org/wiki/AES67 ; https://aimsalliance.org/aes67-faq/
- ADM audio types (channel / object / scene) — https://adm.ebu.io/background/audio_types.html
- Object vs channel vs ambisonics — https://www.production-expert.com/production-expert-1/the-5-types-of-audio-defined-in-an-adm-file
