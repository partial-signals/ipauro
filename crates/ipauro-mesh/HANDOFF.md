# Session handoff — tactus-native audio + ipauro-mesh

Paste the "Opening prompt" at the bottom into a fresh Claude Code session that has
`structuresound/link-wire-spec`, `structuresound/link-wire-rs`, and
`partial-signals/ipauro` in scope. Everything below is the context that was in the
prior chat; the durable artifacts are in git and in this crate.

## Prior session

- Session URL: https://claude.ai/code/session_01PK6xbCGcXAn15MGzHmCuRP

## Where things live (all durable)

- **link-wire-spec** — branch `claude/link-audio-wire-testing-500lif`, pushed.
  - Spec 0.4.1: sync operating envelope (latency/loss/throughput) — ch. 02 §5.1, ch. 03 §5.8.
  - Spec 0.4.2: audio extension envelope — ch. 03 §5.9 (the 512-frame reference-renderer
    crash) + `spec/proposals/tactus-native-audio.md`.
  - Spec 0.4.3: proposal reframed tactus-native (not parity); §7.2 rewritten
    (transport-native clocking vs PTP); §8 added (control plane / mesh).
- **link-wire-rs** — UNTOUCHED (clean-room firewall; see below). Branch exists but no changes.
- **ipauro-mesh** — this crate (GPL control plane). Not yet committed to
  `partial-signals/ipauro` — the prior session lacked write scope to it.

## The clean/dirty firewall (READ FIRST — non-negotiable)

This effort ran on the "dirty" side: the agent read the GPL Ableton Link source.
Therefore:
- **NEVER contribute source to `link-wire-rs` (the MIT clean-room `tactus` crate).**
  Dirty sessions may only file observations / update the spec.
- **link-wire-spec** (CC-BY spec + CC0 vectors) IS writable dirty-side — that's the
  bridge. No reference-source *expression* may appear in it (facts only: byte layouts,
  constants, state machines, measured behavior).
- **ipauro / ipauro-mesh** is GPL and separate; writable dirty-side. It *consumes*
  `tactus`'s public API and must not embed Ableton source.
- Boundary reads off the dep graph: `ipauro-mesh` (GPL) → `tactus` (MIT) → `tactus-wire`.

## Key findings & decisions (condensed)

1. **link-wire-rs works** — passes the spec conformance harness reference-vs-candidate
   across latency/loss/throughput; no candidate-only divergence. Gaps found were in the
   SPEC, now fixed (0.4.1/0.4.2).
2. **Reference bug (ch. 03 §5.9):** a single AudioBuffer chunk > 512 frames overruns a
   fixed 512-sample buffer in the Link example renderer → heap corruption. Per-chunk,
   not per-datagram (2×275-frame chunks in a 1200-byte datagram are fine; 1×550 aborts).
   Bounds backward-compatible throughput: fill the 1200-byte datagram but keep chunks
   ≤512 frames toward any non-tactus peer.
3. **tactus-native design (proposal §1–§8):** capability negotiation via a `tcap`
   payload entry (reference ignores unknown entries — probed); native codecs/FEC/
   multicast/jumbo-chunks between tactus peers; v1 is a graceful-degradation floor.
4. **Clock (§6, §7.2):** Link ghost-time is musical sync, not sample lock. On p2p links
   (USB/Thunderbolt) PTP is the wrong tool (no PHY timestamping exposed on Apple ifaces;
   SIP/DriverKit block workarounds) — use transport-native clocking (USB Audio Class
   async feedback / SOF) or master-by-construction. PTP only on switched fabrics.
5. **Mesh / control plane (§8, this crate):** overlay (iroh) = another virtual gateway
   in Link's per-gateway model; control/media split (reliable QUIC control, unreliable/
   timely media); coordination by gossip + deterministic tie-break, NOT Raft; flow
   optimization converges on shared-objective inputs, not output consensus; service
   order = measured quality + policy, feasibility-first (constraints filter, prefs rank).

## This crate (`ipauro-mesh`)

- Compiles std-only; `cargo test` green (3 tests: routing feasibility-first, election
  tie-break, codec negotiation). See README.md for the module map and the three ideas.
- To integrate: add to the ipauro workspace, uncomment `tactus`/`iroh`/`petgraph` in
  Cargo.toml, write two adapters — a `transport::Gateway` impl over iroh + Link
  interfaces, and a `gossip::Gossip` backend (SWIM or iroh flood).
- Reconcile layout/edition/license header to ipauro's actual conventions before commit.

## Next steps (pick up here)

1. Commit `ipauro-mesh` into `partial-signals/ipauro` (needs write scope), matched to
   its workspace layout.
2. Write the iroh + tactus adapters; wire a first end-to-end native flow.
3. Draft normative `link-wire-spec/spec/04-native-audio.md`: pin the `tcap` fourcc +
   TLV registry, the native data-plane message type + FEC framing + multicast join, and
   the topology/`tcap` gossip encoding (proposal open questions §10.1/§10.2/§10.6).

## Opening prompt for the fresh session

> Continuing the tactus-native audio effort (prior session
> https://claude.ai/code/session_01PK6xbCGcXAn15MGzHmCuRP). Read
> `link-wire-spec/spec/proposals/tactus-native-audio.md` and this repo's
> `ipauro-mesh/HANDOFF.md` for full context. I am on the DIRTY side (have read GPL
> Ableton Link source): do not contribute to link-wire-rs; spec + ipauro only.
> Next: [commit ipauro-mesh into ipauro / write the iroh+tactus adapters / draft
> 04-native-audio] — pick one.
