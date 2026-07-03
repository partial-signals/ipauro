# ipauro-mesh

Control plane for a **tactus-native** audio mesh — the GPL orchestration layer
that sits *above* the MIT `tactus` wire crate and drives it. It answers "given
several transports to several peers, how does audio get from A to B, over what,
and who owns the shared roles?"

This crate is the implementation side of
[`link-wire-spec/spec/proposals/tactus-native-audio.md`](https://github.com/structuresound/link-wire-spec/blob/main/spec/proposals/tactus-native-audio.md)
§8 ("Control plane and mesh"). The spec fixes the *wire* (how capabilities and
topology are encoded, so independent meshes interoperate); this crate owns the
*algorithms* (routing, election, policy).

## Provenance (why this is a separate GPL crate)

```
ipauro            GPL application         (partial-signals/ipauro)
  └── ipauro-mesh GPL control plane       (this crate — authored dirty-side)
        └── tactus   MIT clean-room wire   (link-wire-rs — NEVER modified here)
              └── tactus-wire
```

The clean-room firewall (link-wire-rs `PROVENANCE.md`) forbids anyone who has
read the GPL Ableton Link source from contributing to the MIT `tactus` crate.
`ipauro-mesh` is GPL and merely *consumes* tactus's public API, so it can be
authored on the dirty side without touching the clean crate. It contains no
Ableton Link source; the only protocol knowledge it uses comes from the released
link-wire-spec. Keeping "tactus" = the MIT wire and "ipauro-mesh" = the GPL
orchestration makes the license/provenance boundary read straight off the
dependency graph.

## Architecture

| Module | Role | Spec |
|---|---|---|
| `transport` | `Gateway` = any transport to a peer (Link mcast, iroh, Thunderbolt, USB). Control/media split enforced in the type system: reliable transports expose no `MediaChannel`. | §8.1, §8.2 |
| `capability` | Decoded `tcap`: codecs, FEC, clock domains, per-chunk frame ceiling (§5.9), latency target. Intersection → the native mode two peers run. | §4.2, §5, §6 |
| `gossip` | Link-state records + a `Gossip` backend trait (SWIM / iroh flood). Membership and dissemination, exactly as Link already gossips peer state. | §8.3 |
| `topology` | The union graph everyone converges to. Deterministic peer ordering so a global recompute visits nodes identically everywhere. | §8.3 |
| `routing` | **Feasibility-first, preference-second** path planning. Constraints filter; service-order ranks. Deterministic → same route on every node without consensus. | §8.4 |
| `election` | Single-owner roles (clock master, group/sink owner) by the **lowest-id tie-break Link uses for session election** — not Raft. | §8.3 |
| `policy` | Shared objective: edge-cost `Weights`, `ServiceOrder`, and the monotonic `PolicyEpoch`. Agreeing on the *objective* is what lets independent optimizers converge without consensus on the *outcome*. | §8.3, §8.4 |

## The three ideas worth reading the code for

1. **Consistency without consensus** (`policy` + `routing` + `topology`). Nodes
   agree on the weights/objective (gossiped, epoch-ordered), then each runs the
   *same deterministic* planner on the *same* gossiped graph → the same routes.
   Consistency falls out of consistency of inputs, not a consensus protocol.
   Transient disagreement during churn is a brief suboptimal route (fine for
   audio); oscillation is damped by hysteresis (Link's "replace only with a
   strictly better path", ch. 03 §4.2 — apply the same rule before switching a
   live route).

2. **Feasibility-first routing** (`routing::plan`). "Make it just work" and
   "prefer Thunderbolt" don't fight: constraints (right endpoints, required
   codec/transcode-hub, bandwidth) *filter* the graph; service-order preference
   only *ranks* the survivors, bounded by `override_margin` so a preference can't
   let a genuinely bad link win by an unbounded amount.

3. **Leaders by tie-break, not Raft** (`election`). The handful of single-owner
   roles resolve by the same deterministic lowest-id rule the wire already uses
   for session election, so mesh and session elections never disagree and a
   partition never stalls — each side elects from its view and reconciles
   deterministically on merge.

## What's NOT here (on purpose)

- **No media on the reliable overlay.** `Gateway::media()` returns `None` for
  reliable-only transports, so you cannot stream PCM through QUIC reliability.
- **No PTP implementation.** Clock is *consumed*, not served: an external
  PTP/gPTP domain on a switched fabric, or transport-native recovery on a
  dedicated p2p link (spec §7.2, where PTP is the wrong tool). `capability`
  carries which applies; disciplining the clock is the adapter's job.
- **No wire encoders.** Encoding `tcap`/topology records on the wire is the
  spec's job (open question §10.6); this crate holds the decoded view.

## Status

Design skeleton. Type design and the three algorithms above are fleshed out;
`transport`/`gossip` are traits for the `tactus` and `iroh` adapters to
implement. `cargo build`s against std alone (no external types in the public
API). Wire it into the ipauro workspace by adding the `tactus`/`iroh`/`petgraph`
deps (see `Cargo.toml`) and writing the two adapters.
