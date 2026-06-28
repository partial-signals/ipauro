# IPAuRo

Detect network transports and **steer Layer-3 audio/sync protocols onto the best one**
(USB-C / Thunderbolt / Ethernet over WiFi), **bridge** machines into one domain, and **route
around blockage** (EDR, OS privacy gates, WiFi isolation) — for protocols that bind every
interface and can't be told where to go (Ableton Link, AES67/RTP, Dante, NDI, RTP-MIDI, OSC…).

Status: **core thesis proven on real hardware** (3-Mac Ableton Link mesh over pure USB-C,
surviving WiFi-off). This repo is the handoff for building the product.

IPAuRo is a **yah subcamp** of noisetable: it has its own `.yah/` (architecture graph,
A###/W### doc space, agent context) but its tickets surface on the **noisetable board**.

## Start here
- **`.yah/docs/working/W001-ipauro-plan.md`** — the team plan: problem, what's proven,
  architecture, roadmap (M0–M5), risks, tests. Read this first.
- **`.yah/docs/architecture/A002-ipauro-findings.md`** — every validated finding + correction +
  failure mode (the empirical base; each failure mode → a test case).
- **`.yah/docs/architecture/A001-ipauro-architecture.md`** — detailed threads: desired-state
  controller, N-hub/M-peer topology, de-`sudo`-ing into a tray app + privileged helper
  (Docker/OrbStack model), test strategy.
- **`.yah/quests.md`** — the roadmap epic + M0–M5 tickets (live on the noisetable board).
- **`prototype/`** — the working shell PoC = executable spec for the data plane. Port to Rust.

## TL;DR architecture
- **User-space tray app (Tauri, unprivileged):** UI, hub/peer election, IOKit USB watch, holds
  the macOS Local Network grant, desired-state brain, iroh control plane.
- **Privileged helper (`SMAppService`, root, inert):** bridge/`ifconfig`/`pfctl` only on the
  app's XPC command; fails open on disconnect (quit/crash → restore default networking).
- **Control plane (iroh)** = identity/membership/topology/addressing; **data plane
  (`if_bridge` + `pf`, later NetworkExtension)** = the actual transport. Protocol registry +
  transport-policy engine generalize "prefer the good wire" beyond Link.

## First build target (de-risk the spine)
`M0`: minimal Tauri + Rust + `SMAppService` helper that creates/destroys a bridge over XPC, with
quit/crash → auto-destroy. Validates the whole privilege+lifecycle path before the (already
de-risked) reconcile logic goes in. See `.yah/docs/working/W001-ipauro-plan.md` §6.
