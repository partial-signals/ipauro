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
  controller, N-hub/M-peer topology, de-`sudo`-ing via a privileged helper (Docker/OrbStack
  model; the brain/face split in W001 supersedes its tray-app framing), test strategy.
- **`.yah/quests.md`** — the roadmap epic + M0–M5 tickets (live on the noisetable board).
- **`prototype/`** — the working shell PoC = executable spec for the data plane. Port to Rust.
- **`.yah/docs/working/W002-ipauro-atmos-hdmi-plan.md`** — object-audio sink track: live Dolby Atmos
  objects to an AVR over HDMI (DAW/ADM-OSC → IPAuRo → IEC 61937 → HDMI). Evidence in **A005**; tools in
  `crates/ipauro-iec61937` (`mat-inspect`), `crates/ipauro-hdmi` (`hdmi-probe`,
  `hdmi-passthrough-test`), `crates/ipauro-spatial`.

## TL;DR architecture
- **Brain service (Rust, unprivileged, launchd/systemd-managed):** the product core —
  desired-state brain, iroh control plane, IOKit USB watch, IPC server; holds the macOS Local
  Network grant (execution-context placement validated at M0).
- **UI client (egui, stateless):** a Control-Center-style transient tray panel / compact
  metering widget — thin renderer/commander over the same IPC API external apps use; UI
  quit/crash never touches the mesh.
- **Privileged helper (`SMAppService`, root, inert):** bridge/`ifconfig`/`pfctl` only on the
  service's XPC command (caller-authenticated); fails open on disconnect (service death →
  restore default networking).
- **Control plane (iroh)** = identity/membership/topology/addressing; **data plane
  (`if_bridge` + `pf` anchors, later NetworkExtension)** = the actual transport. Protocol
  registry + transport-policy engine generalize "prefer the good wire" beyond Link.

## Tests

IPAuRo's two planes have very different testability, so the suite is tiered by what each
tier can honestly reach (full rationale in `W001` §9):

| Tier | What it covers | How to run |
|---|---|---|
| **Control plane** — hardware-free, containerized | `ioreg`/`ifconfig`/`netstat` parsing against captured fixtures, the desired-state reconciler, the IPC protocol, mesh gossip/topology/routing/election | `./scripts/ci-control-plane.sh` |
| **Full workspace** — macOS, still no hardware | the above plus the XPC FFI, the tray UI, and the helper's `pf`/bridge/DHCP rule generation (macOS-only by design — see `W002`) | `cargo test --workspace` |
| **L2 / multicast** — macOS VMs on a virtual switch | bridge flooding, host multicast egress, `pf`-forces-onto-interface | R009-T2 (not built yet) |
| **Physical / security reality** — bench runbook | USB data-role negotiation, cable quality, accessory approval, Local Network privacy | R009-T3 (ships as *detection*, not CI) |

`scripts/ci-control-plane.sh` reads the workspace member list from `Cargo.toml` and requires
every crate to be classified as either container-testable or macOS-only-with-a-reason, so a
new crate cannot silently escape CI. `--list` prints that classification, `--native` runs the
same crate set without Docker, and `--verify-exclusions` asserts each macOS-only crate really
still is one. GitHub Actions runs all three (`.github/workflows/ci.yml`).

## First build target (de-risk the spine)
`M0`: minimal brain service + `SMAppService` helper + IPC CLI client that creates/destroys a
bridge over XPC, with service death → auto-destroy (fail-open). Validates the whole
privilege+lifecycle path before the (already de-risked) reconcile logic goes in. See
`.yah/docs/working/W001-ipauro-plan.md` §6.
