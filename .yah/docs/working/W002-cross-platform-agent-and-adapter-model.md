<!--
@yah:relay(R012, "Fold noisetable's measured transport ground truth (BLE, relay, LAN, AWDL) into ipauro-mesh's routing model")
@yah:at(2026-10-05T23:34:02Z)
@yah:status(open)
@yah:next("Source is noisetable's .yah/docs/working/W226-society-multi-transport-selection.md §7 (R742-S14..T16, measured 2026-10-05). The same pair over different transports: AWDL p50 5.9 / p99 135 ms; BLE L2CAP lane p50 51 / p99 91; iroh forced relay p50 38 / p99 114–148; QUIC direct over WiFi p50 15 / p99 83. The medians and tails disagree, so a selector must state which statistic decides. Write a short ipauro A-doc with these numbers and their caveats.")
@yah:next("ipauro-mesh's planned iroh adapter needs two upstream fixes for AWDL. The first is n0-computer/iroh#4584 (IPv6 scope id dropped, so any fe80:: path times out; fix and test prepared). The second is netwatch SO_RECV_ANYIF on Apple: without it AWDL traffic never reaches the socket, the same 'visible below the socket, never delivered' shape as A002's Local Network gate. Also, iroh never advertises fe80:: addresses, so AWDL needs out-of-band address exchange.")
@yah:next("Licence direction: findings and numbers are plain data and fine to copy here. noisetable's transport_rtt_probe code is closed-source noisetable code; bringing it into GPL ipauro is the operator's call, not an agent's.")
@arch:see(crates/ipauro-mesh/README.md)
@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)
-->

<!--
@yah:ticket(R011-F3, "WS5: noisetable audio boundary — cycle participation over shared memory, Q negotiation, re-prepare on period change")
@yah:at(2026-07-25T21:53:16Z)
@yah:status(open)
@yah:assignee()
@yah:phase(P3)
@yah:parent(R011)
@yah:next("The contract is CYCLE PARTICIPATION, not a pipeline: IPAuRo's device callback wakes noisetable, noisetable processes IN PLACE in IPAuRo's buffers, signals done, IPAuRo emits — one period, zero added latency. A free-running SPSC ring costs a period PER CROSSING and the hub+DSP path crosses twice. This cannot be retrofitted onto a ring later.")
@yah:next("Negotiate, do not bridge: vivarium's audio block is quantum × CONTROL_DECIMATION (16) and Q is a free parameter, so set quantum = ipauro_period / 16 at prepare() time and one engine tick IS one cycle. HARD CONSTRAINT for the negotiation: the period must be a multiple of 16 and >= 16 (32/64/128/256 fit; so do 48 and 96). A non-multiple forces an accumulator costing exactly the period this design exists to avoid.")
@yah:next("PERIOD CHANGE IS A RE-PREPARE EVENT, and this is the genuinely new work. IPAuRo changes period when devices change; that changes audio_block_size, hence k = ceil(min_block_size / audio_block_size) for every declaring node, hence the propagated k upstream. The cpal path never exercises this (device period is fixed at stream open), so verify a live re-prepare + k-repropagation path exists rather than assuming compute_k() covers it.")
@yah:next("noisetable keeps its LocalDevice path. This is one seam, two impls (AudioBackend::{LocalDevice, IpauroClient}) — IPAuRo is the default ON THE APPLIANCE IMAGE only, never a hard dependency for someone running noisetable standalone. A111 already anticipates the seam: 'the engine.tick() interface is already OS-agnostic; only the callback frame changes per platform.'")
@yah:verify("a node inside a ContainerNode and one outside it observe the SAME BlockCtx::frame_index under an IPAuRo-driven cycle (the noisetable-side invariant landed 2026-07-25 as test_domain_frame_index_is_caller_owned; this is the cross-process half)")
@yah:gotcha("A router serving N clients must VALIDATE every index and count read out of a client's shared region rather than using them as raw offsets. memfd seals prevent SIGBUS-on-truncate; they do NOT prevent a buggy client writing a bogus write-index. Garbage samples are bad audio and acceptable; a garbage index is an OOB read in the process everyone else's audio flows through.")
@yah:gotcha("memfd sealing is LINUX-ONLY. The shared-ring concept ports to macOS via a mach memory entry or POSIX shm_open, but NEITHER CAN SEAL — so the Mac side needs a different argument for why accepting a peer's fd is safe. IPAuRo is Mac-first, so this is not a late detail.")
@yah:assumes("That noisetable's R097-S4 spike validates BOTH legs (control ring AND cycle-coupled PCM). That scope note was added to R097-S4 on 2026-07-25 but the spike has not run — if it validates only the control case, its conclusions do not transfer to this ticket.")
@arch:see(.yah/docs/working/W002-cross-platform-agent-and-adapter-model.md)
-->

<!--
@yah:ticket(R011-F2, "WS1: app/agent — Linux privileged executor behind the existing HelperChannel/HelperRegistrar traits (nftables / ip-link / udhcpd)")
@yah:at(2026-07-25T21:52:55Z)
@yah:status(open)
@yah:assignee()
@yah:phase(P2)
@yah:parent(R011)
@yah:next("This is NOT a port of app/helper. ipauro-core already builds and runs on Linux — main.rs assembles the brain from three traits with Null/Stub fallbacks under cfg(not(target_os = macos)). The work is filling those in, plus a new binary. If anything above the trait line has to change, that is the finding: report it rather than widening the traits quietly.")
@yah:next("Implement the M1 verb set against ipauro-net-linux: CreateBridge/DestroyBridge/SetBridgeMembers/SetBridgeAddress via `ip link`/`ip addr`; ScopeUdp/ClearScopes via nftables; ServeDhcp/StopDhcp via udhcpd or dnsmasq. The verbs map ~1:1 to the macOS ones — keep the HelperRequest/HelperResponse contract in ipauro-proto UNCHANGED (that crate is manager-owned).")
@yah:next("KEEP THE TWO-PROCESS SPLIT even though root-everything would work on Linux. It costs one small binary and keeps ipauro-core on a single code path. A constrained deployment can collapse them later with an InProcessHelper impl — that is an assembly choice the trait seam already permits, not a redesign.")
@yah:next("Transport for the local leg is a unix socket, not XPC. Registration/lifecycle is a systemd unit (or the appliance's RT init per noisetable W133 — that image has no systemd), so HelperRegistrar's Linux impl is about unit/service state, not SMAppService.")
@yah:verify("the same ipauro-cli commands drive a Linux brain+agent and a macOS brain+helper, with the only differing code below the three-trait line")
@yah:gotcha("pf and nftables differ in a way that bites ScopeUdp: pf needed an explicit STATE FLUSH after a rule change (proven in the prototype, A001 Thread 1) or existing flows kept using the old path. nftables has conntrack with the same hazard. Verify that re-scoping actually moves EXISTING flows, not just new ones — the failure mode is 'the rules look right and the audio still goes the wrong way'.")
@yah:assumes("That udhcpd/dnsmasq can be driven with the same desired-state reconciliation shape as bootpd. The macOS path had a real trap here (R005-T10 finding 2: launchd socket-activation holds port 67 when bootps is enabled), and the Linux equivalent — another DHCP server already bound — needs the same blockage-as-first-class diagnosis rather than a bare bind error.")
@arch:see(.yah/docs/working/W002-cross-platform-agent-and-adapter-model.md)
-->

<!--
@yah:ticket(R011-T1, "WS4: bind ipauro-mesh to xlb-net instead of raw iroh — one Ed25519 machine identity and one QUIC endpoint shared with noisetable")
@yah:at(2026-07-25T21:52:36Z)
@yah:status(open)
@yah:assignee()
@yah:phase(P1)
@yah:parent(R011)
@yah:next("Check the license direction explicitly: IPAuRo is GPL-3.0-or-later, so it can consume an Apache/MIT xlb-net one-way. Confirm xlb-net's actual license before binding. The reverse direction (noisetable linking IPAuRo) stays forbidden — that boundary is IPC only, which is the whole basis of W002 §5.")
@yah:verify("the persisted Ed25519 identity file is the SAME one a co-located noisetable/xlb-net process would use — demonstrated, not assumed")
@yah:gotcha("xlb-net has known gaps that matter here (from noisetable W132's audit of the crate): NO QUIC DATAGRAM API — only reliable streams, with endpoint.inner() as the documented escape hatch; and NO METADATA ON DISCOVERY — PeerHint::Found(EndpointAddr) carries addressing only, so presence/capability needs its own ALPN. Neither blocks this ticket; both shape what you build on top.")
@yah:assumes("That xlb-net's macOS story is sound under the Local Network privacy gate (R002-T8) — unverified. xlb-net's discovery uses mDNS multicast, which is exactly the traffic class that gate governs, so a grant-context failure here would surface as silent non-discovery rather than an error.")
@arch:see(.yah/docs/working/W002-cross-platform-agent-and-adapter-model.md)
-->

<!--
@yah:relay(R011, "Cross-platform agent + adapter model — Linux app/agent, local-hw-as-adapter, xlb-net binding, the noisetable audio boundary")
@yah:at(2026-07-25T21:52:02Z)
@yah:status(open)
@yah:assignee()
@yah:next("W002 §8 carries the six intended workstreams. File child tickets against this relay as each is picked up; WS4 (xlb-net binding) is the recommended first because it is small, unblocks the identity story for the noisetable boundary AND the two-provider clock registry, and turns into a migration if ipauro-mesh binds raw iroh first.")
@yah:gotcha("W002 is a DESIGN RECORD from an operator session, not a refined plan — it was written to stop eight turns of decisions living only in a chat log. Read it before opening children; several of its conclusions (local hardware IS an adapter, the binary stays Mac-only while the protocol goes cross-platform, inferno out-of-process) reverse the intuitive framing.")
@yah:assumes("That ipauro-core's existing three-trait seam (HelperChannel / HelperRegistrar / UsbNcmSource, each with a cfg(not(target_os = macos)) Null/Stub fallback in main.rs) is sufficient for a Linux privileged executor with no changes above the trait line. Verified only by reading; not exercised by a Linux impl.")
@arch:see(.yah/docs/working/W002-cross-platform-agent-and-adapter-model.md)
@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)
-->

# Cross-Platform Agent, the Adapter Model, and the noisetable Boundary

**Status:** DRAFT (design, from an operator design session 2026-07-25). Records
decisions made across that session that existed nowhere else. Not yet refined into
tickets — see "Workstreams" at the end for the intended shape.
**Scope:** what IPAuRo becomes on platforms other than macOS; how local hardware,
LinkAudio and Dante sit in one adapter model; and how noisetable consumes IPAuRo
across a process boundary without linking it.
**Not in scope:** IPAuRo's existing M0–M5 roadmap (`W001` — this doc constrains it,
does not replace it); society's transport/consensus design (noisetable `W132`); the
Buildroot image (noisetable `W133`); the device-config sidecar's Linux mechanism
(noisetable `W136`, which this doc partly absorbs — see §2).

**Related:** `A001` (architecture), `A003` (prior art — "resample, don't sync"),
`A004` (protocol taxonomy — the adapter contract this builds on), `W001` (plan).
noisetable-side: `W132` (society), `W133` (image + `R097-S4` transport spike),
`W136` (config sidecar), `A111` (headless audio node).

---

## 1. Cross-platform is a protocol decision, not a port

**Decision: the binary stays macOS-first; the protocol goes cross-platform now.**

The two halves of IPAuRo have very different portability economics:

| | Already portable | Not portable, and not worth making so |
|---|---|---|
| | `ipauro-mesh` (capability, election, routing, gossip, topology — pure logic, transport behind a trait) | `pf`, `ifconfig` bridges, `bootpd` |
| | `ipauro-proto` (envelope, versioning, snapshot+events, protocol registry) | SMAppService, XPC, notarization |
| | `ipauro-core` — the brain **already builds and runs on Linux today** | the macOS 15 Local Network gate (`R002-T8`), NetworkExtension |

`ipauro-core/src/main.rs` assembles the brain from three traits — `HelperChannel`,
`HelperRegistrar`, `UsbNcmSource` — each with a macOS impl and a `Null`/`Stub`
fallback under `cfg(not(target_os = "macos"))`. The seam exists; it just has nothing
behind it on Linux.

**So the separate app is the privileged executor, not the brain.** And the hard,
expensive parts of IPAuRo are all macOS-specific: none of SMAppService, XPC,
notarization, the Local Network gate or NetworkExtension entitlements have a Linux
analogue. Linux's privileged-executor story is a root process and a unix socket.

The M1 verb set ports close to 1:1:

| `HelperRequest` | macOS (`app/helper`) | Linux (`app/agent`) |
|---|---|---|
| `CreateBridge` / `SetBridgeMembers` / `SetBridgeAddress` | `ifconfig bridge0` | `ip link add … type bridge` / `set master` / `addr add` |
| `ScopeUdp { port, allowed_ifaces }` / `ClearScopes` | `pf` | nftables (more expressive per-interface than pf) |
| `ServeDhcp` / `StopDhcp` | `bootpd` | udhcpd / dnsmasq |

**Keep the two-process split on Linux** even though root-everything would work. It
costs one small binary and keeps `ipauro-core` on a single code path. Because the
seam is a trait, a constrained deployment can later collapse them with an
`InProcessHelper` impl — an assembly choice, not a redesign.

## 2. Local hardware is an adapter; W136's verbs are its instantiation surface

`A004` §2's adapter contract (`ingest`/`emit`, capability flags, degrade rule)
applies unchanged to a CoreAudio device or an ALSA `hw:` — USB Audio Class is
already a row in its §1 table. Saying this out loud resolves what looked like a
separate concern:

**`list_cards` / `select_card` / `apply_overlay` / `load_module` are not "OS
configuration" bolted onto IPAuRo.** They are how a local-hardware endpoint is made
to *exist* so it can be bound as a source or sink — the exact peer of subscribing to
a Dante flow or announcing a LinkAudio channel. noisetable's `W136` device-config
sidecar is therefore the **`device` namespace of the Linux agent**, not a separate
program, and `W133`'s kernel floor (`CONFIG_MODULES`, `OF_OVERLAY`, `SND_USB_AUDIO`,
`/lib/firmware`) exists to widen the set of instantiable endpoints on that adapter.

**Privilege boundary, which is easy to get backwards:** only *some* of those verbs
need root. `apply_overlay` and `load_module` do. **Opening the ALSA device and
streaming does not** — it belongs in the media process alongside every other adapter,
never in the root agent. `select_card` is just desired state in the brain. The
privileged agent stays genuinely tiny.

### Namespaces, not a per-OS union enum

A single union of every platform's verbs would be a lie. Three namespaces, most
present on both platforms:

- **`net`** — bridge / scope / dhcp. Both platforms, different backends, same verbs.
- **`device`** — enumerate cards, select card, set rate/period/buffer. Both platforms
  (ALSA+sysfs vs CoreAudio aggregate devices). `W136`'s `list_cards` /
  `select_card` / `set_audio_config` sketch is **not** Linux-specific; only
  `apply_overlay` / `load_module` are.
- **`system`** — reboot, status. Appliance-relevant, mostly Linux.

Each agent advertises the namespaces it carries as a capability. `W136`'s
`Applied | RequiresReboot | Refused(reason)` result triad is the common envelope.

## 3. Two axes: adapter family × platform backend

| Adapter | Portable Rust | Per-platform backend |
|---|---|---|
| **local hardware** | — | CoreAudio (`coreaudio-rs`/`cpal`) vs ALSA + sysfs |
| **LinkAudio** (`tactus`) | yes | — |
| **Dante** (inferno) | yes *(Linux-only for other reasons — §4)* | — |
| **AES67 / RTP, AVB, …** | yes | — |

**Only the local-hardware adapter has a platform backend.** Every network adapter is
portable Rust. Combined with §1, the Linux app is: one adapter + one privileged
executor + assembly.

**Local hardware is not symmetric with the others in one respect:** it is where the
clock actually lives. `A003` §2 settled "don't sync across families — receiver-side
ASRC", and `R003-F8`'s cascade says output → host hardware clock. Every network
adapter can free-run and resample; the hardware adapter is the *terminus* of that
cascade, because a DAC crystal is the real reference. **Carry this as a capability
flag on the adapter contract** rather than rediscovering it during `R010-F4`.

## 4. Inferno makes the Linux node strictly more capable

Per `R010-T5`, inferno is **Linux-only** (and experimental, dual GPL/AGPL). A Mac can
never be the native-Dante endpoint, so the Linux box is the natural **Protocol NAT /
gateway node** (`R010-F2`) for any mesh containing Macs. The Linux app is not a
lagging port; it unlocks a protocol family the Mac cannot reach. That is a reason to
build it earlier than "after macOS ships."

**Decision: consume inferno out-of-process (A004 §2's second tier), not in-tree.**

- **License.** GPLv3-or-later core can consume the GPL half of the dual license, but
  if any part is AGPL-only, in-tree use escalates IPAuRo — which *is* network
  software — to AGPL terms. Out-of-process, the question does not arise.
- **Patent, not spec.** `R010-T5` already records the wall as Audinate patent risk
  plus maturity, not spec absence. A sidecar isolates that exposure from the shipped
  core binary.

**`tactus`/`link-wire-rs` is consumed as a published dependency only.** We do not
contribute to it; shortcomings are raised as issues against **link-wire-spec**, which
is the correct venue.

## 5. noisetable is an out-of-process adapter

`A004` §2's two-tier locus was designed for exactly this case, and `R003-F7` names it:
an external app that both drives IPAuRo and adds its own protocol, over IPC, catching
no GPL. So noisetable's audio reaches Dante, LinkAudio, AES67, a Mac's CoreAudio or an
appliance's I2S DAC **without linking IPAuRo**, and without noisetable growing any
routing or machine-configuration code.

### The device-ownership question is forced, not chosen

noisetable's `W133` audio decision is `hw:` direct, no PipeWire/Pulse — and **`hw:`
access is exclusive**. One process holds the card. So the moment you want multi-device,
or network audio *and* local audio at once, two processes cannot both touch hardware:
one must own the devices and the other must be its client. `R095-T3` makes this
concrete by widening the appliance to many cards with nothing arbitrating between them.

**But IPAuRo is optional, and that split is by deployment:**

- **On the appliance image** IPAuRo is always present and always owns the devices, so
  it is genuinely the default there.
- **On a Mac or desktop**, noisetable keeps its direct-device path. Someone running
  noisetable standalone must not need a second daemon to hear sound, and `A111`'s
  boot-to-audio path must not gain a hard dependency on another process being healthy.

This is **one seam, two impls** inside noisetable — an `AudioBackend` with
`LocalDevice` and `IpauroClient` — not a fork. `A111` already anticipates it:
*"the `engine.tick()` interface is already OS-agnostic; only the callback frame
changes per platform."* IPAuRo is one more callback frame.

### Cycle participation, not a pipeline

For a node that is both router and DSP, a free-running SPSC ring costs one block
period **per crossing**, and the hub path crosses twice (network in → DSP → device
out). The contract is instead JACK's `process()` across a process boundary: IPAuRo's
device callback wakes noisetable, noisetable processes **in place**, signals done,
IPAuRo emits — one period, zero added latency. Stronger commitment than a ring: miss
the deadline and the whole graph xruns.

For lowest CPU cost:

- **Process in place**; no copy-in/copy-out. The network adapter's `ingest` writes
  once, into the buffer noisetable reads.
- **One wakeup per cycle** carrying a cycle descriptor (frame count, sample position,
  epoch, xrun flag) — not separate control and audio wakeups. ~750/sec at 64 frames /
  48 kHz.
- **futex/eventfd, not spinning.** Spinning buys single-digit µs and costs a whole
  core; wrong trade on four A53s with `isolcpus` already carving one or two.
- **Two legs, two disciplines:** PCM is cycle-coupled; impulses/params stay on a
  decoupled ring where lossy-and-late is fine. Recorded as scope on `R097-S4`.

### Block size: negotiate, don't bridge

vivarium's audio block is `quantum × CONTROL_DECIMATION` (16), and **Q is a free
parameter**, so the boundary needs no accumulator:

```
quantum = ipauro_period / CONTROL_DECIMATION
```

One engine tick *is* one IPAuRo cycle. **Constraint: the period must be a multiple of
16 and ≥ 16.** 32/64/128/256 fit; so do 48 and 96 (Q=3, Q=6). A non-multiple forces an
accumulator costing exactly the period that cycle participation exists to avoid — so
it belongs in the negotiation as a hard constraint, not a fallback.

Nodes declaring `min_block_size` (k > 1, e.g. plaits at k=8) need nothing: k is
relative to the engine block, which is now the cycle, so their inherent latency stays
a property of the graph.

**The requirement this creates: period change is a re-prepare event.** IPAuRo changes
period when devices change. That changes `audio_block_size`, hence
`k = ceil(min_block_size / audio_block_size)` for every declaring node, hence the
propagated k upstream. The backend needs a re-prepare + k-repropagation path; the cpal
path never exercises it, since the device period is fixed at stream open.

**Multiple devices ≠ multiple engine clocks.** In a hub with several devices at
different periods and rates, noisetable participates in exactly **one** cycle. Every
other device is reconciled by per-leg ASRC (`R010-F4`). The multi-device problem stays
inside IPAuRo and never reaches vivarium's block model.

## 6. The clock model — five layers, one authority each

Both projects had written down disjoint subsets of one model and called each "the
clock model."

| # | Layer | Question | Authority | Absent when |
|---|---|---|---|---|
| 1 | Device sample clock | when must buffers be filled | device owner (IPAuRo when present, else vivarium/cpal) | never |
| 2 | Frame counter | what sample position is "now", locally | same owner, published in the cycle descriptor | never |
| 3 | Media-clock reconciliation | how do I consume a stream on a foreign crystal | receiver-side ASRC, per leg (`R010-F4`) | no network audio |
| 4 | Wall-clock offset | how do I map a peer's timestamp onto my frames | **provider registry** — see below | no remote peers |
| 5 | Musical time | what beat is it | Link/tactus when a session exists; society transport state otherwise | never (degenerates to local) |

**Layer 4 is a provider registry, not a single owner.** Link's ghost transform is
*already* an NTP-shaped four-timestamp exchange (spec ch.02 §4), median-filtered over
100+ samples (§5), producing one session-wide ghost origin. Society's `society/clock/1`
is not complementary to it — on a segment with a Link session it is a second
implementation of the same thing. So: `LinkGhost{session_id}` where a session covers
the peer pair, `SocietyClock{room_authority}` otherwise. `A004` §2's
`CanonicalStream.clock.domain: ClockId` **already is** that registry; society's room is
just another `ClockId`.

**What keeps society's own exchange necessary is availability, not capability:**
session scope (a differing session id makes the mapping undefined, ch.03 §6.4); a
~300 ms RTT ceiling above which re-measurement starves **silently**; loss sensitivity
(~10% breaks most measurements) — so the clock is the first thing to break while beats
keep flowing; and multicast-only discovery. Plus one gap of our own: `tactus` keeps
`ghost_offset` on a private module, so the mapping is not reachable today — filed
upstream as [link-wire-spec#8](https://github.com/structuresound/link-wire-spec/issues/8).
Until that lands, `LinkGhost` as a layer-4 provider is blocked on the reference
implementation, not on the protocol.

**Tiering by peer kind (operator):** all noisetable nodes speak the best protocol we
have, so LinkAudio v1's limits bind only the **interop leg** (Ableton and other Link
software) — offset-only, slope fixed at 1, 30 s re-measure, ASRC mandatory. Between our
own nodes the protocol carries `est_rate_ppm` and a real epoch. LinkAudio is the most
widely useful protocol for interop; `tactus` is the track for improving on it.

**Layer 2 has a real gap on our side.** See §7.

## 7. Landed already (noisetable side, 2026-07-25)

Layer 2 had no single authority. `BananaEngine::frame_index` advanced per tick and was
reported outward; `AudioDomain::frame_index` advanced *separately* and is what nodes
actually see as `BlockCtx::frame_index`; and every `ContainerNode` had another, counting
from its own construction — while `ContainerNode::process` took `_ctx`, ignoring its
`BlockCtx` entirely. A node inside a container saw a different timeline from the same
node outside one, and it reset on every container rebuild.

Fixed: domains take the position from their caller and never advance one of their own;
the engine owns the single counter; containers thread `ctx.frame_index` inward. Dead
`AudioDomain::process_quantum` (zero callers) deleted. Test:
`test_domain_frame_index_is_caller_owned`.

**Still open:** no epoch and no cross-thread cycle descriptor. Nothing off the audio
thread reads sample position today, so publishing one now would be a capability with no
consumer. It should land with its first real consumer — the IPAuRo backend (§5) or
society's impulse envelope, whichever moves first. **No layer-4 work lands on anything
until that descriptor is real.**

## 8. Workstreams (to refine into tickets)

| WS | Scope |
|---|---|
| WS1 | **Linux privileged agent** — `app/agent` + `ipauro-net-linux` (nftables / ip-link / udhcpd); the M1 verb set behind the existing `HelperChannel`/`HelperRegistrar` traits. |
| WS2 | **Adapter contract extraction** — `ipauro-adapter` (A004's `ingest`/`emit` + `CanonicalStream`), with the clock-terminus capability flag; local-hw adapters for CoreAudio and ALSA. |
| WS3 | **`device` namespace** — absorbs noisetable `R103-F2`/`F3`/`T4` (sysfs enumerate, libkmod, configfs overlay, `BootConfig` trait + RPi backend). Requires an operator decision on moving those tickets across camps. |
| WS4 | **xlb-net binding** — replace `ipauro-mesh`'s commented-out raw `iroh` with xlb-net, so IPAuRo and noisetable share one Ed25519 machine identity and one QUIC endpoint. This is also what makes §6's two-provider clock registry implementable on one box. |
| WS5 | **noisetable audio boundary** — the cycle-participation contract, consuming `R097-S4`; Q negotiation, re-prepare on period change, the cycle descriptor. |
| WS6 | **inferno out-of-process adapter** — Dante via the second tier; Linux gateway / Protocol NAT node. |

**Sequencing note:** WS4 is small and unblocks both WS5's identity story and §6's
registry; it is the cheapest thing on this list to do early and the most expensive to
retrofit, since `ipauro-mesh` binding raw iroh first turns it into a migration.
