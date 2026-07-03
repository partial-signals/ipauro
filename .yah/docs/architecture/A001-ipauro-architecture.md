<!--
@yah:ticket(R002-T7, "IPC control facet v0: unix socket; snapshot-on-connect + ordered event stream + versioned commands; CLI reference client — UI client and external apps are the same surface")
@yah:at(2026-07-02T18:34:11Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("This is R003-F7's CONTROL facet pulled to P0 — with the brain now a service and the UI a thin client, the IPC API is the PRIMARY control surface from day one, not an extension afterthought. The service's desired-state store is the single source of truth; every client (our tray UI, a closed-source app, the CLI) is a commander/renderer kept in sync by snapshot+events. Design in from v0: protocol versioning, reconnect/resync, and the multi-client rule (N watchers; command arbitration TBD but the protocol must carry client identity). The stream facet (canonical streams, A004) stays later (R003-F7/R010).")
@yah:gotcha("Metering implication (egui UI, decided): realtime multi-stream meters need a HIGH-RATE binary telemetry channel beside the low-rate control/state stream — don't shove meter frames through the JSON event stream. Design the socket so a client can subscribe to telemetry separately (or via shm ring) without perturbing control traffic; the Control-Center-style client subscribes on panel-open and drops the subscription on close.")
-->

<!--
@yah:ticket(R002-T8, "Map the macOS 15 Local Network gate across execution contexts (root daemon / launchd user agent / bundled GUI app / SSH) and pin the brain service's placement")
@yah:at(2026-07-02T18:34:11Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("The tray-app design existed partly to HOLD the Local Network grant; moving the brain into a launchd service reopens the question. Apple's docs suggest out-of-session daemons may be exempt from the gate while user agents can be denied WITHOUT ever showing a prompt — do not trust documentation, verify empirically with the A002 method (BPF sees packet on wire vs app socket receives). Matrix: {root LaunchDaemon, user LaunchAgent in Aqua session, SMAppService agent, bundled GUI app, SSH-launched} x {prompt shown? granted? silently denied?}. Fallback if the agent can't hold the grant: delegate multicast-touching ops (gossip bootstrap beacon, forwarder) to a granted context (the UI client or a helper app). This gate first BITES at M2 (iroh local discovery) — but pin it at M0 while the spine is cheap to reshape.")
-->

<!--
@yah:ticket(R003-F9, "Air-gapped LAN bootstrap: peers learn NodeIds with no internet — multicast/broadcast beacon on the bridge; n0/relay discovery only when internet exists")
@yah:at(2026-07-02T18:34:11Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Chicken-and-egg the plan glosses: iroh-gossip needs at least one known peer, but iroh's default discovery (n0 DNS / pkarr relays) is internet-dependent, and its local-network discovery is mDNS multicast — exactly the traffic class this product manages, and itself subject to the Local Network gate (R002-T8). On a USB-only mesh the bootstrap must be an explicit beacon over the bridge (multicast or subnet broadcast on the appliance net), with internet-based discovery as an additive path, never a dependency. NodeId-derived addressing (R003-T3) gives you WHERE to dial once you know WHO exists; this ticket is the WHO.")
-->

<!--
@yah:ticket(R003-F8, "Sample-rate policy: gossiped mesh-consensus rate (default 48k, evangelized; raise whole-mesh only) + per-stream clock cascade (input->corresponding output; output->host; generic/fan-out->mesh rate)")
@yah:at(2026-06-28T05:21:04Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Rule: 48 kHz is the One Rate — default it, evangelize it, gossip it as a mesh-consensus value (sibling of NodeId addressing). Homogeneity makes the divergent-rate conversion problem evaporate. Raisable (e.g. 96k session) only by lifting the WHOLE mesh together, never two nodes diverging. Cascade governs only exceptions: (a) input -> match corresponding output; (b) output -> match host hardware clock; (c) generic external input OR fan-out with no single partner rate -> mesh rate. (a)+(b) chain so authority lands at the consuming hardware. CRITICAL distinction: nominal-rate agreement != clock drift — even at shared 48k, crystals drift ppm so R010-F4's ASRC still runs, but near-unity (cheap) not a 2x ratio. Caveat: 48k suffices only for HUMAN audiences; machine-listening/measurement/ultrasonic is the only reason to go higher and it's out of IPAuRo's lane.")
@yah:gotcha("Rate participation is CAPABILITY-based, never by protocol name (no type-name-sniffing): a stream participates iff it carries PCM samples (the canonical 'signal' payload). A pure-sync stream (classic tempo/phase sync, no samples) doesn't participate; an audio-carrying stream does — decided from the payload, NOT from whether the protocol is called 'Link'. (NB: 'Link Audio' may carry actual audio — outside the training corpus; confirm its real behavior with the project owner, don't assume sync-only.)")
-->

<!--
@yah:ticket(R003-F7, "IPC/RPC API over socket/port: external control (enrollment, roles, status) + canonical-stream exchange (mixing apps, out-of-process adapters) = the open extension surface; closed-source apps integrate + add protocols without catching GPL")
@yah:at(2026-06-28T04:32:03Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("This is the integration AND extension surface, validated by a real case: a CLOSED-SOURCE app that wants to (a) drive IPAuRo and (b) add its own new audio protocol. IPC is not linking, so the proprietary app catches no GPL. Two-tier adapters (A004): in-tree = GPL, joins the public registry/commons; out-of-process = a sidecar speaking the canonical stream model over this socket, ANY license, so a vendor extends IPAuRo without touching the GPL core. Split in practice: the CONTROL facet is PULLED TO P0 as R002-T7 (with the brain/face split it is the primary surface — our own UI client speaks it); this ticket keeps the STREAM facet (canonical-stream exchange — matures with the A004 model + R010). 'Speak every protocol' becomes community-extensible without copyleft coercion.")
-->

<!--
@yah:ticket(R010-T5, "Exit test: 4-node mesh (Link-only + AVB-only + Dante-only + polyglot gateway) all hear each other at ~8-16ch over 100BASE-T")
@yah:at(2026-06-28T03:56:49Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("'Dante-only' here means DANTE-IN-AES67-MODE (public RTP/PTPv2), a vendor sidecar over the plugin tier, or — pending R010-F8's evaluation — an INFERNO-backed plugin: a reverse-engineered FOSS Dante impl exists (github.com/teodly/inferno, dual GPL/AGPL, Linux-only, experimental), so the native-Dante wall is Audinate PATENT risk + maturity, NOT spec-absence. In-tree NDI stays walled (SDK license, no public spec). The two-tier adapter/plugin model is the designed answer; A004's 'classify one-by-one, done' does not repeal the proprietary-protocol wall. Also: hardware-runbook tier (macOS VMs cap at 2/host).")
-->

<!--
@yah:ticket(R010-F4, "Clock-domain bridge: reconcile Link / AVB-gPTP / Dante-PTP sync domains on a transcode leg (buffer+resample or slave to common ref) — the hard DSP half")
@yah:at(2026-06-28T03:56:49Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("Prior art (A003) settled the clock question: DON'T sync clocks across protocol families — use receiver-side ADAPTIVE RESAMPLING (JackTrip / zita-njbridge / SonoBus). PTPv1 / PTPv2 / gPTP are mutually incompatible (the wall the whole Dante/AES67 world hits); use a boundary-clock only where a specific leg demands hardware PTP. REUSE zita-njbridge's ASRC + a SonoBus-style adaptive jitter buffer — do NOT reinvent. NetJack's zero-packet-loss-tolerance is the explicit anti-pattern for our USB/WiFi/Bluetooth mesh.")
-->

<!--
@yah:ticket(R010-F3, "Stream queue/router core: propagate 1:1 / fan-in / fan-out; each fan-out leg independently passthrough or transcode")
@yah:at(2026-06-28T03:56:49Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("NO MIXING, ever — not even fan-in. Fan-in = route/aggregate multiple DISCRETE streams onto one leg, kept channel-discrete; NEVER sum samples. This app does not mix. A separate app may ask this one to expose I/O streams in various formats and do its own mixing downstream — that consumer boundary is how mixing stays out of scope. We are transport + format-adaptation + routing only; the mixer is someone else's app.")
@yah:gotcha("Reuse a proven resampling engine (zita-njbridge / JackTrip) for the media-plane transport rather than writing ASRC + jitter buffer from scratch (A003 §3). The queue/router is the orchestration; the resampling/buffering is borrowed.")
-->

<!--
@yah:ticket(R010-F2, "Gateway election: control plane elects a polyglot node as protocol-NAT for single-protocol islands (same shape as hub/peer election, one level up)")
@yah:at(2026-06-28T03:56:49Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
-->

<!--
@yah:ticket(R010-F1, "Per-node protocol capability advertisement over gossip (which protocols a node speaks + can translate between); extend registry with media format/packetization/clock per protocol")
@yah:at(2026-06-28T03:56:49Z)
@yah:status(open)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("The iroh control plane carrying per-node protocol capability IS the surpass over the predecessors (A003 §4): it fixes NetJack's 'identical software both ends + manual setup' and AES67's 'sneakernet SDP files around the facility'. Nobody in the prior art discovers capabilities ACROSS protocol families — that cross-family discovery is what makes Protocol NAT electable.")
-->

<!--
@yah:ticket(R004-F6, "Per-port x per-protocol enrollment matrix (opt-in/out/auto) as policy source of truth; pf generator = registry x matrix -> allow/block; ranking only resolves auto cells")
@yah:at(2026-06-28T03:41:59Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
@yah:gotcha("This is the product's core primitive (abstract-before-specific): 'opt WiFi out of Link' is ONE cell of a general per-(interface,protocol) matrix. Cells are opt-in / opt-out / auto. pf generator = registry x matrix -> per-(iface,proto) allow/block; opting a port OUT of a protocol = block that protocol's ports+groups on that iface. SUPPRESSION is first-class, not just preference — because Dante & kin bind FIRST-COME-FIRST-SERVE: two routes to a peer -> they lock to whichever announcement arrives first and stay, so a bad path is only fixable by removing the route from the protocol (matrix opt-out), never by preferring the good one. (Two routes on the SAME L2 domain = a loop = spanning-tree's job, R006; the matrix is per-interface route selection.)")
-->

<!--
@yah:ticket(R003-F6, "Control reachability of audio-segment-only nodes: iroh keeps a node addressable mesh-wide (presence gossip + control routing) with no internet path — beats Dante single-port-invisible failing")
@yah:at(2026-06-28T03:27:59Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Near-term, not a Later tier. A node reachable only over the audio segment (e.g. a single-Ethernet-port box) must stay addressable for control from off-segment nodes — iroh does this via presence gossip + control routing over any path. Full cloud-INTERNET egress (NAT through a peer that has internet) is the heavier piece that can wait; control reachability cannot.")
@yah:gotcha("Mechanism: a hub GOSSIPS each downstream/foreign node as a real next-hop-via-me and FORWARDS its plain control traffic upstream — the hub is a transparent control relay, not a media-only bridge. Concrete failing we design against: MTRX <=> AVB-D16 <=> Apple. The AVB-D16 (Dante/AVB media bridge) converts audio faithfully but DROPS plain IP, so the MTRX's control protocol never reaches the Apple though on a flat LAN they'd see each other. Preserve audio AND control, and advertise the route.")
-->

<!--
@yah:ticket(R006-F6, "Heterogeneous hub bridging: mix USB-NCM + TB/USB4-Ethernet (kernel bridge) and bring in WiFi/Bluetooth PAN as last resort (userspace forwarder; Classic BNEP PAN — no native IP-over-BLE on macOS) into one L2 domain")
@yah:at(2026-06-28T03:09:30Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
-->

<!--
@yah:ticket(R007-F7, "USB-layer blockage detection: accessory-approval gate (enumerates but no NCM enX) + charge-only/marginal cable (empty IOUSB both ends) — detect & report, don't spin")
@yah:at(2026-06-28T03:09:25Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R005-F7, "Robust USB-NCM interface identification: IOKit provenance (host AppleUSBNCMData) + device-side AppleUSBDeviceNCMData + traffic-based peer fallback; never MAC-match, skip anpi decoys")
@yah:at(2026-06-28T03:09:21Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R007-T6, "Resilience + telemetry hardening")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R007-T5, "Developer ID signing + notarization pipeline (also aids EDR pass-through)")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R007-F4, "Blockage as a first-class API state (clear actionable reason per node, over the IPC event stream; UI client + external apps render it)")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R007-T3, "Firewall + no-shared-subnet blockage detection")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R007-F2, "EDR detection (systemextensionsctl known bundle IDs): surface 'blocked by endpoint security, ask IT to allowlist'")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R007-F1, "Local Network privacy detection: packet-on-wire (BPF) vs app-never-receives")
@yah:at(2026-06-28T02:51:28Z)
@yah:status(open)
@yah:phase(P5)
@yah:parent(R007)
-->

<!--
@yah:ticket(R004-T5, "Demonstrate a non-Link protocol moved off WiFi onto USB/Ethernet (verification test)")
@yah:at(2026-06-28T02:51:22Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
-->

<!--
@yah:ticket(R004-F4, "Enrollment-matrix surface: per-port x per-protocol opt-in/out/auto over the IPC API + UI-client toggles (the 'enable this protocol on this port' / 'prefer this port for this' the OS never gives you)")
@yah:at(2026-06-28T02:51:22Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
-->

<!--
@yah:ticket(R004-F3, "Transport policy engine: bandwidth-aware ranking (TB/USB4-Ethernet 1/2.5G > ad-hoc USB-C NCM 480M > WiFi > Bluetooth PAN, user-overridable), emit per-protocol scope")
@yah:at(2026-06-28T02:51:22Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
@yah:gotcha("Ranking is NOT the source of truth — the enrollment matrix (R004-F6) is. The ranking only computes the DEFAULT for 'auto' cells; any explicit user opt-in/opt-out overrides it. USB-C NCM is the DEFAULT medium (480Mb/s, free, every Mac has the port) but NOT the top rank: a TB/USB4->Ethernet 1G/2.5GbE link beats ad-hoc USB-C when present. Rank by real bandwidth/quality, not bus type. WiFi then Bluetooth PAN are last-resort only. OPEN: native IP-over-Thunderbolt (multi-Gb/s, no dongle) is unranked — it is itself a bridge interface (bridge-in-bridge conflict with bridge90), investigate reclaiming its member links before placing it (W001 §8).")
-->

<!--
@yah:ticket(R004-T2, "Generalize pf transport-scope from single port to registry-driven rule generation")
@yah:at(2026-06-28T02:51:22Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
@yah:gotcha("pf scopes the AUDIO PROTOCOL's ports to the chosen wire (so audio can't leak to WiFi + behaves optimally) — it does NOT make the interface audio-exclusive. The same wire stays a normal addressable L3 entity carrying vanilla control + iroh unicast on the same L2 domain. 'Closed appliance' = no default route through it + audio-protocol-scoped, NOT 'no other traffic'. This is the fix for the single-port (Dante) failing where an audio port goes invisible for control.")
@yah:gotcha("The generator is mechanical: registry x enrollment-matrix (R004-F6) -> allow/block rules. A matrix opt-out for (iface, proto) emits 'block that proto's ports+groups on iface'. No per-protocol special-casing in code — it's all data from the registry + matrix.")
-->

<!--
@yah:ticket(R004-F1, "Protocol registry: {name, ports, multicast groups, discovery} for Link, AES67/RTP, Dante, mDNS")
@yah:at(2026-06-28T02:51:22Z)
@yah:status(open)
@yah:phase(P4)
@yah:parent(R004)
@yah:gotcha("Design this so a NEW protocol is data + a small adapter, never a core change — that cheapness IS the strategy (the 'AlphaFold era': exhaustive protocol coverage is now a choice, not heroic labor; W001 'Why now'). Registry holds declarative {name, ports, groups, discovery, media format/clock}; behavior comes from an adapter trait exposing the pass/sink/fan-in/fan-out/transcode verbs. Litmus: if protocol N+1 is more than ~a day's work, the abstraction is wrong. No per-protocol branching in core code (aligns with the repo's no-type-name-sniffing + abstract-before-specific rules).")
@yah:gotcha("Dimensional schema + the canonical 'superset' stream model live in A004 (audio-protocol taxonomy). Registry field set = the UNION of axes {transport, discovery, clock, channelization incl. ADM channel/object/scene, sample format/coding, packetization/mux, QoS, naming (indexed vs named), directionality, identity}. Each protocol is a PROJECTION of the canonical model; translate = ingest into union then emit as target's projection. Degrade rule: drop unsupported semantics, NEVER the signal (lossless LCD floor). ~80% of adapter plumbing already exists as Rust crates (rubato/rtp/statime/symphonia/cpal/coreaudio-rs/mdns-sd/tactus — never rusty_link/the Ableton SDK, see R005-F8).")
-->

<!--
@yah:ticket(R006-T5, "4+ node mixed-mesh integration test: redundant link survives hub loss")
@yah:at(2026-06-28T02:51:16Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
@yah:gotcha("Hardware-runbook tier, not the macOS-VM tier: Apple licensing caps macOS VMs at 2 per host, so a 4+-node mesh can't be virtualized on one machine (same constraint for R010-T5).")
-->

<!--
@yah:ticket(R006-F4, "Hub-loss survival: recompute spanning tree on topology change")
@yah:at(2026-06-28T02:51:16Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
-->

<!--
@yah:ticket(R006-T3, "Daisy-chain topology: interior node forwards between links and participates in Link")
@yah:at(2026-06-28T02:51:16Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
-->

<!--
@yah:ticket(R006-F2, "Userspace Link forwarder: repeat multicast per spanning tree + inject local node (hub-as-peer)")
@yah:at(2026-06-28T02:51:15Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
@yah:gotcha("TRAP: a forwarder that only repeats Link AUDIO multicast becomes an AVB-D16-style media-only bridge — it severs control for downstream nodes exactly like the MTRX<=>AVB-D16<=>Apple failing. The forwarder (or a parallel path, e.g. the kernel bridge / iroh) MUST also carry plain control + iroh traffic for nodes behind it, and the hub must gossip those nodes as real next-hops upstream. See R003-F6.")
-->

<!--
@yah:ticket(R006-F1, "Control-plane spanning tree: loop-free forwarding tree computed from iroh graph")
@yah:at(2026-06-28T02:51:15Z)
@yah:status(open)
@yah:phase(P3)
@yah:parent(R006)
-->

<!--
@yah:ticket(R003-T5, "Surface health/blockage + membership status over the IPC event stream (UI client + external apps render it)")
@yah:at(2026-06-28T02:51:09Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
-->

<!--
@yah:ticket(R003-F4, "Hub/peer role election over the IPC API (UI client renders it); roles propagate via gossip")
@yah:at(2026-06-28T02:51:09Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
-->

<!--
@yah:ticket(R003-T3, "Primary addressing: NodeId-derived address (IPv6 ULA / hashed IPv4), self-applied + gossiped — serverless, collision-free, replug-stable, no DHCP authority")
@yah:at(2026-06-28T02:51:09Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Deterministic NodeId-derived addressing replaces DHCP-as-default. The audio segment is a closed appliance net where the control plane already knows every member, so there's no host to discover and no gateway to learn — DHCP's value is moot and its costs (a stateful server, leases, electing an addressing authority, replug lease churn, accidental default-route injection) are pure downside. Address = f(NodeId) is collision-free and survives replug with no server. Link alone can run on IPv6 link-local; the ULA is for AES67/Dante + iroh-over-bridge.")
@yah:gotcha("'Collision-free' holds for the IPv6 ULA, NOT the hashed-IPv4 fallback: birthday math puts ~20 nodes in a /24 above 50% collision odds, so 'with collision check' is doing heavy lifting. The IPv4 path needs a deterministic resolution rule (e.g. lowest NodeId keeps the slot, loser re-hashes with an incremented salt, result gossiped) and the foreign-DHCP pool (R005-T6) kept disjoint from the hash range. And since Dante/AES67 are IPv4-only, the IPv4 path is the MAIN path once M4 protocols arrive — not an afterthought.")
-->

<!--
@yah:ticket(R003-F2, "iroh-gossip membership: peers auto-discover and join the session")
@yah:at(2026-06-28T02:51:09Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
-->

<!--
@yah:ticket(R003-F1, "iroh NodeId identity (ed25519) + node bootstrap")
@yah:at(2026-06-28T02:51:09Z)
@yah:status(open)
@yah:phase(P2)
@yah:parent(R003)
-->

<!--
@yah:ticket(R005-T6, "DHCP as ingestion adapter for foreign (non-IPAuRo) devices only: control-plane-allocated address, NO gateway option, gossip the assignment; cope with link-local self-assign")
@yah:at(2026-06-28T02:50:51Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
@yah:gotcha("DHCP is NOT network infrastructure here and nobody depends on one node for it. It is ONLY for ingesting a foreign (non-IPAuRo) device plugged into a hub. Even then the hub is not an authority: the CONTROL PLANE allocates the address (so two hubs can't collide), the hub's local responder just delivers it with NO router/gateway option (never makes the audio segment a default route), and the assignment is gossiped so the foreign leaf becomes addressable mesh-wide. If the leaf only self-assigns link-local and won't lease, cope/map it.")
@yah:gotcha("Implementation: an IN-PROCESS DHCP responder, NEVER /etc/bootpd.plist — bootpd's config is shared with Internet Sharing and macOS updates fight over it (the prototype's enable-dhcp.sh is PoC-only). Verify ON THE WIRE that no router/gateway option is emitted; keep the lease pool disjoint from the NodeId hash range (R003-T3).")
-->

<!--
@yah:ticket(R005-T5, "Port pf transport-scope (load/flush/restore; pf off before bridge rebuild) into helper — anchor-based, never whole-ruleset replace")
@yah:at(2026-06-28T02:50:49Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
@yah:gotcha("Do NOT port pf-prefer.sh literally: the PoC replaces the ENTIRE ruleset (clobbering Apple's com.apple/* anchors and any VPN/firewall rules) and flushes ALL states globally (-F states kills other software's connections). The helper uses a dedicated ANCHOR (pfctl -a ipauro) spliced into the existing ruleset, and SELECTIVE state kill (pfctl -k on the scoped port/addresses). The shell script is the spec for the cut-and-restore BEHAVIOR (incl. the stateful-pf flush discipline), not for the mechanism.")
-->

<!--
@yah:ticket(R005-T4, "Port bridge discovery + member reconcile (usb-link-bridge.sh) into helper")
@yah:at(2026-06-28T02:50:46Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R005-F3, "Desired-state reconciler core in Rust: idempotent + ordered actual->desired passes")
@yah:at(2026-06-28T02:49:27Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R005-T2, "Replug self-heal end-to-end: member unplug -> rebuild + app-rebind (M-incident test)")
@yah:at(2026-06-28T02:49:08Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R005-F1, "IOKit USB attach/detach watch in app drives event-driven reconcile")
@yah:at(2026-06-28T02:49:08Z)
@yah:status(open)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R002-T6, "Start-at-login: brain service registered via SMAppService; the checkbox lives in the UI client over IPC")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
-->

<!--
@yah:ticket(R002-F5, "Fail-open on XPC disconnect: helper restores stock networking on service death (with restart grace)")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("Fail-open keys on the BRAIN SERVICE's XPC connection, never the UI client — UI quit/crash/upgrade must not touch the mesh (that's the point of the brain/face split). Add a short grace window so a service restart or upgrade doesn't needlessly tear down and rebuild the mesh mid-session; the grace still fails open if no reconnect arrives.")
-->

<!--
@yah:ticket(R002-F4, "Helper bridge90 create/destroy over XPC; wire tray button")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
-->

<!--
@yah:ticket(R002-T3, "XPC channel service<->helper: narrow, validated, caller-authenticated command API")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("'Validated' means AUTHENTICATE THE CALLER, not just the message schema: verify the connecting process's code signature via its audit token (SecCodeCopyGuestWithAttributes), require same team ID + a minimum version, reject everything else. An unauthenticated root-helper Mach service that rewrites pf and creates bridges is a classic macOS local-privilege-escalation shape (the Docker vmnetd CVE class). Version the XPC protocol from day one — app and helper upgrade on different schedules.")
-->

<!--
@yah:ticket(R002-T2, "SMAppService root helper daemon: register + one-time install auth dialog")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(open)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("Developer ID signing must be stood up HERE (M0), not M5: SMAppService registration effectively requires a properly signed app bundle with the helper embedded (Contents/Library/LaunchDaemons plist + bundle-program requirements). R007-T5 at P5 is only the final notarization/distribution polish, not the first time code gets signed.")
-->

<!--
@yah:ticket(R002-T1, "Scaffold Rust workspace: brain service (launchd-managed) + SMAppService helper + compact egui tray client")
@yah:assignee(agent:fable-manager)
@yah:at(2026-06-28T02:49:00Z)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("UI framework DECIDED (2026-07-02): egui. UX model = Apple Control Center — a transient panel opened from the tray to observe/tweak, then closed; or left up as a compact always-on metering widget. Immediate mode fits exactly this: closed window = zero cost, open window = animating meters anyway (GPU-rendered, telemetry straight off the IPC socket — see R002-T7's telemetry-channel gotcha). egui has no native tray — pair with the tray-icon crate family. The client is STATELESS: everything it shows comes over IPC, so it must be able to open mid-session and render from snapshot instantly.")
@yah:gotcha("Design debt accepted knowingly: egui is 'less designy' OUT OF THE BOX — the stock theme reads as dev-tool, and a Control-Center-style surface lives on polish. A real theming pass is COMMITTED, not optional: custom Style/Visuals (spacing, corner rounding, palette), deliberate font choices, bespoke meter widgets. Scaffold on the stock theme, but never ship it; treat the theming pass as part of the UI client's definition of done, not a nice-to-have.")
-->

# IPAuRo Architecture — control/data plane, topology, reconciler

**Status:** Design canon (pre-implementation; data plane proven on hardware via the shell `prototype/`).
> **Note:** this doc predates several 2026-06-28 design decisions now in **W001** (the per-port×
> per-protocol enrollment matrix, appliance-net addressing, the control-relay/next-hop rule,
> Protocol NAT, the 48 kHz sample-rate policy, the IPC/RPC + two-tier-adapter model, and the GPLv3
> license), **and the 2026-07-02 brain/face split**: the desired-state brain is now a
> launchd/systemd *service*, and the tray UI is a thin, stateless client of the IPC API — Thread
> 2's "tray app holds the brain" table below is superseded (the grant/IOKit/iroh rows move to the
> service, pending R002-T8's grant-context validation). Where this doc and W001 differ, **W001
> wins.** Read W001 first.
`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` — empirical base.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)` — M0–M5 roadmap.

Companion to [A002-ipauro-findings.md](A002-ipauro-findings.md). Two concrete threads to pursue next.
Status as of 2026-06-27: relay↔Air (clean Macs) fully proven — USB-NCM link, Link
discovery/sync over USB, and `pf` transport-scoping (with state flush) all validated on
real hardware. Corp (CrowdStrike Falcon) confirmed blocking Link at the EDR flow layer.

---

## Thread 1 — 3-node session with the "Falcon" machine — SOLVED (2026-06-27)

**RESOLVED: yes, it works.** All three Macs (relay + Air + Corp) reached `peers 2` in a
fully-meshed Link session over USB. **Falcon was NOT the blocker** — see the corrected
findings-doc section. The real cause was **macOS 15 Local Network privacy denying the
SSH-launched hut**; launching it from Corp's GUI Terminal (which holds the Local Network
grant) fixed it instantly. Lesson banked: Link must run in a Local-Network-permitted GUI/agent
context on macOS 15+; never blame a visible EDR before ruling out OS permission + launch
context. The experiments below are retained only as the general method for *if* a real EDR
block is ever encountered.

### (Historical) What we thought we knew
- Corp's CrowdStrike Falcon (`NEFilterDataProvider`) **drops Link's inbound UDP at the
  socket/flow layer.** Proven: packets arrive at `en4` (tcpdump/BPF, below the filter) but the
  app never receives them; app firewall was off; kernel ICMP passes. See findings doc.
- **No client-side networking trick fixes a flow-layer EDR drop.** Bridge topology is
  irrelevant: even member↔member multicast (which floods fine) still lands on Corp's NIC and
  is then dropped by Falcon before the app. The block is *on Corp*, independent of how it's
  wired.
- Therefore: as-is, **Corp cannot be an audio-transport peer.** A 3-node Link session
  including Corp is not achievable without changing Corp's policy.

### Experiments to run (cheap → expensive) — determine if it can EVER work without IT
1. **Signed + notarized binary.** Falcon app-control often keys on code signature / reputation.
   Build the Link app with a Developer ID signature + notarization and test on Corp. If a
   signed binary's flows pass, signing is the unlock (and we need it anyway — see Thread 2).
   *Likely partial:* signature may satisfy app-control but a network-firewall policy can still
   block by port/destination regardless of signer.
2. **Unicast vs multicast.** Re-test whether Falcon drops only multicast (`224.76.78.75`/
   `ff12::8080`) or all `udp/20808`. If unicast survives, a discovery shim that seeds peers
   out-of-band (via the iroh control plane) and runs Link peer-to-peer on unicast *might* slip
   through. Test by sending a unicast `udp/20808` from the relay to Corp and watching whether
   the app receives it.
3. **Outbound check.** Confirm whether Corp can SEND Link (does the relay see Corp's
   `udp/20808` egress?). If outbound is also blocked, even a one-way-fixed path is dead.

### Verdict / fallback design
- **The legitimate fix is organizational:** Corp's IT allowlists the app (signature) and/or
  the port/interface in the Falcon policy. Pursue this if Corp genuinely needs to be in the
  mesh. **Do NOT attempt to disguise/tunnel audio traffic to evade the EDR** — that's
  circumventing a corporate security control on a managed device.
- **Architectural fallback (do this regardless):** represent EDR-blocked nodes as a
  first-class state — *"in the mesh (control plane reachable) but audio-transport blocked by
  endpoint security."* The control plane (iroh, over normal allowed networking) can still see
  Corp; the data plane can't carry its audio. The app should detect this
  (`systemextensionsctl list` for known EDR bundle IDs) and surface it instead of silently
  failing. A 2-node clean session + a visible "Corp blocked by Falcon — ask IT to allowlist"
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
