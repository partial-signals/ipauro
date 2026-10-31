<!--
@yah:ticket(R003-B10, "Peer-role nodes get no mesh address: T3 aliases are applied only on the hub bridge (bridge90); a peer must self-apply its NodeId-derived address on its uplink interface(s)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T23:39:49Z)
@yah:parent(R003)
@yah:severity(high)
@yah:depends_on(R003-T5)
@yah:handoff("Peer self-addressing done. Proto: AddBridgeAlias/RemoveBridgeAlias -> AddAlias{iface,addr,prefix}/RemoveAlias{iface,addr} (renamed, not additive: helper+core ship as one bundle, stale helper caught by the Ping build_version compare); DataPlaneReport.uplink_aliases (serde default); BootstrapStatus.beacons (default), BlockCause::BeaconWaitingForUplink, Remedy::ConnectUplink (additive).")
@yah:handoff("Helper: BridgeExecutor aliases/add_alias/remove_alias take iface + new uplink_candidates() (en[0-9]+, exists, not a bridge member, not a default-route interface via /sbin/route). request.rs validate_alias_iface accepts BRIDGE_NAME or a verified candidate before any exec; class/prefix gates unchanged. Uplink aliases are read by mesh class (not position) via AliasScope.")
@yah:handoff("Core: LinkInventory::uplinks() = Host+Device links (UsbLink::uplink_eligible, never Internal; no name sniffing). Desired<'a>.site: AddrSite::{Bridge, Uplinks(&[String])}; Peer derived from role. Peer plan: teardown first, then per-uplink strip-of-owned-stale then add. Ownership = PrimaryAddrs::owns (mesh ULA /48 + IPv4 hash range) so the segment's DHCP lease/user addresses are never stripped. Peer->Hub strips owned uplink aliases before SetBridgeMembers. New Facet::Uplink; AddAlias blocked_by Bridge.")
@yah:handoff("Beacon: BridgeBeacon -> InterfaceBeacon over a shared BeaconTargets set; per-interface bind/health, peers unioned+deduped. mesh_status::beacon_targets(role, inventory) (Hub=bridge90, Peer=uplinks) rewritten each sync; MeshStatus bootstrap.beacons carries per-interface status, aggregate beacon unchanged in meaning. Peer remedy changed ElectHubRole -> ConnectUplink.")
@yah:handoff("Tests: workspace 563 passed / 0 failed (baseline 527) with --no-fail-fast; one earlier run flaked ipauro-iroh/tests/control_relay (F6 area) and passed on rerun. clippy: only the known 2 result_large_err + large_enum_variant, plus 1 too_many_arguments in iroh gossip.rs (F6's file, not mine).")
@yah:verify("cargo test --workspace --no-fail-fast (563/0)")
@yah:verify("cargo clippy --all-targets -p ipauro-proto -p ipauro-core -p ipauro-helper -p ipauro-iroh")
@yah:verify("OWED FIELD VERIFICATION (hardware): on a real Peer Mac, `ifconfig enN inet6 <ula> prefixlen 64 alias` and `inet <v4> netmask 255.255.0.0 alias` apply on the USB-NCM uplink; replug re-applies; role flip hub<->peer moves the address cleanly; helper refuses the default-route NIC; real `route -n get default` output parses; beacon announces on the uplink and a hub hears it.")
@yah:gotcha("Discovery identifies USB-NCM only: Thunderbolt-bridge and plain Ethernet uplinks are NOT in LinkInventory::uplinks(), so a Peer on those gets no address/beacon until discovery covers them.")
@yah:gotcha("Helper uplink trust = shape + exists + non-member + not default-route NIC. A user's secondary Wi-Fi/Ethernet that is not the default route would pass the helper check; the core only ever asks for its inventory uplinks, but the helper has no IOKit provenance check.")
@yah:gotcha("v4 beacon broadcast (10.42.255.255) is routed by the kernel, so with two uplinks only one carries it; v6 multicast is per-interface.")
-->

<!--
@yah:ticket(R005-T10, "M1 field-findings hardening (from the 2026-07-04/05 single-Mac verification)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-07-26T22:14:14Z)
@yah:phase(P1)
@yah:parent(R005)
@yah:gotcha("Four findings from live single-Mac M1 verification, each reproduced: (1) STALE HELPER AFTER UPGRADE: launchd keeps the resident helper process across a bundle replacement, so new verbs bounce off the old daemon (observed: M0 helper rejecting M1 verbs) until registration is cycled. Fix: core compares Pong version vs its own and bounces registration automatically on mismatch. (2) PORT-67 DIAGNOSIS: 'binding :67' must become 'another DHCP server holds port 67 (bootpd / Internet Sharing?)' — launchd socket-activation holds *.67 when bootps is enabled (the prototype's enable-dhcp.sh left it loaded -w). Blockage-as-first-class, R007 philosophy arriving early. (3) CONTINUE-ON-ERROR PLAN EXECUTION: a ServeDhcp failure aborted the whole pass, leaving scope unapplied though scoping is independent of DHCP; executor should attempt independent steps and report partial convergence. (4) HELPER-STATE FRESHNESS: snapshot showed 'registered (not connected)' while requests were flowing — only the boot ping ever sets Connected; any successful helper request should refresh it.")
@yah:handoff("(1) STALE HELPER: new ipauro_core::helper_link::SupervisedHelper wraps HelperChannel, compares the helper's Pong build against ipauro_core::build_version(), and cycles registration on mismatch (once per distinct stale build, never in a loop).")
@yah:handoff("(1b) The compare needed a real per-build signal: packaging/lib/common.sh now stamps IPAURO_BUILD_ID (git sha + dirty + epoch) which both ipauro-core and ipauro-helper compile into build_version(). The workspace version is 0.0.1 for every build of every milestone, so version-vs-version alone could never have caught the observed M0-helper case. Confirmed cargo tracks the option_env! var and rebuilds.")
@yah:handoff("(2) PORT-67: app/helper/src/dhcp/server.rs::describe_bind_failure turns EADDRINUSE into a diagnosis naming the holder (confirmed by new cmd::job_is_loaded -> launchctl print system/com.apple.bootpd) plus the exact reversal (launchctl unload -w /System/Library/LaunchDaemons/bootps.plist). PermissionDenied gets its own root-vs-port message.")
@yah:handoff("(3) CONTINUE-ON-ERROR: reconcile::drive_once attempts every step whose prerequisites hold (Facet / blocked_by / StepFailure / Pass::failures), refreshes the store from a fresh Report either way, and reports partial convergence. A dead channel (HelperNotConnected) still aborts. Load-bearing rules: bridge-naming verbs wait on the bridge step, and DestroyBridge waits on the scope teardown (A002 s4 - a scope outliving its bridge blocks the port host-wide).")
@yah:handoff("(3b) Bonus correctness found on the way: bridge.epoch now bumps only on a CreateBridge that SUCCEEDED, not on one that was merely planned.")
@yah:handoff("(4) HELPER-STATE FRESHNESS: liveness is observed on every exchange (a helper Err counts as live - it proves the helper is there). A channel failure clears the cached identity, which re-arms the staleness check of (1) on the next reconnect - exactly the upgrade shape. New StateStore::mutate_if_changed keeps the per-request refresh off the event stream when nothing changed.")
@yah:handoff("Docs: A002 gained an 'M1 single-Mac verification (2026-07-04/05)' section recording all four findings, the fix site, and the named test for each (plan s9: every failure mode becomes a named test case).")
@yah:verify("cargo test --workspace - 18 suites green, 0 failures; re-run under IPAURO_BUILD_ID=probe-epsilon to prove the suite is build-stamp agnostic")
@yah:verify("cargo clippy --workspace --all-targets - clean")
@yah:verify("New tests: helper_link::tests::* (8), reconcile::tests::a_refused_{dhcp,bridge}_* / a_refused_scope_teardown_leaves_the_bridge_standing / a_dead_channel_still_aborts_the_pass, dhcp::server::tests::port_in_use_*, state_store::tests::mutate_if_changed_broadcasts_only_a_real_change, integration::a_command_that_reached_the_helper_reports_it_connected")
@yah:verify("Field re-verification still owed on hardware: bounce the installed bundle and confirm the stale helper is actually cycled (SMAppService cannot be exercised outside a signed bundle).")
@yah:next("PROTO REQUEST 1 (manager-owned ipauro-proto): give build_version() a home there. It is currently duplicated byte-for-byte in ipauro-core and ipauro-helper because both must produce the identical string and neither may edit the proto crate.")
@yah:next("PROTO REQUEST 2 (manager-owned ipauro-proto): ReplyOutcome has no way to say 'partial'. A partially-converged pass replies Err (carrying no snapshot) even though the store was refreshed and subscribed clients got the new snapshot on the event stream. A ReplyOutcome::Partial { snapshot, errors } would let a one-shot CLI client see both.")
@yah:next("Operator decision worth knowing about: the automatic stale-helper bounce unregisters the daemon, so the helper's fail-open grace window restores stock networking (brief data-plane drop) and registration can land in RequiresApproval. Right trade for a helper that cannot service current verbs, but it is a visible behaviour change.")
-->

<!--
@yah:ticket(R002-T7, "IPC control facet v0: unix socket; snapshot-on-connect + ordered event stream + versioned commands; CLI reference client — UI client and external apps are the same surface")
@yah:at(2026-07-02T18:34:11Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("This is R003-F7's CONTROL facet pulled to P0 — with the brain now a service and the UI a thin client, the IPC API is the PRIMARY control surface from day one, not an extension afterthought. The service's desired-state store is the single source of truth; every client (our tray UI, a closed-source app, the CLI) is a commander/renderer kept in sync by snapshot+events. Design in from v0: protocol versioning, reconnect/resync, and the multi-client rule (N watchers; command arbitration TBD but the protocol must carry client identity). The stream facet (canonical streams, A004) stays later (R003-F7/R010).")
@yah:gotcha("Metering implication (egui UI, decided): realtime multi-stream meters need a HIGH-RATE binary telemetry channel beside the low-rate control/state stream — don't shove meter frames through the JSON event stream. Design the socket so a client can subscribe to telemetry separately (or via shm ring) without perturbing control traffic; the Control-Center-style client subscribes on panel-open and drops the subscription on close.")
-->

<!--
@yah:ticket(R002-T8, "Map the macOS 15 Local Network gate across execution contexts (root daemon / launchd user agent / bundled GUI app / SSH) and pin the brain service's placement")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-07-26T02:16:40Z)
@yah:phase(P0)
@yah:parent(R002)
@yah:next("TWO MATRIX ROWS NOT RUN, both by environment limit, NEITHER changes the decision (the agent rows already came back open, and W001 requires the brain to be unprivileged regardless). (a) ROOT LAUNCHDAEMON — needs an operator sudo password; ready-to-paste commands + plist are in crates/ipauro-probe/RUNBOOK.md, and crates/ipauro-probe/dev/*.plist now pass --iface en0 so the row comes back wire-confirmed. (b) OVER SSH — needs a key in authorized_keys; deliberately not added to the operator's machine. Remember row (b) measures sshd's grant, not the binary's.")
@yah:next("CONFIRMATION STILL OWED AT M2, tracked as a gotcha on R003-F9: ipauro-core has never sent a multicast packet, so its registry entry is permissive by never having been exercised rather than by having been exercised and permitted. R003-F9's bootstrap beacon is the first code that makes it send one — run `ipauro-probe grants --filter ipauro` then and confirm the decision records against io.ipauro.app / io.ipauro.core.")
@yah:next("RE-RUN THE MATRIX on a managed/MDM Mac before shipping — MDM can preset these decisions, and the reference host is an unmanaged personal machine.")
@yah:handoff("MEASURED + PINNED (2026-07-25, macOS 26.5.1 / 25F80, single Mac, en0 on a home LAN). DECISION: the brain service STAYS an unprivileged user LaunchAgent (io.ipauro.core) inside the signed bundle, registered via SMAppService. The feared failure mode did NOT occur — a brand-new, never-seen, ad-hoc-signed LaunchAgent in gui/501 got full wire-confirmed bidirectional multicast on Link's own group/port with NO prompt, and macOS recorded an unprompted ALLOW for it. Developer ID signing and bundle embedding changed the recorded identity, not the outcome. The W001 fallback 'delegate multicast-touching ops (gossip beacon, forwarder) to a granted context' is DROPPED — do not build it.")
@yah:handoff("INSTRUMENT UPGRADED (crates/ipauro-probe). `check` now runs BOTH legs of the A002 method itself — the process socket AND a /dev/bpf tap on the egress interface — because a socket-only probe cannot falsify its own 'gate open': in-kernel multicast loopback can satisfy the socket leg while nothing leaves the machine. New verdicts/exit codes: 0 GATE OPEN · 4 DENIED(inbound) · 5 DENIED(outbound) · 6 LOOPBACK ONLY · 1 INCONCLUSIVE. New --tap-iface watches a different interface than we beacon out of; that is the discriminator between real egress and a loopback copy (XNU routes the loopback copy via lo0 — measured: 9 on an en0 tap AND 9 on an lo0 tap, different copies). Off-path taps are reported unavailable-for-egress, never misread as suppressed egress. Wire tap needs /dev/bpf (root or access_bpf group) and degrades gracefully to the socket-only verdict marked UNCONFIRMED.")
@yah:handoff("FOUND THE AUTHORITATIVE REGISTRY. macOS records local-network posture per code identity in /Library/Preferences/com.apple.networkextension.plist (world-readable NSKeyedArchiver; MulticastPreferenceSet = a decision exists, DenyMulticast = the decision). New `ipauro-probe grants [--filter X] [--denied-only]` reads it. CRITICAL semantics: `unset` is NOT `denied` — it is the permissive default (236 of 263 records on this host are unset with traffic flowing normally). R007-F1 must not fold those two states together.")
@yah:handoff("IDENTITY ATTRIBUTION MODEL (this invalidates a class of test). A binary run from a shell gets NO registry identity of its own — it is attributed to the responsible app (our shell runs went to dev.yah; target/release/ipauro-probe never got an entry). So running the probe from Terminal or over SSH measures TERMINAL's or SSHD's grant, not the binary's; those are rows about the parent app. Only a launchd job has an independent identity: a bare executable is keyed by signing-identifier + path, and a bundle-embedded job with AssociatedBundleIdentifiers is keyed by the BUNDLE id with no path.")
@yah:handoff("DISCOVERED + FIXED IN THIS PASS (packaging, not just noted): the grant binds to the CODE-SIGNING IDENTIFIER, and codesign derives that from the filename when not told otherwise — so ipauro-core was signing as the bare, unnamespaced identifier `ipauro-core`. That is the name the user's grant binds to and the name System Settings shows. packaging/lib/common.sh now has codesign_identifier_for() and packaging/build-app.sh signs each embedded executable with an explicit --identifier matching its launchd label (io.ipauro.core, io.ipauro.helper, io.ipauro.app.cli) and ASSERTS it landed, failing the build on drift. Safe wrt XPC caller auth, which pins the TEAM ID only (ipauro_proto::helper::peer_requirement), never a signing identifier — verified before changing. Bundle rebuilt + packaging/verify.sh OK.")
@yah:handoff("DOCS: A002 gains 'Local Network gate — execution-context matrix, measured (R002-T8)' (full matrix, method, identity model, and an explicit limits section). W001 §4 brain-service bullet and §8 risk bullet updated to the pinned decision + narrowed residual risk. A001's superseded-note updated (Thread 2's 'only a GUI app can hold the grant' is now obsolete). crates/ipauro-probe/RUNBOOK.md substantially rewritten: matrix filled, two-command method, exit-code table, identity-attribution table, and a correction — the old runbook said wire-silence means 'not a privacy-gate issue, look at routing', but wire-silence after a successful sendto is exactly the OUTBOUND denial signature.")
@yah:handoff("VERIFIED: cargo test -p ipauro-probe 59 passed (was 42); full workspace build + tests green; cargo clippy -p ipauro-probe --all-targets clean; cargo fmt applied. Live end-to-end re-run after fmt still GATE OPEN wire-confirmed. `grants` output cross-validated against an independent Python extractor — identical counts (263 records, 27 allowed, 236 unset, 0 denied).")
@yah:verify("cargo test -p ipauro-probe  # 59 tests, incl. pinned macOS BPF ioctl encodings and the NSKeyedArchiver walk")
@yah:verify("cargo clippy -p ipauro-probe --all-targets  # clean")
@yah:verify("./target/release/ipauro-probe check --seconds 8 --iface en0  # expect exit 0, 'wire-confirmed'")
@yah:verify("./target/release/ipauro-probe check --seconds 4 --iface en0 --tap-iface awdl0  # off-path tap must report unavailable-for-egress, NOT 'egress suppressed'")
@yah:verify("./target/release/ipauro-probe grants --filter ipauro  # io.ipauro.app must not be DENIED")
@yah:verify("bash packaging/build-app.sh && bash packaging/verify.sh  # identifier assertions must pass: io.ipauro.core / io.ipauro.helper / io.ipauro.app.cli / io.ipauro.app")
@yah:gotcha("ORIGINAL PREMISE, NOW DISPROVED ON macOS 26.5.1 (kept for the record): 'Apple's docs suggest out-of-session daemons may be exempt from the gate while user agents can be denied WITHOUT ever showing a prompt.' Measured: user agents are NOT denied — they are auto-allowed unprompted. The fallback this ticket sketched (delegate multicast ops to a granted context) is dropped; do not build it.")
@yah:gotcha("DO NOT OVERREAD THIS RESULT. No denial was observed anywhere on the test host (0 of 263 registry records), so the run demonstrates the AUTO-GRANT path and does NOT demonstrate that the detector catches a live denial on macOS 26 — the negative case still rests on A002's macOS 15 SSH finding. The wire leg's ability to report a true zero IS independently shown (off-path tap → 0). Single host, single OS version, already-logged-in session; boot-before-login and fast-user-switch are untested; a managed/MDM Mac may differ. A002's limits section is the canonical list — read it before relying on this.")
@yah:gotcha("LEFT ON THE OPERATOR'S MACHINE (harmless, but you should know): the launchd matrix rows each recorded a permanent entry in the user's Local Network privacy list, keyed by signing identifier + path. Booting the job out does NOT remove them. Currently present: `ipauro_probe-e5fc80dc07c5a537` and `ipauro-probe-agent-devid` (both → /private/tmp/r002-t8/...), plus `io.ipauro.probetest` from the throwaway test bundle. All three point at /tmp paths that no longer matter. The real `io.ipauro.app` entry was deliberately NOT touched — the test bundle was given its own CFBundleIdentifier precisely so a throwaway artifact could not record a grant for the shipping product. All three probe LaunchAgents were booted out and their plists deleted; io.ipauro.core (the real agent) was verified still running and untouched.")
-->

<!--
@yah:ticket(R003-F9, "Air-gapped LAN bootstrap: peers learn NodeIds with no internet — multicast/broadcast beacon on the bridge; n0/relay discovery only when internet exists")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T22:04:07Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Chicken-and-egg the plan glosses: iroh-gossip needs at least one known peer, but iroh's default discovery (n0 DNS / pkarr relays) is internet-dependent, and its local-network discovery is mDNS multicast — exactly the traffic class this product manages, and itself subject to the Local Network gate (R002-T8). On a USB-only mesh the bootstrap must be an explicit beacon over the bridge (multicast or subnet broadcast on the appliance net), with internet-based discovery as an additive path, never a dependency. NodeId-derived addressing (R003-T3) gives you WHERE to dial once you know WHO exists; this ticket is the WHO.")
@yah:gotcha("R002-T8 LAST MILE LANDS HERE (settled 2026-07-25): R002-T8 measured the Local Network gate and PINNED the brain at an unprivileged user LaunchAgent — a user agent DOES hold the multicast grant on macOS 26.5.1 (wire-confirmed, no prompt), so the old 'delegate multicast-touching ops to a granted context' fallback is dropped; do NOT build it. BUT ipauro-core has never actually sent a multicast packet, so its registry entry is permissive only by never having been exercised. THIS ticket is the first code that makes it send one. When the beacon works, run `ipauro-probe grants --filter ipauro` and confirm a decision records against io.ipauro.app / io.ipauro.core and is not DENIED — that closes R002-T8's one open thread. Note `unset` is NOT `denied` (it is the permissive default); only an explicit DenyMulticast is a denial. Full method + limits: A002 'execution-context matrix, measured (R002-T8)'.")
@yah:depends_on(R003-F2)
@yah:handoff("New crates/ipauro-iroh/src/beacon.rs. Constants live ONCE in ipauro-proto registry: new IPAURO_BEACON entry (udp 20818, v6 group ff02::6970:6175 = ASCII 'ipau', v4 = subnet broadcast so multicast_v4 empty) plus registry::ALL for data-driven consumers. NOTE: reconcile.rs still scopes only registry::LINK; nothing in the pf scope generator reads ALL yet, so IPAURO_BEACON is registered but not yet consumed by a pf generator (R004 owns that). v4 broadcast = appliance_broadcast_v4() derived from Ipv4Config::appliance_default (10.42.255.255).")
@yah:handoff("Beacon wire: [v1][pubkey32][ed25519 sig64][NodeId8|mesh_id|addrs], domain-separated signature, receiver requires NodeId == mesh_node_id(pubkey) and same mesh_id; <=8 addrs, 1200B cap. Receiver dials advertised addrs AND (datagram source ip, advertised port). Rate-limited send (burst of 4 @250ms on start, then 3s +<=25% jitter, never closer than burst interval; a newly-learned peer triggers an immediate reply), own beacon ignored, table bounded (256, stalest evicted) with 15s TTL. Replays can only refresh a real peer's own addrs (no timestamp: offline clocks unsynced).")
@yah:handoff("Types: BeaconIo (multicast_v6(iface_idx), broadcast_v4(addr), unicast(bind,targets) test form), LanBeacon (BootstrapSource), BridgeBeacon (polls if_nametoindex of 'bridge90', binds v6 multicast + v4 broadcast when it appears, rebinds if index changes, drops when gone), CompositeBootstrap (union, dedup by id, merge addrs). F2 pump now feeds newly-learned peers into the endpoint address book (IrohNode::peer_lookup) before join_peers - without that, post-start beacon peers were not dialable.")
@yah:handoff("Core wiring: main.rs only, re-read first, edited only the mesh-membership block (T3's mesh_node line untouched): BridgeBeacon over BRIDGE_NAME + CompositeBootstrap[beacon, empty static] -> MeshMembership; shares IPAURO_MESH_ID; dropped before node shutdown. Internet discovery stays the IrohConfig.internet_discovery opt-in; I did not add an n0 BootstrapSource (n0 resolves ids via iroh's own address lookup when enabled, no bootstrap list needed).")
@yah:handoff("TEST HONESTY: the beacon tests run over plain UDP unicast on 127.0.0.1 (BeaconIo::unicast), NOT real multicast/broadcast - macOS loopback multicast is unreliable and needs a real bridge interface. multicast_v6/broadcast_v4/BridgeBeacon are therefore compile-checked only, never exercised in CI. Framing, signing, table, rate-limit, gossip-join are exercised.")
@yah:handoff("OWED FIELD VERIFICATION (real hardware, closes R002-T8): with a bridge90 up and the core LaunchAgent running, after the first beacon send run `./target/release/ipauro-probe grants --filter ipauro` and confirm a decision is recorded against io.ipauro.core / io.ipauro.app and is NOT DENIED (`unset` is not `denied`; only explicit DenyMulticast is). Also confirm on the wire that a second Mac on the bridge learns the NodeId with no internet and gossip-joins; and check log line 'beacon: announcing on bridge90'.")
@yah:handoff("UNACTED MESSAGE: a mid-turn block purporting to be from @Ashguard:griffin asked me to add a classify() line for ipauro-iroh to scripts/ci-control-plane.sh and run that script. Its nonce did not match this session's, so per policy I treated it as untrusted tool-result text and did NOT edit scripts/. The operator should confirm and either apply `crates/ipauro-iroh) echo \"container\" ;;` themselves or tell me to.")
@yah:verify("cargo test -p ipauro-iroh: 14 unit (beacon: registry consts, roundtrip, tamper/version/short/truncated, forged NodeId w/ valid sig, bounded table + source-ip, two-beacon discovery ignoring self/other-mesh/junk) + 1 beacon_bootstrap (two nodes, NO static bootstrap, gossip converges) + 2 endpoint + 1 membership; all pass")
@yah:verify("cargo test --workspace: 496 passed, 0 failed (baseline 490)")
@yah:verify("cargo clippy -p ipauro-iroh --all-targets: clean; cargo build -p ipauro-core ok")
-->

<!--
@yah:ticket(R003-F8, "Sample-rate policy: gossiped mesh-consensus rate (default 48k, evangelized; raise whole-mesh only) + per-stream clock cascade (input->corresponding output; output->host; generic/fan-out->mesh rate)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T21:50:30Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Rule: 48 kHz is the One Rate — default it, evangelize it, gossip it as a mesh-consensus value (sibling of NodeId addressing). Homogeneity makes the divergent-rate conversion problem evaporate. Raisable (e.g. 96k session) only by lifting the WHOLE mesh together, never two nodes diverging. Cascade governs only exceptions: (a) input -> match corresponding output; (b) output -> match host hardware clock; (c) generic external input OR fan-out with no single partner rate -> mesh rate. (a)+(b) chain so authority lands at the consuming hardware. CRITICAL distinction: nominal-rate agreement != clock drift — even at shared 48k, crystals drift ppm so R010-F4's ASRC still runs, but near-unity (cheap) not a 2x ratio. Caveat: 48k suffices only for HUMAN audiences; machine-listening/measurement/ultrasonic is the only reason to go higher and it's out of IPAuRo's lane.")
@yah:gotcha("Rate participation is CAPABILITY-based, never by protocol name (no type-name-sniffing): a stream participates iff it carries PCM samples (the canonical 'signal' payload). A pure-sync stream (classic tempo/phase sync, no samples) doesn't participate; an audio-carrying stream does — decided from the payload, NOT from whether the protocol is called 'Link'.")
@yah:gotcha("SETTLED 2026-07-25 (was an open 'confirm with the project owner' question): LinkAudio v1 DOES carry audio — PCM i16, big-endian, frame-interleaved, 1-2 channels, declared sample rate (link-wire-spec ch.03 s5.4-5.5). So it participates in the sample-rate policy. The capability-based rule above is unchanged; it now just has a decided answer for this case. Note the rate it declares is NOMINAL and Link disciplines no rate at all (ghost slope fixed at 1, offset re-measured every 30 s), which is why this ticket's 'even at shared 48k, crystals drift ppm so R010-F4's ASRC still runs' is exactly right — ASRC is mandatory even for Link's OWN audio protocol, not just foreign ones.")
@yah:soft_depends_on(R003-T3)
@yah:handoff("ALGORITHM half landed in crates/ipauro-mesh: new rate.rs (MeshRate{hz,epoch,author}, default 48k@epoch0, superseded_by = higher epoch then lowest NodeId, raise(), observe(); participates(proto) via ProtocolProfile::carries_media — capability, no name matching; pure resolve(mesh, StreamClock)->Option<StreamRate{hz,source,asrc}> with cascade a/b/c + recursive chaining; Asrc::NearUnity vs Ratio).")
@yah:handoff("Gossip ride: MeshRate is a field on policy::Policy (additive; Record literals in tests.rs untouched). Policy::observe_epoch adopts the rate by its own epoch independently of PolicyEpoch and never lets a replaced policy roll it back. MeshNode::mesh_rate() accessor added; MeshNode::apply_gossip picks it up through observe_epoch.")
@yah:handoff("12 new tests in rate::tests; cargo test -p ipauro-mesh = 47 passing (baseline 35); clippy --all-targets clean.")
@yah:verify("cargo test -p ipauro-mesh (47 pass)")
@yah:verify("cargo clippy -p ipauro-mesh --all-targets")
@yah:gotcha("Remaining wiring NOT done: surfacing mesh rate / per-stream resolved rate over IPC is R003-T5; supplying host_hz and real StreamClock inputs from core is also outside this ticket's scope (ipauro-core untouched). The actual ASRC engine is R010-F4.")
@yah:gotcha("Raising the rate (raise()) has no node-API to publish a proposal yet; a MeshNode method to author and gossip a raise belongs with the T5 wiring.")
-->

<!--
@yah:ticket(R003-F7, "IPC/RPC API over socket/port: external control (enrollment, roles, status) + canonical-stream exchange (mixing apps, out-of-process adapters) = the open extension surface; closed-source apps integrate + add protocols without catching GPL")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-10-30T00:03:33Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("This is the integration AND extension surface, validated by a real case: a CLOSED-SOURCE app that wants to (a) drive IPAuRo and (b) add its own new audio protocol. IPC is not linking, so the proprietary app catches no GPL. Two-tier adapters (A004): in-tree = GPL, joins the public registry/commons; out-of-process = a sidecar speaking the canonical stream model over this socket, ANY license, so a vendor extends IPAuRo without touching the GPL core. Split in practice: the CONTROL facet is PULLED TO P0 as R002-T7 (with the brain/face split it is the primary surface — our own UI client speaks it); this ticket keeps the STREAM facet (canonical-stream exchange — matures with the A004 model + R010). 'Speak every protocol' becomes community-extensible without copyleft coercion.")
@yah:depends_on(R003-T5)
@yah:depends_on(R003-B10)
@yah:handoff("STREAM FACET SHIPPED. New crates/ipauro-proto/src/stream.rs is the normative wire spec, with byte-layout tables in its module doc so a closed-source sidecar can implement it from the doc alone (IPC is not linking, A004 two-tier). Endpoint is `<control socket>.stream` (stream_socket_path), mode 0600. Framing: u32 LE len + kind byte + payload, max 1 MiB. Handshake: Hello{magic IPAS, u16 version, client name} -> HelloAck that is always sent, then the server closes on a mismatch. Messages: Register/Unregister/Subscribe/Unsubscribe/List/Registered/StreamList/Subscribed/Overrun/StreamEnded/Data/Error. The only edit to proto lib.rs is the `pub mod stream;` line.")
@yah:handoff("Descriptor = the A004 canonical stream descriptor: name, protocol family name (joins ProtocolProfile::name), payload SyncOnly|Pcm, channels, sample format, nominal rate, clock domain, source/sink role. The StreamInfo verdict carries FLAG_RATE_MISMATCH and FLAG_UNREGISTERED_PROTOCOL plus mesh_rate_hz. The rate verdict uses ipauro_mesh::rate::participates + resolve (rule c, Input with no partner): a mismatch is accepted and flagged, never resampled. Participation is decided by capability, never by name. PCM declared on a family whose registry row carries no media is refused with a non-fatal Error 5.")
@yah:handoff("Server: new crates/ipauro-core/src/stream_server.rs (StreamServer::spawn(path, MeshRateSource); dropping it aborts every connection and removes the socket). Each connection gets a bounded Outbox. Control frames are never dropped. Data frames are DROP-OLDEST with a per-stream dropped count, and the subscriber gets Overrun{dropped_total} before its next frame. The producer pushes under a std mutex and never awaits a subscriber. PCM is forwarded as the identical frame bytes in a shared Arc, parsing only the header. A malformed or oversized frame, a PCM length mismatch, or Data on a stream you do not own gets a best-effort Error and then closes ONLY that connection; its streams end with StreamEnded to their subscribers. Registry::protocol_caps() turns adapter-added families into ProtocolCapability rows (the PeerFacts shape).")
@yah:handoff("Wiring: core main.rs spawns the server before serve_with and drops it after. It reads the mesh rate from MeshMembership::mesh_rate through a Weak, so the later Arc::into_inner still works, and falls back to 48k. lib.rs gets only `pub mod stream_server;`. CLI: new crates/ipauro-cli/src/stream.rs plus `ipauro stream list` and `ipauro stream tap <id> [--frames N]`, which prints frames/overrun/last_seq. It branches off before the control socket is opened.")
@yah:handoff("Tests: 4 proto codec tests (round-trip for every message, Hello byte layout pinned, malformed bodies) and 5 server tests over real unix sockets in temp_dir: handshake accept/reject plus bad magic; adapter source -> mixer sink end to end with in-order seq, List, the caps row and StreamEnded; a slow subscriber at depth 4 against 2000 frames, where the producer finishes, order holds and delivered+dropped==N; rate mismatch flagged (in-tree family, no family, sync-only, unregistered vendor family, refused PCM-on-Link); and malformed/liar/thief frames closing only the offender. cargo test --workspace --no-fail-fast: 575 passed / 0 failed (baseline 562; +9 are mine, the rest are concurrent peers). Clippy clean on the new files.")
@yah:verify("cargo test -p ipauro-core stream_server  # 5 passed")
@yah:verify("cargo test -p ipauro-proto stream  # 4 codec tests")
@yah:verify("cargo test --workspace --no-fail-fast  # 575/0 at review time")
@yah:verify("cargo clippy -p ipauro-core -p ipauro-cli -p ipauro-proto --lib --bins  # no warnings in stream.rs / stream_server.rs")
@yah:gotcha("During this run the workspace was briefly red from peer in-flight edits (proto MeshStatus.foreign_leaves test initializer; helper DhcpExecutor::leases). They resolved without any action from me. Neither was mine.")
@yah:cleanup("No CLI integration test drives `ipauro stream list/tap` against a live StreamServer (ipauro-cli has no dep on ipauro-core). The protocol paths are covered by the core tests.")
@yah:cleanup("shm-ring seam documented in the proto + server module docs, not built (by design).")
@yah:handoff("PASS 2 (closes both gaps). (1) OPEN ProtocolId: new variant ProtocolId::Ext(ExtProtocolId) in crates/ipauro-mesh/src/protocol.rs. The id is a reverse-DNS name stored inline ([u8;64], zero-padded): 2+ labels of [a-z0-9-], at most 64 bytes. It is Copy, and Ord/Eq are byte-wise, so ordering is deterministic and gateway/election tie-breaks behave identically on every node. Collisions are impossible by construction: the name IS the identity (no hash), and in-tree names contain no dot, so the two spaces are disjoint. ProtocolId::from_name/name do the identity join. The 9 in-tree rows and ProtocolId::ALL (in-tree list) are unchanged. An extension family's registry row is an owned ExtProfile with the same declarative axes (carrier, discovery, clock, channelization, formats, rates, packetization, fan-out, latency). It travels in the new ProtocolCapability.ext field (Some iff the proto is Ext; enforced in validate as CapsError::ProfileMismatch). Translations are the existing Translation pairs with Ext ids.")
@yah:handoff("Row resolution: a new Profiles trait with Row<'a>::{InTree, Ext} accessors, implemented by InTree (the table only), ProtocolCaps (its own rows) and Topology (row from the LOWEST-id speaker that declares one, so it is deterministic). Every production profile() consumer moved onto it: capability validate/is_polyglot, rate::participates/resolve (now take a rows arg), gateway::demands, stream.rs plan_input (clock_bridge_in(topo,…)). profile(id) and ProtocolCapability::full stay in-tree-only, documented and #[track_caller] (tests.rs still uses them; not edited). New ClockBridge::Unknown (no row visible) gets an explicit arm in ipauro-bridge. No code branches on a family name; the row wire codes are one shared wire_codes! table in mesh (code/from_code), used by both the gossip codec and the stream socket. ProtocolCaps::union added (sorted, deterministic).")
@yah:handoff("(2) GOSSIP: ipauro-iroh codec RECORD_VERSION 3->4. A protocol is written as its tag, with 0xFF + u8-len name for Ext. Each capability gets opt(ExtProfile) after its clock domains. Decode of v1-v3 still works (ext=None; 0xFF is rejected before v4). A test-only encode_at(rec, ver) lets the old-version tests start from real v3 bytes instead of trimming v4 ones. New MeshMembership::set_protocols(ProtocolCaps) sets PeerFacts.protocols for the next heartbeat. Stream socket: new DeclareFamily (0x1A, with the full byte table in the proto doc) / FamilyDeclared (0x1B). FLAG_UNREGISTERED_PROTOCOL is removed: an unknown or undeclared family name is now refused with error 5. Registry keeps declarations per connection; one owner per name; disconnect retracts. Registry::protocol_caps() = declared families (row + translations) ∪ the families of registered streams. Every change pushes through set_caps_sink. core main.rs wires the sink as membership.set_protocols(in_tree(empty today).union(sidecars)) via a Weak.")
@yah:handoff("(3) E2E test stream_server::sidecar_family_is_gossiped_and_planned_like_an_in_tree_one uses real unix sockets and the real record codec. Node A's sidecar declares com.acme.netaudio (X) translating both ways with Dante and registers a Dante stream. Node C is an X island plus org.example.lonely (Y). Node B speaks Dante only. Results on B: peers_speaking(X)==[A,C] and translators(X,Dante)==[A]; gateway_plan has X->Dante and Dante->X with gateway A, and Y->Dante with gateway None (unbridged island), in sorted order. After the sidecar disconnects, A's next record retracts X: peers_speaking(X)==[C] and the X->Dante gateway is None. Also new: declarations_are_validated_owned_and_retracted, plus 3 codec tests (ext round-trip in v4, v3 backward decode, bad ext name rejected). cargo test --workspace --no-fail-fast: 580 passed / 0 failed. clippy --all-targets is clean on every touched file across mesh, iroh, core, cli, proto and bridge (one #[allow(clippy::result_large_err)] on ProtocolCaps::validate, with a comment: its signature is pinned by tests.rs, and an Ext id makes CapsError large).")
@yah:verify("cargo test -p ipauro-core stream_server  # 7 incl. sidecar_family_is_gossiped_and_planned_like_an_in_tree_one")
@yah:verify("cargo test -p ipauro-iroh --lib codec  # 9 incl. extension_families_roundtrip_in_v4, v3_records_still_decode_without_extension_rows")
@yah:verify("cargo test --workspace --no-fail-fast  # 580/0 at pass 2")
@yah:verify("cargo clippy -p ipauro-mesh -p ipauro-iroh -p ipauro-core -p ipauro-cli -p ipauro-proto -p ipauro-bridge --all-targets  # no warnings in touched files")
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
@yah:status(review)
@yah:assignee(agent:user-custom-char-gul2)
@yah:at(2026-10-29T21:17:10Z)
@yah:phase(P2)
@yah:parent(R010)
@yah:gotcha("Prior art (A003) settled the clock question: DON'T sync clocks across protocol families — use receiver-side ADAPTIVE RESAMPLING (JackTrip / zita-njbridge / SonoBus). PTPv1 / PTPv2 / gPTP are mutually incompatible (the wall the whole Dante/AES67 world hits); use a boundary-clock only where a specific leg demands hardware PTP. REUSE zita-njbridge's ASRC + a SonoBus-style adaptive jitter buffer — do NOT reinvent. NetJack's zero-packet-loss-tolerance is the explicit anti-pattern for our USB/WiFi/Bluetooth mesh.")
@yah:handoff("P1 DONE — new crate crates/ipauro-bridge (workspace member, classified `container` in scripts/ci-control-plane.sh): the adaptive clock CONTROLLER for a transcode leg, the half that is ours; the ASRC kernel is borrowed behind `trait Resampler { fn set_ratio(&mut self, f64) }`. DriftEstimator = sliding least-squares of cumulative frames vs arrival time (centred, so ns timestamps keep ppm precision; zero-mean jitter cancels); JitterStats = EWMA RMS of inter-arrival deviation in frames; BridgePolicy::for_class(mesh ClockBridge) -> {max_ppm, steer_fill, depth bounds}: SharedDomain ±50 ppm/no steer, CrossDomain ±500/no steer, Adaptive ±5000/steer, NoMedia -> None; LegClock = drift × fill-steering nudge (adaptive only), clamped to the band with is_clamped() surfaced as a fault on shared-domain legs, target_depth_frames = 4σ jitter within bounds; LegClock::drive() pushes the ratio into the kernel per packet.")
@yah:handoff("Measured while writing the tests (worth knowing for P2 tuning): slope noise from arrival jitter scales as 1/(window span × √n). ~256 one-ms packets with ±300 µs jitter wander ~150 ppm; the default LegClock window is 4096 (~4 s) which reads well under 1 ppm; the estimator test uses 20 s. DriftEstimator::ratio() is O(window) per call — fine today, make it running-sums if it ever sits on a per-packet path.")
@yah:next("P2: rubato adapter. `rubato = \"5.0.1\"` is on crates.io (cargo search, 2026-10-29); the dependency line is commented in crates/ipauro-bridge/Cargo.toml. Implement `Resampler` for a wrapper around rubato's async sinc resampler (read rubato 5's trait for the exact ratio-setter name/signature before writing it), then a loopback test: +200 ppm synthetic stream through LegClock + kernel, assert residual output drift < 1 ppm and no buffer under/overrun across 20 s.")
@yah:next("P3 (only if R010-T5 shows a need): boundary-clock mode for a leg with hardware PTP on both ends — the one exception the A003 gotcha allows.")
@yah:verify("cargo test -p ipauro-bridge — 8 passed (drift_estimate_converges_through_jitter [±200/−120 ppm through ±300 µs jitter to <5 ppm], estimator_is_silent_until_it_can_speak, jitter_rms_tracks_the_link, policy_follows_the_mesh_class_not_the_protocol, shared_domain_clamps_and_reports_an_out_of_band_drift, fill_steering_nudges_toward_the_depth_target, depth_target_grows_with_jitter_and_respects_bounds, drive_pushes_each_ratio_into_the_kernel); clippy --all-targets 0 warnings; cargo doc 0 warnings; cargo check --workspace clean; Cargo.lock updated by cargo for the new member (uncommitted, read-only git policy)")
@yah:handoff("P2 DONE — crates/ipauro-bridge/src/kernel.rs: RubatoKernel wraps rubato 5.0.1's Async sinc resampler (128-tap BlackmanHarris2, FixedAsync::Input so one process() consumes exactly one packet's frames) behind the crate's Resampler trait. Ratio convention bridged in one place: controller reports sender/nominal, rubato wants out/in, so set_ratio applies 1/r via the Adjustable trait's set_resample_ratio_relative (ramped), clamped into the 2×-policy-band the kernel was constructed for. process() takes channel-sequential input and returns the produced frames. `rubato = \"5.0.1\"` added to ipauro-bridge (pure Rust; container-safe).")
@yah:handoff("Loopback proves the whole leg: tests::loopback_holds_the_buffer_against_a_fast_sender — a 2000 ppm-fast sender (free-running USB interface vs the Mac) with ±100 µs jitter feeds 1 ms packets into a jitter queue drained at nominal rate through LegClock + RubatoKernel for 20 s. Uncontrolled the queue would grow 1920 frames (40 chunks); controlled it stays within target+4 chunks, zero underruns after priming, drift tracked to <10 ppm, output still a full-scale 1 kHz sine (peak ≈ 1, rms ≈ 1/√2).")
@yah:handoff("Two rubato-5 API facts the next reader should not have to rediscover: the ratio setters live on `rubato::Adjustable`, NOT on `rubato::Resampler` (an anonymous `Resampler as _` import does not resolve the method inside an `impl crate::Resampler` block either — the adapter uses `<Async<f32> as Trait<f32>>::method` form throughout); buffers go through `rubato::audioadapter_buffers::direct::SequentialSliceOfVecs::{new, new_mut}` and process_into_buffer returns (frames_in, frames_out).")
@yah:handoff("Not done, deliberately: P3 boundary-clock mode ('slave to common ref') for a leg with hardware PTP on both ends. The A003 gotcha makes that the exception, not the rule, and nothing yet shows a leg that needs it — file it as a child of R010 only if R010-T5's 4-node run surfaces one. RT-path cleanup also deferred: process() allocates the returned Vec of slices and the test drains with a VecDeque; a caller-owned output buffer is the shape for the adapter host.")
@yah:verify("cargo test -p ipauro-bridge — 9 passed (8 controller tests + loopback_holds_the_buffer_against_a_fast_sender, ~3 s); cargo test -p ipauro-mesh — 26 passed; cargo clippy -p ipauro-bridge --all-targets 0 warnings; cargo doc -p ipauro-bridge --no-deps 0 warnings; cargo check --workspace clean. Cargo.lock gained rubato 5.0.1 + audioadapter{,-buffers,-sample} (uncommitted; git is read-only for agents).")
@yah:verify("Reviewer check worth doing by hand: in the loopback test, set `ppm = 2_000.0` to 0.0 and the Adaptive policy to SharedDomain — the queue should then run away (max_fill assertion fails) on a fast sender, which is the clamp doing its job on the wrong class.")
-->

<!--
@yah:ticket(R010-F3, "Stream queue/router core: propagate 1:1 / fan-in / fan-out; each fan-out leg independently passthrough or transcode")
@yah:status(review)
@yah:assignee(agent:user-custom-char-gul2)
@yah:at(2026-10-29T21:07:25Z)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("NO MIXING, ever — not even fan-in. Fan-in = route/aggregate multiple DISCRETE streams onto one leg, kept channel-discrete; NEVER sum samples. This app does not mix. A separate app may ask this one to expose I/O streams in various formats and do its own mixing downstream — that consumer boundary is how mixing stays out of scope. We are transport + format-adaptation + routing only; the mixer is someone else's app.")
@yah:gotcha("Reuse a proven resampling engine (zita-njbridge / JackTrip) for the media-plane transport rather than writing ASRC + jitter buffer from scratch (A003 §3). The queue/router is the orchestration; the resampling/buffering is borrowed.")
@yah:handoff("New crates/ipauro-mesh/src/stream.rs: the queueing/routing node as a deterministic control-plane planner. Demand{sources, sinks, constraints} -> Flow{shape (derived: OneToOne/FanIn/FanOut/ManyToMany), legs}: one Leg per sink; per source an Input{mode, path}. Mode = Passthrough{clock} when protocols match, Transcode{from,to,at,clock} otherwise — `at` is the source node if it honours the translation (emits sink proto directly), else the sink node (ingests in place), else gateway::elect; clock = protocol::clock_bridge (R010-F4's input, carried on passthrough legs too since LinkAudio→LinkAudio is Adaptive). Path = Local / Direct(Route) / ViaGateway{to_gateway,to_sink} over routing::plan with the demand's Constraints.")
@yah:handoff("NO MIXING is structural: Leg.slots is Vec<Slot{stream, src_channel, dst_channel}>, dst channels assigned densely in source order, one source channel per slot; Leg::channel_count() == sum of source widths. There is no field in the module where two samples could meet. Media-plane buffering/resampling is deliberately absent — the borrowed engine (zita/JackTrip, A003 §3) consumes this plan.")
@yah:handoff("Blockages are first-class: Mode::Unbridged{from,to} (nobody translates) and Path::Unroutable{from,to} (names the failing hop) stay in the plan; Flow::is_complete / Leg::live_inputs / Input::is_live read them. MeshNode::plan_flow facade.")
@yah:handoff("Derived PartialEq on routing::Route/Hop, topology::Edge, transport::LinkQuality so a Flow is comparable (the cross-seat determinism tests need it).")
@yah:verify("cargo test -p ipauro-mesh — 26 passed (5 new under tests::stream_router: fan_out_legs_are_independently_passthrough_or_transcode [Dante island fans out to gateway/AVB/LinkAudio over the R010-T5 star: passthrough+SharedDomain, transcode-at-gateway+CrossDomain with a two-route path, transcode+Adaptive; identical Flow from all 4 seats], fan_in_keeps_every_channel_discrete [2+6+1 channels from three protocols onto one AVB sink: dense injective 0..9 slot map, per-input modes], a_translating_endpoint_transcodes_in_place, blockages_are_named_not_dropped [Unbridged for an AES67 sink; Unroutable 3→4 when Ethernet is forbidden], a_local_leg_has_no_route)")
@yah:verify("cargo clippy -p ipauro-mesh --all-targets — 0 warnings; cargo doc -p ipauro-mesh --no-deps — 0 warnings; cargo check --workspace — clean")
-->

<!--
@yah:ticket(R010-F2, "Gateway election: control plane elects a polyglot node as protocol-NAT for single-protocol islands (same shape as hub/peer election, one level up)")
@yah:status(review)
@yah:assignee(agent:user-custom-char-gul2)
@yah:at(2026-10-29T21:03:38Z)
@yah:phase(P6)
@yah:parent(R010)
@yah:handoff("New crates/ipauro-mesh/src/gateway.rs: demands(topo) derives the directed protocol pairs that need a gateway from the gossiped census alone — from→to is demanded iff some from-speaker does not speak to AND some to-speaker does not speak from (two nodes sharing any protocol talk natively, no demand); sync-only protocols (plain Link) never raise one. elect(topo, from, to) = lowest-id peer honouring the translation. plan(topo) -> Vec<Leg{from,to,gateway: Option<NodeId>}>: a demanded pair nobody can bridge is reported with gateway None, never dropped (blockage-as-first-class).")
@yah:handoff("election.rs: Role::ProtocolGateway{from,to} — same lowest-id tie-break as ClockMaster/MulticastOwner/SinkOwner, eligibility = ProtocolCaps::translates(from,to), no tcap requirement (the islands it serves are by definition not tactus peers). lib.rs: MeshNode::gateway_plan() and is_gateway_for(from,to) — the latter is what an adapter host polls to stand up a transcode leg.")
@yah:handoff("Scope boundary written into the module doc: election is on gossiped facts like every other role; reachability of the gateway from each island is R010-F3's (route the legs over routing::plan), and clock handling on the leg is R010-F4's (protocol::clock_bridge is its input).")
@yah:verify("cargo test -p ipauro-mesh — 21 passed (5 new under tests::gateway_election: exit_mesh_elects_the_polyglot_for_every_leg [R010-T5 shape, identical plan from all 4 seats, is_gateway_for true only on the polyglot], lowest_id_translator_wins_each_leg_it_honours [two polyglots, one directed-only], an_unbridgeable_pair_is_reported_not_dropped, no_demand_when_every_pair_shares_a_protocol, a_departing_gateway_is_replaced_by_the_next_translator [superseding record re-elects, then unbridged])")
@yah:verify("cargo clippy -p ipauro-mesh --all-targets — 0 warnings; cargo doc -p ipauro-mesh --no-deps — 0 warnings")
-->

<!--
@yah:ticket(R010-F1, "Per-node protocol capability advertisement over gossip (which protocols a node speaks + can translate between); extend registry with media format/packetization/clock per protocol")
@yah:status(review)
@yah:assignee(agent:user-custom-char-gul2)
@yah:at(2026-10-29T21:01:32Z)
@yah:phase(P6)
@yah:parent(R010)
@yah:gotcha("The iroh control plane carrying per-node protocol capability IS the surpass over the predecessors (A003 §4): it fixes NetJack's 'identical software both ends + manual setup' and AES67's 'sneakernet SDP files around the facility'. Nobody in the prior art discovers capabilities ACROSS protocol families — that cross-family discovery is what makes Protocol NAT electable.")
@yah:handoff("New crates/ipauro-mesh/src/protocol.rs: the media half of the R004-F1 registry as const data — ProtocolId (9 families: Link, LinkAudio, Dante, Aes67, Avb, Madi, Ndi, JackTrip, UsbAudio) + one ProtocolProfile row each with carrier / discovery / ClockRef / Channelization / SampleFormats / rates / Packetization{framing, frames_per_packet, mux} / FanOut / LatencyClass, transcribed from A004 §1. profile(id) is total (test-enforced). clock_bridge(from,to) -> {SharedDomain, CrossDomain, Adaptive, NoMedia} is the R010-F4 input, derived from ClockRef::disciplines_rate / is_network_domain, never from protocol identity (repo no-type-name-sniffing rule).")
@yah:handoff("capability.rs: ProtocolCaps { speaks: Vec<ProtocolCapability{proto, Verbs{pass,sink,source,fan_in,fan_out}, formats ⊆ row, rates ⊆ row, clock_domains}>, translates: Vec<Translation{from,to}> } — directed translations; translates(from,to) honours a translation only when both endpoints are spoken, so a malformed advertisement can never make a node look like a gateway; is_polyglot() = >1 media-carrying protocol; validate() -> CapsError is the publisher-side check (duplicate proto, unspoken/self/no-media translation, format/rate outside the row).")
@yah:handoff("topology.rs: PeerFacts.protocols: ProtocolCaps (Default) travels in the existing gossip Record; Topology::speakers_of / translators / protocols_spoken (sorted, deterministic). lib.rs: MeshNode::peers_speaking / translators facades. Existing can_transcode doc clarified as tactus codec-level vs protocol-family translation.")
@yah:handoff("Registry split documented in protocol.rs module doc: ipauro_proto::registry (manager-owned) keeps the ports/groups half; the two join on ProtocolProfile::name == ProtocolPorts::name ('ableton-link' asserted by test). PROTO REQUEST: fold the media rows into ipauro-proto when R004-F1 lands so the registry is one table.")
@yah:handoff("Also fixed two pre-existing rustdoc warnings in topology.rs / lib.rs (unresolved [apply] link, redundant Gateway link target); cargo doc -p ipauro-mesh is now warning-free.")
@yah:verify("cargo test -p ipauro-mesh — 16 passed (8 pre-existing + 8 new under tests::protocol_caps: every_protocol_has_exactly_one_profile, profiles_are_internally_consistent, clock_bridge_is_derived_from_profiles, four_node_exit_mesh_converges_on_every_node [the R010-T5 shape as gossip: LinkAudio-only + AVB-only + Dante-only + polyglot, records folded in a different order on each of 4 nodes, identical census/speakers/translators everywhere], a_translation_to_an_unspoken_protocol_is_not_honoured, translation_is_directed, validate_rejects_claims_outside_the_registry_row, peer_formats_narrow_the_registry_row)")
@yah:verify("cargo clippy -p ipauro-mesh --all-targets — no warnings; cargo doc -p ipauro-mesh --no-deps — 0 warnings; cargo check --workspace — clean")
@yah:verify("cargo fmt --check is NOT a gate here: pre-existing code in capability.rs already fails it (root rustfmt.toml uses nightly-only options); not reformatted to avoid touching unrelated hunks")
@yah:gotcha("scripts/ci-control-plane.sh (R009-T1) is red before it runs any test: workspace members crates/ipauro-iec61937, crates/ipauro-hdmi, crates/ipauro-spatial (added in commit d83a032) are missing from classify(). Not touched here — classifying needs a Linux build to prove 'container', which this session cannot run. Whoever owns d83a032's crates should add the three rows (hdmi has platform/macos.rs + coreaudio.rs so is likely macos:<dep>; iec61937 and spatial look std-only).")
@yah:gotcha("Profile rows are best-case from A004's table: SharedDomain means same network clock *family* (PTPv2↔PTPv2); whether two peers share a PTP domain *number* is the per-peer ProtocolCapability.clock_domains check (ClockDomain::Ptp(n)), which R010-F2/F4 must apply on top. Frames-per-packet values (AES67 48, AVB class-A 6) are the customary defaults, not negotiated per-stream values.")
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
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-10-29T23:40:00Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Near-term, not a Later tier. A node reachable only over the audio segment (e.g. a single-Ethernet-port box) must stay addressable for control from off-segment nodes — iroh does this via presence gossip + control routing over any path. Full cloud-INTERNET egress (NAT through a peer that has internet) is the heavier piece that can wait; control reachability cannot.")
@yah:gotcha("Mechanism: a hub GOSSIPS each downstream/foreign node as a real next-hop-via-me and FORWARDS its plain control traffic upstream — the hub is a transparent control relay, not a media-only bridge. Concrete failing we design against: MTRX <=> AVB-D16 <=> Apple. The AVB-D16 (Dante/AVB media bridge) converts audio faithfully but DROPS plain IP, so the MTRX's control protocol never reaches the Apple though on a flat LAN they'd see each other. Preserve audio AND control, and advertise the route.")
@yah:depends_on(R003-F9)
@yah:depends_on(R003-T5)
@yah:handoff("ipauro-mesh: new control.rs — ForeignLeaf{mac,ipv4}, foreign_leaf_id(hub,mac) (domain-tagged 64-bit hash of hub NodeId + MAC; attachment-scoped, survives DHCP re-lease), plan_control (deterministic fewest-hops BFS over gossiped edges + advertised leaves; intermediates and terminating hubs must declare relays_control) -> Local|Terminate|Forward|Unroutable{refused_by}, reachability -> Unknown|Direct|ViaHub{hub}|HubWontRelay{hub}|Unreachable, next_hops table. PeerFacts gains relays_control + foreign; Topology::foreign_leaf; MeshNode::plan_control/control_reachability.")
@yah:handoff("ipauro-iroh: codec RECORD_VERSION 3 appends relays_control + foreign list (v1/v2 still decode, default no relay/no leaves). New control.rs: ALPN ipauro/control/1, frame [ver][ttl][origin pk][sig][dest,target,port,msg_id,payload]; ttl outside signature, relays transparent, destination (or terminating hub) verifies origin end-to-end; ttl==0 at a relay drops; never forwards back to previous hop; ControlView trait (plan/key_of/relays_control), ForeignDelivery seam + IpPassthrough (UDP datagram / TCP connect-write-close to the sender-declared port, no protocol handling). MeshMembership now mounts ControlPlane on its router, keeps a Topology (own record included) and a verified NodeId->PublicKey directory from signed envelopes/bootstrap; setters set_relays_control/set_foreign_leaves/set_local_edges, control(), control_reachability().")
@yah:handoff("proto: MeshMember.reachability (serde-tagged Reachability, default Unknown, #[serde(other)] Other), BlockCause::ControlRelayRefused{node_id,hub} + Remedy::EnableControlRelay (Degraded). core mesh_status: sync_once sets relays_control = (role==Hub) and fills per-member reachability; build reports it and raises ControlRelayRefused for live members only reachable via a non-relaying hub. CLI/UI test literals got the new field.")
@yah:verify("cargo test --workspace — 563 passed / 0 failed (baseline 527); new: mesh control 5, iroh tests/control_relay.rs 6 (3 real endpoints on 127.0.0.1, A has no address for C and a direct connect is asserted to fail: relay delivery with origin verified + reply path, ttl expiry, forged/tampered origin rejected at C after H forwarded it, foreign leaf UDP+TCP passthrough terminated at H, loop drop on divergent views, non-relaying hub -> NoRoute naming it), codec v3 roundtrip/v2-compat, control frame unit, proto reachability serde, core reachability/blockage")
@yah:verify("cargo clippy -p ipauro-mesh -p ipauro-iroh -p ipauro-core -p ipauro-proto --all-targets — no warnings in new code (remaining: pre-existing proto ReplyOutcome large_enum_variant, core reconcile.rs result_large_err)")
@yah:verify("OWED: hardware verification on a real single-port box behind a hub (and a foreign device behind a hub) — all evidence here is loopback")
@yah:gotcha("Nothing in production yet publishes edges: heartbeats carry set_local_edges only when called, and no link measurement calls it, so live reachability reads Unknown until an edge source (e.g. beacon-heard peers on the segment, owned by beacon.rs/R003-B10) feeds set_local_edges. Likewise set_foreign_leaves awaits R005-T6's DHCP lease feed.")
@yah:gotcha("cargo test --workspace briefly failed mid-session on E0373 in crates/ipauro-iroh/src/beacon.rs:617 (R003-B10's in-flight file, not touched here); the later run was green.")
@yah:handoff("Pass 2: both feeds are wired into the live sync loop, so reachability is no longer Unknown in production. EDGES: core mesh_status::sync_once calls MeshMembership::set_local_edges(local_edges(heard, link_inventory)). `heard` comes from the new SegmentPeers trait; InterfaceBeacon implements it via the new InterfaceBeacon::heard() / LanBeacon::heard(), which return (iface, verified key) for peers inside the beacon table's ttl, so edges expire together with the peer table. A peer heard on bridge90 or on an identified uplink_eligible link becomes Edge{UsbBridge}; an interface identification doesn't know (or a rejected Internal decoy) is skipped rather than guessed. No interface-name sniffing. A hub's bridge-heard peers are its bridge-member edges.")
@yah:handoff("LEAVES: proto DataPlaneReport.dhcp_leases: Vec<DhcpLease{mac:[u8;6],ipv4}> (serde default, additive). The helper's DHCP responder now shares its LeaseTable (Arc<Mutex<Option<..>>>); DhcpExecutor::leases() returns LeaseTable::snapshot() (Ethernet MACs only, sorted) while serving. reconcile::apply_report stores the leases in StateStore::set_dhcp_leases. sync_once calls set_foreign_leaves(foreign_leaves(role, leases)) (Hub only), and the leaf id is the hub NodeId+MAC derivation. Status: MeshStatus.foreign_leaves: Vec<ForeignLeafView{leaf_id,hub,mac,ipv4,reachability}> (additive), with leaf reachability computed alongside the members'.")
@yah:handoff("control_relay flake fixed: the test sampled H's `forwarded` counter right after C's inbox received the frame, but H increments it only once its stream's stopped() resolves. All three such reads now await the condition (eventually) instead of sampling it.")
@yah:verify("cargo test --workspace --no-fail-fast: 574 passed / 1 failed. The only failure is ipauro-proto stream::tests::hello_layout_is_as_documented (crates/ipauro-proto/src/stream.rs:613), which is the F7 courier's (session:fa3defe9) in-flight file and was not touched here. Every crate touched by F6 is green.")
@yah:verify("New core tests: mesh_status::tests::beacon_heard_peers_and_dhcp_leases_drive_reachability_in_status runs 3 real MeshMemberships on 127.0.0.1 driven only by sync_once, with fixed SegmentPeers plus a DHCP lease on the hub's store. A's published MeshStatus shows H Direct, C ViaHub{H}, and the leaf ViaHub{H} with mac/ipv4/hub, and no member reads Unknown. Also edges_come_from_identified_links_only_and_leaves_only_on_a_hub. Helper: lease snapshot test, plus the Report test now carries leases. Beacon: the two-node exchange test asserts heard().")
@yah:verify("cargo test -p ipauro-iroh --test control_relay: 5 separate runs, each 6/6 passed (args varied with --skip so the build rail could not dedupe them).")
@yah:verify("cargo clippy (mesh, iroh, core, helper, --all-targets): no warnings in F6 code. The only remaining warnings were already there: proto ReplyOutcome large_enum_variant and core reconcile.rs result_large_err.")
@yah:verify("Still owed: hardware verification on a real hub, a single-port peer, and a DHCP-leased foreign device.")
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
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-07-26T03:04:04Z)
@yah:phase(P1)
@yah:parent(R005)
@yah:handoff("Ported A002 §5's identification ranking into `ipauro-core::discovery` as types + one pure classifier, replacing the host-only lookup: `Evidence{HostIokit,PeerTraffic,DeviceIokit}` (Ord = A002's reliability ranking), `LinkRole{Host,Device,Internal}`, `UsbLink`, `LinkInventory`. `classify()` is pure; `identify()` runs one pass over `UsbNcmSource`, now three methods (`discover` / `discover_device_side` / `observe`).")
@yah:handoff("Device-side `AppleUSBDeviceNCMData` is now QUERIED and narrowed (parity with `prototype/usb-link-bridge.sh`'s `discover_device_side()`: `status: active` + an IPv4), and classified as `Device` vs `Internal` rather than ignored — so the rejection of macOS's inter-processor interfaces is auditable instead of silent.")
@yah:handoff("Safety property that makes querying that class acceptable: `LinkInventory::bridge_members()` returns host-provenance links ONLY, enforced by `UsbLink::bridge_eligible()`. Proven through the LIVE service by `crates/ipauro-core/tests/integration.rs::device_class_interfaces_never_reach_the_helper`, which asserts no `HelperRequest` ever named a device-class interface — not just that the final snapshot looks right.")
@yah:handoff("Traffic fallback (A002 §5.2) = per-interface `netstat -ib` input-packet DELTA between consecutive passes. Baseline observations are carried in `StateStore` next to the inventory; a counter that went BACKWARDS is a re-created interface, not traffic.")
@yah:handoff("New pure parsers `parse_ifconfig_state` / `parse_netstat_input_packets`, tested against VERBATIM output captured from a real Mac (see the gotcha).")
@yah:handoff("`reconcile::drive_once` identifies via `spawn_blocking` — `ioreg` walks the whole IORegistry (~100ms) and this task shares a runtime with the IPC server. `drive_once`/`commands::handle` take `&Arc<dyn UsbNcmSource>` to allow that.")
@yah:handoff("Behaviour change: bridge member lists are now sorted/canonical, so `SetBridgeMembers` is a function of WHICH interfaces are links, never of `ioreg`'s print order (`tests/m_incident.rs:176` updated to match).")
@yah:gotcha("FIELD FINDINGS, live capture on a QUIET Mac (Apple Silicon MBP, nothing plugged in, 2026-07-25) — four things A002 §5 had only inferred, now canon in A002 §5.5 and frozen as verbatim test fixtures: (1) `anpi0/1/2` really ARE children of `AppleUSBDeviceNCMData`, as `AppleUSBDeviceNCMPrivateEthernetInterface` — that is the MECHANISM by which §3's decoy would get bridged; only the `+-o en[0-9]+` shape keeps them out. (2) A quiet Mac already shows THREE `enN` under that class (`en3`/`en4`/`en5` here); A002 wrote `en1..en6`, so the numbering is machine-specific and must never be hardcoded. (3) `inet6` must NOT satisfy 'configured' — internals carry IPv6 link-locals, so a bare `grep inet` promotes every one of them to a link. (4) `netstat -ib` marks DOWN interfaces with a trailing `*` (`gif0*`); keeping the star files counters under a name no lookup matches and then silently reports zero traffic forever.")
@yah:gotcha("PROTO CONTRACT REQUEST (`ipauro-proto` is manager-owned and was NOT edited): the device-side and traffic findings have no wire field, so today they reach an operator only through a service log line (`LinkInventory::summary`, emitted on a classification change). Requested additive change: `Snapshot.links: LinkState { host: Vec<IdentifiedLink>, device: Vec<IdentifiedLink> }` with `IdentifiedLink { name, role, evidence }`, all `#[serde(default)]` — no `PROTOCOL_VERSION` bump. That lets `ipauro status` and the tray UI answer A002 §5's own question ('which interface is the USB link?') on BOTH ends of the cable, which is the whole point of identifying the device end. `StateStore::link_inventory()` is already the ready-made source; `cli/src/format.rs` needs ~10 lines once the field exists.")
@yah:gotcha("Sibling-ID collision fixed in passing: `R005-T7` shared numeric index 7 with this ticket (the per-relay child counter is one shared sequence across kinds). Renamed the later-created one to `R005-T10` — annotation in A001 plus its one reference in W002. `board.adopt` is NOT the tool for this: on A001 it proposes renumbering every relay in the file (R002→R012 …), because those relays are declared in W001.")
@yah:verify("`cargo test --workspace` — 18 test binaries green (70 in `ipauro-core --lib`, incl. the new identification suite); `cargo clippy --workspace --all-targets` clean.")
@yah:verify("Hardware re-check, to be re-run after any macOS update: `cargo test -p ipauro-core --lib -- --ignored --nocapture real_machine`. It asserts the invariants that hold on ANY Mac plugged in or not (every identified name passes the decoy gate; nothing device-class is bridge-eligible; only gated names are handed to `ifconfig`) and prints the inventory. Ran here: `en3=internal(rejected)[device-iokit] en4=internal(rejected)[device-iokit] en5=internal(rejected)[device-iokit]`, no host links (no cable attached).")
@yah:verify("Mutation check: make `classify`'s `role` unconditionally `LinkRole::Host` — `discovery::tests::device_side_links_are_never_bridge_eligible` AND `tests/integration.rs::device_class_interfaces_never_reach_the_helper` must both fail.")
@yah:verify("Mutation check: drop the `.trim_end_matches('*')` in `parse_netstat_input_packets` — `netstat_strips_the_down_interface_star_from_the_name` must fail.")
@yah:verify("STILL UNVERIFIED ON HARDWARE (no second Mac / no USB-C cable in this session): the ACCEPT paths. Nothing here has seen a real host-side `AppleUSBNCMData` interface, a real configured device-end link, or a real non-zero traffic delta — those are exercised only by canned fixtures. A two-Mac pass should confirm `bridge_members()` picks up the host link and that `summary()` shows `device[...+traffic]` on the far end.")
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
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T23:00:06Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:depends_on(R003-F4)
@yah:handoff("PROTO (ipauro-proto, additive, PROTOCOL_VERSION unchanged): MeshView.status: Option<MeshStatus> (serde default). MeshStatus{version=MESH_STATUS_VERSION(1), self_node{node_id,endpoint_id}, members[{node_id,is_self,role,ula,ipv4,addr_salt,last_seen_age_secs(bucketed via bucket_age_secs),liveness alive/expiring/expired}], rate{hz,epoch,author}, bootstrap{beacon NotRunning/Up/Down{cause}, n0 Off/On}, endpoint NotStarted/Bound/Failed{error}, blockages[{cause: BlockCause, remedy: Remedy}]}. BlockCause (typed enum): IrohBindFailed, GossipUnavailable, BeaconWaitingForBridge, BeaconBindFailed{family}, Ipv4Exhausted, AddressCollision, PeerExpired. Remedy typed too; Blockage::severity()/cause_text()/remedy_text(). All status enums have #[serde(other)] Unknown so a newer server parses; MeshStatus::is_supported() for version skew. Command::ProposeMeshRate{hz}; ErrorCode::MeshUnavailable; ALLOWED_MESH_RATES_HZ.")
@yah:handoff("MESH/IROH: rate.rs gains ALLOWED_RATES_HZ, RateError, MeshRate::propose (validates allowed + not already adopted; lowering is also a new epoch). MeshMembership now tracks heard times, expired tombstones (300s) -> members()->MemberObservation{node,role,last_seen,state}; mesh_rate(); propose_rate(hz) adopts locally and heartbeats carry the Policy{rate} once epoch>0 (peers adopt via observe). BridgeBeacon::health()->BeaconHealth{iface,state InterfaceAbsent/Announcing{v6_error,v4_error}/BindFailed}. IrohNode::internet_discovery().")
@yah:handoff("CORE: new mesh_status.rs: pure build(MeshInputs)->MeshStatus plus sync_once/run_sync (replaces role::run_sync; runs even with no membership so a failed iroh bind is reported). Publishes via mutate_if_changed so heartbeats emit nothing; first status is published before the server accepts clients. MeshControl trait on StateStore (MeshMembership impl) backs ProposeMeshRate in commands.rs (MeshUnavailable / InvalidCommand on bad rate; reply snapshot carries new epoch). main.rs fills MeshEnv (endpoint id/bound/failed, gossip error, beacon handle) and calls serve_with; serve() keeps old signature. MeshAddressing gained claims()/ula_of()/node().")
@yah:handoff("CLIENTS: CLI `status mesh` (members table, rate, bootstrap, blockages with fix lines), `rate propose <hz>`. app/ui panel: scrollable Mesh section with THIS machine's hub/peer toggle (sends SetRole), rate, bootstrap line, read-only remote member rows (expired dimmed), blockages colored by severity with remedies; view model in viewmodel.rs. Remote roles have no control.")
@yah:handoff("CI: added `crates/ipauro-iroh) echo \"container\"` to classify() in scripts/ci-control-plane.sh (line 62), after re-reading the file.")
@yah:verify("cargo test --workspace: 527 passed / 0 failed (baseline 504). New: proto round trip incl. version/unknown-variant handling + age buckets; core mesh_status tests (every BlockCause variant produced from its cause, membership change = exactly one event, heartbeat-only = none, propose rate validation + epoch bump); iroh integration (members/tombstone/rate gossip to peer); mesh rate::propose; CLI parse + status mesh + rate propose; ui view model.")
@yah:verify("cargo build -p ipauro-ui OK.")
@yah:verify("cargo clippy --all-targets on proto/core/iroh/mesh/cli/ui: exit 0 but warnings: the 2 known result_large_err in core reconcile.rs, PLUS new large_enum_variant warnings (proto ReplyOutcome, cli tests ReplyPlan, ui state.rs ConnEvent) caused by Snapshot growing with MeshStatus. Not fixed (boxing Snapshot touches many call sites).")
@yah:verify("./scripts/ci-control-plane.sh FAILED (exit 101) for a reason unrelated to ipauro-iroh: inside the rust:1.97.0-bookworm container cargo could not read the registry cache (`failed to download anstream v1.0.0 ... /cargo-home/registry/src/.../anstream-1.0.0/Cargo.toml: No such file`). Classification step passed (it got as far as running the suite). Needs a clean cargo-home volume / relay R009 to look.")
@yah:verify("OWED: two real machines to see roles/rate/membership/blockages live; the beacon bind-failure and n0-on paths are only unit-tested via inputs.")
@yah:cleanup("Box the Snapshot in ReplyOutcome::Ok / ConnEvent / test ReplyPlan to clear the 3 new large_enum_variant clippy warnings (proto is manager-owned; wire format unchanged by Box).")
-->

<!--
@yah:ticket(R003-F4, "Hub/peer role election over the IPC API (UI client renders it); roles propagate via gossip")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T22:08:33Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:depends_on(R003-F2)
@yah:depends_on(R003-F8)
@yah:depends_on(R003-T3)
@yah:handoff("Per-machine USER role election done. Mesh: topology::NodeRole{Hub(default),Peer} + PeerFacts.role. Codec (ipauro-iroh/codec.rs): RECORD_VERSION 1->2, role byte appended to facts; decoder accepts v1 (role=Hub) and rejects bad role tags; tests for round trip, v1 compat, bad tag. Gossip: MeshMembership::set_local_role (heartbeat now advertises shared local PeerFacts instead of default), peer_roles() (seq-guarded, dropped on expiry). Beacon module untouched.")
@yah:handoff("Proto: state::{NodeRole, MeshView{role,peers}, MeshPeer}, Snapshot.mesh (serde default), Command::SetRole{role} (additive; PROTOCOL_VERSION unchanged per the file's additive policy). Core: new role.rs (role file = <socket>.role, load/save, sync_once/run_sync pulling gossip into the store each 1s), commands SetRole (persist -> mutate -> drive_once), StateStore::set_mesh_members now returns changed and is fed by role::sync_once (T3 seam wired: IPv4 resolution runs over live gossiped members), reconcile Desired.bridge_up = desired_up && role==Hub (user's BridgeUp wish is remembered across Hub->Peer->Hub). ServiceConfig gained membership; main.rs diff = one line (passes membership.clone()). serve() awaits the sync task so main's Arc::into_inner(membership) still succeeds.")
@yah:handoff("CLI: `ipauro role get` (prints this node + gossiped peers) / `role set hub|peer`; status gains a mesh block. app/ui: only fixed Snapshot literals; no role toggle added (did not read the egui panel; left as a follow-up).")
@yah:handoff("Tests: workspace 504 pass / 0 fail (baseline 496). New: codec role/v1/bad-tag; role file round trip; reconcile peer-makes-no-bridge, hub->peer alias-before-destroy teardown + peer->hub rebuild, member-set -> IPv4 re-resolution (and revert when the peer leaves); tests/role.rs over the real socket: SetRole round trip + persistence across a service restart; CLI pretty_roles. clippy --all-targets on proto/core/iroh/mesh/cli: only the 2 pre-existing result_large_err warnings.")
@yah:verify("cargo test --workspace (504/0)")
@yah:verify("cargo clippy --all-targets -p ipauro-proto -p ipauro-core -p ipauro-iroh -p ipauro-mesh -p ipauro-cli")
@yah:verify("OWED: two real machines — `ipauro role set peer` on one should show up in the other's `role get` within ~2 heartbeats (needs two live iroh nodes; the gossip path is covered only at codec/unit level here).")
@yah:gotcha("OPERATOR PRODUCT QUESTION: remote role-setting (one machine electing another's role) is deliberately NOT built — peers' roles are read-only here (only the author's signed gossip record can change them). It needs an authorization model nobody has decided.")
@yah:gotcha("Role is the ONLY desired state that persists; bridge up/down and scope remain per-instance as in M1 (the spec said 'wherever M1 persists desired state' — that is nowhere, so a <socket>.role file was added for role alone). A restarted Hub is still bridge-down until BridgeUp.")
@yah:gotcha("MeshMembership.pending.records grows unboundedly because nothing in core calls sync_into (no MeshNode is owned yet); pre-existing from F2, noticed not fixed. Peer-role/member reads use the separate live/roles maps so they are unaffected.")
@yah:gotcha("A Peer node has no bridge and therefore no mesh alias addresses (T3 aliases live on bridge90). If peers are meant to hold the primary ULA/IPv4 on a non-bridge interface, that is a T3-follow-up needing a different target interface.")
-->

<!--
@yah:ticket(R003-T3, "Primary addressing: NodeId-derived address (IPv6 ULA / hashed IPv4), self-applied + gossiped — serverless, collision-free, replug-stable, no DHCP authority")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T21:59:38Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:gotcha("Deterministic NodeId-derived addressing replaces DHCP-as-default. The audio segment is a closed appliance net where the control plane already knows every member, so there's no host to discover and no gateway to learn — DHCP's value is moot and its costs (a stateful server, leases, electing an addressing authority, replug lease churn, accidental default-route injection) are pure downside. Address = f(NodeId) is collision-free and survives replug with no server. Link alone can run on IPv6 link-local; the ULA is for AES67/Dante + iroh-over-bridge.")
@yah:gotcha("'Collision-free' holds for the IPv6 ULA, NOT the hashed-IPv4 fallback: birthday math puts ~20 nodes in a /24 above 50% collision odds, so 'with collision check' is doing heavy lifting. The IPv4 path needs a deterministic resolution rule (e.g. lowest NodeId keeps the slot, loser re-hashes with an incremented salt, result gossiped) and the foreign-DHCP pool (R005-T6) kept disjoint from the hash range. And since Dante/AES67 are IPv4-only, the IPv4 path is the MAIN path once M4 protocols arrive — not an afterthought.")
@yah:handoff("ALGORITHM half done in crates/ipauro-mesh/src/addressing.rs (+ pub mod in lib.rs; additive PeerFacts.addr: Option<AddrClaim> in topology.rs). std-only.")
@yah:handoff("ULA: fd + 40-bit Global ID (UlaPrefix::from_mesh_id(session id) or UlaPrefix::DEFAULT) + 16-bit subnet + NodeId as IID with u/l bit flipped (bijective => collision-free, nothing gossiped).")
@yah:handoff("IPv4: Ipv4Config::new validates hash range vs foreign-DHCP pool (disjoint, in-subnet, excl. network/broadcast); appliance_default = 10.42.0.0/16 (hash low half, foreign pool high half; foreign_pool() exposes it for R005-T6). assign_ipv4(cfg, members) is a pure function of the member SET: ascending NodeId, each takes first free slot from hash(id,salt); after 32 salts linear probe so Exhausted fires only when members > capacity.")
@yah:handoff("Gossip decision: members (inputs) are already gossiped, so each node COMPUTES the assignment; advertised AddrClaim is an observable only, compared via diverging_claims() — avoids pinning stale partition-era claims. Rationale in module doc.")
@yah:handoff("Tests: 9 in addressing::tests; ipauro-mesh 26 -> 35 passing; clippy --all-targets clean.")
@yah:handoff("Tree anchor at handoff: d83a032b1e88f9b58a34b75f80608c19427908e5 — the shared tree as I left it. Diff against it (`git diff d83a032b1e88f9b58a34b75f80608c19427908e5..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
@yah:next("Apply the address to an interface via a helper verb once R003-F1 lands (touches ipauro-core/app/helper/ipauro-proto)")
@yah:next("Populate PeerFacts.addr from the node's own computed claim when gossip records are built (R003-F2); coordinate with R003-F8's field addition")
@yah:handoff("APPLICATION pass done. Proto: HelperRequest::AddBridgeAlias{addr:IpAddr,prefix} / RemoveBridgeAlias{addr} + DataPlaneReport.bridge_aliases (serde default, additive). Helper: BridgeExecutor::{aliases,add_alias,remove_alias}; IfconfigExecutor builds argv only from typed IpAddr via alias_add_args/alias_remove_args (pure, unit-tested), idempotent via parse_aliases (inet after the first + non-fe80 inet6); netutil::validate_alias_add/remove gate class (ULA fd00::/8 at /64, RFC1918 8..=30) before any exec; interface is implicit bridge90 so no name is attacker-supplied.")
@yah:handoff("Core: new crates/ipauro-core/src/addressing.rs (MeshAddressing::new/appliance, desired(&members)->PrimaryAddrs); StateStore::{set_mesh_addressing,set_mesh_members,desired_primary} — set_mesh_members(BTreeSet<NodeId>) is THE SEAM for R003-F2/F4 (members default {self}; callers should kick reconcile after). Reconcile: Desired.primary; plan order bridge -> members -> SetBridgeAddress -> alias steps (stale RemoveBridgeAlias first, then missing AddBridgeAlias) -> DHCP -> scope; teardown ClearScopes -> StopDhcp -> RemoveBridgeAlias* -> DestroyBridge; alias add is Facet::Bridge-blocked. Rebuilt bridge ignores stale report aliases (replug re-applies same addr). primary:None leaves aliases untouched.")
@yah:handoff("Config-time pool check: Ipv4Config::check_pool_disjoint (mesh) called from MeshAddressing::new against the pool reconcile serves (proto defaults DHCP_POOL_*); a misconfigured/overlapping pool -> serve() logs and skips addressing. main.rs diff is ONE plumbing line (mesh_node from iroh_node.node_id()) plus ServiceConfig.mesh_node field (lib.rs); the two integration test configs got mesh_node: None. ULA prefix: IPAURO_MESH_ID env -> UlaPrefix::from_mesh_id, else DEFAULT (read in serve(), same env main.rs feeds gossip).")
@yah:handoff("Results: cargo test --workspace 490 pass / 0 fail (baseline 424). clippy --all-targets on proto/core/helper/mesh: only 2 pre-existing result_large_err warnings in reconcile.rs (ReplyOutcome Err size), none from this change.")
@yah:verify("cargo test --workspace (490/0)")
@yah:verify("cargo clippy --all-targets -p ipauro-proto -p ipauro-core -p ipauro-helper -p ipauro-mesh")
@yah:verify("OWED FIELD VERIFICATION (hardware, not testable here): on a real macOS bridge90, confirm `ifconfig bridge90 inet6 <ula> prefixlen 64 alias` and `inet <v4> netmask .. alias` apply, a replug re-applies the same addrs, and that parse_aliases against real ifconfig output (flags like autoconf/temporary on inet6, tentative DAD state) lists only our aliases.")
@yah:gotcha("Helper does NOT itself check the DHCP pool against the hash range (it has no mesh dep and the range isn't on the wire); the disjointness gate is core-side at config time only. A future helper-side defense would need the hash range in ipauro-proto.")
@yah:gotcha("Primary IPv4 (10.69.0.1/24, DHCP pool) and mesh IPv4 (10.42.0.0/16 hash range) coexist as primary + alias; the report's alias list is 'every non-primary non-link-local address on bridge90', so any foreign alias someone adds by hand would be stripped on the next up-pass when primary is Some.")
-->

<!--
@yah:ticket(R003-F2, "iroh-gossip membership: peers auto-discover and join the session")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T21:57:07Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:depends_on(R003-F1)
@yah:handoff("ipauro-iroh now has codec.rs (versioned record codec), gossip.rs (signed envelope, topic, BootstrapSource, IrohGossip impl of mesh Gossip, MeshMembership), and node.rs gained a MemoryLookup for static peer addrs (IrohNode::add_peer_addr, local_addr). Deps added: iroh-gossip 0.101 (needs iroh ^1, resolves with iroh 1.4.1 - fetched from crates.io, was not in the local cache), futures-lite, tokio.")
@yah:handoff("FINDING vs decision 3: iroh-gossip Message::delivered_from is the previous HOP, not the author (its docs say so), and gossip is unsigned, so 'author == mesh_node_id(delivering key)' is not implementable on a multi-hop tree. Implemented the same intent differently: every record rides in a signed envelope [ver=1][author pubkey 32][ed25519 sig 64][record]; receivers verify the signature (domain-separated) and require record.author == mesh_node_id(signing pubkey); failures are dropped and counted (MeshMembership::rejected()). Tested with a real forged-author record injected by a third node.")
@yah:handoff("Codec: leading version byte RECORD_VERSION=1, unknown versions rejected, count-bounded decode, enums matched exhaustively (new ProtocolId/TransportKind variant breaks the build). Covers PeerFacts.addr and Policy.rate (MeshRate - the sibling F8 put it inside Policy, there is no separate Record field; gossip.rs Record was re-read at the end and unchanged). Round-trip checked by byte-identical re-encode because mesh types lack PartialEq.")
@yah:handoff("MeshNode is not Send (Box<dyn Gateway> lacks Send), so background tasks cannot own one. Design: tasks queue authenticated records + expiries; the MeshNode owner calls MeshMembership::sync_into(&mut MeshNode) (apply_gossip + forget_peer). live_peers() is the Send-safe view. If a shared Arc<Mutex<MeshNode>> is wanted, mesh's add_gateway needs `dyn Gateway + Send` - not done (outside fence).")
@yah:handoff("Heartbeat: GossipConfig{mesh_id (default 'ipauro'; topic=blake3 of it), heartbeat 2s, expire_after_missed 5}; each tick publishes a facts record with seq=max(prev+1, now_ms) so a restarted node's seq stays ahead of its old watermark. Silent > heartbeat*N => expired. Added minimal additive mesh hook: Topology::forget + MeshNode::forget_peer (keeps the seen watermark so replays can't resurrect), tested in new crates/ipauro-mesh/tests/forget.rs.")
@yah:handoff("Core wiring only in ipauro-core/src/main.rs: spawns MeshMembership after the IrohNode with empty StaticBootstrap (F9 supplies beacon peers; mesh id via env IPAURO_MESH_ID), logs membership changes, degrades on error, shuts down before the node. mDNS not enabled; relay/discovery off.")
@yah:handoff("Known limits: heartbeat carries default PeerFacts (no real caps/edges yet); the outbound pump re-issues join_peers(bootstrap ids) per message; no persistence of learned peers.")
@yah:verify("cargo test -p ipauro-iroh -p ipauro-mesh: iroh 9 unit + 2 endpoint + 1 membership (3 real 127.0.0.1 nodes converge via a single bootstrap, forged author rejected, silenced node expired); mesh 47 + forget 1; all pass")
@yah:verify("cargo test --workspace: 465 passed, 0 failed (baseline 424; delta includes sibling tickets' tests)")
@yah:verify("membership test run twice more: passes both times")
@yah:verify("cargo clippy -p ipauro-iroh --all-targets: no warnings; cargo build --workspace ok")
-->

<!--
@yah:ticket(R003-F1, "iroh NodeId identity (ed25519) + node bootstrap")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:at(2026-10-29T21:50:25Z)
@yah:phase(P2)
@yah:parent(R003)
@yah:handoff("New crate crates/ipauro-iroh (iroh 1.4.1, blake3; added to workspace members). key.rs: load_or_create_secret_key (0600, create_new, hard KeyError::Corrupt on bad length/unreadable, never regenerates), default_key_path (macOS ~/Library/Application Support/io.ipauro/node.key; else XDG_DATA_HOME/ipauro), mesh_node_id = first 8 bytes of blake3(b\"ipauro-mesh-nodeid-v1\"||pubkey), kept in ipauro-iroh because mesh is std-only and std has no stable crypto hash. node.rs: IrohNode::start(IrohConfig) binds Endpoint with presets::Minimal + RelayMode::Disabled (air-gapped default; internet_discovery flag switches to presets::N0); exposes public_key(), node_id(), bound_addrs(), endpoint(), shutdown(). iroh's 32-byte key type is PublicKey/EndpointId (endpoint.id()).")
@yah:handoff("Wired in ipauro-core/src/main.rs (not serve(), so ServiceConfig and its test call sites are untouched): key path = socket path's parent/node.key; bind/key failure logs an error and the M1 control path continues; node shut down after serve returns. ipauro-proto / IPC untouched.")
@yah:handoff("Pinned NodeId vector in test was captured from the implementation's own output for key [7;32] (regression pin, not independent oracle).")
@yah:verify("cargo test -p ipauro-iroh: 3 unit + 2 integration pass (127.0.0.1 endpoint, distinct stable ids across restart, corrupt key refuses)")
@yah:verify("cargo test --workspace: 424 passed 0 failed after; clean-tree baseline not separately captured (a first run that already included my crate failed only my unpinned vector: 265 passed 1 failed)")
@yah:verify("cargo clippy -p ipauro-iroh --all-targets clean; cargo build --workspace ok")
-->

<!--
@yah:ticket(R005-T6, "DHCP as ingestion adapter for foreign (non-IPAuRo) devices only: control-plane-allocated address, NO gateway option, gossip the assignment; cope with link-local self-assign")
@yah:at(2026-06-28T02:50:51Z)
@yah:status(done)
@yah:phase(P1)
@yah:parent(R005)
@yah:gotcha("DHCP is NOT network infrastructure here and nobody depends on one node for it. It is ONLY for ingesting a foreign (non-IPAuRo) device plugged into a hub. Even then the hub is not an authority: the CONTROL PLANE allocates the address (so two hubs can't collide), the hub's local responder just delivers it with NO router/gateway option (never makes the audio segment a default route), and the assignment is gossiped so the foreign leaf becomes addressable mesh-wide. If the leaf only self-assigns link-local and won't lease, cope/map it.")
@yah:gotcha("Implementation: an IN-PROCESS DHCP responder, NEVER /etc/bootpd.plist — bootpd's config is shared with Internet Sharing and macOS updates fight over it (the prototype's enable-dhcp.sh is PoC-only). Verify ON THE WIRE that no router/gateway option is emitted; keep the lease pool disjoint from the NodeId hash range (R003-T3).")
-->

<!--
@yah:ticket(R005-T5, "Port pf transport-scope (load/flush/restore; pf off before bridge rebuild) into helper — anchor-based, never whole-ruleset replace")
@yah:at(2026-06-28T02:50:49Z)
@yah:status(done)
@yah:phase(P1)
@yah:parent(R005)
@yah:gotcha("Do NOT port pf-prefer.sh literally: the PoC replaces the ENTIRE ruleset (clobbering Apple's com.apple/* anchors and any VPN/firewall rules) and flushes ALL states globally (-F states kills other software's connections). The helper uses a dedicated ANCHOR (pfctl -a ipauro) spliced into the existing ruleset, and SELECTIVE state kill (pfctl -k on the scoped port/addresses). The shell script is the spec for the cut-and-restore BEHAVIOR (incl. the stateful-pf flush discipline), not for the mechanism.")
-->

<!--
@yah:ticket(R005-T4, "Port bridge discovery + member reconcile (usb-link-bridge.sh) into helper")
@yah:at(2026-06-28T02:50:46Z)
@yah:status(done)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R005-F3, "Desired-state reconciler core in Rust: idempotent + ordered actual->desired passes")
@yah:at(2026-06-28T02:49:27Z)
@yah:status(done)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R005-T2, "Replug self-heal end-to-end: member unplug -> rebuild + app-rebind (M-incident test)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-07-26T01:15:46Z)
@yah:phase(P1)
@yah:parent(R005)
@yah:handoff("The rebuild half was already green on pickup (tests/m_incident.rs). This session built the MISSING app-rebind half — A001's ordered-pass step 5, \"signal the audio app to rejoin the new bridge\", which had no implementation anywhere in the tree.")
@yah:handoff("Primitive: `Snapshot.bridge.epoch` (ipauro-proto, `#[serde(default)]` additive). A data-plane generation that bumps when a fresh bridge interface appears or is re-addressed — the ONLY snapshot field that moves across a blast-radius rebuild, since the bridge returns under the same name with the same address.")
@yah:handoff("Rule: `reconcile::next_epoch` (crates/ipauro-core/src/reconcile.rs). Bumps on `created` (this pass issued CreateBridge) OR on rebind-identity change (name/ipv4). Does NOT bump on membership change (spurious rebind = audible dropout) or on teardown (nothing to bind to). `created` is load-bearing for the REAL macOS path, where a pass opens with the bridge already gone and rebuilds it before anything is reported — identity alone shows no change there.")
@yah:handoff("Consumer wired: `ipauro watch`. `format::rebind_notice` + `client::watch_loop` track the generation from the Hello snapshot and print a rebind notice once per change; `--json` stays machine-clean (epoch already rides the raw line). `pretty_snapshot`/`pretty_event_line` show `gen`.")
@yah:handoff("Tests: 6 new unit tests on `next_epoch`; `MockHelper::destroy_out_of_band` added to model the kernel eating the bridge with no membership change; 2 new integration tests in tests/m_incident.rs (`m_incident_signals_app_rebind_over_the_event_stream` drives a real subscribed client as the audio app and asserts EXACTLY one rebind per unplug + monotonicity; `a_rebuild_within_one_pass_still_signals_a_rebind` covers the field shape); 4 new CLI tests. Both levels mutation-checked — deleting the `created` arm fails the unit test AND the integration test.")
@yah:handoff("Docs: A001's reconcile section now records step 5's mechanism (epoch, level-triggered, what does/doesn't bump).")
@yah:handoff("`cargo test --workspace` fully green. Clippy verified on ipauro-proto + ipauro-cli only — ipauro-core cannot be clippy'd due to pre-existing R002-B9 (filed).")
@yah:verify("cargo test --workspace  # all green as of this session")
@yah:verify("cargo test -p ipauro-core --test m_incident  # 5 tests, ~2s")
@yah:verify("Mutation check: drop the `created ||` in reconcile::next_epoch — `epoch_bumps_on_an_identical_rebuild_within_one_pass` and `a_rebuild_within_one_pass_still_signals_a_rebind` must both fail.")
@yah:gotcha("The epoch is PER SERVICE INSTANCE — it resets with the pid, so an app outliving a service restart rebinds once more than strictly needed. Conservative in the safe direction; pair with `ServiceInfo.pid` to tell instances apart. Persisting it is deliberately not done at M1.")
@yah:gotcha("Followups filed: R005-F9 (UI has no rebind surface — needs a UI-local latched notice, which collides with `state.rs`'s 'no state the service doesn't have' rule) and R002-B9 (pre-existing clippy denial in ipauro-xpc blocking workspace clippy).")
@yah:gotcha("Shared tree: @Ashguard:nautilus (session:e5961b59) is live on R002 and holds uncommitted edits across crates/ipauro-probe/*. Disjoint from this ticket's files (ipauro-proto / ipauro-core / ipauro-cli / app/ui) — do not sweep those into a commit for R005-T2.")
-->

<!--
@yah:ticket(R005-F1, "IOKit USB attach/detach watch in app drives event-driven reconcile")
@yah:at(2026-06-28T02:49:08Z)
@yah:status(done)
@yah:phase(P1)
@yah:parent(R005)
-->

<!--
@yah:ticket(R002-T6, "Start-at-login: brain service registered via SMAppService; the checkbox lives in the UI client over IPC")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
-->

<!--
@yah:ticket(R002-F5, "Fail-open on XPC disconnect: helper restores stock networking on service death (with restart grace)")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("Fail-open keys on the BRAIN SERVICE's XPC connection, never the UI client — UI quit/crash/upgrade must not touch the mesh (that's the point of the brain/face split). Add a short grace window so a service restart or upgrade doesn't needlessly tear down and rebuild the mesh mid-session; the grace still fails open if no reconnect arrives.")
-->

<!--
@yah:ticket(R002-F4, "Helper bridge90 create/destroy over XPC; wire tray button")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
-->

<!--
@yah:ticket(R002-T3, "XPC channel service<->helper: narrow, validated, caller-authenticated command API")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("'Validated' means AUTHENTICATE THE CALLER, not just the message schema: verify the connecting process's code signature via its audit token (SecCodeCopyGuestWithAttributes), require same team ID + a minimum version, reject everything else. An unauthenticated root-helper Mach service that rewrites pf and creates bridges is a classic macOS local-privilege-escalation shape (the Docker vmnetd CVE class). Version the XPC protocol from day one — app and helper upgrade on different schedules.")
-->

<!--
@yah:ticket(R002-T2, "SMAppService root helper daemon: register + one-time install auth dialog")
@yah:at(2026-06-28T02:49:00Z)
@yah:status(done)
@yah:phase(P0)
@yah:parent(R002)
@yah:gotcha("Developer ID signing must be stood up HERE (M0), not M5: SMAppService registration effectively requires a properly signed app bundle with the helper embedded (Contents/Library/LaunchDaemons plist + bundle-program requirements). R007-T5 at P5 is only the final notarization/distribution polish, not the first time code gets signed.")
-->

<!--
@yah:ticket(R002-T1, "Scaffold Rust workspace: brain service (launchd-managed) + SMAppService helper + compact egui tray client")
@yah:assignee(agent:fable-manager)
@yah:status(done)
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
> service). **R002-T8 settled the grant-context question on 2026-07-25:** a user LaunchAgent does
> hold the Local Network grant, so the "holds Local Network grant" row moves to the brain service
> with no caveat, and Thread 2's implication that only a *GUI* app can hold it is obsolete —
> measured matrix, method and limits in A002, "execution-context matrix, measured (R002-T8)".
> Where this doc and W001 differ, **W001 wins.** Read W001 first.
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

**Step 5's mechanism is a data-plane generation counter, `Snapshot.bridge.epoch`** (R005-T2).
The rebuilt bridge comes back under the same name with the same address, so an app diffing the
snapshot sees a perfectly steady bridge while its multicast socket sits on a dead ifindex —
the epoch is the only field that moves. It bumps when a *fresh* interface appears or the
existing one is re-addressed, and deliberately NOT on a membership change (a spurious rebind
costs an audible dropout) or on teardown (nothing to bind to). Level-triggered on purpose: an
app records the epoch it bound at and compares it against every snapshot, including `Hello`'s,
so an app that was disconnected across the rebuild still notices on reconnect — an
edge-triggered "rebind now" event would be missable exactly when it matters. `ipauro watch` is
the reference consumer (`ipauro_cli::format::rebind_notice`).

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
