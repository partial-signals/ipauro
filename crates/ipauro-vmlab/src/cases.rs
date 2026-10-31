//! The named L2 cases (W001 §9 tier 2). Each one is an A002 finding turned
//! into an assertion against a real macOS kernel: real `if_bridge`, real pf,
//! real IGMP — with every observation taken from OUTSIDE the guest, on the
//! segment sockets.
//!
//! The discipline every pf case follows (A002 "pf is STATEFUL"): a verdict
//! about a rule is only ever read off a session that was STARTED AFTER the
//! rule loaded. A session that merely stayed up proves nothing, because pf
//! consults its state table before its ruleset. The cases also run the
//! converse on purpose — `pf-stateful-trap` loads a rule under a live session
//! WITHOUT flushing and asserts the stale flow keeps flowing — so the harness
//! itself is shown able to see the trap it guards against.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Child, ChildStdin};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use std::io::Write;

use crate::agent::Tick;
use crate::frame::{Mac, Parsed};
use crate::lima::{Lima, iface_with_mac};
use crate::segment::{AGENT_MAGIC, LINK_GROUP, Peer, Segment, payload_peer};

pub const GUEST_A: Mac = [0x52, 0x55, 0x55, 0xa0, 0, 1];
pub const GUEST_B: Mac = [0x52, 0x55, 0x55, 0xb0, 0, 1];
const PEER_A: Mac = [0x52, 0x55, 0x55, 0xa0, 0, 2];
const PEER_B: Mac = [0x52, 0x55, 0x55, 0xb0, 0, 2];
/// Ours, by name, so reset can never destroy a bridge something else made.
const BRIDGE: &str = "bridge69";
const GUEST_AGENT: &str = "/tmp/ipauro-vmlab";
const GUEST_HELPER: &str = "/tmp/ipauro-helper";
const PORT: u16 = crate::segment::LINK_PORT;

pub const CASES: &[&str] = &[
    "bridge-floods-member-multicast",
    "bridge-host-multicast-egress",
    "pf-stateful-trap",
    "pf-scope-forces-onto-interface",
    "pf-scope-on-bridge-keeps-forwarding",
];

#[derive(Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub failed: usize,
    pub passed: usize,
}

impl Report {
    fn check(&mut self, case: &str, ok: bool, what: impl Into<String>) {
        let what = what.into();
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        let line = format!("{} {case}: {what}", if ok { "PASS" } else { "FAIL" });
        eprintln!("{line}");
        self.lines.push(line);
    }
    fn info(&mut self, case: &str, what: impl Into<String>) {
        let line = format!("info {case}: {}", what.into());
        eprintln!("{line}");
        self.lines.push(line);
    }
}

/// One agent process in the guest = one Link session.
struct Session {
    child: Child,
    rx: Receiver<(Instant, String)>,
    first: Instant,
    early: Vec<(Instant, String)>,
}

struct SessionLog {
    ticks: Vec<(Instant, Tick)>,
    summary: Tick,
}

impl SessionLog {
    /// Datagrams from `peer` the agent's sockets received in ticks that
    /// ARRIVED within `[from, to)`.
    fn rx(&self, peer: &str, from: Instant, to: Instant) -> u64 {
        self.ticks.iter().filter(|(at, _)| *at >= from && *at < to).filter_map(|(_, t)| t.rx.get(peer)).sum()
    }
}

impl Session {
    fn finish(mut self) -> Result<SessionLog> {
        let status = self.child.wait()?;
        if !status.success() {
            bail!("guest agent exited {status}");
        }
        let mut lines = std::mem::take(&mut self.early);
        lines.extend(self.rx.try_iter());
        let mut ticks = Vec::new();
        let mut summary = None;
        for (at, line) in lines {
            let t: Tick = serde_json::from_str(&line).with_context(|| format!("agent line {line:?}"))?;
            if t.done {
                summary = Some(t);
            } else {
                ticks.push((at, t));
            }
        }
        Ok(SessionLog { ticks, summary: summary.context("agent printed no summary line")? })
    }
}

struct PfConsole {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<(Instant, String)>,
}

impl PfConsole {
    fn cmd(&mut self, line: &str) -> Result<String> {
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;
        let (_, reply) = self.rx.recv_timeout(Duration::from_secs(60)).context("helper --pf-console did not answer")?;
        match reply.strip_prefix("ok") {
            Some(rest) => Ok(rest.trim().to_string()),
            None => bail!("helper refused `{line}`: {reply}"),
        }
    }
    fn close(mut self) -> Result<()> {
        drop(self.stdin);
        let status = self.child.wait()?;
        if !status.success() {
            bail!("helper --pf-console exited {status}");
        }
        Ok(())
    }
}

pub struct Lab {
    pub lima: Lima,
    pub a: Segment,
    pub b: Segment,
    ia: String,
    ib: String,
}

fn after(t: Instant, ms: u64) -> Instant {
    t + Duration::from_millis(ms)
}

/// Frames on `seg` within `[from, to)` that carry a Link-port UDP datagram
/// whose payload satisfies `pred`, as `(dst ip, payload)`.
fn link_udp(seg: &Segment, from: Instant, to: Instant) -> Vec<(Mac, Ipv4Addr, Vec<u8>)> {
    seg.captured_since(from)
        .into_iter()
        .filter(|c| c.at < to)
        .filter_map(|c| match c.frame.parsed {
            Parsed::Udp { src, dst, payload } if src.1 == PORT || dst.1 == PORT => Some((c.frame.src_mac, dst.0, payload)),
            // Not Link traffic: ARP, IGMP, IPv6 ND, other UDP.
            Parsed::Udp { .. } | Parsed::Arp { .. } | Parsed::Other { .. } => None,
        })
        .collect()
}

fn agent_mcast(frames: &[(Mac, Ipv4Addr, Vec<u8>)]) -> usize {
    frames.iter().filter(|(_, d, p)| *d == LINK_GROUP && p.starts_with(AGENT_MAGIC)).count()
}
fn agent_unicast(frames: &[(Mac, Ipv4Addr, Vec<u8>)], to: Ipv4Addr) -> usize {
    frames.iter().filter(|(_, d, p)| *d == to && p.starts_with(AGENT_MAGIC)).count()
}
fn from_peer(frames: &[(Mac, Ipv4Addr, Vec<u8>)], peer: &str) -> Vec<Mac> {
    frames.iter().filter(|(_, _, p)| payload_peer(p) == Some(peer)).map(|(m, _, _)| *m).collect()
}

impl Lab {
    pub fn new(lima: Lima, a: Segment, b: Segment) -> Result<Self> {
        let ifc = lima.sh("ifconfig -a")?;
        let ia = iface_with_mac(&ifc, GUEST_A).context("no guest NIC carries segment A's MAC — are the socket networks attached?")?;
        let ib = iface_with_mac(&ifc, GUEST_B).context("no guest NIC carries segment B's MAC")?;
        eprintln!("guest NICs: segment a = {ia}, segment b = {ib}");
        Ok(Lab { lima, a, b, ia, ib })
    }

    pub fn install(&self, agent: &Path, helper: &Path) -> Result<()> {
        self.lima.copy_in(agent, GUEST_AGENT)?;
        self.lima.copy_in(helper, GUEST_HELPER)?;
        Ok(())
    }

    /// Back to stock: no agents, no bridge of ours, no addresses on the test
    /// NICs, stock /etc/pf.conf, pf disabled with an empty state table.
    /// Run before every case so no case inherits another's state.
    fn reset(&self) -> Result<()> {
        let (ia, ib) = (&self.ia, &self.ib);
        self.lima.sh(&format!(
            "sudo pkill -f '{GUEST_AGENT} guest' ; sudo pkill -f '{GUEST_HELPER}' ; \
             sudo ifconfig {BRIDGE} destroy 2>/dev/null ; \
             for i in {ia} {ib}; do for a in $(ifconfig $i | awk '/inet /{{print $2}}'); do sudo ifconfig $i -alias $a; done; sudo ifconfig $i up; done ; \
             sudo pfctl -a ipauro -F all 2>/dev/null ; sudo sed -i '' '/ipauro/d' /etc/pf.conf ; \
             sudo pfctl -f /etc/pf.conf 2>/dev/null ; sudo pfctl -d 2>/dev/null ; sudo pfctl -F states 2>/dev/null ; true"
        ))?;
        self.a.clear_peers();
        self.b.clear_peers();
        Ok(())
    }

    /// The A002 precondition for the stateful trap: pf already enabled with a
    /// STATEFUL pass, as on the bench Mac. A stock macOS pf.conf has no pass
    /// rule at all, and pf passes unmatched packets WITHOUT creating state —
    /// so on a stock guest no flow ever has state, the trap cannot occur, and
    /// every "the scope cut a live session" check would pass vacuously.
    /// UDP only: the trap is a UDP-flow phenomenon, and a TCP pass would
    /// adopt lima's already-established SSH session mid-stream — measured to
    /// kill it intermittently (exit 255) even with `flags any`, since pf
    /// picking up a connection mid-stream never saw its window scaling.
    /// Unmatched TCP stays stateless and untouched. Inserted ABOVE where the
    /// helper appends its anchor point, so the anchor's `quick` rules still
    /// get the last word. `reset` removes it (the line carries "ipauro").
    fn pf_fixture(&self) -> Result<()> {
        self.lima.sh(
            "printf 'pass proto udp all keep state # ipauro-vmlab fixture\\n' | sudo tee -a /etc/pf.conf >/dev/null && \
             sudo pfctl -f /etc/pf.conf 2>/dev/null && sudo pfctl -e 2>/dev/null; sudo pfctl -s info | head -1",
        )?;
        Ok(())
    }

    /// Two separate L3 links, like the A002 "USB vs WiFi" pair.
    fn l3(&self, beacon: bool) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let (ga, gb) = (Ipv4Addr::new(10, 70, 1, 1), Ipv4Addr::new(10, 70, 2, 1));
        self.lima.sh(&format!(
            "sudo ifconfig {} inet {ga} netmask 255.255.255.0 up && sudo ifconfig {} inet {gb} netmask 255.255.255.0 up",
            self.ia, self.ib
        ))?;
        self.a.add_peer(Peer { name: "pa".into(), mac: PEER_A, ip: Ipv4Addr::new(10, 70, 1, 2), beacon, unicast_to: vec![ga] });
        self.b.add_peer(Peer { name: "pb".into(), mac: PEER_B, ip: Ipv4Addr::new(10, 70, 2, 2), beacon, unicast_to: vec![gb] });
        Ok((ga, gb))
    }

    /// The relay shape: both NICs as members of one bridge, the address on
    /// the bridge (A002 predictable #5), one subnet for everyone.
    fn bridged(&self, beacon: bool) -> Result<Ipv4Addr> {
        let g = Ipv4Addr::new(10, 69, 0, 1);
        self.lima.sh(&format!(
            "sudo ifconfig {BRIDGE} create && sudo ifconfig {BRIDGE} addm {} addm {} up && \
             sudo ifconfig {BRIDGE} inet {g} netmask 255.255.255.0",
            self.ia, self.ib
        ))?;
        self.a.add_peer(Peer { name: "pa".into(), mac: PEER_A, ip: Ipv4Addr::new(10, 69, 0, 2), beacon, unicast_to: vec![g] });
        self.b.add_peer(Peer { name: "pb".into(), mac: PEER_B, ip: Ipv4Addr::new(10, 69, 0, 3), beacon, unicast_to: vec![g] });
        Ok(g)
    }

    fn agent(&self, ifaces: &[&str], unicast: &[Ipv4Addr], seconds: f64) -> Result<Session> {
        let mut cmd = format!("sudo {GUEST_AGENT} guest --seconds {seconds}");
        for i in ifaces {
            cmd.push_str(&format!(" --iface {i}"));
        }
        for u in unicast {
            cmd.push_str(&format!(" --unicast {u}"));
        }
        let (child, rx) = self.lima.spawn(&cmd)?;
        // Session start = the first tick reaching the host, not the spawn:
        // `limactl shell` costs a variable ssh round-trip before the agent runs.
        let first = rx.recv_timeout(Duration::from_secs(60)).context("guest agent produced no output")?;
        Ok(Session { child, rx, first: first.0, early: vec![first] })
    }

    fn pf_console(&self) -> Result<PfConsole> {
        let (mut child, rx) = self.lima.spawn(&format!("sudo IPAURO_INSECURE_DEV=1 {GUEST_HELPER} --pf-console"))?;
        let stdin = child.stdin.take().expect("piped");
        Ok(PfConsole { child, stdin, rx })
    }

    pub fn run(&self, only: Option<&str>) -> Result<Report> {
        let mut r = Report::default();
        for &case in CASES {
            if only.is_some_and(|o| o != case) {
                continue;
            }
            eprintln!("== {case}");
            self.reset()?;
            let res = match case {
                "bridge-floods-member-multicast" => self.bridge_floods(&mut r, case),
                "bridge-host-multicast-egress" => self.host_egress(&mut r, case),
                "pf-stateful-trap" => self.stateful_trap(&mut r, case),
                "pf-scope-forces-onto-interface" => self.scope_forces(&mut r, case),
                "pf-scope-on-bridge-keeps-forwarding" => self.scope_on_bridge(&mut r, case),
                other => bail!("case {other} is listed in CASES but has no body"),
            };
            if let Err(e) = res {
                r.check(case, false, format!("case aborted: {e:#}"));
            }
        }
        self.reset()?;
        Ok(r)
    }

    /// A002 predictable #2: `if_bridge` floods member↔member multicast,
    /// unmodified, and never back out the ingress port. Built, measured,
    /// torn down and REBUILT, then measured again — "re-run on replug" is a
    /// first-class requirement (A002 wrangle-able #1), so one good bridge is
    /// not the claim.
    fn bridge_floods(&self, r: &mut Report, case: &str) -> Result<()> {
        for round in ["built", "rebuilt"] {
            if round == "rebuilt" {
                self.reset()?;
            }
            self.bridged(true)?;
            let t0 = Instant::now();
            thread::sleep(Duration::from_secs(3));
            // Skip the first second: the member ports pass through a
            // learning/forwarding delay after `addm` on some kernels.
            let (from, to) = (after(t0, 1000), Instant::now());
            let (on_a, on_b) = (link_udp(&self.a, from, to), link_udp(&self.b, from, to));
            let a_to_b = from_peer(&on_b, "pa");
            let b_to_a = from_peer(&on_a, "pb");
            r.check(case, a_to_b.len() >= 10, format!("[{round}] pa's multicast forwarded onto segment b: {} frames in 2s", a_to_b.len()));
            r.check(case, b_to_a.len() >= 10, format!("[{round}] pb's multicast forwarded onto segment a: {} frames in 2s", b_to_a.len()));
            r.check(
                case,
                a_to_b.iter().all(|m| *m == PEER_A) && b_to_a.iter().all(|m| *m == PEER_B),
                format!("[{round}] forwarded frames keep the originating peer's source MAC (L2 bridge, not a router)"),
            );
            let hairpin = from_peer(&on_a, "pa").len() + from_peer(&on_b, "pb").len();
            r.check(case, hairpin == 0, format!("[{round}] nothing flooded back out its ingress port: {hairpin} frames"));
        }
        Ok(())
    }

    /// A002 "HUB-AS-PEER": the relay's OWN multicast, sent from a socket on
    /// the bridge interface, egresses every member; the relay's group join on
    /// the bridge receives from every member; unicast is learned, not flooded.
    fn host_egress(&self, r: &mut Report, case: &str) -> Result<()> {
        let g = self.bridged(true)?;
        let (pa, pb) = (Ipv4Addr::new(10, 69, 0, 2), Ipv4Addr::new(10, 69, 0, 3));
        thread::sleep(Duration::from_secs(1)); // let both peers be learned
        let s = self.agent(&[BRIDGE], &[pa, pb], 4.0)?;
        let first = s.first;
        let log = s.finish()?;
        let (from, to) = (after(first, 500), after(first, 3500));
        let (on_a, on_b) = (link_udp(&self.a, from, to), link_udp(&self.b, from, to));
        r.check(case, agent_mcast(&on_a) >= 10, format!("relay-originated multicast reaches member a: {}", agent_mcast(&on_a)));
        r.check(case, agent_mcast(&on_b) >= 10, format!("relay-originated multicast reaches member b: {}", agent_mcast(&on_b)));
        r.check(
            case,
            agent_unicast(&on_a, pa) >= 10 && agent_unicast(&on_b, pa) == 0,
            format!("unicast to pa is learned onto a only: a={} b={}", agent_unicast(&on_a, pa), agent_unicast(&on_b, pa)),
        );
        r.check(
            case,
            agent_unicast(&on_b, pb) >= 10 && agent_unicast(&on_a, pb) == 0,
            format!("unicast to pb is learned onto b only: b={} a={}", agent_unicast(&on_b, pb), agent_unicast(&on_a, pb)),
        );
        let (rx_a, rx_b) = (log.rx("pa", from, to), log.rx("pb", from, to));
        r.check(case, rx_a > 0 && rx_b > 0, format!("the bridge-bound app hears both members (join on {BRIDGE} at {g}): pa={rx_a} pb={rx_b}"));
        Ok(())
    }

    /// A002's trap, reproduced on purpose: a block rule loaded under a LIVE
    /// session does not stop it, because the flow's state entry is consulted
    /// before the ruleset; flushing states does. If this case ever fails its
    /// first check, the kernel's pf changed and A002 needs revisiting — and
    /// until then it proves this harness can see a stale-state survivor.
    fn stateful_trap(&self, r: &mut Report, case: &str) -> Result<()> {
        self.pf_fixture()?;
        let (ga, gb) = self.l3(true)?;
        let (pa, pb) = (Ipv4Addr::new(10, 70, 1, 2), Ipv4Addr::new(10, 70, 2, 2));
        let s = self.agent(&[&self.ia, &self.ib], &[pa, pb], 10.0)?;
        thread::sleep(after(s.first, 2000).saturating_duration_since(Instant::now()));
        let rules = format!(
            "pass quick on {ia} proto udp from any to any port {PORT}\npass quick on {ia} proto udp from any port {PORT} to any\n\
             block drop quick proto udp from any to any port {PORT}\nblock drop quick proto udp from any port {PORT} to any\n",
            ia = self.ia
        );
        // Deliberately NOT the helper: this is the naive load, no flush.
        self.lima.sh(&format!(
            "printf 'anchor \"ipauro\"\\n' | sudo tee -a /etc/pf.conf >/dev/null && sudo pfctl -f /etc/pf.conf 2>/dev/null && \
             sudo pfctl -E 2>/dev/null; printf '{}' | sudo pfctl -a ipauro -f -",
            rules.replace('\n', "\\n")
        ))?;
        let loaded = Instant::now();
        thread::sleep(Duration::from_millis(2500));
        self.lima.sh("sudo pfctl -F states 2>/dev/null")?;
        let flushed = Instant::now();
        let log = s.finish()?;

        let stale = link_udp(&self.b, after(loaded, 500), flushed);
        let stale_uni = agent_unicast(&stale, pb);
        r.check(case, stale_uni > 0, format!("TRAP: the established unicast flow on b survives a loaded block rule: {stale_uni} frames"));
        r.info(case, format!("stale-state survivors on b, multicast leg: {}", agent_mcast(&stale)));
        let post = link_udp(&self.b, after(flushed, 500), Instant::now());
        r.check(
            case,
            agent_unicast(&post, pb) + agent_mcast(&post) == 0,
            format!("after `pfctl -F states` the same session is cut on b: {} frames", agent_unicast(&post, pb) + agent_mcast(&post)),
        );
        let a_post = agent_unicast(&link_udp(&self.a, after(flushed, 500), Instant::now()), pa);
        r.check(case, a_post > 0, format!("...and keeps flowing on the allowed interface a: {a_post} frames"));
        r.info(case, format!("agent rx: pa={} pb={} (guest {ga}/{gb})", log.summary.rx.get("pa").unwrap_or(&0), log.summary.rx.get("pb").unwrap_or(&0)));
        Ok(())
    }

    /// The shipped helper's `ScopeUdp` — anchor point appended to a stock
    /// pf.conf, reference-counted enable, per-interface state flush — forces
    /// a Link-shaped app onto one interface. Verified the A002 way:
    /// teardown-and-re-establish, both when scoping and when clearing.
    fn scope_forces(&self, r: &mut Report, case: &str) -> Result<()> {
        self.pf_fixture()?;
        self.l3(true)?;
        let (pa, pb) = (Ipv4Addr::new(10, 70, 1, 2), Ipv4Addr::new(10, 70, 2, 2));
        let ifaces = [self.ia.as_str(), self.ib.as_str()];
        let mut pf = self.pf_console()?;

        // 1. Baseline: an unscoped session uses both links.
        let base = self.agent(&ifaces, &[pa, pb], 3.0)?;
        let first = base.first;
        base.finish()?;
        let b_base = link_udp(&self.b, after(first, 500), Instant::now());
        r.check(case, agent_mcast(&b_base) > 0 && agent_unicast(&b_base, pb) > 0, "baseline: an unscoped session uses link b");

        // 2. Scope while a session is LIVE: the helper's own flush must cut
        //    it (this is `flush_affected_states`' `-F states -i` per iface).
        let live = self.agent(&ifaces, &[pa, pb], 6.0)?;
        thread::sleep(after(live.first, 1500).saturating_duration_since(Instant::now()));
        let states_b = format!("sudo pfctl -s states 2>/dev/null | grep -F '{pb}:{PORT}' || true");
        r.info(case, format!("link-b states before scope: {:?}", self.lima.sh(&states_b)?.lines().collect::<Vec<_>>()));
        pf.cmd(&format!("scope {PORT} {}", self.ia))?;
        let scoped = Instant::now();
        r.info(case, format!("link-b states after scope: {:?}", self.lima.sh(&states_b)?.lines().collect::<Vec<_>>()));
        live.finish()?;
        let b_live = link_udp(&self.b, after(scoped, 500), Instant::now());
        r.check(
            case,
            b_live.is_empty(),
            format!("helper scope cuts an ALREADY-LIVE session off link b (its own state flush works): {} frames", b_live.len()),
        );
        let conf = self.lima.sh("grep -c '^anchor \"ipauro\"' /etc/pf.conf || true")?;
        r.check(case, conf.trim() == "1", format!("anchor point appended to a stock /etc/pf.conf exactly once: {}", conf.trim()));

        // 3. THE verdict: a session established AFTER the scope.
        let fresh = self.agent(&ifaces, &[pa, pb], 4.0)?;
        let first = fresh.first;
        let log = fresh.finish()?;
        let (from, to) = (after(first, 250), Instant::now());
        let (on_a, on_b) = (link_udp(&self.a, from, to), link_udp(&self.b, from, to));
        r.check(case, on_b.is_empty(), format!("re-established session emits nothing on link b: {} frames", on_b.len()));
        r.check(
            case,
            agent_mcast(&on_a) > 0 && agent_unicast(&on_a, pa) > 0,
            format!("...and both legs on link a: mcast={} unicast={}", agent_mcast(&on_a), agent_unicast(&on_a, pa)),
        );
        let (rx_a, rx_b) = (log.rx("pa", from, to), log.rx("pb", from, to));
        r.check(case, rx_a > 0 && rx_b == 0, format!("...and hears only link a's peer: pa={rx_a} pb={rx_b}"));
        r.info(case, format!("send errors on blocked link (pf drop on output): {:?}", log.summary.tx_err));

        // 4. A second scope call is idempotent on pf.conf.
        pf.cmd(&format!("scope {PORT} {}", self.ia))?;
        let conf = self.lima.sh("grep -c '^anchor \"ipauro\"' /etc/pf.conf || true")?;
        r.check(case, conf.trim() == "1", format!("a repeated scope does not re-append the anchor point: {}", conf.trim()));

        // 5. Clear, then re-establish: both links come back (fail-open shape).
        pf.cmd("clear")?;
        let back = self.agent(&ifaces, &[pa, pb], 3.0)?;
        let first = back.first;
        back.finish()?;
        let b_back = link_udp(&self.b, after(first, 500), Instant::now());
        r.check(case, agent_mcast(&b_back) > 0, format!("after clear, a re-established session uses link b again: {}", agent_mcast(&b_back)));
        let enabled = self.lima.sh("sudo pfctl -s info 2>/dev/null | head -1")?;
        r.info(case, format!("pf after clear (the helper released its -E reference): {}", enabled.trim()));
        pf.close()
    }

    /// A002 hub-as-peer requirement (3): a relay that scopes Link onto its
    /// bridge must keep (a) its own multicast egressing every member and (b)
    /// member↔member forwarding. pf can see bridged frames on the members as
    /// well as on the bridge, and the helper's block rule is interface-
    /// unqualified — so this is where a scope could silently cut the very
    /// mesh it was meant to protect.
    fn scope_on_bridge(&self, r: &mut Report, case: &str) -> Result<()> {
        self.pf_fixture()?;
        self.bridged(true)?;
        let sysctl = self.lima.sh("sysctl net.link.bridge 2>/dev/null || true")?;
        r.info(case, format!("bridge pfil knobs: {}", sysctl.split_whitespace().collect::<Vec<_>>().join(" ")));
        let mut pf = self.pf_console()?;
        pf.cmd(&format!("scope {PORT} {BRIDGE}"))?;
        let (pa, pb) = (Ipv4Addr::new(10, 69, 0, 2), Ipv4Addr::new(10, 69, 0, 3));
        let s = self.agent(&[BRIDGE], &[pa, pb], 4.0)?;
        let first = s.first;
        let log = s.finish()?;
        let (from, to) = (after(first, 500), after(first, 3500));
        let (on_a, on_b) = (link_udp(&self.a, from, to), link_udp(&self.b, from, to));
        r.check(case, agent_mcast(&on_a) > 0 && agent_mcast(&on_b) > 0, format!(
            "scoped to {BRIDGE}, the relay's multicast still reaches both members: a={} b={}", agent_mcast(&on_a), agent_mcast(&on_b)));
        let (fwd_ab, fwd_ba) = (from_peer(&on_b, "pa").len(), from_peer(&on_a, "pb").len());
        r.check(case, fwd_ab > 0 && fwd_ba > 0, format!("member↔member forwarding survives the scope: a→b={fwd_ab} b→a={fwd_ba}"));
        let (rx_a, rx_b) = (log.rx("pa", from, to), log.rx("pb", from, to));
        r.check(case, rx_a > 0 && rx_b > 0, format!("the scoped relay app hears both members: pa={rx_a} pb={rx_b}"));
        pf.cmd("clear")?;
        pf.close()
    }
}
