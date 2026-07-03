# ipauro-probe RUNBOOK — R002-T8: mapping the macOS 15+ Local Network gate

`ipauro-probe` is a diagnostic CLI, not a feature of the product. It exists to
answer one empirical question per execution context: **does this process hold
the macOS 15+ "Local Network" privacy grant for multicast**, on the exact
group/port Ableton Link uses (`224.76.78.75:20808`)?

Background: `.yah/docs/architecture/A001-ipauro-architecture.md` (ticket
`R002-T8`) and `.yah/docs/architecture/A002-ipauro-findings.md` ("macOS 15
'Local Network' privacy gate"). The short version: macOS 15 (Sequoia) gates
local multicast/subnet traffic behind a per-app permission with a GUI prompt.
A process that can't show the prompt (SSH, headless, some launchd contexts)
may be **silently denied** — packets still land on the wire (visible to
`tcpdump`/BPF, which sits below the gate) but never reach the app's socket.
Sonoma 14 and earlier have no such gate at all.

This tool automates the empirical test from A002: send a beacon, see if our
own socket receives it back via multicast loopback. `check`'s exit code
encodes the verdict:

| exit | meaning |
|---|---|
| `0` | **GATE OPEN** — received our own beacon back; app-layer multicast reception works here. |
| `4` | **SILENT DENY** — beacons were sent but none came back; the gate's signature. Cross-check with `tcpdump` (below) to confirm it's a privacy denial and not something else. |
| `1` | Setup error, or inconclusive (nothing was ever sent — see stderr for the underlying error). |

## Quick start

```sh
cargo build --release -p ipauro-probe
BIN=./target/release/ipauro-probe

# One-shot verdict for the current context:
$BIN check --seconds 5

# Or run the two halves separately (e.g. in two terminals) to eyeball traffic:
$BIN listen                       # prints one line per datagram: ts, src, summary
$BIN beacon --interval-ms 500     # sends "IPAURO-PROBE v0 host=... pid=... seq=..."
```

`--iface <name>` (e.g. `en0`, `bridge90`, `lo0`) scopes multicast group
membership / `IP_MULTICAST_IF` to that interface; omitted, the OS picks the
default. `--port` / `--group` default to Link's own `20808` / `224.76.78.75`.

`listen` labels every datagram it doesn't recognize as `foreign (Link?)` —
including real Ableton Link traffic, which it deliberately never parses.

## The R002-T8 execution-context matrix

Fill this in by running `check` (or the launchd plists below) in each
context, on both a Sonoma 14 (no gate — expect all-pass) and a Sequoia 15+
Mac. This is the deliverable of R002-T8: it pins where the brain
service/beacon/forwarder can safely live.

| Execution context | OS | Prompt shown? | Granted? | `check` exit | Verdict text | Notes |
|---|---|---|---|---|---|---|
| GUI Terminal.app | | | | | | |
| Over SSH | | | | | | |
| Root LaunchDaemon (`launchctl bootstrap system/...`) | | | | | | |
| User LaunchAgent, Aqua session (`launchctl bootstrap gui/<uid>/...`) | | | | | | |
| Inside the signed app bundle | | | | | | *(later — pending R002-T2/R007-T5 signing+bundling; no bundle exists yet)* |

How to fill each row:
1. Run `ipauro-probe check --seconds 10` (or install the matching plist below)
   in that context.
2. Note whether System Settings → Privacy & Security → Local Network showed a
   new prompt for the binary (or already had an entry — check the list even
   if no prompt appeared this run; a prior grant/denial persists silently).
3. Record the `check` exit code and the printed verdict line.
4. If exit is `4` (silent deny) or ambiguous, run the wire cross-check below
   in parallel to confirm packets really are arriving at the NIC.

Observed in this agent's non-interactive sandbox shell (`sw_vers` reports
macOS 26.5.1 — post-Sequoia; `uname`-visible sandbox, not itself a matrix row
since it's neither an Aqua GUI Terminal session nor a real SSH login, and the
sandboxing may itself affect the result in ways a bare-metal Mac wouldn't
see): `check --seconds 3 --iface lo0` and the default-interface run both
returned exit `0` (`GATE OPEN`, all beacons looped back). That establishes
the tool itself works end-to-end over loopback multicast, and hints the gate
(if present at all in this OS/sandbox combination) doesn't block loopback
multicast from this shell — it is not a substitute for running the real
matrix on target hardware across the named contexts.

### GUI Terminal.app / over SSH

No plist needed — just run the `check` quick-start command directly in each
context. Same machine, same OS, same build; the only variable is launch
context, exactly per A002's Falcon-was-innocent finding (SSH-launched was
silently denied; the same binary from GUI Terminal.app worked instantly).

### Root LaunchDaemon

```sh
cargo build --release -p ipauro-probe
BIN_PATH="$(pwd)/target/release/ipauro-probe"
sed "s#__IPAURO_PROBE_BIN__#${BIN_PATH}#" crates/ipauro-probe/dev/io.ipauro.probe.daemon.plist \
  | sudo tee /Library/LaunchDaemons/io.ipauro.probe.daemon.plist > /dev/null
sudo chown root:wheel /Library/LaunchDaemons/io.ipauro.probe.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/io.ipauro.probe.daemon.plist

# Load + run once (RunAtLoad):
sudo launchctl bootstrap system /Library/LaunchDaemons/io.ipauro.probe.daemon.plist

# Inspect: check state + last exit status once the 10s check window has passed.
sudo launchctl print system/io.ipauro.probe.daemon | grep -E "state|last exit"
cat /tmp/ipauro-probe-daemon.log /tmp/ipauro-probe-daemon.err.log

# Unload:
sudo launchctl bootout system/io.ipauro.probe.daemon
sudo rm /Library/LaunchDaemons/io.ipauro.probe.daemon.plist
```

`check`'s exit code becomes the daemon's process exit status — read it via
`launchctl print`'s `last exit code` field, and the verdict line from the log.

### User LaunchAgent (Aqua session)

```sh
cargo build --release -p ipauro-probe
BIN_PATH="$(pwd)/target/release/ipauro-probe"
mkdir -p ~/Library/LaunchAgents
sed "s#__IPAURO_PROBE_BIN__#${BIN_PATH}#" crates/ipauro-probe/dev/io.ipauro.probe.agent.plist \
  > ~/Library/LaunchAgents/io.ipauro.probe.agent.plist

# Load + run once, into the current GUI session (must be run FROM a logged-in
# Aqua session for the gui/<uid> domain to exist):
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.ipauro.probe.agent.plist

launchctl print gui/$(id -u)/io.ipauro.probe.agent | grep -E "state|last exit"
cat /tmp/ipauro-probe-agent.log /tmp/ipauro-probe-agent.err.log

# Unload:
launchctl bootout gui/$(id -u)/io.ipauro.probe.agent
rm ~/Library/LaunchAgents/io.ipauro.probe.agent.plist
```

This is the context R002-T8's gotcha is most worried about: Apple's docs
suggest a `gui/<uid>` agent **can be denied without ever showing a prompt**.
If this row comes back `4` (SILENT DENY) on Sequoia while GUI Terminal.app
comes back `0`, that's the confirmation — the brain service cannot rely on
plain LaunchAgent placement alone for the Link/multicast-touching parts;
see A001 ticket R002-T8's fallback (delegate multicast ops to a granted
context) and Thread 2's tray/helper split.

### Inside the app bundle (later)

No app bundle exists yet (`R002-T2`/`R007-T5` — Developer ID signing +
`SMAppService`-registered bundle are still open). When one exists, repeat the
LaunchAgent test with the binary embedded in
`Contents/Library/LaunchAgents/` (or `SMAppService.agent`/`.daemon`
registration) instead of an ad-hoc plist, since bundle identity + code
signature are exactly what the privacy grant is scoped to.

## Wire cross-check (BPF sees below the gate)

The gate operates above the kernel's packet capture point, so `tcpdump` sees
traffic the app never does — this is the A002 diagnostic method itself, and
the way to disambiguate "SILENT DENY" from "nothing was on the wire at all"
(e.g. a routing/firewall/interface problem instead of a privacy denial):

```sh
sudo tcpdump -ni <iface> 'udp port 20808'
```

Run this in parallel with `check` (or the daemon/agent plist) in another
terminal/session that DOES hold the grant (or just as root, which sees
everything regardless of the gate). Interpretation:

- **Wire-visible + app-silent** (tcpdump shows the beacon; `check` reports
  `received-own: 0`) → confirms Local Network privacy denial, not a network
  problem. This is the exact symptom that was originally misattributed to
  CrowdStrike Falcon in A002 before the real cause was found.
- **Wire-silent** (tcpdump shows nothing either) → not a privacy-gate issue;
  look at interface selection, routing, or whether the beacon socket actually
  sent (check stderr / the `beacon` command's own stdout for send errors).

## Sonoma 14 baseline

macOS 14 (Sonoma) and earlier have no Local Network privacy gate at all. Every
row of the matrix run on a Sonoma machine is expected to come back `0` (GATE
OPEN) regardless of launch context — this is the control case. If a Sonoma
run ever comes back `4`, that points at something else (firewall, EDR,
routing) rather than the gate this tool targets, and is worth investigating
separately before trusting a Sequoia `4` result as gate-specific.
