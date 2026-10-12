# ipauro-probe RUNBOOK — R002-T8: mapping the macOS Local Network gate

`ipauro-probe` is a diagnostic CLI, not a feature of the product. It exists to
answer, per execution context: **does this process hold macOS 15+'s "Local
Network" privacy grant for multicast**, on the exact group/port Ableton Link
uses (`224.76.78.75:20808`)?

Background: `.yah/docs/architecture/A002-ipauro-findings.md` — both the
original "macOS 15 Local Network privacy gate" section and the
**"execution-context matrix, measured (R002-T8)"** section that records this
tool's results. The short version: macOS 15 (Sequoia) added a per-app
permission gating local multicast and local-subnet unicast. A process that
can't show the prompt may be **silently denied** — packets stay visible to
BPF, which sits below the gate, while never reaching the app's socket. Sonoma
14 and earlier have no such gate.

> **The matrix in this file is filled in.** It was measured on one host
> (macOS 26.5.1) on 2026-07-25 and the placement decision it fed is recorded
> in A002. Re-run it on a new OS version, a managed/corporate Mac, or after
> any change to how the core agent is signed or registered.

## The two questions, and the two commands

| Question | Command | Answers with |
|---|---|---|
| Did traffic actually flow *here, now*? | `check` | a behavioural verdict + exit code |
| What decision is the system *carrying*? | `grants` | macOS's own recorded posture |

You need both. Behaviour alone can't distinguish "this context holds the
grant" from "someone approved this months ago", and a denial persists silently
with no prompt ever shown again.

## `check` — the behavioural test

```sh
cargo build --release -p ipauro-probe
BIN=./target/release/ipauro-probe

# One-shot verdict for the current context. --iface is what arms the wire leg;
# without it the verdict is socket-only and says so.
$BIN check --seconds 8 --iface en0

# Or run the halves separately to eyeball traffic:
$BIN listen                       # one line per datagram: ts, src, summary
$BIN beacon --interval-ms 500     # "IPAURO-PROBE v0 host=... pid=... seq=..."
```

`check` runs **two independent observations against the same beacons**: this
process's own socket, and a `/dev/bpf` tap on the interface. That second leg is
what makes a verdict falsifiable — a socket-only probe cannot tell an open gate
from in-kernel multicast loopback succeeding while nothing leaves the machine.

| exit | verdict | meaning |
|---|---|---|
| `0` | `GATE OPEN` | beacons came back to our socket **and** reached the wire. |
| `4` | `DENIED (inbound)` | beacons reached the wire; our socket received none. Packets exist; this context may not receive them. |
| `5` | `DENIED (outbound)` | `sendto` reported success but nothing reached the wire and nothing came back. The denial is on the **send** path. |
| `6` | `LOOPBACK ONLY` | our beacons looped back in-process but none reached the wire. A socket-only probe would have called this open; it is not. |
| `1` | `INCONCLUSIVE` | nothing was ever sent — see stderr for the setup error. |

Without a usable wire leg, `check` degrades to the socket-only reading, keeps
the original exit codes (`0`/`4`), and marks the verdict `UNCONFIRMED` rather
than overclaiming.

Flags that matter:

- `--iface <name>` — scopes group membership / `IP_MULTICAST_IF`, **and** tells
  the wire tap what to watch. Omitted, the OS picks and the wire leg is off.
- `--tap-iface <name>` — watch a different interface than the one we beacon
  out of. This is the discriminator between a real transmission and a loopback
  copy: XNU delivers the multicast loopback copy via `lo0`, so
  `--iface en0 --tap-iface lo0` counts loopback copies while `--iface en0`
  alone counts frames that actually left. An off-path tap is reported as
  unavailable-for-egress rather than being misread as suppressed egress.
- `--no-wire` — skip the tap deliberately.
- `--port` / `--group` — default to Link's own `20808` / `224.76.78.75`.

The wire tap needs read access to `/dev/bpf*`: root, or membership of the
`access_bpf` group (which Wireshark's ChmodBPF installs — check with
`id -Gn | grep access_bpf`). Without it the tap reports itself unavailable and
`check` still runs. If the kernel capture buffer overflows the tap reports
*unavailable* rather than a possibly-short count, so a "0 on the wire" is never
an artifact of a busy interface.

`listen` labels every datagram it doesn't recognize as `foreign (Link?)` —
including real Ableton Link traffic, which it deliberately never parses.

## `grants` — what macOS has recorded

```sh
$BIN grants                      # every app with a local-network record
$BIN grants --filter ipauro      # just ours
$BIN grants --denied-only        # exit 4 if anything is denied
```

Reads `/Library/Preferences/com.apple.networkextension.plist` (world-readable,
an `NSKeyedArchiver` archive). Three decisions:

- **`allowed`** — an explicit allow is recorded.
- **`DENIED`** — an explicit deny is recorded. This is the state that persists
  silently and produces "it used to work."
- **`unset`** — *no explicit decision*, which behaves as **allowed**. On the
  reference host 236 of 263 records were `unset` with traffic flowing normally.
  Never fold `unset` in with `DENIED`.

### Which identity a grant attaches to

This determines what you are even measuring, so read it before running a row:

| Launch shape | Registry identity |
|---|---|
| Binary run from a shell | **none of its own** — attributed to the responsible app (Terminal, or whatever launched the shell) |
| Bare executable as a launchd job | its own **code-signing identifier + path** |
| Executable in a bundle, launchd job with `AssociatedBundleIdentifiers` | the **associated bundle id**, no path |

**Consequence:** running the probe from Terminal or over SSH measures
*Terminal's* or *`sshd`'s* grant, not the binary's. Those rows are about the
parent app. Only a launchd job has an independent identity — which is why the
brain service's placement had to be measured as a launchd job.

Corollary for the product: because the grant binds to the code-signing
identifier, `packaging/build-app.sh` signs each embedded executable with an
explicit `--identifier` matching its launchd label. Don't remove that.

## The R002-T8 execution-context matrix — measured

Host: single Mac, **macOS 26.5.1 (25F80)**, Apple silicon, `en0` on a home LAN,
2026-07-25. Every row `check --seconds 8 --iface en0`.

| Execution context | Signing | Prompt? | Registry | exit | Verdict |
|---|---|---|---|---|---|
| Non-interactive shell (agent) | ad-hoc | none | inherits the parent app's (allowed) | `0` | GATE OPEN, wire-confirmed |
| User LaunchAgent, `gui/<uid>` | ad-hoc, never-seen path | none | auto-recorded **allowed** | `0` | GATE OPEN, wire-confirmed |
| User LaunchAgent, `gui/<uid>` | Developer ID | none | auto-recorded **allowed** | `0` | GATE OPEN, wire-confirmed |
| User LaunchAgent, `gui/<uid>`, binary inside a signed app bundle + `AssociatedBundleIdentifiers` | Developer ID | none | bundle id, `unset` | `0` | GATE OPEN, wire-confirmed |
| Root LaunchDaemon | — | **not run** — needs an operator password | — | — | below |
| Over SSH | — | **not re-run** — denied on macOS 15 per A002 | — | — | below |

**Result: the feared failure mode did not occur.** A brand-new, never-seen,
ad-hoc-signed LaunchAgent got full bidirectional multicast, wire-confirmed, with
no prompt, and the system recorded an allow for it unprompted.

**Limits.** No denial was observed anywhere on this host (0 of 263 records), so
this run demonstrates the auto-grant path and does **not** demonstrate that the
instrument catches a real denial on macOS 26 — the negative case still rests on
A002's macOS 15 SSH observation. The wire leg's ability to report a true zero is
independently shown by the off-path-tap control. Single host, single OS version,
already-logged-in session; a managed/MDM Mac may differ.

## The two rows still owed

Neither changes the placement decision — the agent rows already came back open,
and W001 requires the brain to be unprivileged regardless — but both are worth
having on a fresh machine.

### Root LaunchDaemon

Needs `sudo`. Apple's docs suggest out-of-session daemons may be exempt from the
gate; note that third-party root daemons *do* appear in the registry
(`org.pqrs.Karabiner-Elements-Privileged-Daemons-v2` is there), so they are at
least tracked.

```sh
cargo build --release -p ipauro-probe
BIN_PATH="$(pwd)/target/release/ipauro-probe"
sed "s#__IPAURO_PROBE_BIN__#${BIN_PATH}#" crates/ipauro-probe/dev/io.ipauro.probe.daemon.plist \
  | sudo tee /Library/LaunchDaemons/io.ipauro.probe.daemon.plist > /dev/null
sudo chown root:wheel /Library/LaunchDaemons/io.ipauro.probe.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/io.ipauro.probe.daemon.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/io.ipauro.probe.daemon.plist
sleep 15
sudo launchctl print system/io.ipauro.probe.daemon | grep -E "state|last exit"
cat /tmp/ipauro-probe-daemon.log /tmp/ipauro-probe-daemon.err.log

# ALWAYS unload afterwards:
sudo launchctl bootout system/io.ipauro.probe.daemon
sudo rm /Library/LaunchDaemons/io.ipauro.probe.daemon.plist
```

`check`'s exit code becomes the job's exit status — read it from
`launchctl print`'s `last exit code`, and the verdict line from the log.

### Over SSH

Requires working SSH-to-self (a key in `authorized_keys`), which is why it
wasn't re-run here. Remember this row measures **`sshd`'s** grant, not the
binary's.

```sh
ssh localhost "$(pwd)/target/release/ipauro-probe check --seconds 8 --iface en0"
```

### User LaunchAgent (the rows that were run)

```sh
cargo build --release -p ipauro-probe
BIN_PATH="$(pwd)/target/release/ipauro-probe"
mkdir -p ~/Library/LaunchAgents
sed "s#__IPAURO_PROBE_BIN__#${BIN_PATH}#" crates/ipauro-probe/dev/io.ipauro.probe.agent.plist \
  > ~/Library/LaunchAgents/io.ipauro.probe.agent.plist

# Must be run FROM a logged-in Aqua session for the gui/<uid> domain to exist:
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.ipauro.probe.agent.plist
sleep 15
launchctl print gui/$(id -u)/io.ipauro.probe.agent | grep -E "state|last exit"
cat /tmp/ipauro-probe-agent.log /tmp/ipauro-probe-agent.err.log

# ALWAYS unload afterwards — and check `grants` for the entry it left behind:
launchctl bootout gui/$(id -u)/io.ipauro.probe.agent
rm ~/Library/LaunchAgents/io.ipauro.probe.agent.plist
./target/release/ipauro-probe grants --filter ipauro
```

To test Developer ID signing or bundle embedding, sign the copy first
(`codesign --force --options runtime --timestamp --sign "Developer ID Application: …"`)
or place it inside a signed `.app` and add `AssociatedBundleIdentifiers` to the
plist. **Give a test bundle its own `CFBundleIdentifier`** — reusing
`io.ipauro.app` would record a grant for the real product from a throwaway
artifact.

> **Cleanup note.** Each launchd row leaves a permanent entry in the user's
> Local Network privacy list, visible in System Settings, keyed by the binary's
> signing identifier and path. Booting the job out does not remove it. Prefer a
> stable scratch path, and check `grants --filter <name>` afterwards so you know
> what you left behind.

## Wire cross-check by hand

`check`'s wire leg does this internally, but to watch it live:

```sh
sudo tcpdump -ni en0 'udp port 20808'      # or without sudo if you're in access_bpf
```

Interpretation, with `check` running in the context under test:

- **Wire-visible + app-silent** → inbound denial (`check` reports exit `4`).
  This is the exact symptom originally misattributed to CrowdStrike Falcon.
- **Wire-silent after a successful `sendto`** → **outbound** denial (exit `5`).
  Note this is *not* automatically "a routing problem": macOS suppresses a
  denied app's egress while `sendto` still reports success, so wire-silence is a
  legitimate gate signature and not grounds to go looking at interfaces first.
- **Wire-silent and `sent: 0`** → nothing was ever transmitted; a genuine setup
  or socket error (exit `1`, see stderr).

## Sonoma 14 baseline

macOS 14 and earlier have no Local Network privacy gate at all, so every row on
a Sonoma machine is expected to be `0` regardless of launch context — the
control case. A `4`/`5`/`6` there points at something else (firewall, EDR,
routing) and is worth investigating before trusting a Sequoia-or-later denial as
gate-specific.
