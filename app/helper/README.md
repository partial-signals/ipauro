# ipauro-helper

The privileged root daemon (ticket R002, M0 "privilege + lifecycle spine").
Listens on the XPC mach service `io.ipauro.helper`
(`ipauro_proto::ids::HELPER_LABEL`), authenticates every connecting peer by
code signature *before* parsing any message, and drives `bridge90`
create/destroy/status via `/sbin/ifconfig`. Fails open (destroys the bridge)
if no authenticated connection has been seen for `FAILOPEN_GRACE_SECS` (15s)
after the last one drops.

See `crates/ipauro-proto/src/lib.rs`'s `helper` module for the wire contract
and `.yah/docs/architecture/A001-ipauro-architecture.md` (ticket comments
R002-T2/T3/F4/F5) for the design gotchas this daemon exists to satisfy.

## Building

```
cargo build -p ipauro-helper
cargo test -p ipauro-helper
```

## Running it for real: `SMAppService` (not covered by this dev harness)

The shipping path is `SMAppService.daemon`, registered by the signed app
bundle (Contents/Library/LaunchDaemons + bundle-program requirements) per
ticket R002-T2. That requires Developer ID signing and the app bundle
scaffold, neither of which exist yet. **The dev harness below is a stand-in**
for exercising the XPC listener / bridge lifecycle / fail-open spine before
that scaffold lands — it talks to the exact same code, just launched as a
plain root `LaunchDaemon` instead of an `SMAppService` daemon.

## Dev harness: manual `launchctl bootstrap`

`dev/io.ipauro.helper.dev.plist` runs the debug binary straight out of the
cargo workspace `target/` dir, no packaging or signing involved.

**1. Build, then point the plist at your checkout:**

```bash
cargo build -p ipauro-helper
sed -i '' "s#__IPAURO_REPO__#$(pwd)#" app/helper/dev/io.ipauro.helper.dev.plist
```

(Re-run the `sed` line — or just re-copy from a clean checkout of the file —
if you ever move the repo, since the plist embeds an absolute path.)

**2. Install + bootstrap it as a root LaunchDaemon:**

```bash
sudo cp app/helper/dev/io.ipauro.helper.dev.plist /Library/LaunchDaemons/io.ipauro.helper.dev.plist
sudo chown root:wheel /Library/LaunchDaemons/io.ipauro.helper.dev.plist
sudo chmod 644 /Library/LaunchDaemons/io.ipauro.helper.dev.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.ipauro.helper.dev.plist
```

**3. Check it's alive and inspect logs:**

```bash
sudo launchctl print system/io.ipauro.helper
tail -f /tmp/io.ipauro.helper.dev.log
```

**4. Tear it down:**

```bash
sudo launchctl bootout system/io.ipauro.helper
sudo rm /Library/LaunchDaemons/io.ipauro.helper.dev.plist
```

If you only want to stop/start without re-installing the plist:
`sudo launchctl kickstart -k system/io.ipauro.helper` restarts it in place
(also the way to pick up a rebuilt binary — see the dev-loop caveat below).

## Dev-loop caveats

- **`IPAURO_INSECURE_DEV=1` is baked into the dev plist.** A local `cargo
  build` binary is unsigned (or ad-hoc signed), so it — and any client built
  the same way — cannot satisfy `peer_requirement()`'s real code-signing
  requirement (`anchor apple generic and certificate leaf[subject.OU] =
  <team id>`). With the env var set, the daemon skips
  `xpc_connection_set_peer_code_signing_requirement` entirely and logs a loud
  warning at startup and on every accepted connection. **Never set this
  outside local dev** — an unauthenticated root XPC service that creates
  bridges and (eventually) rewrites `pf` is exactly the local-privilege-
  escalation shape ticket R002-T3 exists to prevent.
- **Rebuilding does not restart the daemon.** `launchd`'s `KeepAlive` only
  relaunches the process if it exits; overwriting
  `target/debug/ipauro-helper` mid-dev-loop does nothing to an already-running
  instance. After every `cargo build -p ipauro-helper`, run
  `sudo launchctl kickstart -k system/io.ipauro.helper` to force it to pick up
  the new binary.
- **Fail-open / restart-grace exercise:** `sudo launchctl kickstart -k
  system/io.ipauro.helper` also doubles as a way to test the "service
  restart" tolerance — kill the process while a client is connected and
  confirm the bridge survives the ~instant relaunch, but gets torn down if no
  client reconnects within `FAILOPEN_GRACE_SECS` (15s).
- **Nothing speaks the client side yet.** `ipauro-core` (the brain service)
  and `ipauro-cli` are separate Wave 1 stubs at the time of writing. Until
  one of them dials `io.ipauro.helper` and sends a `HelperRequest`, the only
  verification available for the request-handling logic itself is this
  crate's own unit tests (`cargo test -p ipauro-helper`) against a mock
  `BridgeExecutor` — see `src/request.rs`.

## Wire format

One XPC dictionary per message, single key `"msg"` holding the `serde_json`
bytes of `ipauro_proto::helper::HelperRequest` (request) or `HelperResponse`
(reply, built via `xpc_dictionary_create_reply` so it correlates with the
original message for `xpc_connection_send_message_with_reply[_sync]`
callers).
