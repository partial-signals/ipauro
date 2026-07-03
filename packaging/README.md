# packaging

Assembles `dist/IPAuRo.app`:

- `Contents/MacOS/ipauro-ui` — the `CFBundleExecutable` (egui tray client).
- `Contents/MacOS/ipauro-core` — the brain service, registered as an
  `SMAppService` **agent** (`io.ipauro.core`).
- `Contents/MacOS/ipauro-helper` — the privileged root daemon, embedded as an
  `SMAppService` **daemon** (`io.ipauro.helper`).
- `Contents/MacOS/ipauro` — the reference CLI client, embedded purely so it
  can be symlinked onto `PATH` (`install-dev.sh` does this).

Codesigned with a Developer ID identity (team `7BW4R8G8Q6` by default,
overridable — see below). See `.yah/docs/working/W001-ipauro-plan.md` §4/§6
and tickets **R002-T2** (SMAppService requires a properly signed bundle with
the helper embedded — signing is stood up at M0, not M5) and **R002-T6**
(start-at-login via `SMAppService.loginItem`).

## Scripts

| Script | Does |
|---|---|
| `build-app.sh` | `cargo build` the four binaries, assemble `dist/IPAuRo.app`, lint every plist, codesign inside-out. |
| `verify.sh` | Structural + signature + Gatekeeper sanity checks on an assembled bundle. |
| `install-dev.sh` | `rsync --delete` the bundle to `/Applications`, symlink the CLI onto `PATH`. |
| `uninstall-dev.sh` | Best-effort `launchctl bootout` of both labels + remove the app. |
| `notarize.sh` | Documented stub — prints the `notarytool`/`stapler` flow; only submits with `--execute` + real credentials. |

All scripts source `packaging/lib/common.sh` for shared config (paths, bundle
ID, launchd labels, team ID, build profile) and are safe to re-run.

## The flow

```bash
bash packaging/build-app.sh      # cargo build --release + assemble + sign
bash packaging/verify.sh         # sanity-check the result
bash packaging/install-dev.sh    # copy to /Applications, symlink `ipauro` onto PATH
```

**First run:** launch `IPAuRo.app` (Finder, or `open /Applications/IPAuRo.app`).
The running app is what calls `SMAppService.daemon(...).register()` and
`SMAppService.agent(...).register()` — this packaging never does that itself,
it only places a properly signed bundle where SMAppService can find it.
macOS shows a one-time approval dialog (and/or a **System Settings > General
> Login Items & Extensions** entry) the first time each job registers —
accept it. After that, `launchctl print system/io.ipauro.helper` and
`launchctl print gui/$(id -u)/io.ipauro.core` should show both jobs loaded.

To tear a dev install back down: `bash packaging/uninstall-dev.sh`.

## M0 exit-run steps (via the CLI)

M0's exit criterion (W001 §6): *"an IPC command (CLI or tray button) makes a
bridge appear/disappear; killing the service removes it; restarting the UI
client changes nothing."* Once `ipauro-cli` implements the `ipauro-proto::ipc`
commands (`BridgeUp` / `BridgeDown` / `GetSnapshot`) — **it is currently a
Wave-1 stub that only prints its version**, not yet wired to the socket —
the closed-loop check is:

```bash
ipauro bridge up                       # or the tray's equivalent button
ifconfig bridge90                      # bridge90 should now exist
ipauro bridge down
ifconfig bridge90                      # should be gone

# fail-open check
launchctl kickstart -k gui/$(id -u)/io.ipauro.core   # kill the service
ifconfig bridge90                      # helper should have torn it down (fail-open)

# UI statelessness check
ipauro bridge up
# quit/relaunch ipauro-ui — bridge90 must still be up; nothing changes
```

Until `ipauro-cli` catches up to the protocol, `packaging/verify.sh` +
`launchctl print` are the closed-loop checks available for the packaging
layer itself (bundle structure, signature, registration).

Note: `ipauro-probe` (the R002-T8 Local Network gate probe) is a standalone
diagnostic binary, not part of the shipped bundle — `build-app.sh` does not
embed it.

## Knobs

- **`SKIP_SIGN=1`** — assemble an unsigned bundle (CI / dev assembly checks).
  `verify.sh` reports an unsigned bundle as a note, not a failure — but
  SMAppService will refuse to register an unsigned bundle for real, so this
  is assembly validation only, never a substitute for a signed build.
- **`IPAURO_TEAM_ID=<team>`** — override the Developer ID team, for forks.
  Must match both a `Developer ID Application: ... (<team>)` identity in the
  signing keychain *and* what `ipauro_proto::ids::team_id()` compiles in
  (it reads the same env var via `option_env!()` at compile time — exporting
  it before `cargo build` is enough; Cargo tracks `option_env!`-referenced
  vars and recompiles `ipauro-proto` on change, verified empirically while
  building this packaging).
- **`IPAURO_PROFILE=debug`** — build in the `dev` profile and assemble from
  `target/debug` instead of `target/release` (faster local iteration; skips
  nothing else — plists, linting, and optional signing are unchanged).

## Notarization

`packaging/notarize.sh` is a stub: it prints the exact `ditto` /
`notarytool submit` / `stapler staple` commands and does nothing further
unless run with `--execute` and a `NOTARY_PROFILE` that already exists in the
keychain (set up once, interactively, via `xcrun notarytool
store-credentials` — never scripted, never held by an agent). Until
notarized, `verify.sh`'s `spctl -a -t exec` assessment is expected to reject
the bundle; that's normal for a signed-but-unnotarized build, not a packaging
bug.

## Known gaps / open questions

- **No entitlements file yet.** Hardened runtime is on (`--options runtime`)
  but nothing has been added to an entitlements plist. The Local Network
  grant (R002-T8) and the XPC peer-authentication requirement
  (`ipauro_proto::helper::peer_requirement()`, R002-T3) may need explicit
  entitlements once those pieces land — flagged here rather than guessed at.
- **No app icon.** `Info.plist` has no `CFBundleIconFile`; cosmetic, not
  blocking M0.
- **No `NSBonjourServices`.** Only `NSLocalNetworkUsageDescription` is set,
  which is sufficient to trigger the Local Network permission prompt itself;
  if/when the app starts Bonjour-browsing specific service types (mDNS,
  M2+), the corresponding service-type strings will need to be added here.
- **Versioning is single-track.** `CFBundleShortVersionString` and
  `CFBundleVersion` are both set to the workspace's `0.0.1` — no separate
  build-number scheme exists yet; fine for M0, worth revisiting before a
  real release cadence.
