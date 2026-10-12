# IPAuRo — Live Dolby Atmos objects over HDMI: diligence, experiments, roadmap

**Status:** In-flight plan. Phase 0 (tooling + research) is done; Phase 1 needs the Mac + Yamaha.
Evidence lives in **A005** (every claim tagged [V]/[P]/[S]/[F]/[U]); this doc holds decisions,
hypotheses, experiments and the roadmap.
`@arch:see(.yah/docs/architecture/A005-ipauro-atmos-hdmi-research.md)`: protocol, transport and legal findings.
`@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)`: the canonical `Object{pos,gain,t}` role.
`@arch:see(.yah/docs/working/W001-ipauro-plan.md)`: §4 plugins (OS-specific endpoints on a cross-platform core).

**Origin.** An engineering brief, "Open, cross-platform real-time Dolby Atmos object transport": a Rust
program on a Mac generates object audio + live positions, sends it over HDMI in an Atmos-compatible
format, and a Yamaha AVR renders it. The brief was judged right in direction but naive in places.
This doc is the result of checking it before building.

---

## 0. Bottom line

1. **The hard wall is probably authentication, not protocol knowledge or the OS.**
   - DD+ JOC metadata carries a *keyed* MAC (`emdf_protection`), and certified hardware has been
     observed rejecting independently made streams.
   - TrueHD Atmos carries a truncated HMAC-SHA-256.
   - Sinks advertise, in their EDID, whether MAT object PCM needs a source-side "hash".
   - The brief forbids leaked keys, and so do we. So **the first experiments test authentication and
     transport, not encoders.** All of them are cheap. (A005 §1, §5, §9)
2. **There are three carriers, not one.** The candidate is **MAT object PCM** ("MAT 2.x"):
   - Its payload is reportedly *uncompressed PCM slots + a tiny position table*. No codec, no JOC
     analysis, 20 dynamic objects + a 7.1.4 bed, 20 ms framing. Technically the easiest real-time encoder
     by far.
   - Its blockers: the layout is undocumented, it may be hash-gated per sink, and it needs HBR.

   **DD+ JOC** has a public ETSI spec but needs a full lossy codec + JOC encoder, and it is the
   carrier where the MAC wall was observed. **TrueHD Atmos** is out. (A005 §1)
3. **macOS may not be the blocker the brief feared.**
   - macOS 15+ passes DD+ JOC through to AVRs, but only in Apple's own apps.
   - More importantly, one log shows the macOS 15 HAL listing **undocumented non-mixable physical formats
     whose packet geometry is exactly IEC 61937 E-AC-3 (`'cec3'`/`'cc+3'`) and HBR MAT (`'mtct'`/`'mtc+'`)**.
   - If that holds on our Mac, the classic hog-mode passthrough path reaches HBR. (A005 §6, H-T2)
4. **Decision order** (each step is hours, not weeks):
   1. Read the Yamaha's EDID: is MAT object PCM advertised, and is a hash required?
   2. Read the Mac's HAL formats.
   3. Play FFmpeg-made TrueHD/E-AC-3 bursts through those formats and read the AVR display.
   4. Tamper-test genuine DD+ JOC to see whether the Yamaha enforces the MAC.

   Only then invest in MAT 2.x reverse engineering and an encoder.
5. **Honest risk.** If the Yamaha requires the MAT hash *and* enforces the EMDF MAC, the brief's final
   success criterion cannot be met without a Dolby licence. That would be a finding, not a failure, and
   we would know within the first two phases.

## 1. Where this sits in IPAuRo

```
DAW / object editor ──ADM-OSC──▶ IPAuRo: canonical Object stream (A004)        [ipauro-spatial]
                                   │  carrier encoder: MAT object PCM | DD+ JOC  [ipauro-spatial::encoder → future crate]
                                   ▼
                          IEC 61937 bursts (type 22 / 21)                         [ipauro-iec61937]
                                   │
        ┌──────────────────────────┼─────────────────────────────┐
  macOS HAL hog-mode          Linux ALSA hdmi:,AES0=6        Linux gateway node (RPi/NUC)
  ('mtc+'/'cec3' if real)     (HBR proven in kernel)         over the IPAuRo mesh            [ipauro-hdmi]
        └──────────────────────────┴─────────────────────────────┘
                                   ▼
                         Yamaha AVR: Dolby Atmos renderer → speakers
```

- **It's a W001 §4 plugin**: a terminating endpoint. The encoders are pure, portable Rust; the transports
  are per-OS. This is the brief's "keep object generation, protocol encoding, and platform-specific
  output isolated", in IPAuRo's existing vocabulary.
- **The gateway node is the IPAuRo-native Plan B.** Don't fight a Mac's HDMI driver: let a cheap Linux
  node with proven HBR passthrough be the mesh's Atmos sink, with the Mac as scene source. It mirrors the
  inferno/Dante gateway idea (R010-F8). Formally it stays Plan B, per the brief, until the macOS path is
  measured.
- **Scope gate** ("does this make patching any source to any destination feel more analog?"): yes. An AVR
  becomes a patchable *object* destination, and ADM-OSC sources become patchable object sources.
- **Degrade rule (A004):** when no carrier is available, objects degrade to channels (render 7.1.4 LPCM at
  the host). That is IPAuRo-correct behaviour, and explicitly **not** success for this brief.

## 2. What the brief got wrong or missed

| # | Brief's assumption | Finding | Consequence |
|---|---|---|---|
| 1 | The obstacle is format knowledge plus OS transport | Dolby gates object metadata with keyed integrity: the EMDF MAC, the TrueHD HMAC, and the MAT "hash" SAD bit (A005 §1, §5) | Test authentication **first** with genuine streams (E-A1, E-A2). Under the brief's own no-leaked-keys rule, a MAC-enforcing sink is a hard stop |
| 2 | "Dolby MAT 2.0 real-time object transport" is the target | Three carriers. DD+ JOC is publicly specified (ETSI TS 103 420) and needs no HBR. MAT object PCM is undocumented but the simplest payload. TrueHD is out | Run Track M (MAT) as primary; Track J (JOC) behind the authentication gate |
| 3 | macOS transport is the first unknown; probe Core Audio | Apple passes DD+ JOC (macOS 15+, its own apps only); the HAL reportedly lists `'cec3'`/`'mtct'`/`'mtc+'` | `hdmi-probe` answers this in a minute. The brief's "AVFoundation passthrough" angle has no public API to use (A005 §6) |
| 4 | Find "MAT start/middle/end codes" and reuse MAT framing | The codes are empirical constants nobody understands. FFmpeg master reworked TrueHD-MAT padding in 2026-07 | Use them only for TrueHD transport tests. Learn MAT 2.x framing from captures (H-M3) |
| 5 | Validate by AVR display plus listening | The AVR display can't prove object rendering | Use a **height test** (E-R1): a 5.1-core or bed-only signal can't drive top speakers with the upmixer off, so overhead output proves metadata was rendered. Plus a same-PCM, different-metadata A/B |
| 6 | A standalone 9-crate, 5-app workspace | IPAuRo is the right home. The abstractions (transport trait, 9 crates) come before any second implementation exists | 3 crates + 3 bins now. Add the transport trait when a second transport is real |
| 7 | "Document the coordinate system" | Six conventions in play; OAMD's y-axis runs front→back, the reverse of ADM (A005 §7) | Canonical = ADM cartesian = ADM-OSC; conversions live in one module, with provisional ones marked |
| 8 | Latency < 100 ms is a goal | DD+ JOC's floor is about 80 ms before the AVR; MAT is about 20 ms framing plus AVR decode (estimates) | MAT also wins on latency. Measure (E-L1) |
| 9 | Legal: "document considerations" | JOC patents live into the 2030s. Licence traps: Cavern and dolby-atmos-encoder are not GPL-compatible; spatial-audio-lab has no licence. The MAC makes key extraction the legal hot spot | Policy in §8. Get a freedom-to-operate review before *distributing* any object encoder |
| 10 | Captures A–F from "authorized implementations" | No HBR capture hardware needed: a Windows virtual audio endpoint receives Dolby Access's MAT 2.x directly (shown by spatial-audio-lab) | Windows for **research capture only**, never at runtime (the brief allows this) |
| 11 | (missing) Sink capability negotiation is a detail | EDID SAD byte 3 holds the decisive bits (JOC; MAT object PCM; hash required) and Linux's `/proc` ELD hides them | `hdmi-probe` decodes them, cross-checked against edid-decode |

## 3. Tracks

- **Track M: MAT object PCM.** Primary.
  - Real-time encoder = a multiplexer: PCM slots + quantised positions + integrity fields + MAT framing.
  - Needs: (a) the sink to advertise MAT object PCM (ideally hash *not* required); (b) MAT 2.x layout and
    integrity algorithm from our own captures; (c) an HBR transport (Linux now, macOS if `'mtc+'` is real).
- **Track J: DD+ JOC.** Parked behind gate G2.
  - Needs an E-AC-3 core encoder (oxideav-ac3, MIT, is the candidate), a QMF-domain JOC encoder, and an
    OAMD/EMDF writer from the ETSI text.
  - Proceed only if the Yamaha accepts metadata with a stale MAC (E-A2). Patent exposure is the highest of
    the three.
- **Track T: TrueHD Atmos.** Dropped: it needs a lossless MLP encoder plus an HMAC key. It stays useful as a
  *transport* test signal, since FFmpeg can make TrueHD and we can MAT-frame it.

## 4. Hypotheses register

Each row is falsifiable by the named experiment. Update **Conf.** and add results in §6's log. Never
rewrite the claim.

| ID | Claim | Evidence now | Conf. | Falsified by |
|---|---|---|---|---|
| H-T1 | macOS hog-mode `'cac3'` passthrough of AC-3 reaches the Yamaha as Dolby Digital | mpv/VLC/Kodi do this [P] | S | E-T1 |
| H-T2 | On macOS 15+ / Apple silicon with an Atmos AVR, the HAL lists `'cec3'`/`'mtct'` (and `'+'` variants), a hogging process can select them, and bit-exact IEC 61937 E-AC-3 / MAT bursts written there make the Yamaha lock (DD+ / TrueHD) | One mpv log [F]; geometry matches FFmpeg exactly | F | E-0, E-T2 |
| H-T3 | Linux ALSA HBR (`hdmi:…,AES0=0x06`, 8 ch @ 192 kHz) carries our MAT-framed TrueHD to the Yamaha as Dolby TrueHD | Kodi/kernel [P]; our framing = FFmpeg byte-exact [V] | S | E-T3 |
| H-T4 | The Yamaha detects IEC 61937 E-AC-3 inside 2-ch 192 kHz *LPCM* (no non-audio bit), as Kodi's Darwin hack assumes | Kodi code [P]; sink behaviour [U] | U | E-T4 |
| H-A1 | The Yamaha falls back (to Dolby Surround / core) on DD+ JOC whose `emdf_protection` doesn't verify | Denon/LG observation [F]; spec says keyed [V] | F | E-A2 |
| H-A2 | The CTA-861 MAT "hash required" bit is exactly whether the sink verifies a keyed hash on MAT object PCM; a "not required" sink accepts unsigned frames | Bit verified [V]; semantics inferred | U | E-A1 + E-A3 |
| H-A3 | The EMDF MAC also covers the E-AC-3 core frame, so dolby-atmos-encoder's two walls are one | truehdd shows the TrueHD MAC covers AU audio [V] | F | E-A2(b) |
| H-M1 | Windows "Dolby Atmos for home theater" emits MAT 2.1 "Profile 3" = 2 × 10 ms blocks of 31 PCM16 slots + LFE@12 kHz + 20 × 36-bit position records, also toward a *hash-required* sink | spatial-audio-lab [F], toward a no-hash sink only | F | E-M1 |
| H-M2 | The MAT 2.x integrity fields are unkeyed CRCs (at least in no-hash mode) | none | U | E-M2 (CRC RevEng) |
| H-M3 | MAT 2.x frames don't use FFmpeg's TrueHD start/middle/end codes; the start code encodes version/payload | none | U | E-M2 (`mat-inspect scan` reports `codes …=false`) |
| H-C1 | OAMD: x 0 L → 1 R, y 0 front → 1 back, z sign + magnitude; MAT 2.1 table "X, Z, Y" in 0..62 | 3 implementations [S]; MAT [F] | S/F | ETSI text read; E-M2 |
| H-R1 | With the AVR's upmixer off, energy in top speakers ⇔ object metadata rendered overhead | standard renderer behaviour | S | E-R1 |
| H-L1 | Motion-to-sound latency: MAT ≤ ~60 ms, DD+ JOC ≥ ~100 ms on the Yamaha | estimates (A005 §6a) | U | E-L1 |

## 5. Experiments

Record every run in §6 using the template there. Put genuine Dolby streams (legitimately obtained, e.g.
public demo trailers) and any capture from proprietary software in `fixtures/reference/`, which is
**gitignored**. Commit only hashes and the derived field tables.

**E-0 — Baseline inventory (the brief's M0).** Record:
- macOS version, Mac model/chip, port or adapter.
- Yamaha model + firmware, input, speaker layout.
- `hdmi-probe --json > mac.json` (no flags: read-only).
- `hdmi-probe --try-formats --json > mac-trials.json` (briefly hogs the HDMI device and restores it).

Then play a genuine DD+ Atmos title in **Apple's TV app with "Prefer HDMI Passthrough" on**, and photograph
the Yamaha's signal info. That proves this exact Mac→cable→Yamaha path carries Atmos at all.

**E-A1 — Sink flags.** From E-0's EDID section:
- E-AC-3 JOC bit?
- MAT object PCM bit?
- **Hash required?**

This decides between Track M and the stop branch (§7, G1). Also record the speaker allocation.

**E-T1 — AC-3 via `'cac3'`.**
1. `ffmpeg -f lavfi -i sine=440:d=30 -ac 6 -c:a ac3 t.ac3`
2. `mat-inspect packetize --codec ac3 t.ac3 t.ac3.spdif`
3. `hdmi-passthrough-test --device N --format cac3 --channels 2 --rate 48000 t.ac3.spdif`
4. Expect: Yamaha shows Dolby Digital.

**E-T2 — E-AC-3 and MAT through the undocumented formats** (only if E-0 lists them):
- `--format cec3 --channels 2 --rate 192000` with `mat-inspect packetize --codec eac3` output → expect DD+.
- `--format mtct --channels 2 --rate 768000` with `--codec truehd` output (FFmpeg-encoded TrueHD) → expect
  Dolby TrueHD.
- Repeat with `'cc+3'` / `'mtc+'`.
- Then a **genuine** DD+ JOC stream on `'cc+3'`/`'cec3'` → expect "Dolby Atmos": the macOS transport is
  proven for JOC by a third-party process.
- Log every OSStatus (the tool prints them).
- If a set-format call fails, run `hdmi-probe --try-formats` and record the result codes. That is the
  brief's "exact blocker" evidence.

**E-T3 — Linux HBR baseline.** On any Linux box with HDMI to the Yamaha:
1. `hdmi-probe` to find the device.
2. `aplay -D 'hdmi:CARD=X,DEV=Y,AES0=0x06' -t raw -f S16_LE -c 8 -r 192000 t.thd.spdif` → expect Dolby
   TrueHD.
3. Repeat with `-c 2 -r 192000` E-AC-3 → expect DD+.

This decouples "does the AVR accept our framing" from macOS.

**E-T4 — PCM-carrier.** `hdmi-passthrough-test --format lpcm --channels 2 --rate 192000 t.eac3.spdif` (a
plain LPCM physical format). Does the Yamaha detect DD+ anyway?

**E-A2 — DD+ JOC tamper test** (needs a ~300-line tool, ticketed). Take one genuine DD+ JOC stream and make
four variants, each with `frmsiz`/`crc1`/`crc2` recomputed:
- (a) **null rewrite** (parse → re-serialise, no change). Must still show Atmos, which proves the rewriter
  is clean.
- (b) flip LSBs of core mantissas outside EMDF; MAC left as is.
- (c) change one OAMD object's position bits; MAC left stale.
- (d) zero the protection bits.

Play each through the E-T2/E-T3 transport.

| Variant | Atmos | Falls back |
|---|---|---|
| (c), (d) | MAC not enforced on this Yamaha → Track J viable | H-A1 confirmed |
| (b) | MAC doesn't cover audio | MAC covers audio (H-A3) |

**E-M1 — MAT 2.x captures (research only, Windows).**
- Set up Windows + Dolby Access + a virtual endpoint that receives exclusive-mode IEC 61937 (SysVAD sample
  as spatial-audio-lab did; or any WASAPI-exclusive loopback), with a configurable EDID.
- Capture the brief's controlled set, with the source PCM held constant:
  - A: silence / no objects
  - B: one stationary object
  - C: left
  - D: right
  - E: moving
  - F: two objects
- Capture each set twice: once with the EDID MAT byte `0x03` (hash not required), once with `0x01` (hash
  required).
- Store hashes in `fixtures/reference/MANIFEST`.

**E-M2 — Differential analysis.**
1. `mat-inspect scan` each capture. Are the FFmpeg codes present? (H-M3)
2. `mat-inspect diff A B`, `diff C D` and so on: position-dependent byte ranges.
3. Locate the slots, the 36-bit records and the integrity fields.
4. Run CRC RevEng over the integrity fields (H-M2).
5. Compare the hash-required vs hash-not-required captures: what's added?
6. Write confirmed and unresolved fields into A005 §4. A field counts as confirmed only when replicated
   across ≥ 2 independent captures.

**E-A3 — MAT acceptance.** Replay a captured hash-not-required MAT 2.x stream to the Yamaha over E-T2/E-T3:
- (i) unchanged → expect Atmos/PCM
- (ii) one position record changed, integrity recomputed
- (iii) changed, integrity stale

Results map to: frames accepted at all; integrity understood; integrity enforced.

**E-R1 — Renderer proof.**
- Set the Yamaha to its straight/decoder mode, with Dolby Surround upmix and any "Surround:AI" off.
- Same object PCM, two metadata streams: z = 0 vs z = 1 (and front vs rear). Heights must activate only
  for z = 1.
- Bonus: an SPL meter or measurement mic per speaker, logged.

**E-L1 — Latency.**
- Inject a position step and a simultaneous click on a reference channel.
- Record both with a measurement mic. Motion-to-sound latency = mic delay to the spatial change.
- Report mean and jitter over 100 steps.

## 6. Experiment log

Template (copy per run):

```
### YYYY-MM-DD E-xx <short name>
Hypothesis: H-..            Setup: <Mac, macOS, adapter, AVR+fw, input, layout>
Inputs (sha256): ...        Command(s): ...
Expected: ...               Actual: ... (AVR screen photo: fixtures/reference/...)
HAL/ALSA result codes: ...  Confidence change: H-.. U→S / F→refuted
Next experiment: ...
```

### 2026-10-12 Phase 0 (no hardware)
- **IEC 61937 framing reproduced byte-for-byte vs FFmpeg 6.1.1** for AC-3, E-AC-3 and TrueHD-in-MAT
  (SHA-256 pinned plus live diff): `cargo test -p ipauro-iec61937`. The `mat-inspect` scan, diff, extract
  and packetize commands were all checked against FFmpeg output.
- **CTA-861 SAD Atmos bits verified against edid-decode** on synthetic EDIDs: `cargo test -p ipauro-hdmi`.
  Confirms MAT byte-3 bit 1 = hash *not* required.
- `hdmi-probe` and `hdmi-passthrough-test` build on Linux and type-check for `aarch64-apple-darwin`.
  **Not run on a Mac yet**, so no macOS claim is upgraded.
- Research findings went to A005, including two not-yet-replicated single sources that this plan's first
  experiments target (mpv log → H-T2; spatial-audio-lab → H-M1).

## 7. Roadmap (gated)

| Phase | Work | Needs | Gate |
|---|---|---|---|
| **0 ✓** | Framing crate (FFmpeg-exact), `mat-inspect`, `hdmi-probe`, `hdmi-passthrough-test`, object model + ADM-OSC, A005 research | — | — |
| **1 — Hardware truth** (~1 day) | E-0, E-A1, E-T1, E-T2, E-T4; E-T3 if a Linux box is handy | Mac + Yamaha (+ Linux box) | **G1**: which transports work from macOS? Which carriers does the Yamaha advertise? Is a hash required? |
| **2 — Authentication truth** (~2–4 days) | `eac3-rewrite` tool (frame parse/serialise, CRC-16, OAMD bit locator, using public TS 102 366/103 420 syntax) + E-A2 | A genuine DD+ JOC stream + a G1 transport | **G2**: does the Yamaha enforce the EMDF MAC? Does it cover the core? |
| **3 — Track M reverse engineering** (~1–3 weeks) | E-M1 captures; E-M2 analysis; `mat2` parser in `ipauro-iec61937`; integrity algorithm; E-A3 replay tests | Windows research box (capture only) + G1 transport | **G3**: (i) regenerate a captured MAT 2.x stream bit-exactly from its decoded parts; (ii) the Yamaha accepts a modified-and-reintegrated stream |
| **4 — Live object encoder + demo** (~1–2 weeks) | `ObjectEncoder for MatObjectPcm` (bed + up to 20 objects, 10 ms blocks, preallocated, lock-free SPSC metadata); `object-orbit-demo` (keyboard + ADM-OSC on udp/4001: the brief's front-centre → … → circle sequence); transport via macOS `'mtc+'` or Linux ALSA | G3 | **G4** (the brief's success): Yamaha shows Atmos; E-R1 passes; 10 min with no dropouts; E-L1 measured |
| **5 — IPAuRo integration** | Atmos sink as an IPAuRo plugin: registry entry, capability gossip ("node X: Atmos sink, carriers {MAT-PCM}"), ADM-OSC ingest adapter feeding the canonical Object stream, Linux gateway-node packaging (RPi 5 / NUC), macOS + Linux CI on synthetic fixtures | G4 | — |
| **J (parked)** | E-AC-3 core (oxideav-ac3 or own) + JOC encoder + OAMD/EMDF writer from the ETSI text; freedom-to-operate review before distribution | G2 = "MAC not enforced" | Same G4 criteria |

**Stop and branch rules**
- **G1 says the hash is required and G2 says the MAC is enforced** → stop the Atmos carriers. Report with
  evidence. The options are then a Dolby licence (MAT encoder SDK) or IPAuRo's object→channel degrade.
  Neither satisfies the brief.
- **G1: no macOS transport** (no `'mtct'`/`'cec3'`, set-format fails) → document the exact selector and
  OSStatus, then use the Linux gateway node as the Atmos sink (Plan B). The Mac stays the scene source over
  the IPAuRo mesh. Don't build custom HDMI hardware.
- **G3 fails** because the integrity fields are keyed even in no-hash mode → same as the first rule, for
  Track M.

## 8. Policies

- **Never** extract, use or accept a Dolby key or signing credential. Never decompile Dolby binaries.
  Observe only the streams sent to endpoints we control.
- Don't copy code from Cavern-licensed projects, or from projects with no licence. Facts from their
  documentation may be cited with attribution (A005 §8).
- Proprietary or captured fixtures stay out of git (`fixtures/reference/` is gitignored). Commit hashes
  and derived field tables only.
- No FFmpeg at runtime. FFmpeg is a *test oracle* only (golden hashes, plus a live diff when installed).
- No UI or configuration system before G4. CLI tools with `--help`, `--json` and explicit errors.
- Encoders that don't exist return `EncodeError::Unimplemented` with the reason. Never emit placeholder bytes.
- Trademarks: technical names in the UI and docs. "Dolby Atmos" appears only as what the AVR displays.

## 9. Compatibility and limitations (known now)

- **HBR is mandatory for MAT:**
  - HDMI 1.3+ end to end.
  - Through a TV, eARC (not ARC).
  - USB-C→HDMI adapters vary: DP-to-HDMI converters may not pass HBR audio; prefer the built-in HDMI port.
- **macOS:**
  - Apple's passthrough is Apple-silicon-only.
  - The undocumented formats may depend on the macOS version and on the sink's SADs.
  - Intel Macs are unknown. Asahi notes the formats are DCP-firmware-mediated (A005 §6).
- **Yamaha:** some early "4K" models needed firmware updates for MAT [F]. Record the firmware.
- **Object budget:** MAT 2.x is 20 dynamic objects + a 7.1.4 bed [F/P]; DD+ JOC is typically 12–16
  elements.
- **Latency floors** (estimates): MAT ~20 ms framing; DD+ JOC ≥ ~80 ms before the AVR adds its own.

## 10. What exists now, and how to run it

| Crate / bin | What | Verified |
|---|---|---|
| `ipauro-iec61937` | Burst writer (no alloc), AC-3 / E-AC-3 / MAT(TrueHD) packetizers (FFmpeg n6.1.1 port), AC-3/E-AC-3 header parser, TrueHD AU + major sync parser, EMDF container finder, burst scanner | Byte-exact vs FFmpeg [V]; EMDF on synthetic only |
| `mat-inspect` | `scan` (types, periods, MAT code check, TrueHD units/Atmos flag, E-AC-3 headers + EMDF payload IDs), `diff` (per-offset payload differences: the A/B method), `extract`, `packetize` | [V] on FFmpeg streams |
| `ipauro-hdmi` | EDID/CTA-861 + ELD parsing, SAD Atmos bits, carrier summary; Linux (procfs/DRM) + macOS (Core Audio HAL, ioreg EDID) backends | SAD bits vs edid-decode [V]; macOS type-checked only |
| `hdmi-probe` | One-shot sink + host report, text or `--json`; `--edid FILE` offline; `--try-formats` (macOS, restores state) | Linux run [V]; macOS pending E-0 |
| `hdmi-passthrough-test` | macOS hog-mode IEC 61937 player with step-by-step OSStatus logging; Linux prints the `aplay` equivalents | Type-checked; pending E-T1 |
| `ipauro-spatial` | Canonical coordinates + conversions, ADM-OSC v1.0 message mapping, `ObjectEncoder` contract with explicit `Unimplemented` | Unit tests [V] |

```
cargo test -p ipauro-iec61937 -p ipauro-hdmi -p ipauro-spatial      # Linux: everything above
cargo check -p ipauro-hdmi --target aarch64-apple-darwin           # macOS type-check from Linux
cargo run -p ipauro-hdmi --bin hdmi-probe -- --help                 # on the Mac: E-0
```

The brief named `hdmi-probe`, `mat-inspect`, `encoded-passthrough-test` (here `hdmi-passthrough-test`),
`object-orbit-demo` (Phase 4) and `receiver-test` (E-T/E-A procedures; a tool only if they need automating).

## 11. Ready-to-file tickets

IDs come from the noisetable board's shared sequence, so **file these with `yah board` from the noisetable
workspace root**. Don't hand-number them here.

Relay: **"IPAuRo — Atmos-over-HDMI object sink (W002)"**, parent Q001, phase P6 (it terminates streams, like R010).

1. **E-0/E-A1/E-T1/E-T2 hardware truth run** on Mac + Yamaha.
   - Gotcha: run `hdmi-probe` *before* anything mutating. Photograph the AVR info screen for every stream.
2. **E-T3 Linux HBR baseline + gateway-node feasibility** (RPi 5 or Intel NUC).
   - Gotcha: the `/proc` ELD hides the JOC/MAT flags; use `hdmi-probe` (DRM EDID).
3. **`eac3-rewrite` tool + E-A2 tamper matrix.**
   - Gotcha: write it from the public TS 102 366 / 103 420 syntax and MediaInfoLib (BSD). Never from Cavern
     or dolby-atmos-encoder source (licence).
4. **Windows research capture rig for MAT 2.x (E-M1)**, with switchable EDID hash bit.
   - Gotcha: research only. Captures go to the gitignored `fixtures/reference/`; commit hashes only.
5. **MAT 2.x differential analysis + `mat2` parser (E-M2)**, including CRC RevEng of the integrity fields.
   - Gotcha: a field is confirmed only when replicated across independent captures (brief §5).
6. **E-A3 MAT acceptance replay** on the Yamaha.
7. **`MatObjectPcm` real-time encoder** (after G3): preallocated buffers, lock-free metadata.
8. **`object-orbit-demo`**: keyboard + ADM-OSC input, the brief's position sequence, 10-minute soak, E-R1 +
   E-L1 measurements.
9. **IPAuRo plugin integration**: protocol-registry entry, capability gossip, ADM-OSC ingest adapter.
10. **Legal**: freedom-to-operate review before any release that contains an object encoder (JOC
    and object-audio families; A005 §9).
