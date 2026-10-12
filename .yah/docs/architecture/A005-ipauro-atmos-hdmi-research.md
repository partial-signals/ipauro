# IPAuRo — Dolby Atmos over HDMI: protocol, transport & legal findings

**Status:** Research canon (evidence base for W002). Every claim carries a confidence tag. Update the
tag when an experiment in W002 confirms or kills it. Don't silently edit a claim.
`@arch:see(.yah/docs/working/W002-ipauro-atmos-hdmi-plan.md)`: the plan, hypotheses and experiments.
`@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)`: the `Object{pos,gain,t}`
role this feeds.

**Confidence tags**
- **[V]** verified in this repo by a test or by reading the primary source directly.
- **[P]** a primary source (standard, vendor doc, source code) as reported by research, not re-read here.
- **[S]** several independent secondary sources or implementations.
- **[F]** a single forum post or a single unverified project.
- **[U]** unknown or not public.

Research date: 2026-10-12. Several key sources are under three months old (dolby-atmos-encoder
2026-07, spatial-audio-lab 2026-07, truehdd 0.6.x 2026-08/09, FFmpeg `2db563f` 2026-07). Expect drift.

---

## 1. The three carriers (and why "MAT 2.0" alone is the wrong frame)

A Yamaha AVR's Atmos renderer can receive objects over HDMI in three bitstream families. They share
little beyond IEC 61937 framing:

| | **DD+ JOC** (E-AC-3 + Joint Object Coding) | **MAT object PCM** ("MAT 2.0/2.1") | **TrueHD Atmos in MAT** |
|---|---|---|---|
| What carries the objects | E-AC-3 5.1/7.1 core downmix + parametric JOC upmix matrices + OAMD positions in EMDF containers | Uncompressed PCM slots (bed + dynamic objects) + a compact position table | 16-ch spatially coded presentation in TrueHD substream 4 + Evolution-frame metadata |
| Public spec | **Yes**: ETSI TS 102 366 (E-AC-3, EMDF = Annex H) + ETSI TS 103 420 (JOC, OAMD). Free. [P] | **No.** IEC 61937-9 (paid) covers only carriage. Payload layout: one RE project. [F] | **No.** Reverse-engineered for decode (truehdd, oadec). [S] |
| Encoder complexity | High: lossy transform codec + QMF-domain JOC analysis + OAMD/EMDF writer | **Low**: multiplex PCM + quantise positions + framing + integrity fields | Very high: lossless MLP encoder + Atmos presentation + metadata |
| IEC 61937 type / link | 21 (0x15), 4× rate: **2 ch @ 192 kHz**, ordinary audio sample packets (no HBR) [V: framing; P: link] | 22 (0x16), **HDMI HBR**: 8 ch @ 192 kHz (768 kHz frame rate) [P] | 22 (0x16), HBR [V: framing] |
| Frame duration | 1536 samples = 32 ms [V] | 20 ms per 61440-byte burst; two 10 ms blocks inside [V: burst; F: blocks] | 20 ms MAT frame of 24 × 1/1200 s access units [V] |
| Auth / integrity | `emdf_protection` = **keyed MAC** per TS 102 366 §H.2.2 (`key_id` "identifies the authentication key"; algorithm "not defined") [V: quoted in dolby-atmos-encoder README]. Certified hardware reportedly rejects unsigned/foreign metadata [F] | CTA-861 MAT SAD bit says whether the sink **requires a hash** for object/channel PCM [V]. The RE capture, made against a no-hash sink, still shows integrity fields of unknown algorithm [F] | Evolution protection = truncated **HMAC-SHA-256** over the access unit + frame, key not public [V: truehdd source] |
| Who emits it in real time | Broadcast/streaming encoders (licensed). macOS 15+ only *passes through* existing DD+ JOC [P] | Windows "Dolby Atmos for home theater", Xbox, Apple TV 4K (re-encodes) [P/S] | Nobody in real time; pre-authored discs |
| Patents | E-AC-3 core: last known US patent expired 2026-01 [S]. JOC/object families active to ~2031–2034+ [S] | Unknown; likely object-audio families too [U] | n/a |

**Verdict:** TrueHD Atmos is out (needs an MLP encoder plus an HMAC key). The live candidates are DD+ JOC
(public spec, big encoder, MAC wall reported on real hardware) and MAT object PCM (tiny encoder,
undocumented, maybe hash-gated per sink). The brief's assumption that "MAT 2.0 is the transport" is
directionally right for *real-time* sources but missed DD+ JOC's public spec, its non-HBR link, and the
authentication question that dominates both.

## 2. IEC 61937 framing (shared layer): verified

All [V], reproduced byte-for-byte against FFmpeg 6.1.1 `spdif` (crates/ipauro-iec61937,
`tests/ffmpeg_golden.rs`):

- Preamble `Pa=0xF872 Pb=0x4E1F Pc Pd`. `Pc` bits 0–6 data type, 7 error, 8–12 type-dependent,
  13–15 bitstream number. `Pd` counts **bits** for AC-3 and **bytes** for E-AC-3 and MAT.
- Little-endian 16-bit words on the wire buffer (S16LE device), payload byte-swapped per word.
  An odd last byte goes MSB-aligned.
- AC-3: type 1, `bsmod` in Pc bits 8–10, period 6144 B (1536 frames).
- E-AC-3: type 21, access units concatenated to 6 blocks, period 24576 B (6144 frames = 4×).
  The payload cap is 24568 B/burst.
- MAT: type 22, Pd = 61424, period 61440 B. FFmpeg's TrueHD-in-MAT layout: start code (20 B) at 0,
  middle code (12 B) at 30708, end code (16 B) at 61408. TrueHD units are placed by `input_timing`
  at a nominal 2560 B per 1/1200 s, and the codes count as padding. The codes are **empirical
  constants with unknown meaning**; FFmpeg, Kodi and LAV all say so [P]. Do not assume MAT 2.x PCM
  frames use them. FFmpeg master (`2db563f`, 2026-07-26) reworked padding for seamless-branch discs
  (6-slot ring, `output_timing`). We match n6.1.1 [P].
- HBR: HDMI packet type 0x09 vs 0x02 for ordinary audio samples. Linux enables the HBR pin mode when
  the stream is non-PCM and 8-channel (`is_hbr_format`), and sets channel status `AES0` non-audio
  plus FS = 768 kHz (`AES3=0x09`) [P].

## 3. Sink capability signalling (CTA-861 SADs): verified with an oracle

[V] via `edid-decode` (tests/edid_decode_oracle.rs); [P] edid-decode source.

| SAD | Byte 3 bit 0 | Byte 3 bit 1 |
|---|---|---|
| AFC 10 E-AC-3 | Supports **Joint Object Coding** (DD+ Atmos) | JOC with ACMOD 28 |
| AFC 12 MAT | 1 = **TrueHD + object audio PCM + channel-based PCM**; 0 = TrueHD only | (only if bit 0) 1 = hash **not** required; 0 = hash **required** for object/channel PCM |

- The Linux `/proc/asound/*/eld#*` text drops byte 3, so these flags are invisible there. Read the DRM EDID
  or the binary ELD control [V].
- libdisplay-info's MAT hash flag is reported buggy (reads bit 0 instead of bit 1) in several mirrors [S].
- No SAD bit distinguishes TrueHD with vs without Atmos.
- Yamaha front panels reportedly show MAT object PCM as "Atmos/PCM" / "PCM/Dolby Atmos", DD+ JOC as
  "Dolby Atmos/DD+", TrueHD Atmos as "Dolby Atmos/TrueHD" (or "DTHD") [F]. Sonos's API enumerates
  "Dolby Atmos (DD+)", "(TrueHD)" and "(MAT 2.0)" as distinct [S].

## 4. MAT object PCM: what one RE project observed

Source: barralutz/spatial-audio-lab `docs/TECHNICAL_NOTES.md` (Spanish; last commit 2026-07-20;
**no licence file**, so facts may be cited but no code or data reused). Everything here is **[F]**:

- Capture setup: a Windows SysVAD virtual endpoint whose generated EDID advertised
  `MAT 67 54 03`, i.e. object PCM **with hash not required**. Dolby Access opened "**MAT 2.1 Profile 3**".
- Bursts every 61440 B, `Pc=0x16`, words byte-swapped, 8 ch × 192 kHz × 16-bit carrier.
- Each 20 ms burst = **two 10 ms blocks**. Each block = **31 full-band PCM16 slots @ 48 kHz + one LFE PCM16
  slot @ 12 kHz**. Slots 0–10 are the 7.1.4 static bed (without LFE); slots 11–30 are **20 dynamic objects**.
  A test object's audio was **bit-identical** in slot 11.
  - 31 × 48000 × 16 + 12000 × 16 = 24.000 Mb/s, which matches Microsoft's "LPCM up to 24 Mbps" for MAT 2.0/2.1
    and its "32 active objects" (7.1.4 + 20) [P].
- Positions: per block, **20 records × 36 bits = six 6-bit fields**. The first three are **X, Z, Y**:
  - X: 0 = left, 62 = right.
  - "Z": 0 = front, 62 = back.
  - "Y": 32 = bed plane, 62 = top.
  - The other three fields were constant (4, 3, 31) and are unknown.
  - Values are *after* a "perceptual transform" in the Windows renderer, so they are panning codes, not
    metres.
  - No `0x5838` EMDF sync at any bit alignment.
- "The only other differences between positions are **integrity fields at the end of the metadata and of
  each block**." Algorithm unknown.
- Not validated against a real AVR or a Dolby reference decoder; decoded only by the project's own
  renderer.

**Unresolved MAT 2.x fields** (each is an experiment in W002 §5):
- MAT 2.x frame header/codes vs the TrueHD layout.
- What distinguishes 2.0 / 2.1 / "Profile 3".
- Block boundaries inside the 61424 B frame.
- Slot interleave and bit depth (PCM16 only?), LFE placement.
- The three auxiliary 6-bit fields.
- The position quantisation/transform.
- The integrity field algorithms (CRC vs keyed).
- What changes when the sink *requires* the hash.
- Object activity/silence signalling.
- Behaviour with fewer than 20 objects.

## 5. DD+ JOC: public structure, and the authentication wall

From ETSI TS 103 420 / TS 102 366 as implemented by MediaInfoLib (BSD), Cavern (custom licence; not
reusable) and dolby-atmos-encoder (Cavern licence; not reusable). [S] unless marked.

- **EMDF** in E-AC-3:
  - Sync `0x5838`, 16-bit container length.
  - Version, then `key_id`, then a payload loop (5-bit IDs, 0 terminates, `variable_bits` extension).
  - Each payload has a config block (smploffst, duration, groupid, codecdata, discard/priority) and a size.
  - Then `emdf_protection`: primary length code 1/2/3 → 8/32/128 bits; secondary 0–3.
  - Payload IDs: **11 = OAMD**, **14 = JOC**.
  - Carried in audio-block **skip fields**, not byte-aligned; auxdata is also possible.
  - The Atmos flag is `addbsi` LSB `flag_ec3_extension_type_a` + `complexity_index`.
  - Our `emdf.rs` finder implements this container syntax [V: synthetic tests only; no genuine
    stream tested yet].
- **OAMD position**:
  - x, y: 6-bit, value/62.
  - z: sign + 4-bit magnitude, value/15.
  - x 0 = left; **y 0 = front, 1 = back** (the reverse of ADM's +y = front); z 0 = ear plane, +1 = ceiling.
  - Up to 8 metadata update blocks per frame, with ramp durations.
  - Up to 159 objects counting beds.
- **JOC**:
  - 5- or 7-channel core; up to 64 objects.
  - Parameter bands {1,3,5,7,9,12,15,23} over a 64-band complex QMF.
  - 1–2 data points per 1536-sample frame; Huffman-coded matrices.
  - Decoder QMF delay ≈ 577 samples [S: oxideav-ac3 test].
- **Encoders available**:
  - FFmpeg `eac3` handles ≤ 5.1 only and writes no skip fields, EMDF or addbsi [P].
  - oxideav-ac3 (MIT, pure Rust) has an E-AC-3 encoder up to 7.1 and a JOC *decoder*; JOC encoding is out of
    scope [P].
  - **No GPL-compatible JOC encoder exists.**
- **The wall** (dolby-atmos-encoder README, read here [V]; the hardware result itself is [F]):
  - Their JOC streams pass ffmpeg 7 and Cavern as Atmos, but "**do not engage Atmos on Dolby-certified
    hardware — playback falls back to Dolby Surround**".
  - Bisection:
    - FFmpeg core + genuine Dolby metadata → fallback.
    - Genuine Dolby core + their metadata → fallback.
  - A brute-force search over CRC-8/CRC-32 variants found no match for the protection bits, so they
    conclude the field is a keyed MAC.
- **Our alternative reading of their "Wall 1"** (hypothesis H-A3):
  - truehdd shows Dolby's TrueHD MAC covers the *access-unit audio data* as well as the metadata frame.
  - If the EMDF MAC likewise covers the core frame, then "genuine metadata on a foreign core" fails for the
    same reason as "foreign metadata on a genuine core". That would mean one wall, not two, and the
    FFmpeg core may be acceptable.
  - Testable without any encoder: W002 E-A2.

## 6. Host transport

**macOS**
- **macOS 15 Sequoia+ supports HDMI passthrough of AC-3, E-AC-3 and E-AC-3 JOC (Atmos)**, on Apple-silicon
  Macs, via the built-in HDMI port or a supported USB-C adapter, in Apple Music, QuickTime Player and the
  Apple TV app, as a per-app setting. **Never MAT, never TrueHD** [P via search extracts; Apple Mac User
  Guide "About HDMI Passthrough"].
  - So the OS's HDMI path *can* carry 192 kHz IEC 61937 E-AC-3.
  - Whether a third-party process can reach it (Core Audio HAL non-mixable formats, or AVFoundation with a
    compressed sample buffer) is **[U]**; that's W002 E-T1/E-T2.
- Pre-Sequoia: decoded LPCM / binaural only [S].
- **No public API** for Apple's passthrough.
  - The 15.5/26.5 SDK AVFoundation headers expose only `allowedAudioSpatializationFormats`.
  - The 26.5 Core Audio header diff vs 15.5 adds only `…WantsControlsRestored` / `…WantsStreamFormatsRestored` [P].
- **Third-party players (mpv, VLC, Kodi, IINA) all use one HAL sequence** [P: their source]:
  1. hog mode (`'oink'` = own pid)
  2. disable mixing (`'mix?'` = 0)
  3. pick a non-mixable `'cac3'` entry of `kAudioStreamPropertyAvailablePhysicalFormats`
  4. set `kAudioStreamPropertyPhysicalFormat`
  5. `AudioDeviceCreateIOProcID`, then copy IEC 61937 bytes into `mBuffers[i]`

  `hdmi-passthrough-test` reproduces exactly this.
- **What actually passes today** [P]:
  - Only **AC-3 and DTS core**.
  - VLC rejects E-AC-3/TrueHD up front (`AOUT_FMT_HDMI`).
  - mpv requests everything as `'cac3'` and fails with "Passthrough format unsupported" when E-AC-3 needs
    192 kHz or TrueHD needs 8 ch.
  - Kodi hides the E-AC-3/TrueHD/DTS-HD passthrough settings on Darwin. Its only E-AC-3 route is a
    2-ch 16-bit 192 kHz *LPCM* "bitstream hack" (no non-audio bit).
- **Undocumented non-mixable HDMI formats on macOS 15.1.1** (M1 MacBook Pro → TCL TV with eARC; mpv issue
  #15383 log, relayed by research; the attachment was blocked from this sandbox, so **[F], not re-read**).
  The flags are 0x4C = signed | packed | **non-mixable**:

  | FourCC | Rates | Packet geometry | Matches |
  |---|---|---|---|
  | `'cac3'` | 96/48/44.1/32 kHz | 6144 B / 1536 fr | IEC 61937 AC-3 |
  | `'cec3'` | 384/192/176.4/128 kHz | **24576 B / 6144 fr** | FFmpeg's E-AC-3 burst exactly |
  | `'cc+3'` | same | same | E-AC-3, presumably JOC (Atmos) |
  | `'mtct'` | **768 kHz, 2 ch** | **61440 B / 15360 fr** | FFmpeg's MAT burst exactly (HBR rate) |
  | `'mtc+'` | same | same | MAT, presumably object PCM |

  None of these is in the public SDK headers, and no public code uses them. **If this holds on our Mac, the
  macOS HAL already exposes both an E-AC-3 and an HBR/MAT physical format to any process that hogs the
  device.** That would remove the presumed macOS transport blocker for *both* carriers (W002 H-T2, E-T2).
  `hdmi-probe` labels these FourCCs, and `hdmi-passthrough-test --format mtct --channels 2 --rate 768000`
  drives them.
- **EDID on macOS** [P]:
  - Core Audio exposes no ELD/SAD property.
  - Intel: `IODisplayConnect` → `IODisplayEDID`.
  - Apple silicon: the private `IOAVServiceCopyEDID` on `DCPAVServiceProxy` (Wine, m1ddc, RetroArch use it),
    or an `EDID` property on `IOPortTransportStateDisplayPort` (OSHI).
  - `hdmi-probe` scans `ioreg -l -w0` for any EDID-shaped `<hex>` blob, which is key-agnostic. If that finds
    nothing, `--edid` takes a dump from any tool.
- Bindings: `objc2-core-audio`/`-types` 0.3.2 and `coreaudio-rs` ≥ 0.13 type-check for darwin from Linux;
  `coreaudio-sys` doesn't (bindgen needs the SDK) [P]. We hand-wrote ~15 HAL entry points instead
  (`ipauro-hdmi/src/coreaudio.rs`) so every selector is auditable. Swapping to objc2 bindings later is
  mechanical.
- Apple-silicon HDMI audio formats are mediated by DCP firmware (Asahi `drivers/gpu/drm/apple/av.c`), which
  is consistent with the format list mirroring the sink's SADs [P/inference].

**Linux** [P]
- ALSA `hdmi:` device with `AES0=0x06` (non-audio):
  - 2 ch @ 48 kHz for AC-3.
  - 2 ch @ 192 kHz for E-AC-3.
  - **8 ch @ 192 kHz for HBR** (TrueHD/MAT, DTS-HD MA).
- The HDA HDMI codec driver switches the pin to HBR when the stream is non-PCM + 8 channels and the pin
  supports it.
- Kodi does exactly this. Raspberry Pi 4/5 (vc4) HD-audio passthrough exists in LibreELEC [S, to verify on
  hardware].

## 6a. Latency (estimates, not measurements)

| Stage | Value | Conf. |
|---|---|---|
| E-AC-3 frame | 1536 samples = 32 ms @ 48 kHz (1-block frames: 5.3 ms) | [V] framing / [P] |
| FFmpeg E-AC-3 encoder delay | 256 samples + 1 frame of input buffering | [P] |
| E-AC-3 decode | ≥ 1 frame (crc2/auxdata at the frame end) + overlap | [S] |
| JOC QMF analysis + synthesis | ≈ 577 samples ≈ 12 ms | [S] |
| MAT burst | 20 ms (two 10 ms blocks for object PCM [F]); the source buffers ≥ 1 burst | [V]/[F] |
| AVR decode + render + room EQ | unknown per model; no reliable published numbers | [U] |

Rough source-side floors: **DD+ JOC ≈ 80 ms+**, **MAT object PCM ≈ 20–30 ms**, each before the AVR adds its
own. Measure (W002 E-L1) before claiming the brief's < 100 ms target.

## 7. Coordinate conventions (summary; code in `ipauro-spatial`)

| Domain | x | y | z | Conf. |
|---|---|---|---|---|
| **IPAuRo canonical = ADM cartesian = ADM-OSC** | −1 L … +1 R | −1 back … +1 **front** | −1 floor … +1 ceiling, 0 ear plane | [V] ADM-OSC v1.0 quick reference |
| ADM-OSC polar | az 0 front, **+ left** | el +90 up | dist 0..1 | [V]; the ADM polar↔cart mapping (BS.2127) is not spherical trig |
| Dolby OAMD (JOC/TrueHD) | 0 L … 1 R | 0 **front** … 1 back | −1..1, sign + 4-bit | [S] |
| DAMF `pos` | −1 L … +1 R | +1 front … −1 back | 0 floor … 1 ceiling | [S] (3 impls agree) |
| MAT 2.1 table | "X" 0 L … 62 R | "Z" 0 front … 62 back | "Y" 32 bed … 62 top | [F], post-perceptual-transform |
| Windows ISpatialAudioObject | metres | — | **+z = behind** | [P] |

## 8. Open-source landscape (capability, licence, usability in GPL-3.0 IPAuRo)

| Project | What it really is | Licence | Reusable here? |
|---|---|---|---|
| FFmpeg `spdifenc.c` | IEC 61937 packer; TrueHD→MAT wrapper (not an object encoder) | LGPL-2.1+ | **Yes** (LGPL §3 → GPL); ported in `ipauro-iec61937` [V] |
| FFmpeg `mlpdec`/`eac3` | Decodes cores only; Atmos = profile flag | LGPL | Reference only |
| Kodi `PackerMAT.cpp`, LAV `BitstreamMAT.cpp` | MAT packers with dynamic padding | GPL-2+ | Reference (GPL-2+ is compatible) |
| truehdd / truehdd-oamd | Rust TrueHD+Atmos **decoder** → DAMF; OAMD parser; Evolution HMAC verify with a user key | Apache-2.0 | **Yes** (compatible); best OAMD reference |
| oadec | Clean-room TrueHD Atmos + DD+ JOC decoder → DAMF/ADM | GPL-3.0 | Yes |
| oxideav-ac3 | Pure-Rust E-AC-3 encoder (≤7.1) + JOC decoder | MIT | **Yes**: the candidate core encoder if Track J is ever needed |
| OpenJOC | JOC decoder/renderer | Apache-2.0 | Yes (not inspected) |
| MediaInfoLib `File_Ac3.cpp` | EMDF/OAMD/JOC *parsing* | BSD-2 | Yes |
| Cavern | E-AC-3/JOC/OAMD decoder, DAMF/ADM writer; **no JOC encoder** | Custom, non-commercial, propagating | **No**; don't read-and-port |
| raress96/dolby-atmos-encoder | Clean-room OAMD+JOC+EMDF injector; **rejected by certified hardware** | Cavern licence | **No** code; its findings are cited |
| barralutz/spatial-audio-lab | Windows MAT 2.1 capture + RE notes + renderer | **None stated** | Facts only |
| harletty-bridge | MAT/TrueHD unwrapper | Apache-2.0 src | Yes |
| deew, DRX-Lab Atmos-Encoder, subwoofa | Wrappers around Dolby Encoding Engine | MIT/GPL | Irrelevant (proprietary binary at runtime) |

## 9. Legal & licensing notes (not legal advice)

- **Copyright / licences:**
  - The FFmpeg port is fine (LGPL-2.1-or-later → GPL-3.0-or-later; copyright lines kept in the module
    header).
  - Never port Cavern-licensed code.
  - Cite unlicensed RE notes as facts only.
- **Patents:**
  - AC-3 expired (2017).
  - E-AC-3's last known US patent expired 2026-01-30 [S].
  - JOC / object-audio / OAMD families (e.g. US 9,666,198 → 12,243,542; US 9,179,236 continuations) are
    live into the 2030s [S].
  - Shipping a JOC encoder, and plausibly an object-PCM MAT encoder, is a real exposure. A freedom-to-operate
    review is a precondition of *distribution*, not of research.
- **Reverse engineering:**
  - US: 17 USC §1201(f) interoperability exemption (narrow); *Sega v. Accolade*, *Sony v. Connectix*
    (intermediate copying fair use); *Lexmark v. Static Control*, where an authentication handshake did not
    "effectively control access".
  - EU: Directive 2009/24/EC Art. 6, with Art. 8 voiding contrary contract terms; *SAS v WPL* (formats
    unprotected).
  - EULAs: Dolby Access and similar EULAs prohibit RE. Capture-based observation of a stream sent to *our
    own* endpoint is the cleanest posture; avoid decompiling Dolby binaries.
- **The MAC changes the posture.** Emitting a bitstream circumvents nothing. But if certified sinks require
  a keyed MAC, then getting a valid MAC means obtaining Dolby's key. That is where DMCA §1201, trade-secret
  and contract risk concentrate, and the brief itself forbids "stolen signing credentials, leaked
  encryption keys". **Policy for this project: we never extract, use or accept a Dolby key.** A
  MAC-enforcing sink is a hard stop for that carrier, reported as such.
- **Trademarks:**
  - Use "E-AC-3 / TS 103 420 object audio", "MAT", "IEC 61937 type 22" in UI and docs.
  - "Dolby Atmos" only nominatively (what the AVR displays); no logos, no implied certification.

## 10. Sources

- **IPAuRo code and evidence:**
  - `crates/ipauro-iec61937/tests/ffmpeg_golden.rs`
  - `crates/ipauro-hdmi/tests/edid_decode_oracle.rs`
- **FFmpeg:**
  - https://github.com/FFmpeg/FFmpeg/blob/n6.1.1/libavformat/spdifenc.c
  - `mlp_parse.c`, `mlpdec.c`, `ac3_parser.c`
  - master `2db563f`
- **ETSI:**
  - TS 102 366 V1.4.1: https://www.etsi.org/deliver/etsi_ts/102300_102399/102366/01.04.01_60/ts_102366v010401p.pdf
  - TS 103 420 V1.2.1: https://www.etsi.org/deliver/etsi_ts/103400_103499/103420/01.02.01_60/ts_103420v010201p.pdf
  - Not opened from this sandbox; fetch and check before Track J work.
- **Microsoft:**
  - IEC 61937 formats (MAT 1.0/2.0/2.1 GUIDs, "LPCM up to 24 Mbps", HBR): https://learn.microsoft.com/en-us/windows/win32/coreaudio/representing-formats-for-iec-61937-transmissions
  - Spatial sound (20 dynamic objects, 32 total): https://learn.microsoft.com/en-us/windows/win32/coreaudio/spatial-sound
- **Android:** `AudioFormat.ENCODING_DOLBY_MAT`; `AUDIO_FORMAT_MAT_1_0/2_0/2_1`
- **Apple:**
  - About HDMI Passthrough: https://support.apple.com/guide/mac-help/about-hdmi-passthrough-mchle3a1461c/mac
  - Apple TV Dolby MAT: https://support.apple.com/102218
- **Linux:**
  - `sound/hda/codecs/hdmi/hdmi.c` (`is_hbr_format`)
  - `include/linux/hdmi.h`
  - `sound/pci/hda/hda_eld.c`
- **edid-decode:** `parse-cta-block.cpp` (mirror https://github.com/oe-mirrors/edid-decode)
- **truehdd:** https://github.com/truehdd/truehdd (`truehd/src/structs/evolution.rs`)
- **dolby-atmos-encoder:** https://github.com/raress96/dolby-atmos-encoder (README "Why it can't fully work")
- **spatial-audio-lab:** https://github.com/barralutz/spatial-audio-lab (`docs/TECHNICAL_NOTES.md` §"Resultado MAT 2.1")
- **oxideav-ac3:** https://github.com/OxideAV/oxideav-ac3
- **MediaInfoLib:** `File_Ac3.cpp`
- **ADM-OSC:** https://github.com/immersive-audio-live/ADM-OSC (`docs/adm-osc-quick-reference.md`)
- **Dolby PMD tool:** https://github.com/DolbyLaboratories/pmd_tool (ADM speaker coordinates)
