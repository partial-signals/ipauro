#!/usr/bin/env bash
# Regenerate the golden-reference fixtures for ipauro-iec61937.
#
# Inputs are synthetic sine tones encoded by FFmpeg (no third-party content).
# The IEC 61937 outputs are NOT committed (TrueHD/MAT is ~3 MB/s); only their
# SHA-256 is, in SHA256SUMS, recorded from FFmpeg 6.1.1 (Ubuntu 7:6.1.1-3ubuntu5).
# tests/ffmpeg_golden.rs packetizes the committed elementary streams with our
# Rust implementation and compares against those hashes; when `ffmpeg` is on
# PATH it also regenerates the reference live and diffs byte-for-byte.
#
# Usage: tests/fixtures/gen.sh            # rewrite inputs + SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")"

ff() { ffmpeg -hide_banner -loglevel error -y "$@"; }

# 0.5 s, 48 kHz. TrueHD: stereo 440/660 Hz (FFmpeg's TrueHD encoder is
# experimental, hence -strict -2; fine for framing tests). AC-3/E-AC-3: 5.1.
ff -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=0.5" \
   -f lavfi -i "sine=frequency=660:sample_rate=48000:duration=0.5" \
   -filter_complex "[0][1]amerge=inputs=2" -c:a truehd -strict -2 tone.thd
ff -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=0.5" -ac 6 -c:a ac3 -b:a 384k tone.ac3
ff -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=0.5" -ac 6 -c:a eac3 -b:a 384k tone.eac3

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ff -f truehd -i tone.thd  -c copy -f spdif "$tmp/tone.thd.spdif"
ff -f ac3    -i tone.ac3  -c copy -f spdif "$tmp/tone.ac3.spdif"
ff -f eac3   -i tone.eac3 -c copy -f spdif "$tmp/tone.eac3.spdif"
(cd "$tmp" && sha256sum tone.thd.spdif tone.ac3.spdif tone.eac3.spdif) > SHA256SUMS
cat SHA256SUMS
