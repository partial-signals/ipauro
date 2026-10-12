"""Synthetic EDIDs for ipauro-hdmi tests. NOT dumps of real devices.

Each fixture is a minimal EDID 1.3 base block (manufacturer 'YMH', one
1080p60 DTD, a monitor-name descriptor) plus one CTA-861 extension with an
audio data block and a speaker allocation block. Regenerate: python3 mk_edid.py
"""
import sys
def edid(sads, spk=(0x7f,0x0f,0x00), name=b"TEST AVR"):
    b = bytearray(128)
    b[0:8] = bytes([0,0xff,0xff,0xff,0xff,0xff,0xff,0])
    # manufacturer "YMH" (Yamaha): letters 5-bit, 'A'=1
    m = ((ord('Y')-64)<<10)|((ord('M')-64)<<5)|(ord('H')-64)
    b[8]=m>>8; b[9]=m&0xff
    b[10]=0x34; b[11]=0x12
    b[16]=1; b[17]=34; b[18]=1; b[19]=3
    b[20]=0x80
    # one DTD 1920x1080@60 (148.5 MHz)
    dtd = bytes([0x02,0x3a,0x80,0x18,0x71,0x38,0x2d,0x40,0x58,0x2c,0x45,0x00,0x40,0x84,0x63,0x00,0x00,0x1e])
    b[54:72]=dtd
    d = bytearray(18); d[3]=0xfc; nm=(name+b"\n").ljust(13,b" ")[:13]; d[5:18]=nm
    b[72:90]=d
    for off in (90,108):
        dd=bytearray(18); dd[3]=0x10; b[off:off+18]=dd
    b[126]=1
    b[127]=(-sum(b[:127]))&0xff
    c = bytearray(128); c[0]=2; c[1]=3
    blocks = bytearray()
    sadb = bytearray()
    for s in sads: sadb += bytes(s)
    blocks += bytes([(1<<5)|len(sadb)]) + sadb
    blocks += bytes([(4<<5)|3]) + bytes(spk)
    c[2] = 4+len(blocks); c[3]=0x40|0x01
    c[4:4+len(blocks)]=blocks
    c[127]=(-sum(c[:127]))&0xff
    return bytes(b+c)
FIXTURES = {
    # Dolby-era AVR: DD+ with JOC, MAT with object PCM; MAT requires the hash.
    "synth-avr-hash.bin": dict(name=b"SYNTH AVR H", spk=(0x0f, 0x09, 0x01), sads=[
        [(1 << 3) | 7, 0x7f, 0x07], [(2 << 3) | 5, 0x07, 0x50], [(7 << 3) | 5, 0x07, 0xc0],
        [(10 << 3) | 7, 0x07, 0x01], [(11 << 3) | 7, 0x7f, 0x03], [(12 << 3) | 7, 0x54, 0x01]]),
    # Same, but MAT object PCM accepted without the hash.
    "synth-avr-nohash.bin": dict(name=b"SYNTH AVR N", spk=(0x0f, 0x09, 0x01), sads=[
        [(1 << 3) | 7, 0x7f, 0x07], [(10 << 3) | 7, 0x07, 0x03], [(12 << 3) | 7, 0x54, 0x03]]),
    # Older receiver: E-AC-3 without JOC, TrueHD-only MAT.
    "synth-legacy.bin": dict(name=b"SYNTH OLD", spk=(0x0f, 0x00, 0x00), sads=[
        [(1 << 3) | 7, 0x7f, 0x07], [(2 << 3) | 5, 0x07, 0x50], [(10 << 3) | 7, 0x07, 0x00],
        [(12 << 3) | 7, 0x54, 0x00]]),
}

if __name__ == "__main__":
    for fname, f in FIXTURES.items():
        with open(fname, "wb") as out:
            out.write(edid(f["sads"], spk=f["spk"], name=f["name"]))
