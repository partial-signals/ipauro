//! Minimal MSB-first bit reader for header parsing (not a hot path).

#[derive(Clone)]
pub struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize, // in bits
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn at_bit(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        (self.buf.len() * 8).saturating_sub(self.pos)
    }

    /// Reads `n` (≤ 32) bits, or `None` past the end of the buffer.
    pub fn read(&mut self, n: u32) -> Option<u32> {
        debug_assert!(n <= 32);
        if self.remaining() < n as usize {
            return None;
        }
        let mut v: u32 = 0;
        for _ in 0..n {
            let byte = self.buf[self.pos / 8];
            let bit = (byte >> (7 - (self.pos % 8))) & 1;
            v = (v << 1) | u32::from(bit);
            self.pos += 1;
        }
        Some(v)
    }

    pub fn flag(&mut self) -> Option<bool> {
        self.read(1).map(|b| b == 1)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.pos += n;
        Some(())
    }
}
