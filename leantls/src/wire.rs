//! Lezen en schrijven van TLS-velden met lengteprefix.
//!
//! Een [`Builder`] die lengtes achteraf invult en een [`Reader`] die een
//! fout geeft in plaats van over zijn buffer heen te lezen. Samen de veertig
//! regels die een cryptobyte-achtige afhankelijkheid overbodig maken.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Bouwt een bytestroom met achteraf ingevulde lengteprefixen. Elke groei is
/// faalbaar.
pub(crate) struct Builder {
    /// De opgebouwde bytes.
    buf: Vec<u8>,
}

impl Builder {
    /// Een lege builder.
    pub(crate) const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Voegt bytes toe.
    pub(crate) fn bytes(&mut self, p: &[u8]) -> Result {
        self.buf.try_reserve(p.len()).map_err(|_| Error::Alloc)?;
        self.buf.extend_from_slice(p);
        Ok(())
    }

    /// Voegt één byte toe.
    pub(crate) fn u8(&mut self, v: u8) -> Result {
        self.bytes(&[v])
    }

    /// Voegt een u16 big-endian toe.
    pub(crate) fn u16(&mut self, v: u16) -> Result {
        self.bytes(&v.to_be_bytes())
    }

    /// Opent een blok met een lengteprefix van `width` bytes (1, 2 of 3) en
    /// geeft de positie terug voor [`Builder::close`].
    pub(crate) fn open(&mut self, width: usize) -> Result<Mark> {
        let at = self.buf.len();
        self.bytes(&[0, 0, 0][..width.min(3)])?;
        Ok(Mark {
            at,
            width: width.min(3),
        })
    }

    /// Sluit een blok en vult zijn lengte in; te lang is een fout, geen
    /// paniek.
    pub(crate) fn close(&mut self, m: Mark) -> Result {
        let n = self.buf.len() - m.at - m.width;
        let max = (1usize << (8 * m.width)) - 1;
        if n > max {
            return Err(Error::Internal("length-prefixed block overflow"));
        }
        let be = (n as u32).to_be_bytes();
        let dst = self
            .buf
            .get_mut(m.at..m.at + m.width)
            .ok_or(Error::Internal("length mark out of range"))?;
        dst.copy_from_slice(&be[4 - m.width..]);
        Ok(())
    }

    /// Geeft de bytes.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// De plek van een open lengteprefix.
pub(crate) struct Mark {
    /// Positie van het prefix.
    at: usize,
    /// Breedte van het prefix in bytes.
    width: usize,
}

/// Leest velden met lengteprefix zonder over de buffer heen te gaan.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    /// Wat nog ongelezen is.
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Een lezer over `buf`.
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Of alles gelezen is.
    pub(crate) const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Wat nog ongelezen is.
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// Neemt `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Leest één byte.
    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        Ok(b[0])
    }

    /// Leest een u16 big-endian.
    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Leest een u24 big-endian.
    pub(crate) fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    /// Een blok met een lengte van één byte, als eigen lezer.
    pub(crate) fn vec8(&mut self) -> Result<Reader<'a>> {
        let n = self.u8()?;
        Ok(Reader::new(self.take(usize::from(n))?))
    }

    /// Een blok met een lengte van twee bytes.
    pub(crate) fn vec16(&mut self) -> Result<Reader<'a>> {
        let n = self.u16()?;
        Ok(Reader::new(self.take(usize::from(n))?))
    }

    /// Een blok met een lengte van drie bytes.
    pub(crate) fn vec24(&mut self) -> Result<Reader<'a>> {
        let n = self.u24()?;
        Ok(Reader::new(self.take(n)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_backfills_lengths() {
        let mut b = Builder::new();
        let outer = b.open(3).unwrap();
        let inner = b.open(2).unwrap();
        b.bytes(b"abc").unwrap();
        b.close(inner).unwrap();
        b.u8(7).unwrap();
        b.close(outer).unwrap();
        assert_eq!(b.finish(), [0, 0, 6, 0, 3, b'a', b'b', b'c', 7]);
    }

    #[test]
    fn builder_refuses_overflow() {
        let mut b = Builder::new();
        let m = b.open(1).unwrap();
        b.bytes(&[0u8; 256]).unwrap();
        assert!(b.close(m).is_err());
    }

    #[test]
    fn reader_never_crosses_its_buffer() {
        let mut r = Reader::new(&[0, 5, 1, 2]);
        assert_eq!(r.vec16().err(), Some(Error::Truncated));
        let mut r = Reader::new(&[0, 2, 1, 2, 9]);
        let mut v = r.vec16().unwrap();
        assert_eq!(v.u16().unwrap(), 0x0102);
        assert!(v.is_empty());
        assert_eq!(r.u8().unwrap(), 9);
        assert_eq!(r.u8().err(), Some(Error::Truncated));
    }
}
