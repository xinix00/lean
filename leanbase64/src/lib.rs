//! Base64 (RFC 4648), de twee vormen die in gebruik zijn.
//!
//! - [`STANDARD`]: `+` en `/`, met `=`-padding; HTTP-koppen,
//!   `Sec-WebSocket-Accept`, JSON-velden met bytes.
//! - [`URL`]: `-` en `_`, zonder padding (RFC 4648 §5); tokens, VAPID en
//!   Web Push.
//!
//! Decoderen is strikt: alleen het alfabet van de gekozen vorm, padding
//! precies waar die hoort (of nergens), en geen ongebruikte bits die niet
//! nul zijn. Zo heeft elke reeks bytes één tekst en elke tekst hoogstens één
//! reeks bytes.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Een vorm van base64: een alfabet en of er padding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Form {
    alphabet: &'static [u8; 64],
    pad: bool,
}

/// `+`, `/` en `=`-padding.
pub const STANDARD: Form = Form {
    alphabet: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    pad: true,
};

/// `-`, `_` en geen padding.
pub const URL: Form = Form {
    alphabet: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    pad: false,
};

/// Waarom een tekst geen base64 van deze vorm is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Een teken buiten het alfabet, of padding op de verkeerde plek.
    Symbol(usize),
    /// Een lengte die geen geldige base64 kan zijn.
    Length,
    /// Ongebruikte bits in het laatste teken die niet nul zijn.
    Trailing,
    /// De heap weigerde.
    OutOfMemory,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Symbol(i) => write!(f, "base64: invalid symbol at {i}"),
            Self::Length => f.write_str("base64: invalid length"),
            Self::Trailing => f.write_str("base64: non-zero trailing bits"),
            Self::OutOfMemory => f.write_str("base64: out of memory"),
        }
    }
}

impl Form {
    /// De lengte van de tekst voor `n` bytes.
    pub const fn encoded_len(self, n: usize) -> usize {
        if self.pad {
            n.div_ceil(3) * 4
        } else {
            (n / 3) * 4 + [0, 2, 3][n % 3]
        }
    }

    /// Schrijft `bytes` als tekst achter `out`.
    pub fn encode_to(self, bytes: &[u8], out: &mut String) -> Result<(), Error> {
        out.try_reserve(self.encoded_len(bytes.len()))
            .map_err(|_| Error::OutOfMemory)?;
        let symbol = |v: u32| char::from(self.alphabet[(v & 63) as usize]);
        let mut chunks = bytes.chunks_exact(3);
        for c in &mut chunks {
            let v = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
            for shift in [18, 12, 6, 0] {
                out.push(symbol(v >> shift));
            }
        }
        match *chunks.remainder() {
            [a] => {
                let v = u32::from(a) << 16;
                out.push(symbol(v >> 18));
                out.push(symbol(v >> 12));
                if self.pad {
                    out.push_str("==");
                }
            }
            [a, b] => {
                let v = (u32::from(a) << 16) | (u32::from(b) << 8);
                out.push(symbol(v >> 18));
                out.push(symbol(v >> 12));
                out.push(symbol(v >> 6));
                if self.pad {
                    out.push('=');
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// `bytes` als tekst.
    pub fn encode(self, bytes: &[u8]) -> Result<String, Error> {
        let mut out = String::new();
        self.encode_to(bytes, &mut out)?;
        Ok(out)
    }

    fn value(self, c: u8) -> Option<u32> {
        self.alphabet
            .iter()
            .position(|&a| a == c)
            .and_then(|i| u32::try_from(i).ok())
    }

    /// Schrijft de bytes van `text` achter `out`.
    pub fn decode_to(self, text: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let body = if self.pad {
            if !text.len().is_multiple_of(4) {
                return Err(Error::Length);
            }
            let pads = text
                .iter()
                .rev()
                .take(2)
                .take_while(|&&c| c == b'=')
                .count();
            &text[..text.len() - pads]
        } else {
            text
        };
        if body.len() % 4 == 1 {
            return Err(Error::Length);
        }
        out.try_reserve(body.len() / 4 * 3 + 2)
            .map_err(|_| Error::OutOfMemory)?;
        let mut acc = 0u32;
        let mut bits = 0u32;
        for (i, &c) in body.iter().enumerate() {
            let v = self.value(c).ok_or(Error::Symbol(i))?;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        if acc != 0 {
            return Err(Error::Trailing);
        }
        Ok(())
    }

    /// De bytes van `text`.
    pub fn decode(self, text: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.decode_to(text, &mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        let cases: [(&[u8], &str, &str); 7] = [
            (b"", "", ""),
            (b"f", "Zg==", "Zg"),
            (b"fo", "Zm8=", "Zm8"),
            (b"foo", "Zm9v", "Zm9v"),
            (b"foob", "Zm9vYg==", "Zm9vYg"),
            (b"fooba", "Zm9vYmE=", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy", "Zm9vYmFy"),
        ];
        for (bytes, padded, bare) in cases {
            assert_eq!(STANDARD.encode(bytes).unwrap(), padded);
            assert_eq!(URL.encode(bytes).unwrap(), bare);
            assert_eq!(STANDARD.decode(padded.as_bytes()).unwrap(), bytes);
            assert_eq!(URL.decode(bare.as_bytes()).unwrap(), bytes);
            assert_eq!(STANDARD.encoded_len(bytes.len()), padded.len());
            assert_eq!(URL.encoded_len(bytes.len()), bare.len());
        }
    }

    #[test]
    fn the_alphabets_differ() {
        let bytes = [0xfb, 0xff];
        assert_eq!(STANDARD.encode(&bytes).unwrap(), "+/8=");
        assert_eq!(URL.encode(&bytes).unwrap(), "-_8");
        assert_eq!(STANDARD.decode(b"-_8="), Err(Error::Symbol(0)));
        assert_eq!(URL.decode(b"+/8"), Err(Error::Symbol(0)));
    }

    #[test]
    fn decoding_is_strict() {
        assert_eq!(STANDARD.decode(b"Zg="), Err(Error::Length));
        assert_eq!(STANDARD.decode(b"Zg=a"), Err(Error::Symbol(2)));
        assert_eq!(STANDARD.decode(b"Zh=="), Err(Error::Trailing));
        assert_eq!(URL.decode(b"Zg=="), Err(Error::Symbol(2)));
        assert_eq!(URL.decode(b"Z"), Err(Error::Length));
        assert_eq!(URL.decode(b"Zh"), Err(Error::Trailing));
    }
}
