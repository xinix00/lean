//! De twee traits waarmee leantls over een transport praat.
//!
//! Poll-gebaseerd over `core::task`, zonder executor en zonder allocatie.
//! leanhttp definieert dezelfde vorm, zodat leanhttps de twee zonder omweg
//! aan elkaar knoopt.

use core::pin::Pin;
use core::task::{Context, Poll};

/// Een bron van bytes.
pub trait AsyncRead {
    /// De fout van het transport.
    type Error;

    /// Leest hoogstens `buf.len()` bytes. `Ok(0)` betekent einde van de
    /// stroom (bij een niet-lege `buf`). `Pending` registreert de waker uit
    /// `cx`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>>;
}

/// Een put voor bytes.
pub trait AsyncWrite {
    /// De fout van het transport.
    type Error;

    /// Schrijft hoogstens `buf.len()` bytes en geeft terug hoeveel. Na
    /// `Pending` roept de aanroeper opnieuw aan met dezelfde bytes.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>>;
}
