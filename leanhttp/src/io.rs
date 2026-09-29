//! De naad naar de verbinding: drie poll-traits (lezen, schrijven, sluiten),
//! kleine futures eromheen, en de gebufferde lezer waarmee de parser regels
//! leest.
//!
//! De traits nemen `&mut self` en geen `Pin`: een verbinding is een handvat
//! (een socket-id, een TLS-sessie) en heeft geen zelfverwijzingen. Termijnen
//! zijn relatief en optioneel; de verbinding bezit de klok. Een verbinding
//! zonder klok laat de standaard staan en zet zelf een termijn, of de
//! aanroeper legt een `select` rond de future.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::future::poll_fn;
use core::task::{Context, Poll};
use core::time::Duration;

use crate::error::{Error, Result};
use crate::header::{try_string, valid_field_value};
use crate::{BUF_SIZE, MAX_HEADER_BYTES};

/// Een fout van de verbinding zelf.
///
/// Einde van de stroom is geen fout: dat is `Ok(0)` uit een read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// Een termijn die de verbinding droeg, is verlopen.
    TimedOut,
    /// De andere kant brak de verbinding af.
    Reset,
    /// Deze kant is al gesloten.
    Closed,
    /// Iets anders; de verbinding is niet meer bruikbaar.
    Other,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IoError::TimedOut => "timed out",
            IoError::Reset => "reset by peer",
            IoError::Closed => "closed",
            IoError::Other => "failed",
        })
    }
}

/// De leeskant van een verbinding.
pub trait AsyncRead {
    /// Leest bytes in `buf`; `Ok(0)` betekent einde van de stroom.
    ///
    /// `Pending` registreert de waker uit `cx`, zoals elke future.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>>;

    /// Zet (of wist met `None`) een leestermijn die nu ingaat: elke read na
    /// "nu plus `timeout`" geeft [`IoError::TimedOut`], tot de volgende aanroep.
    ///
    /// Het is een deadline zoals Go's `SetReadDeadline(now + timeout)`, geen
    /// stiltetermijn per read: een client die elke paar seconden één byte
    /// stuurt, rekt de kop van een verzoek zo niet op. De verbinding rekent
    /// "nu" met haar eigen klok.
    ///
    /// De server zet hier de fasetermijnen uit KAM (verzoekkop, body, drain);
    /// de client alleen `header_timeout` en het `Expect`-oordeel. De standaard
    /// doet niets: een verbinding zonder klok laat dit aan de aanroeper.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> core::result::Result<(), IoError> {
        let _ = timeout;
        Ok(())
    }
}

/// De schrijfkant van een verbinding.
pub trait AsyncWrite {
    /// Schrijft een deel van `buf` en zegt hoeveel.
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>>;

    /// Duwt wat de verbinding zelf buffert naar de draad (een TLS-record).
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        let _ = cx;
        Poll::Ready(Ok(()))
    }

    /// Zet (of wist met `None`) een schrijftermijn die nu ingaat, met dezelfde
    /// betekenis als [`AsyncRead::set_read_timeout`].
    ///
    /// De server zet [`WRITE_TIMEOUT`](crate::WRITE_TIMEOUT) per socketwrite,
    /// zodat een client die niet leest geen taak gijzelt.
    fn set_write_timeout(
        &mut self,
        timeout: Option<Duration>,
    ) -> core::result::Result<(), IoError> {
        let _ = timeout;
        Ok(())
    }
}

/// Het einde van een verbinding.
pub trait Close {
    /// Sluit de verbinding (een FIN, een TLS close_notify).
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>>;

    /// Zegt of de buffers van deze verbinding gegroeid zijn.
    ///
    /// Leannet: een verbinding waarvan de ringen groeiden, was een bulk-
    /// overdracht, en het geadverteerde venster houdt budget vast zolang hij
    /// openstaat (de belofte kan niet naar links krimpen). De server sluit zo'n
    /// verbinding na het verzoek en de pool neemt hem niet aan; kleine,
    /// praterige verbindingen blijven herbruikbaar.
    fn has_grown(&self) -> bool {
        false
    }
}

/// Alles wat een HTTP-verbinding moet kunnen, als één naam voor bounds.
pub trait Conn: AsyncRead + AsyncWrite + Close {}

impl<T: AsyncRead + AsyncWrite + Close> Conn for T {}

/// Leest één keer in `buf`; `Ok(0)` is einde van de stroom.
pub async fn read<R: AsyncRead + ?Sized>(
    r: &mut R,
    buf: &mut [u8],
) -> core::result::Result<usize, IoError> {
    poll_fn(|cx| r.poll_read(cx, buf)).await
}

/// Schrijft `buf` helemaal; een write van nul bytes is een gesloten verbinding.
pub async fn write_all<W: AsyncWrite + ?Sized>(
    w: &mut W,
    mut buf: &[u8],
) -> core::result::Result<(), IoError> {
    while !buf.is_empty() {
        let n = poll_fn(|cx| w.poll_write(cx, buf)).await?;
        if n == 0 {
            return Err(IoError::Closed);
        }
        buf = buf.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

/// Duwt de buffer van de verbinding naar de draad.
pub async fn flush<W: AsyncWrite + ?Sized>(w: &mut W) -> core::result::Result<(), IoError> {
    poll_fn(|cx| w.poll_flush(cx)).await
}

/// Sluit de verbinding.
pub async fn close<C: Close + ?Sized>(c: &mut C) -> core::result::Result<(), IoError> {
    poll_fn(|cx| c.poll_close(cx)).await
}

/// Legt `bytes` achter `v`, en faalt in plaats van het programma af te breken
/// als de heap op is.
pub(crate) fn try_extend(v: &mut Vec<u8>, bytes: &[u8]) -> Result {
    v.try_reserve(bytes.len())
        .map_err(|_| Error::Alloc { bytes: bytes.len() })?;
    v.extend_from_slice(bytes);
    Ok(())
}

/// Een `fmt::Write` op een `Vec<u8>` die faalbaar groeit.
///
/// Zo kan een statusregel of een foutmelding met `write!` worden opgebouwd
/// zonder de afbrekende allocatie van `format!`.
pub(crate) struct FmtBuf<'a>(pub(crate) &'a mut Vec<u8>);

impl fmt::Write for FmtBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        try_extend(self.0, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// De leesbuffer van één verbinding, `BUF_SIZE` groot.
///
/// Hij is tegelijk de grens voor een headerregel: een regel die niet in de
/// buffer past, is te lang.
///
/// # Invariants
///
/// `start <= end <= buf.len() == BUF_SIZE`; `buf[start..end]` is gelezen maar
/// nog niet verbruikt.
pub(crate) struct ReadBuf {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl ReadBuf {
    /// Alloceert de buffer; faalt netjes als de heap op is.
    pub(crate) fn new() -> Result<Self> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(BUF_SIZE)
            .map_err(|_| Error::Alloc { bytes: BUF_SIZE })?;
        buf.resize(BUF_SIZE, 0);
        // INVARIANT: lege buffer van precies BUF_SIZE.
        Ok(ReadBuf {
            buf,
            start: 0,
            end: 0,
        })
    }

    /// De gelezen, nog niet verbruikte bytes.
    pub(crate) fn buffered(&self) -> &[u8] {
        self.buf.get(self.start..self.end).unwrap_or(&[])
    }

    /// Verbruikt `n` gebufferde bytes (hoogstens wat er is).
    pub(crate) fn consume(&mut self, n: usize) {
        // INVARIANT: start blijft onder end; een lege buffer begint weer vooraan.
        self.start = self.start.saturating_add(n).min(self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Geeft de onderliggende buffer met alleen de ongelezen bytes, voor wie
    /// de verbinding overneemt.
    pub(crate) fn into_unread(mut self) -> Vec<u8> {
        self.buf.truncate(self.end);
        self.buf.drain(..self.start);
        self.buf
    }

    /// Leest meer bytes achter de buffer; `Ok(0)` is einde van de stroom.
    async fn fill<R: AsyncRead + ?Sized>(&mut self, r: &mut R) -> Result<usize> {
        if self.end == self.buf.len() && self.start > 0 {
            // Schuif de ongelezen staart naar voren zodat er plek komt.
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let tail = self.buf.get_mut(self.end..).unwrap_or(&mut []);
        if tail.is_empty() {
            return Err(Error::LineTooLong { limit: BUF_SIZE });
        }
        let n = read(r, tail).await?;
        // INVARIANT: de verbinding schreef hoogstens tail.len() bytes.
        self.end = self.end.saturating_add(n).min(self.buf.len());
        Ok(n)
    }

    /// Leest zoals `bufio.Reader.Read`: eerst uit de buffer, een grote vraag
    /// direct van de verbinding, anders één keer bijvullen.
    pub(crate) async fn read<R: AsyncRead + ?Sized>(
        &mut self,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.start == self.end {
            if out.len() >= self.buf.len() {
                return Ok(read(r, out).await?);
            }
            if self.fill(r).await? == 0 {
                return Ok(0);
            }
        }
        let have = self.buffered();
        let n = have.len().min(out.len());
        out.get_mut(..n)
            .unwrap_or(&mut [])
            .copy_from_slice(have.get(..n).unwrap_or(&[]));
        self.consume(n);
        Ok(n)
    }

    /// Zorgt dat er iets gebufferd is; `Ok(false)` is einde van de stroom.
    pub(crate) async fn fill_some<R: AsyncRead + ?Sized>(&mut self, r: &mut R) -> Result<bool> {
        if self.start < self.end {
            return Ok(true);
        }
        Ok(self.fill(r).await? > 0)
    }

    /// Leest één strikte CRLF-regel onder een cumulatief budget.
    ///
    /// Een kale LF en controlebytes zijn fouten, zodat deze parser het nooit
    /// oneens kan zijn met een proxy ervoor. Een regel die niet in de buffer
    /// past, is [`Error::LineTooLong`]; einde van de stroom vóór de LF is
    /// [`Error::Eof`], ook met een halve regel.
    pub(crate) async fn read_line<R: AsyncRead + ?Sized>(
        &mut self,
        r: &mut R,
        budget: &mut usize,
    ) -> Result<String> {
        let mut scanned = 0;
        let len = loop {
            let have = self.buffered();
            if let Some(i) = have
                .get(scanned..)
                .unwrap_or(&[])
                .iter()
                .position(|&b| b == b'\n')
            {
                break scanned + i + 1;
            }
            scanned = have.len();
            if scanned >= self.buf.len() {
                return Err(Error::LineTooLong { limit: BUF_SIZE });
            }
            if self.fill(r).await? == 0 {
                return Err(Error::Eof);
            }
        };
        let raw = self.buffered().get(..len).unwrap_or(&[]);
        let fits = len <= *budget;
        let crlf = len >= 2 && raw.get(len - 2) == Some(&b'\r');
        let line = raw.get(..len.saturating_sub(2)).unwrap_or(&[]);
        let valid = valid_field_value(line);
        let text = core::str::from_utf8(line).map(try_string);
        self.consume(len);
        if !fits {
            return Err(Error::HeadersTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        *budget -= len;
        if !crlf {
            return Err(Error::NotCrlf);
        }
        if !valid {
            return Err(Error::ControlByte);
        }
        match text {
            Ok(s) => s,
            Err(_) => Err(Error::NotUtf8),
        }
    }
}

impl ReadBuf {
    /// Leest velden tot de lege regel, voor client en server; `each` krijgt
    /// naam en waarde (zonder OWS) van elke regel.
    ///
    /// RFC 9112 §5.1: de naam is een token zonder witruimte voor de `:`.
    /// Mildheid hier laat twee parsers het oneens zijn over de framing.
    pub(crate) async fn read_header_block<R: AsyncRead + ?Sized>(
        &mut self,
        r: &mut R,
        budget: &mut usize,
        mut each: impl FnMut(&str, &str) -> Result,
    ) -> Result {
        loop {
            let line = self.read_line(r, budget).await?;
            if line.is_empty() {
                return Ok(());
            }
            let (k, v) = line.split_once(':').ok_or(Error::MalformedHeader)?;
            if !crate::header::valid_token(k) {
                return Err(Error::InvalidHeaderName);
            }
            each(k, crate::header::trim_ows(v))?;
        }
    }
}
