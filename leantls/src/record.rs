//! De recordlaag van TLS 1.3 (RFC 8446 §5).
//!
//! Drie regels die bij 1.3 horen blijven hier bij elkaar:
//!
//! - TLSInnerPlaintext draagt het echte inhoudstype binnen de versleuteling;
//!   het buitenste type is altijd application_data (23).
//! - De nonce komt uit een niet-verzonden recordteller die na elke
//!   sleutelwissel opnieuw begint, dus beide kanten moeten gelijk tellen.
//! - De AAD is de vijf bytes header, inclusief de lengte van de ciphertext.
//!
//! change_cipher_spec blijft klaartekst als betekenisloos
//! compatibiliteitsrecord: deze client stuurt er één en negeert ontvangen
//! exemplaren.
//!
//! Lezen en schrijven gaan via buffers die de verbinding bezit. Een record
//! dat half binnen of half buiten is, blijft daar staan tot de volgende
//! poll; zo is elke poll te annuleren zonder de stroom te breken.

use core::pin::Pin;
use core::task::{Context, Poll, ready};

use crate::conn::Conn;
use crate::crypto::gcm::TAG_LEN;
use crate::error::{ConnError, Error, Result};
use crate::io::{AsyncRead, AsyncWrite};

/// change_cipher_spec.
pub(crate) const REC_CCS: u8 = 20;
/// alert.
pub(crate) const REC_ALERT: u8 = 21;
/// handshake.
pub(crate) const REC_HANDSHAKE: u8 = 22;
/// application_data.
pub(crate) const REC_APP_DATA: u8 = 23;

/// Lengte van de recordheader.
pub(crate) const HEADER: usize = 5;
/// De klaartekstgrens van de RFC (2^14).
pub(crate) const MAX_PLAIN: usize = 1 << 14;
/// Inclusief inhoudstype, tag en de marge van §5.2. De aangekondigde lengte
/// wordt hiertegen getoetst voordat er iets gelezen wordt.
pub(crate) const MAX_CIPHER: usize = MAX_PLAIN + 256;
/// Het grootste record dat deze client zelf maakt.
pub(crate) const MAX_OUT_RECORD: usize = HEADER + MAX_PLAIN + 1 + TAG_LEN;
/// De schrijfbuffer: een applicatierecord dat nog weg moet plus één
/// KeyUpdate-antwoord erachter.
pub(crate) const WRITE_BUF: usize = 2 * MAX_OUT_RECORD;

/// De clean-shutdown-alert (§6.1).
pub(crate) const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Vertaalt een alert. close_notify wordt `None`: een net einde, geen fout.
pub(crate) fn alert_error(payload: &[u8]) -> Option<Error> {
    match payload {
        [_, ALERT_CLOSE_NOTIFY] => None,
        [level, code] => Some(Error::Alert {
            level: *level,
            code: *code,
        }),
        _ => Some(Error::MalformedAlert),
    }
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Zet een record in de schrijfbuffer: klaartekst zolang er geen
    /// sleutels zijn, daarna versleutelde TLSInnerPlaintext. De teller schuift
    /// hier door, dus een record in de buffer is definitief.
    pub(crate) fn queue_record(&mut self, typ: u8, data: &[u8]) -> Result {
        if let Some(e) = self.write_err {
            return Err(e);
        }
        if data.len() > MAX_PLAIN {
            return Err(Error::Internal("record larger than 2^14"));
        }
        if self.wstart == self.wend {
            self.wstart = 0;
            self.wend = 0;
        }
        let extra = if self.write.is_some() { 1 + TAG_LEN } else { 0 };
        let total = HEADER + data.len() + extra;
        let start = self.wend;
        let Some(out) = self.wbuf.get_mut(start..start + total) else {
            return Err(Error::WriteBacklog);
        };
        let (hdr, body) = out.split_at_mut(HEADER);
        body[..data.len()].copy_from_slice(data);
        let body_len = (data.len() + extra) as u16;
        hdr.copy_from_slice(&[typ, 3, 3, 0, 0]);
        hdr[3..].copy_from_slice(&body_len.to_be_bytes());
        if let Some(dir) = self.write.as_mut() {
            // §5.4-opvulling is optioneel en weggelaten: het kost bandbreedte
            // op kleine nodes en verbergt hier niets wat de lengte al zegt.
            hdr[0] = REC_APP_DATA;
            body[data.len()] = typ;
            let nonce = dir.next_nonce()?;
            let (inner, tag) = body.split_at_mut(data.len() + 1);
            let t = dir.aead.seal(&nonce, hdr, inner);
            tag.copy_from_slice(&t);
        }
        self.wend = start + total;
        Ok(())
    }

    /// Zet ruwe bytes in de schrijfbuffer (het klaartekst-CCS).
    pub(crate) fn queue_raw(&mut self, raw: &[u8]) -> Result {
        let start = self.wend;
        let dst = self
            .wbuf
            .get_mut(start..start + raw.len())
            .ok_or(Error::WriteBacklog)?;
        dst.copy_from_slice(raw);
        self.wend = start + raw.len();
        Ok(())
    }

    /// Schrijft de buffer leeg. Elke fout plakt: de teller van het record is
    /// verbruikt en de ciphertext kan half verstuurd zijn, dus een latere
    /// poging kan deze stroom niet veilig hervatten.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ConnError<E>>> {
        while self.wstart < self.wend {
            if let Some(e) = self.write_err {
                return Poll::Ready(Err(e.into()));
            }
            let pending = &self.wbuf[self.wstart..self.wend];
            match ready!(Pin::new(&mut self.io).poll_write(cx, pending)) {
                Ok(0) => {
                    self.write_err = Some(Error::WriteBroken);
                    return Poll::Ready(Err(Error::WriteZero.into()));
                }
                Ok(n) => self.wstart += n.min(self.wend - self.wstart),
                Err(e) => {
                    self.write_err = Some(Error::WriteBroken);
                    return Poll::Ready(Err(ConnError::Transport(e)));
                }
            }
        }
        self.wstart = 0;
        self.wend = 0;
        self.key_update_queued = false;
        Poll::Ready(Ok(()))
    }

    /// Markeert de leesrichting als stuk en geeft de fout.
    fn read_fail(&mut self, e: Error) -> Poll<Result<(u8, usize, usize), ConnError<E>>> {
        self.read_err = Some(e);
        Poll::Ready(Err(e.into()))
    }

    /// Leest één volledig record en geeft het echte inhoudstype en het bereik
    /// van de klaartekst in `rbuf`. Die klaartekst blijft geldig tot de
    /// volgende aanroep.
    pub(crate) fn poll_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(u8, usize, usize), ConnError<E>>> {
        if let Some(e) = self.read_err {
            return Poll::Ready(Err(e.into()));
        }
        loop {
            let need = if self.rfill < HEADER {
                HEADER
            } else {
                let n = usize::from(u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]));
                if n > MAX_CIPHER {
                    return self.read_fail(Error::RecordTooLarge(n));
                }
                HEADER + n
            };
            if self.rfill >= need {
                break;
            }
            let dst = &mut self.rbuf[self.rfill..need];
            let room = dst.len();
            match ready!(Pin::new(&mut self.io).poll_read(cx, dst)) {
                Ok(0) => return self.read_fail(Error::Eof),
                Ok(n) => self.rfill += n.min(room),
                Err(e) => {
                    self.read_err = Some(Error::ReadBroken);
                    return Poll::Ready(Err(ConnError::Transport(e)));
                }
            }
        }
        let n = self.rfill - HEADER;
        self.rfill = 0;
        let typ = self.rbuf[0];

        // change_cipher_spec blijft klaartekst, ook met sleutels.
        let Some(dir) = self.read.as_mut() else {
            return Poll::Ready(Ok((typ, HEADER, HEADER + n)));
        };
        if typ == REC_CCS {
            return Poll::Ready(Ok((typ, HEADER, HEADER + n)));
        }
        let seq = dir.seq;
        if n < TAG_LEN {
            return self.read_fail(Error::Decrypt(seq));
        }
        let nonce = match dir.next_nonce() {
            Ok(v) => v,
            Err(e) => return self.read_fail(e),
        };
        let (hdr, body) = self.rbuf.split_at_mut(HEADER);
        let (ct, tag) = body[..n].split_at_mut(n - TAG_LEN);
        if dir.aead.open(&nonce, hdr, ct, tag).is_err() {
            // Een record overslaan zou de tellers uit de pas brengen en elk
            // volgend record onleesbaar maken: fataal.
            return self.read_fail(Error::Decrypt(seq));
        }
        // De laatste byte die geen nul is, is het inhoudstype; nullen erna
        // zijn §5.4-opvulling.
        let Some(last) = ct.iter().rposition(|b| *b != 0) else {
            return self.read_fail(Error::NoContentType);
        };
        if last > MAX_PLAIN {
            return self.read_fail(Error::RecordOverflow(last));
        }
        Poll::Ready(Ok((ct[last], HEADER, HEADER + last)))
    }
}
