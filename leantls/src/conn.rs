//! De verbinding: één eigenaar, een lees- en een schrijfrichting, en de
//! berichten die een server na de handshake nog mag sturen.
//!
//! Go had een slot per richting zodat twee goroutines tegelijk konden lezen
//! en schrijven. Hier is er één eigenaar met `&mut self`; gelijktijdig
//! schrijven kan niet eens gecompileerd worden, dus er is geen nonce om
//! dubbel te gebruiken. Wie een verbinding wil sluiten terwijl een schrijf
//! vastzit, laat die future vallen en daarna de verbinding: Drop sluit het
//! transport precies één keer.

use alloc::vec::Vec;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll, ready};

use crate::crypto::sha256::Sha256;
use crate::error::{ConnError, Error, Result};
use crate::io::{AsyncRead, AsyncWrite};
use crate::record::{
    self, HEADER, MAX_CIPHER, MAX_PLAIN, REC_ALERT, REC_APP_DATA, REC_CCS, REC_HANDSHAKE, WRITE_BUF,
};
use crate::schedule::Direction;
use crate::trust::PeerKey;
use crate::wire::Reader;

/// Handshake-berichttype NewSessionTicket.
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
/// Handshake-berichttype KeyUpdate.
pub(crate) const HS_KEY_UPDATE: u8 = 24;

/// Een TLS 1.3-verbinding over transport `T`, gemaakt door
/// [`connect`](crate::connect).
///
/// Leest en schrijft applicatiedata via [`AsyncRead`] en [`AsyncWrite`], en
/// handelt NewSessionTicket en KeyUpdate van de server stil af. Sleutels en
/// geheimen worden gewist als de verbinding wegvalt.
pub struct Conn<T> {
    /// Het transport.
    pub(crate) io: T,

    /// Het binnenkomende record: header plus hoogstens [`MAX_CIPHER`].
    pub(crate) rbuf: Vec<u8>,
    /// Aantal bytes van het huidige record dat al binnen is.
    pub(crate) rfill: usize,
    /// Nog niet teruggegeven applicatiedata in `rbuf`.
    pub(crate) plain: (usize, usize),
    /// De leessleutels, na de ServerHello.
    pub(crate) read: Option<Direction>,
    /// Een plakkende leesfout: recordfouten zijn blijvend.
    pub(crate) read_err: Option<Error>,
    /// De server stuurde close_notify.
    pub(crate) peer_closed: bool,

    /// Uitgaande records die nog naar het transport moeten.
    pub(crate) wbuf: Vec<u8>,
    /// Begin van het onverzonden deel.
    pub(crate) wstart: usize,
    /// Einde van het onverzonden deel.
    pub(crate) wend: usize,
    /// Applicatiebytes die al in een record in `wbuf` zitten maar nog niet
    /// als geschreven gemeld zijn.
    pub(crate) wcommitted: usize,
    /// De schrijfsleutels.
    pub(crate) write: Option<Direction>,
    /// Een plakkende schrijffout.
    pub(crate) write_err: Option<Error>,
    /// Er staat een KeyUpdate-antwoord in `wbuf` dat nog niet weg is.
    pub(crate) key_update_queued: bool,
    /// close_notify is al in de buffer gezet.
    pub(crate) close_queued: bool,

    /// Handshake-bytes die nog geen volledig bericht vormen.
    pub(crate) hs: Vec<u8>,
    /// Het lopende transcript; tussenstanden zijn een `clone`.
    pub(crate) transcript: Sha256,
    /// De pin die de server bewees, in gepinde modus.
    pub(crate) peer_key: Option<PeerKey>,
}

/// Een nulgevulde buffer van `n` bytes, of [`Error::Alloc`].
fn zeroed(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Alloc)?;
    v.resize(n, 0);
    Ok(v)
}

impl<T> Conn<T> {
    /// Een verbinding zonder sleutels, met de twee recordbuffers
    /// (samen ongeveer 49 KiB) al gealloceerd.
    pub(crate) fn new(io: T) -> Result<Self> {
        Ok(Self {
            io,
            rbuf: zeroed(HEADER + MAX_CIPHER)?,
            rfill: 0,
            plain: (0, 0),
            read: None,
            read_err: None,
            peer_closed: false,
            wbuf: zeroed(WRITE_BUF)?,
            wstart: 0,
            wend: 0,
            wcommitted: 0,
            write: None,
            write_err: None,
            key_update_queued: false,
            close_queued: false,
            hs: Vec::new(),
            transcript: Sha256::new(),
            peer_key: None,
        })
    }

    /// De sleutel die de server bewees, in gepinde modus.
    pub fn peer_key(&self) -> Option<&PeerKey> {
        self.peer_key.as_ref()
    }

    /// Het transport, bijvoorbeeld om zijn bulk-classificatie te lezen (de
    /// Go-versie gaf `Grown` door).
    pub fn get_ref(&self) -> &T {
        &self.io
    }

    /// Geeft het transport terug; sleutels en buffers worden gewist en
    /// vrijgegeven. Stuur eerst [`Conn::close_notify`] voor een net einde.
    pub fn into_inner(self) -> T {
        let Self { io, .. } = self;
        io
    }
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Leest applicatiedata en handelt berichten na de handshake af.
    fn poll_read_app(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError<E>>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Een KeyUpdate-antwoord mag niet blijven liggen omdat de applicatie
        // alleen leest. Pending is hier geen reden om niet te lezen.
        if self.wstart < self.wend
            && let Poll::Ready(Err(e)) = self.poll_flush(cx)
        {
            return Poll::Ready(Err(e));
        }
        loop {
            let (start, end) = self.plain;
            if start < end {
                let n = buf.len().min(end - start);
                buf[..n].copy_from_slice(&self.rbuf[start..start + n]);
                self.plain = (start + n, end);
                return Poll::Ready(Ok(n));
            }
            if self.peer_closed {
                return Poll::Ready(Ok(0));
            }
            let (typ, s, e) = ready!(self.poll_record(cx))?;
            match typ {
                REC_APP_DATA => self.plain = (s, e),
                REC_ALERT => match record::alert_error(&self.rbuf[s..e]) {
                    None => self.peer_closed = true,
                    Some(err) => return Poll::Ready(Err(self.fail_read(err))),
                },
                // Het compatibiliteits-CCS mag ook na de handshake komen.
                REC_CCS => {}
                REC_HANDSHAKE => {
                    if let Err(err) = self.post_handshake(s, e) {
                        return Poll::Ready(Err(self.fail_read(err)));
                    }
                }
                other => return Poll::Ready(Err(self.fail_read(Error::UnexpectedRecord(other)))),
            }
        }
    }

    /// Maakt een leesfout blijvend.
    fn fail_read(&mut self, e: Error) -> ConnError<E> {
        self.read_err = Some(e);
        e.into()
    }

    /// Verwerkt berichten die een server na de handshake mag sturen.
    fn post_handshake(&mut self, start: usize, end: usize) -> Result {
        let mut pos = start;
        while pos < end {
            let mut r = Reader::new(&self.rbuf[pos..end]);
            let typ = r.u8()?;
            let mut body = r.vec24()?;
            let consumed = (end - pos) - r.rest().len();
            match typ {
                // Hervatting bestaat hier niet, maar tickets sturen mag.
                HS_NEW_SESSION_TICKET => {}
                HS_KEY_UPDATE => {
                    // RFC 8446 §4.6.3: vernieuw de leessleutels en antwoord
                    // als daarom gevraagd wordt.
                    let request = body.u8()?;
                    if request > 1 {
                        return Err(Error::KeyUpdateValue(request));
                    }
                    let next = self
                        .read
                        .as_ref()
                        .ok_or(Error::Internal("no read keys"))?
                        .keys
                        .next()?;
                    self.read = Some(Direction::new(next));
                    if request == 1 && !self.key_update_queued {
                        self.queue_key_update()?;
                    }
                }
                other => return Err(Error::PostHandshake(other)),
            }
            pos += consumed;
        }
        Ok(())
    }

    /// Zet een KeyUpdate zonder verzoek in de buffer en wisselt daarna de
    /// schrijfsleutels. "update_not_requested" voorkomt een eindeloze
    /// uitwisseling; een tweede verzoek terwijl het eerste antwoord nog in de
    /// buffer staat, wordt door dat antwoord al beantwoord.
    fn queue_key_update(&mut self) -> Result {
        self.queue_record(REC_HANDSHAKE, &[HS_KEY_UPDATE, 0, 0, 1, 0])?;
        let next = self
            .write
            .as_ref()
            .ok_or(Error::Internal("no write keys"))?
            .keys
            .next()?;
        self.write = Some(Direction::new(next));
        self.key_update_queued = true;
        Ok(())
    }

    /// Schrijft applicatiedata: hoogstens één record van 2^14 per aanroep.
    ///
    /// Het record staat in de buffer voordat het transport het heeft; geeft
    /// het transport `Pending`, dan meldt de volgende aanroep (met dezelfde
    /// bytes, zoals het poll-contract vraagt) het aantal als geschreven.
    fn poll_write_app(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ConnError<E>>> {
        if let Some(e) = self.write_err {
            return Poll::Ready(Err(e.into()));
        }
        if self.close_queued {
            return Poll::Ready(Err(Error::Closed.into()));
        }
        ready!(self.poll_flush(cx))?;
        if self.wcommitted > 0 {
            let n = core::mem::take(&mut self.wcommitted);
            return Poll::Ready(Ok(n.min(buf.len())));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_PLAIN);
        self.queue_record(REC_APP_DATA, &buf[..n])?;
        self.wcommitted = n;
        ready!(self.poll_flush(cx))?;
        self.wcommitted = 0;
        Poll::Ready(Ok(n))
    }

    /// Stuurt een close_notify, zodat de peer een volledige stroom van een
    /// afgekapte kan onderscheiden.
    ///
    /// Best effort en onbegrensd in tijd: een peer die niet meer leest, houdt
    /// deze poll `Pending`. De Go-versie begrensde dat op 250 ms; hier zet de
    /// aanroeper die grens met zijn eigen timer (een `select` met `after`) en
    /// laat daarna de verbinding vallen, wat het transport sluit.
    pub fn poll_close_notify(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ConnError<E>>> {
        if !self.close_queued {
            if let Some(e) = self.write_err {
                return Poll::Ready(Err(e.into()));
            }
            // Niveau 1 (warning), zoals crypto/tls en OpenSSL; TLS 1.3 negeert
            // het niveau van close_notify.
            self.queue_record(REC_ALERT, &[1, record::ALERT_CLOSE_NOTIFY])?;
            self.close_queued = true;
        }
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    /// De async-vorm van [`Conn::poll_close_notify`].
    pub async fn close_notify(&mut self) -> Result<(), ConnError<E>> {
        poll_fn(|cx| self.poll_close_notify(cx)).await
    }

    /// Schrijft de buffer leeg, als future.
    pub(crate) async fn flush(&mut self) -> Result<(), ConnError<E>> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }
}

impl<T, E> AsyncRead for Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    type Error = ConnError<E>;

    /// Leest applicatiedata. `Ok(0)` betekent dat de server netjes afsloot
    /// met close_notify; een transport dat zonder close_notify sluit, geeft
    /// [`Error::Eof`], omdat de stroom dan afgekapt kan zijn.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        self.get_mut().poll_read_app(cx, buf)
    }
}

impl<T, E> AsyncWrite for Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    type Error = ConnError<E>;

    /// Schrijft applicatiedata, gefragmenteerd op de recordgrens.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        self.get_mut().poll_write_app(cx, buf)
    }
}
