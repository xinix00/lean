//! Eén stream vanuit de handler gezien: het verzoek, de body, het antwoord, en
//! de brievenbus waarlangs die met de verbinding praten.
//!
//! Deze module bezit de brievenbus en de regels voor wat een verzoek of
//! antwoord mag bevatten. Vensters, framing en de draad bezit hij niet; die
//! zijn van `conn.rs`.
//!
//! De brievenbus is het `Channel` uit het handboek (§2), in de kleinste vorm
//! die deze crate nodig heeft zonder een executor-crate te importeren: één
//! slot per stream, dat de handler vult ("dit is mijn kop", "dit zijn mijn
//! bytes", "ik heb zoveel gelezen") en de verbinding leegt. Het slot is een
//! `Cell` die met `take`/`set` wordt geopend: er is geen leenvlag die kan
//! botsen, dus ook geen paniek, en een opening duurt nooit langer dan één
//! functieaanroep zonder `.await`. Beide kanten draaien in dezelfde taak
//! ([`crate::Conn::serve`] pollt de handlers zelf), dus er is geen gelijktijdige
//! toegang om tegen te beschermen.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::future::{Future, poll_fn};
use core::task::Poll;

use crate::hpack::{self, Field};
use crate::{Error, OUR_INITIAL_WINDOW, OUR_MAX_FRAME, OUR_MAX_HEADER_LIST, Result};

/// De inhoud van één brievenbus.
#[derive(Default)]
pub(crate) struct Slot {
    /// Of het verzoek HEAD was; dan heeft geen antwoord een body.
    pub(crate) head: bool,
    /// Ongelezen body, vanaf `body_pos`.
    pub(crate) body: Vec<u8>,
    /// Waar het ongelezen deel van `body` begint.
    pub(crate) body_pos: usize,
    /// `None` zolang de body open is, `Some(Ok)` na een schone END_STREAM,
    /// `Some(Err)` na een reset, afbreken of sluiten door de handler.
    pub(crate) body_end: Option<Result>,
    /// Bytes die de handler las en waarvoor nog krediet terug moet.
    pub(crate) consumed: u32,
    /// Bytes die de handler met [`Body::close`] weggooide; alleen
    /// verbindingskrediet, want de stream krijgt niets meer.
    pub(crate) discarded: u32,
    /// De handler sloot de body.
    pub(crate) body_closed: bool,
    /// Een gecodeerd kopblok dat op de draad wacht.
    pub(crate) header: Option<Vec<u8>>,
    /// De handler heeft zijn koppen gegeven.
    pub(crate) header_sent: bool,
    /// Of dit antwoord een body mag hebben.
    pub(crate) body_allowed: bool,
    /// Antwoordbytes die op venster wachten; hoogstens één frame.
    pub(crate) data: Vec<u8>,
    /// Een fout van de handler-kant; afronden wordt dan een RST_STREAM.
    pub(crate) failed: Option<Error>,
    /// De verbinding liet deze stream los: schrijven faalt met deze reden.
    pub(crate) gone: Option<Error>,
}

impl Slot {
    /// Het aantal ongelezen bodybytes.
    pub(crate) fn unread(&self) -> usize {
        self.body.len().saturating_sub(self.body_pos)
    }

    /// Gooit de ongelezen body weg en geeft hoeveel dat was; zet de reden,
    /// tenzij de body al schoon en leeg was.
    pub(crate) fn discard(&mut self, why: Error) -> usize {
        let n = self.unread();
        self.body.clear();
        self.body_pos = 0;
        let clean_eof = matches!(self.body_end, Some(Ok(())));
        if self.body_end.is_none() || (clean_eof && n > 0) {
            self.body_end = Some(Err(why));
        }
        n
    }

    /// Of de body een echte END_STREAM kreeg en helemaal gelezen is. Sluiten
    /// door de handler en een reset zijn bewust andere toestanden.
    pub(crate) fn clean_eof(&self) -> bool {
        matches!(self.body_end, Some(Ok(()))) && self.unread() == 0
    }

    /// Eén leespoging voor [`Body::read`].
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<Result<usize>> {
        let unread = self.body.get(self.body_pos..).unwrap_or(&[]);
        if !unread.is_empty() {
            let n = unread.len().min(buf.len());
            if let (Some(dst), Some(src)) = (buf.get_mut(..n), unread.get(..n)) {
                dst.copy_from_slice(src);
            }
            self.body_pos += n;
            if self.body_pos == self.body.len() {
                self.body.clear();
                self.body_pos = 0;
            }
            // n is hoogstens 64 KiB (het streamvenster), dus past in u32.
            self.consumed = self
                .consumed
                .saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
            return Poll::Ready(Ok(n));
        }
        match self.body_end {
            None => Poll::Pending,
            Some(Ok(())) => Poll::Ready(Ok(0)),
            Some(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

/// De brievenbus van één stream.
#[derive(Default)]
pub(crate) struct Mailbox(Cell<Slot>);

impl Mailbox {
    /// Opent het slot voor één handeling.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Slot) -> R) -> R {
        let mut slot = self.0.take();
        let r = f(&mut slot);
        self.0.set(slot);
        r
    }

    /// Maakt het slot leeg voor een nieuwe stream.
    pub(crate) fn reset(&self, head: bool) {
        self.0.set(Slot {
            head,
            ..Slot::default()
        });
    }
}

/// Eén verzoek van de peer.
pub struct Request<'s> {
    /// De methode, zoals `GET`.
    pub method: String,
    /// Het pad met eventuele query.
    pub path: String,
    /// Het schema, zoals `https`.
    pub scheme: String,
    /// De authority (de host), of leeg.
    pub authority: String,
    /// De gewone velden, namen in kleine letters, in ontvangstvolgorde. Een
    /// gesplitste `cookie` is al samengevoegd met `"; "`.
    pub header: Vec<(String, String)>,
    /// De stream; hoort in logregels, want een verbinding met tien verzoeken
    /// tegelijk is zonder dit onleesbaar.
    pub stream_id: u32,
    /// De body. Lezen is wat flow-control-krediet aan de peer teruggeeft.
    pub body: Body<'s>,
}

impl Request<'_> {
    /// De eerste waarde van een veld (naam in kleine letters), als die er is.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.header
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// De verzoekbody: een begrensde buffer die de verbinding vult en de handler
/// leegt, waarbij legen krediet teruggeeft.
///
/// Dit is bewust geen synchrone overdracht: dan zou de verbinding wachten tot
/// de handler leest, en één trage handler zou PING, SETTINGS en elke andere
/// stream stilzetten. De peer kan de buffer nooit overlopen, want zijn venster
/// is precies de buffergrootte en krediet volgt het lezen.
pub struct Body<'s> {
    /// De brievenbus van deze stream.
    pub(crate) mb: &'s Mailbox,
}

impl Body<'_> {
    /// Leest bodybytes in `buf`. `Ok(0)` is een schoon einde: END_STREAM van de
    /// peer, met een content-length die klopte. Een reset of een verbinding die
    /// eindigt is een fout, nooit een einde.
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> impl Future<Output = Result<usize>> + 'a {
        poll_fn(move |_| self.mb.with(|s| s.poll_read(buf)))
    }

    /// Stopt de interesse van de handler in de body. Gebufferde bytes worden
    /// weggegooid en gecrediteerd; het afronden van het antwoord zegt de peer
    /// dat hij met de rest kan stoppen.
    pub fn close(&mut self) {
        self.mb.with(|s| {
            s.body_closed = true;
            let n = s.discard(Error::BodyClosed);
            s.discarded = s
                .discarded
                .saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        });
    }
}

/// De antwoordhelft van één stream. Schrijven mag beginnen terwijl de
/// verzoekbody nog binnenkomt: een bidirectionele stream blijft open zolang de
/// verbinding dat is.
pub struct Response<'s> {
    /// De brievenbus van deze stream.
    pub(crate) mb: &'s Mailbox,
}

impl Response<'_> {
    /// Geeft status en koppen; één keer per stream. Velden worden gecontroleerd
    /// voordat er iets de draad op gaat: pseudo-koppen, verbindingsspecifieke
    /// velden, trailers en content-length weigert hij, want DATA plus
    /// END_STREAM is de enige lengtetoestand.
    pub fn write_header(&mut self, status: u16, fields: &[(&str, &str)]) -> Result {
        let head = self.mb.with(|s| s.head);
        let (block, allowed) = match encode_response(status, fields, head) {
            Ok(v) => v,
            Err(e) => {
                self.mb.with(|s| {
                    s.failed.get_or_insert(e);
                });
                return Err(e);
            }
        };
        self.mb.with(|s| {
            if let Some(e) = s.gone.or(s.failed) {
                return Err(e);
            }
            if s.header_sent {
                return Err(Error::HeadersAlreadySent);
            }
            s.header_sent = true;
            s.body_allowed = allowed;
            s.header = Some(block);
            Ok(())
        })
    }

    /// Schrijft bodybytes. Zonder eerdere koppen gaat eerst een 200 uit. Het
    /// wacht als de peer geen venster geeft, en dat is de bedoeling: die
    /// tegendruk draagt een groot antwoord door een smalle uplink zonder hier
    /// te bufferen.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.mb.with(|s| s.header_sent) {
            self.write_header(200, &[])?;
        }
        let refused = self.mb.with(|s| {
            s.gone.or(s.failed).or_else(|| {
                (!data.is_empty() && !s.body_allowed).then_some(Error::BodylessResponse)
            })
        });
        if let Some(e) = refused {
            return Err(e);
        }
        let mut done = 0usize;
        poll_fn(|_| {
            self.mb.with(|s| {
                if let Some(e) = s.gone {
                    return Poll::Ready(Err(e));
                }
                let room = OUR_MAX_FRAME.saturating_sub(s.data.len());
                let rest = data.get(done..).unwrap_or(&[]);
                let n = room.min(rest.len());
                if n > 0 {
                    if s.data.try_reserve(n).is_err() {
                        return Poll::Ready(Err(Error::OutOfMemory));
                    }
                    s.data.extend_from_slice(rest.get(..n).unwrap_or(&[]));
                    done += n;
                }
                if done == data.len() {
                    Poll::Ready(Ok(done))
                } else {
                    Poll::Pending
                }
            })
        })
        .await
    }
}

/// Bedient één stream. De future mag wachten: [`crate::Conn::serve`] pollt
/// hem naast de andere streams, dus één traag verzoek houdt de rest niet op.
///
/// Een `Err` uit de future reset de stream met INTERNAL_ERROR en laat de
/// verbinding staan; zo blijft een kapotte handler één kapot verzoek.
pub trait Handler {
    /// De future van één stream. `Unpin`, omdat `serve` hem in een vaste tabel
    /// bewaart; een `Pin<Box<...>>` voldoet.
    type Future<'s>: Future<Output = Result> + Unpin + 's
    where
        Self: 's;

    /// Begint het werk voor één verzoek.
    fn call<'s>(&mut self, request: Request<'s>, response: Response<'s>) -> Self::Future<'s>;
}

/// Wat er mis is met een verzoek (RFC 9113 §8.2 en §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// Een lege veldnaam.
    EmptyName,
    /// Een ongeldige veldwaarde.
    InvalidValue,
    /// Een pseudo-kop na een gewoon veld.
    PseudoAfterRegular,
    /// Een pseudo-kop die twee keer voorkomt.
    DuplicatePseudo(&'static str),
    /// Een pseudo-kop die niet bestaat, zoals `:protocol`.
    UnknownPseudo,
    /// Een veldnaam die geen token in kleine letters is.
    NotLowercaseToken,
    /// Een verbindingsspecifiek veld.
    ConnectionSpecific,
    /// `te` met iets anders dan `trailers`.
    Te,
    /// Meer dan één content-length.
    MultipleContentLength,
    /// Een content-length die geen strikt decimaal getal is.
    BadContentLength,
    /// Een ontbrekende pseudo-kop.
    Missing(&'static str),
    /// Een lege of ongeldige `:method`.
    InvalidMethod,
    /// CONNECT, ook in origin-vorm.
    Connect,
    /// Een lege `:scheme`.
    EmptyScheme,
    /// Een lege `:path`.
    EmptyPath,
    /// De heap weigerde.
    OutOfMemory,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => f.write_str("empty field name"),
            Self::InvalidValue => f.write_str("field has an invalid value"),
            Self::PseudoAfterRegular => f.write_str("pseudo-header after a regular field"),
            Self::DuplicatePseudo(name) => write!(f, "duplicate {name}"),
            Self::UnknownPseudo => f.write_str("unknown pseudo-header"),
            Self::NotLowercaseToken => {
                f.write_str("field name is not lowercase or not an HTTP token")
            }
            Self::ConnectionSpecific => f.write_str("connection-specific field"),
            Self::Te => f.write_str("te: other than trailers"),
            Self::MultipleContentLength => f.write_str("more than one content-length"),
            Self::BadContentLength => f.write_str("content-length is not unsigned decimal"),
            Self::Missing(name) => write!(f, "missing {name}"),
            Self::InvalidMethod => f.write_str("empty or invalid :method"),
            Self::Connect => f.write_str("CONNECT is not supported"),
            Self::EmptyScheme => f.write_str("empty :scheme"),
            Self::EmptyPath => f.write_str("empty :path"),
            Self::OutOfMemory => f.write_str("out of memory"),
        }
    }
}

/// Een verzoek zonder body, zoals [`request_from`] het uit de velden haalt.
pub(crate) struct RequestParts {
    /// `:method`.
    pub(crate) method: String,
    /// `:path`.
    pub(crate) path: String,
    /// `:scheme`.
    pub(crate) scheme: String,
    /// `:authority`.
    pub(crate) authority: String,
    /// De gewone velden.
    pub(crate) header: Vec<(String, String)>,
    /// De content-length, als die er was.
    pub(crate) content_length: Option<u64>,
}

/// De HTTP/1.1-velden die hier geen betekenis hebben en geweigerd worden
/// (RFC 9113 §8.2.2).
fn is_connection_field(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

/// Maakt van een gedecodeerde koplijst een verzoek, of weigert. Precies één
/// `:method`, `:scheme` en `:path`, hoogstens één `:authority`, niets anders,
/// en geen pseudo-kop na een gewoon veld (RFC 9113 §8.3).
pub(crate) fn request_from(fields: Vec<Field>) -> Result<RequestParts, RequestError> {
    let mut method = None;
    let mut scheme = None;
    let mut path = None;
    let mut authority = None;
    let mut header: Vec<(String, String)> = Vec::new();
    header
        .try_reserve(fields.len())
        .map_err(|_| RequestError::OutOfMemory)?;
    let mut regular = false;
    for f in fields {
        if f.name.is_empty() {
            return Err(RequestError::EmptyName);
        }
        if !valid_field_value(&f.value) {
            return Err(RequestError::InvalidValue);
        }
        if f.name.starts_with(':') {
            if regular {
                return Err(RequestError::PseudoAfterRegular);
            }
            let (slot, name) = match f.name.as_str() {
                ":method" => (&mut method, ":method"),
                ":scheme" => (&mut scheme, ":scheme"),
                ":path" => (&mut path, ":path"),
                ":authority" => (&mut authority, ":authority"),
                _ => return Err(RequestError::UnknownPseudo),
            };
            if slot.is_some() {
                return Err(RequestError::DuplicatePseudo(name));
            }
            *slot = Some(f.value);
            continue;
        }
        regular = true;
        if !valid_lower_token(&f.name) {
            return Err(RequestError::NotLowercaseToken);
        }
        if is_connection_field(&f.name) {
            return Err(RequestError::ConnectionSpecific);
        }
        if f.name == "te" && f.value != "trailers" {
            return Err(RequestError::Te);
        }
        header.push((f.name, f.value));
    }
    join_cookies(&mut header)?;
    let method = method.ok_or(RequestError::Missing(":method"))?;
    let scheme = scheme.ok_or(RequestError::Missing(":scheme"))?;
    let path = path.ok_or(RequestError::Missing(":path"))?;
    if !valid_token(&method) {
        return Err(RequestError::InvalidMethod);
    }
    if method == "CONNECT" {
        return Err(RequestError::Connect);
    }
    if scheme.is_empty() {
        return Err(RequestError::EmptyScheme);
    }
    if path.is_empty() {
        return Err(RequestError::EmptyPath);
    }
    let content_length = content_length(&header)?;
    Ok(RequestParts {
        method,
        path,
        scheme,
        authority: authority.unwrap_or_default(),
        header,
        content_length,
    })
}

/// HTTP/2 staat een peer toe `cookie` te splitsen voor compressie. Eén keer
/// samenvoegen, na het lezen, zodat de generieke weergave van RFC 9113 §8.2.3
/// van een lang gesplitst cookie geen kwadratisch kopieerwerk maakt.
fn join_cookies(header: &mut Vec<(String, String)>) -> Result<(), RequestError> {
    let count = header.iter().filter(|(n, _)| n == "cookie").count();
    if count < 2 {
        return Ok(());
    }
    let len: usize = header
        .iter()
        .filter(|(n, _)| n == "cookie")
        .map(|(_, v)| v.len() + 2)
        .sum();
    let mut joined = String::new();
    joined
        .try_reserve(len)
        .map_err(|_| RequestError::OutOfMemory)?;
    for (i, (_, v)) in header.iter().filter(|(n, _)| n == "cookie").enumerate() {
        if i > 0 {
            joined.push_str("; ");
        }
        joined.push_str(v);
    }
    let mut first = true;
    header.retain_mut(|(n, v)| {
        if n != "cookie" {
            return true;
        }
        if first {
            first = false;
            *v = core::mem::take(&mut joined);
            return true;
        }
        false
    });
    Ok(())
}

/// Accepteert één strikt decimale waarde. Afwezig is `None`: HTTP/2-DATA heeft
/// zijn eigen streamgrens.
fn content_length(header: &[(String, String)]) -> Result<Option<u64>, RequestError> {
    let mut values = header.iter().filter(|(n, _)| n == "content-length");
    let Some((_, v)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RequestError::MultipleContentLength);
    }
    if v.is_empty() {
        return Err(RequestError::BadContentLength);
    }
    let mut n: u64 = 0;
    for c in v.bytes() {
        if !c.is_ascii_digit() {
            return Err(RequestError::BadContentLength);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(c - b'0')))
            .ok_or(RequestError::BadContentLength)?;
    }
    Ok(Some(n))
}

/// Controleert en codeert een antwoordkop; geeft het blok en of het antwoord
/// een body mag hebben.
fn encode_response(status: u16, fields: &[(&str, &str)], head: bool) -> Result<(Vec<u8>, bool)> {
    if !(200..=599).contains(&status) {
        return Err(Error::StatusOutOfRange { status });
    }
    let allowed = !head && !matches!(status, 204 | 205 | 304);
    let mut block = Vec::new();
    let digits = [
        b'0' + (status / 100) as u8,
        b'0' + (status / 10 % 10) as u8,
        b'0' + (status % 10) as u8,
    ];
    let status_text = core::str::from_utf8(&digits).unwrap_or("500");
    hpack::encode(&mut block, ":status", status_text).map_err(|_| Error::OutOfMemory)?;
    let mut total = ":status".len() + 3 + 32;
    let mut name = String::new();
    for &(raw, value) in fields {
        name.clear();
        name.try_reserve(raw.len())
            .map_err(|_| Error::OutOfMemory)?;
        name.push_str(raw);
        name.make_ascii_lowercase();
        if !valid_lower_token(&name) {
            return Err(Error::ResponseFieldName);
        }
        if is_connection_field(&name) || name == "te" || name == "trailer" {
            return Err(Error::ResponseFieldForbidden);
        }
        // DATA plus END_STREAM geeft al exacte framing, en de enige gemeten
        // gebruiker strookt de content-length van de oorsprong bewust weg. Een
        // tweede lengtetoestand die met de stream kan botsen, bestaat dus niet.
        if name == "content-length" {
            return Err(Error::ResponseContentLength);
        }
        if !valid_field_value(value) {
            return Err(Error::ResponseFieldValue);
        }
        total += name.len() + value.len() + 32;
        if total > OUR_MAX_HEADER_LIST {
            return Err(Error::ResponseHeaderTooLarge);
        }
        hpack::encode(&mut block, &name, value).map_err(|_| Error::OutOfMemory)?;
    }
    Ok((block, allowed))
}

/// Een HTTP-token in kleine letters.
fn valid_lower_token(s: &str) -> bool {
    valid_token(s) && !s.bytes().any(|c| c.is_ascii_uppercase())
}

/// Een HTTP-token (RFC 9110 §5.6.2).
fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Een geldige veldwaarde: geen witruimte aan de randen, geen controletekens
/// behalve tab.
fn valid_field_value(s: &str) -> bool {
    let b = s.as_bytes();
    let edge = |c: Option<&u8>| matches!(c, Some(b' ' | b'\t'));
    if edge(b.first()) || edge(b.last()) {
        return false;
    }
    b.iter().all(|&c| c != 0x7f && (c >= 0x20 || c == b'\t'))
}

/// Het ontvangstvenster per stream, als bufferplafond.
pub(crate) const BODY_LIMIT: usize = OUR_INITIAL_WINDOW as usize;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::tests::f;

    #[test]
    fn adversarial_split_cookies_become_one_request_field() {
        let parts = request_from(vec![
            f(":method", "GET"),
            f(":scheme", "https"),
            f(":path", "/"),
            f("cookie", "a=1"),
            f("cookie", "b=2"),
        ])
        .unwrap();
        let cookies: Vec<_> = parts.header.iter().filter(|(n, _)| n == "cookie").collect();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].1, "a=1; b=2");
    }
}
