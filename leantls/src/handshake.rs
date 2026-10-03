//! De TLS 1.3-handshake aan clientkant (RFC 8446 §4): één versie, één suite,
//! één groep, en in gepinde modus één handtekeningalgoritme. Een andere
//! keuze van de server faalt in plaats van onderhandelingsstaat toe te
//! voegen.
//!
//! De vlucht van de server:
//!
//! ```text
//! ServerHello         -> TLS 1.3 en het sleuteldeel van de server
//! EncryptedExtensions -> overslaan; niets gevraagd dat antwoord behoeft
//! Certificate         -> de identiteit van de peer
//! CertificateVerify   -> de handtekening over het transcript
//! Finished            -> de transcript-HMAC met het handshake-geheim
//! ```
//!
//! CertificateVerify bewijst de identiteit; Finished bindt die identiteit aan
//! deze sleuteluitwisseling, zodat een middlebox niet alleen de handtekening
//! kan doorsturen.

use alloc::vec::Vec;
use core::future::poll_fn;

use crate::conn::Conn;
use crate::crypto::ct;
use crate::crypto::ed25519::{self, SIGNATURE_LEN};
use crate::crypto::x25519::{BASEPOINT, x25519};
use crate::error::{ConnError, Error, Result};
use crate::io::{AsyncRead, AsyncWrite};
use crate::record::{REC_ALERT, REC_CCS, REC_HANDSHAKE, alert_error};
use crate::schedule::{
    self, Direction, HASH_LEN, TrafficKeys, cert_verify_content, derive_secret, finished_data,
};
use crate::spki::peer_key_from_cert;
use crate::trust::{CertChain, Entropy, Trust, VerifyPeer};
use crate::wire::{Builder, Reader};

/// ClientHello.
const HS_CLIENT_HELLO: u8 = 1;
/// ServerHello.
const HS_SERVER_HELLO: u8 = 2;
/// EncryptedExtensions.
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
/// Certificate.
const HS_CERTIFICATE: u8 = 11;
/// CertificateRequest.
const HS_CERTIFICATE_REQUEST: u8 = 13;
/// CertificateVerify.
const HS_CERTIFICATE_VERIFY: u8 = 15;
/// Finished.
const HS_FINISHED: u8 = 20;

/// server_name.
const EXT_SERVER_NAME: u16 = 0;
/// supported_groups.
const EXT_SUPPORTED_GROUPS: u16 = 10;
/// signature_algorithms.
const EXT_SIGNATURE_ALGS: u16 = 13;
/// supported_versions.
const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// key_share.
const EXT_KEY_SHARE: u16 = 51;

/// TLS 1.3.
const VERSION_TLS13: u16 = 0x0304;
/// TLS 1.3 zet 1.2 in de oude versievelden en onderhandelt de echte versie
/// via een extensie.
const LEGACY_VERSION: u16 = 0x0303;
/// X25519.
const GROUP_X25519: u16 = 0x001d;
/// Ed25519.
pub(crate) const SIG_ED25519: u16 = 0x0807;
/// TLS_AES_128_GCM_SHA256.
const SUITE_AES128_GCM: u16 = 0x1301;

/// De vaste ServerHello.random die om een andere groep vraagt (§4.1.3).
/// Omdat alleen X25519 wordt aangeboden, faalt die duidelijk.
pub(crate) const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Een certificaatketen is normaal een paar KiB; deze grens voorkomt dat een
/// peer één bericht tot een onbegrensde allocatie maakt.
const MAX_HANDSHAKE: usize = 1 << 16;

/// Het compatibiliteits-CCS: zes bytes klaartekst, ook als er al
/// schrijfsleutels zijn.
const CCS_RECORD: [u8; 6] = [REC_CCS, 3, 3, 0, 1, 1];

/// Maakt een TLS 1.3-verbinding over `io`.
///
/// `server_name` gaat per verbinding als SNI mee en is bij
/// [`Trust::Chain`] ook de naam waartegen de keten wordt getoetst; leeg
/// betekent geen SNI (alleen toegestaan met een pin). De handshake is
/// gretig, zodat een vertrouwensfout hier opvalt en niet pas bij de eerste
/// applicatie-I/O.
///
/// Een deadline zet de aanroeper door deze future te laten vallen (de
/// Go-versie begrensde TCP-opzet en handshake elk op 10 s, gelijk aan
/// leanhttp, zodat een zwijgende peer geen socket kan vasthouden). Bij een
/// fout of annulering wordt het transport met de rest opgeruimd; er is niets
/// om apart te sluiten.
///
/// # Examples
///
/// ```
/// # use leantls::{connect, Entropy, PeerKey, Trust, Error, ConnError};
/// # use leantls::{AsyncRead, AsyncWrite};
/// # use core::{pin::Pin, task::{Context, Poll}};
/// # struct Dead;
/// # impl AsyncRead for Dead { type Error = ();
/// #   fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, ()>> { Poll::Ready(Err(())) } }
/// # impl AsyncWrite for Dead { type Error = ();
/// #   fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<Result<usize, ()>> { Poll::Ready(Err(())) } }
/// // Ketenverificatie zonder naam weigert voordat er iets verstuurd wordt.
/// # struct V;
/// # impl leantls::VerifyPeer for V {
/// #   fn signature_algorithms(&self) -> &[u16] { &[] }
/// #   fn verify_chain(&self, _: leantls::CertChain<'_>, _: &str) -> leantls::Result { Ok(()) }
/// #   fn verify_signature(&self, _: &[u8], _: u16, _: &[u8], _: &[u8]) -> leantls::Result { Ok(()) } }
/// let fut = connect(Dead, &Trust::Chain(&V), "", Entropy::new([7; 96]));
/// # let mut fut = core::pin::pin!(fut);
/// # let mut cx = Context::from_waker(core::task::Waker::noop());
/// # match fut.as_mut().poll(&mut cx) {
/// #   Poll::Ready(Err(e)) => assert!(matches!(e, ConnError::Tls(Error::ServerNameRequired))),
/// #   _ => unreachable!(),
/// # }
/// # use core::future::Future;
/// ```
pub async fn connect<T, E>(
    io: T,
    trust: &Trust<'_>,
    server_name: &str,
    entropy: Entropy,
) -> Result<Conn<T>, ConnError<E>>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    check_config(trust, server_name)?;
    let mut conn = Conn::new(io)?;
    conn.handshake(trust, server_name, entropy).await?;
    Ok(conn)
}

/// Weigert een configuratie die niets bewijst, voordat er een byte over het
/// transport gaat.
pub(crate) fn check_config(trust: &Trust<'_>, server_name: &str) -> Result {
    if matches!(trust, Trust::Chain(_)) && server_name.is_empty() {
        return Err(Error::ServerNameRequired);
    }
    if server_name.len() > 255 {
        return Err(Error::ServerNameTooLong(server_name.len()));
    }
    Ok(())
}

/// Wie de CertificateVerify controleert, gekozen bij het Certificate-bericht.
enum Verifier<'a> {
    /// De pin, al vergeleken met het certificaat.
    Pinned([u8; 32]),
    /// De ketenverificatie met een kopie van het blad.
    Chain(&'a dyn VerifyPeer, Vec<u8>),
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Doorloopt de handshake en installeert de applicatiesleutels.
    pub(crate) async fn handshake(
        &mut self,
        trust: &Trust<'_>,
        server_name: &str,
        entropy: Entropy,
    ) -> Result<(), ConnError<E>> {
        let mut private = crate::crypto::ct::Secret::new([0u8; 32]);
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        private.copy_from_slice(&entropy.bytes[..32]);
        random.copy_from_slice(&entropy.bytes[32..64]);
        session_id.copy_from_slice(&entropy.bytes[64..]);
        drop(entropy);
        let share = x25519(&private, &BASEPOINT);

        // --- ClientHello ---------------------------------------------------
        let ch = client_hello(&random, &session_id, &share, server_name, sig_algs(trust))?;
        self.transcript.update(&ch);
        self.queue_record(REC_HANDSHAKE, &ch)?;
        self.flush().await?;

        // --- ServerHello ---------------------------------------------------
        let len = self.expect(HS_SERVER_HELLO).await?;
        let server_share = parse_server_hello(self.body(len), &session_id);
        self.consume(len);
        let server_share = server_share?;
        // Handshake-berichten mogen geen sleutelwissel overspannen.
        self.require_boundary()?;

        // --- Sleutels ------------------------------------------------------
        let shared = crate::crypto::ct::Secret::new(x25519(&private, &server_share));
        drop(private);
        // RFC 8446 §7.4.2: een nul-uitkomst betekent een zwak punt; afbreken.
        if ct::eq(&shared[..], &[0u8; 32]) {
            return Err(Error::KeyShare.into());
        }
        let secrets = schedule::new_secrets(&shared);
        drop(shared);
        let secrets = secrets?;
        let chsh = self.transcript.clone().finish();
        let c_hs =
            TrafficKeys::from_secret(derive_secret(&secrets.handshake, b"c hs traffic", &chsh)?)?;
        let s_hs =
            TrafficKeys::from_secret(derive_secret(&secrets.handshake, b"s hs traffic", &chsh)?)?;
        self.read = Some(Direction::new(s_hs));
        self.write = Some(Direction::new(c_hs));

        // --- Versleutelde vlucht van de server -----------------------------
        let len = self.expect(HS_ENCRYPTED_EXTENSIONS).await?;
        self.consume(len);

        let (typ, len) = self.read_handshake().await?;
        if typ == HS_CERTIFICATE_REQUEST {
            return Err(Error::ClientAuthRequested.into());
        }
        if typ != HS_CERTIFICATE {
            return Err(Error::UnexpectedMessage {
                want: HS_CERTIFICATE,
                got: typ,
            }
            .into());
        }
        let verifier = self.trust_decision(trust, server_name, len);
        self.consume(len);
        let verifier = verifier?;
        // De ketenverificatie is het zwaarste rekenwerk van de handshake; één
        // beurt voor de buren op dezelfde executor voordat de handtekening
        // volgt (HopOS docs/apps.md).
        cooperate().await;

        // CertificateVerify dekt het transcript tot en met Certificate.
        let before_cv = self.transcript.clone().finish();
        let len = self.expect(HS_CERTIFICATE_VERIFY).await?;
        let checked = verify_certificate_verify(self.body(len), &verifier, &before_cv);
        self.consume(len);
        checked?;
        cooperate().await;

        let before_fin = self.transcript.clone().finish();
        let len = self.expect(HS_FINISHED).await?;
        let s_secret = &self
            .read
            .as_ref()
            .ok_or(Error::Internal("no read keys"))?
            .keys
            .secret;
        let want = finished_data(s_secret, &before_fin)?;
        let ok = ct::eq(self.body(len), &want);
        self.consume(len);
        if !ok {
            return Err(Error::FinishedMismatch.into());
        }
        self.require_boundary()?;

        // --- Onze kant afmaken ---------------------------------------------
        // De applicatiesleutels dekken tot en met de Finished van de server.
        let after_fin = self.transcript.clone().finish();
        // Middleboxes verwachten nog steeds change_cipher_spec.
        self.queue_raw(&CCS_RECORD)?;
        let c_secret = &self
            .write
            .as_ref()
            .ok_or(Error::Internal("no write keys"))?
            .keys
            .secret;
        let fin = finished_data(c_secret, &after_fin)?;
        let mut msg = [0u8; 4 + HASH_LEN];
        msg[..4].copy_from_slice(&[HS_FINISHED, 0, 0, HASH_LEN as u8]);
        msg[4..].copy_from_slice(&fin);
        self.queue_record(REC_HANDSHAKE, &msg)?;

        let s_ap = derive_secret(&secrets.master, b"s ap traffic", &after_fin)?;
        let c_ap = derive_secret(&secrets.master, b"c ap traffic", &after_fin)?;
        self.read = Some(Direction::new(TrafficKeys::from_secret(s_ap)?));
        self.write = Some(Direction::new(TrafficKeys::from_secret(c_ap)?));
        self.flush().await?;
        // Het voltooide transcript en de certificaten zijn niet meer nodig.
        self.hs = Vec::new();
        Ok(())
    }

    /// De enige vertrouwensbeslissing: een pin vergelijken zonder keten, naam
    /// of datum, of de keten aan de aanroeper geven.
    fn trust_decision<'a>(
        &mut self,
        trust: &Trust<'a>,
        server_name: &str,
        len: usize,
    ) -> Result<Verifier<'a>> {
        let chain = CertChain::parse(self.body(len))?;
        match *trust {
            Trust::Pinned(pin) => {
                let got = peer_key_from_cert(chain.leaf())?;
                if got != *pin.as_bytes() {
                    return Err(Error::PinMismatch {
                        got,
                        want: *pin.as_bytes(),
                    });
                }
                self.peer_key = Some(pin);
                Ok(Verifier::Pinned(got))
            }
            Trust::Chain(v) => {
                v.verify_chain(chain, server_name)?;
                let mut leaf = Vec::new();
                leaf.try_reserve_exact(chain.leaf().len())
                    .map_err(|_| Error::Alloc)?;
                leaf.extend_from_slice(chain.leaf());
                Ok(Verifier::Chain(v, leaf))
            }
        }
    }

    /// De inhoud van het bericht vooraan in de handshake-buffer.
    pub(crate) fn body(&self, len: usize) -> &[u8] {
        self.hs.get(4..4 + len).unwrap_or(&[])
    }

    /// Haalt het bericht vooraan uit de handshake-buffer.
    pub(crate) fn consume(&mut self, len: usize) {
        let n = (4 + len).min(self.hs.len());
        self.hs.drain(..n);
    }

    /// Eist dat er geen half bericht over een sleutelwissel heen hangt.
    pub(crate) fn require_boundary(&self) -> Result {
        match self.hs.first() {
            None => Ok(()),
            Some(t) => Err(Error::UnexpectedMessage { want: 0, got: *t }),
        }
    }

    /// Leest één handshake-bericht van het vereiste type en geeft zijn
    /// lengte.
    pub(crate) async fn expect(&mut self, want: u8) -> Result<usize, ConnError<E>> {
        let (got, len) = self.read_handshake().await?;
        if got != want {
            return Err(Error::UnexpectedMessage { want, got }.into());
        }
        Ok(len)
    }

    /// Geeft type en lengte van het volgende handshake-bericht en neemt het
    /// op in het transcript. Buffert over recordgrenzen heen, want records en
    /// berichten lopen niet gelijk.
    async fn read_handshake(&mut self) -> Result<(u8, usize), ConnError<E>> {
        loop {
            if let [typ, a, b, c, ..] = self.hs[..] {
                let n = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
                if n > MAX_HANDSHAKE {
                    return Err(Error::HandshakeTooLarge(MAX_HANDSHAKE).into());
                }
                if let Some(msg) = self.hs.get(..4 + n) {
                    self.transcript.update(msg);
                    return Ok((typ, n));
                }
            }
            let (typ, s, e) = poll_fn(|cx| self.poll_record(cx)).await?;
            match typ {
                // Middlebox-compatibiliteit (§5); geen handshake-bericht.
                REC_CCS => {}
                REC_ALERT => {
                    return Err(alert_error(&self.rbuf[s..e])
                        .unwrap_or(Error::CloseNotify)
                        .into());
                }
                REC_HANDSHAKE => {
                    if self.hs.len() + (e - s) > MAX_HANDSHAKE {
                        return Err(Error::HandshakeTooLarge(MAX_HANDSHAKE).into());
                    }
                    self.hs.try_reserve(e - s).map_err(|_| Error::Alloc)?;
                    self.hs.extend_from_slice(&self.rbuf[s..e]);
                }
                other => return Err(Error::UnexpectedRecord(other).into()),
            }
        }
    }
}

/// De aangeboden handtekeningalgoritmen: die van de ketenverificatie, of
/// alleen Ed25519. Bied nooit meer aan dan de actieve verificatie kan.
fn sig_algs<'a>(trust: &Trust<'a>) -> &'a [u16] {
    match trust {
        Trust::Chain(v) if !v.signature_algorithms().is_empty() => v.signature_algorithms(),
        _ => &[SIG_ED25519],
    }
}

/// Bouwt de vaste ClientHello rond zijn drie willekeurige velden.
pub(crate) fn client_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    share: &[u8; 32],
    server_name: &str,
    sig_algs: &[u16],
) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(HS_CLIENT_HELLO)?;
    let body = b.open(3)?;
    b.u16(LEGACY_VERSION)?;
    b.bytes(random)?;
    let m = b.open(1)?;
    b.bytes(session_id)?;
    b.close(m)?;
    let m = b.open(2)?;
    b.u16(SUITE_AES128_GCM)?;
    b.close(m)?;
    b.bytes(&[1, 0])?; // Compressie: alleen "geen".

    let exts = b.open(2)?;
    if !server_name.is_empty() && server_name.parse::<core::net::IpAddr>().is_err() {
        b.u16(EXT_SERVER_NAME)?;
        let ext = b.open(2)?;
        let list = b.open(2)?;
        b.u8(0)?; // host_name
        let name = b.open(2)?;
        b.bytes(server_name.as_bytes())?;
        b.close(name)?;
        b.close(list)?;
        b.close(ext)?;
    }
    b.u16(EXT_SUPPORTED_GROUPS)?;
    b.bytes(&[0, 4, 0, 2])?;
    b.u16(GROUP_X25519)?;

    b.u16(EXT_SIGNATURE_ALGS)?;
    let ext = b.open(2)?;
    let list = b.open(2)?;
    for a in sig_algs {
        b.u16(*a)?;
    }
    b.close(list)?;
    b.close(ext)?;

    b.u16(EXT_SUPPORTED_VERSIONS)?;
    b.bytes(&[0, 3, 2])?;
    b.u16(VERSION_TLS13)?;

    b.u16(EXT_KEY_SHARE)?;
    b.bytes(&[0, 38, 0, 36])?;
    b.u16(GROUP_X25519)?;
    b.u16(32)?;
    b.bytes(share)?;
    b.close(exts)?;
    b.close(body)?;
    Ok(b.finish())
}

/// Controleert de keuzes in de ServerHello en geeft het sleuteldeel.
pub(crate) fn parse_server_hello(body: &[u8], session_id: &[u8; 32]) -> Result<[u8; 32]> {
    let mut r = Reader::new(body);
    r.u16()?; // legacy_version is niet gezaghebbend.
    if r.take(32)? == HELLO_RETRY_RANDOM {
        return Err(Error::HelloRetryRequest);
    }
    // De compatibiliteits-sessie-id moet de onze echoën.
    if r.vec8()?.rest() != session_id {
        return Err(Error::SessionIdMismatch);
    }
    let suite = r.u16()?;
    if suite != SUITE_AES128_GCM {
        return Err(Error::CipherSuite(suite));
    }
    // TLS 1.3 kent geen compressie; toestaan zou ook CRIME terugbrengen.
    let comp = r.u8()?;
    if comp != 0 {
        return Err(Error::Compression(comp));
    }
    let mut exts = r.vec16()?;
    let mut share = None;
    let mut saw_version = false;
    while !exts.is_empty() {
        let typ = exts.u16()?;
        let mut ext = exts.vec16()?;
        match typ {
            EXT_SUPPORTED_VERSIONS => {
                let v = ext.u16()?;
                if v != VERSION_TLS13 {
                    return Err(Error::Version(v));
                }
                saw_version = true;
            }
            EXT_KEY_SHARE => {
                let g = ext.u16()?;
                if g != GROUP_X25519 {
                    return Err(Error::Group(g));
                }
                let k = ext.vec16()?.rest();
                let mut s = [0u8; 32];
                if k.len() != s.len() {
                    return Err(Error::KeyShare);
                }
                s.copy_from_slice(k);
                share = Some(s);
            }
            // Onbekende extensies mogen van TLS genegeerd worden.
            _ => {}
        }
    }
    // Zonder supported_versions is dit een TLS 1.2-server, geen geldige
    // downgrade.
    if !saw_version {
        return Err(Error::NotTls13);
    }
    share.ok_or(Error::NoKeyShare)
}

/// Roept de verificatie aan met de §4.4.3-invoer over het transcript tot en
/// met Certificate. Deze crate bouwt die invoer zelf in plaats van de
/// protocolopbouw aan de verificatie over te laten.
fn verify_certificate_verify(
    body: &[u8],
    verifier: &Verifier<'_>,
    transcript: &[u8; HASH_LEN],
) -> Result {
    let mut r = Reader::new(body);
    let alg = r.u16()?;
    let sig = r.vec16()?.rest();
    let content = cert_verify_content(transcript);
    match verifier {
        Verifier::Pinned(key) => {
            if alg != SIG_ED25519 {
                return Err(Error::SignatureAlgorithm(alg));
            }
            let sig: &[u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| Error::BadSignature)?;
            if ed25519::verify(key, &content, sig) {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
        Verifier::Chain(v, leaf) => v.verify_signature(leaf, alg, &content, sig),
    }
}

/// Eén beurt aan de executor: de taak meldt zich meteen weer en gaat
/// verder zodra de anderen hun beurt hadden. Zonder executor-afhankelijkheid,
/// zodat deze crate `no_std` en vrij van runtimes blijft.
async fn cooperate() {
    let mut yielded = false;
    core::future::poll_fn(|cx| {
        if yielded {
            core::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await;
}
