//! Het vertrouwensmodel: een gepinde Ed25519-sleutel of een ketenverificatie
//! die de aanroeper aanlevert.
//!
//! Precies één van de twee, en dat is een type: een [`Trust`] zonder model of
//! met allebei bestaat niet. Er is geen stille "vertrouw alles"-modus.

use crate::crypto::ct::wipe;
use crate::crypto::ed25519::PUBLIC_KEY_LEN;
use crate::error::{Error, Result};
use crate::wire::Reader;

/// Een gepinde Ed25519-sleutel van 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerKey([u8; PUBLIC_KEY_LEN]);

impl PeerKey {
    /// Een pin uit precies 32 bytes.
    pub const fn new(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Een pin uit een slice, bijvoorbeeld uit een configuratiebestand; een
    /// verkeerde lengte is een fout met beide getallen.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(leantls::PeerKey::from_slice(&[0u8; 5]).is_err());
    /// assert!(leantls::PeerKey::from_slice(&[0u8; 32]).is_ok());
    /// ```
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut k = [0u8; PUBLIC_KEY_LEN];
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::PeerKeySize(bytes.len()));
        }
        k.copy_from_slice(bytes);
        Ok(Self(k))
    }

    /// De sleutelbytes.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

/// De certificaatketen zoals de server hem stuurde, blad eerst, als DER.
///
/// Leent de bytes van het Certificate-bericht; er wordt niets gekopieerd.
/// De structuur is al gecontroleerd voordat een keten bestaat: elk element
/// is niet leeg en de lijst ook niet.
#[derive(Debug, Clone, Copy)]
pub struct CertChain<'a> {
    /// De `certificate_list` uit het bericht.
    list: &'a [u8],
    /// Het bladcertificaat.
    leaf: &'a [u8],
}

impl<'a> CertChain<'a> {
    /// Controleert de lijst uit een Certificate-bericht (RFC 8446 §4.4.2).
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        r.vec8()?; // certificate_request_context
        let list = r.vec24()?.rest();
        let mut it = Reader::new(list);
        let mut leaf = None;
        while !it.is_empty() {
            let cert = it.vec24()?.rest();
            if cert.is_empty() {
                return Err(Error::EmptyCertificate);
            }
            leaf.get_or_insert(cert);
            // OCSP- en SCT-extensies per certificaat bepalen geen identiteit.
            it.vec16()?;
        }
        let leaf = leaf.ok_or(Error::EmptyCertificateList)?;
        Ok(Self { list, leaf })
    }

    /// Het bladcertificaat (het eerste).
    pub fn leaf(&self) -> &'a [u8] {
        self.leaf
    }

    /// Alle certificaten, blad eerst.
    pub fn iter(&self) -> CertIter<'a> {
        CertIter {
            r: Reader::new(self.list),
        }
    }
}

/// Iterator over de certificaten van een [`CertChain`].
#[derive(Clone)]
pub struct CertIter<'a> {
    /// Wat nog over is.
    r: Reader<'a>,
}

impl<'a> Iterator for CertIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.r.is_empty() {
            return None;
        }
        let cert = self.r.vec24().ok()?.rest();
        self.r.vec16().ok()?;
        Some(cert)
    }
}

/// Ketenverificatie die de aanroeper aanlevert, zoals x509verify in de
/// Go-versie. Stateloos: de handshake geeft het blad bij de handtekening
/// opnieuw mee, zodat er niets gealloceerd hoeft te worden.
pub trait VerifyPeer {
    /// De handtekeningcodes (RFC 8446 §4.2.3) die deze verificatie kan
    /// controleren. Leeg betekent alleen Ed25519. Bied nooit iets aan dat
    /// [`VerifyPeer::verify_signature`] niet kan: de server kiest hieruit.
    fn signature_algorithms(&self) -> &[u16];

    /// Controleert de keten tegen `server_name`. Een fout weigert de peer.
    fn verify_chain(&self, chain: CertChain<'_>, server_name: &str) -> Result;

    /// Controleert de CertificateVerify: `alg` is de gekozen code, `signed`
    /// de exacte invoer, `sig` de handtekening, `leaf` het blad uit de keten.
    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result;
}

/// Wie de server moet zijn. Precies één model; er is geen standaardwaarde.
///
/// Een verbinding zonder model of met twee modellen compileert niet:
///
/// ```compile_fail
/// let t = leantls::Trust::default();
/// ```
///
/// ```compile_fail
/// let t = leantls::Trust::Pinned(leantls::PeerKey::new([0; 32]), &());
/// ```
#[derive(Clone, Copy)]
pub enum Trust<'a> {
    /// Een bekende Ed25519-sleutel. Geen keten, geen naam, geen datum: de
    /// pin is de identiteit. SNI is dan optioneel.
    Pinned(PeerKey),
    /// Ketenverificatie door de aanroeper; de servernaam is verplicht.
    Chain(&'a dyn VerifyPeer),
}

/// De willekeur die één handshake verbruikt: 32 bytes X25519-sleutel, 32
/// bytes ClientHello.random en 32 bytes sessie-id.
///
/// De crate heeft geen eigen bron (geen std, geen afhankelijkheden); de
/// aanroeper vult hem uit leanrand of de hardware. [`connect`](crate::connect)
/// neemt hem over als waarde, zodat hij niet twee keer gebruikt kan worden,
/// en hij wist zichzelf bij het opruimen.
pub struct Entropy {
    /// De bytes.
    pub(crate) bytes: [u8; Entropy::LEN],
}

impl Entropy {
    /// Aantal bytes dat een handshake nodig heeft.
    pub const LEN: usize = 96;

    /// Neemt 96 willekeurige bytes over.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self { bytes }
    }
}

impl Drop for Entropy {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}
