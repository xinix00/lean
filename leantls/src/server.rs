//! TLS 1.3-server met één eigenaar en een vooraf gecontroleerde identiteit.
//!
//! De transport-eigenaar begrenst de handshaketijd door `accept` te annuleren.
//! Geen applicatiebytes worden vrijgegeven voordat de client-Finished klopt.
//!
//! De privésleutel blijft bij de aanroeper: [`Identity`] levert de keten en
//! tekent de CertificateVerify, zodat deze crate zonder externe crates kan
//! (de verificatiekant hier is publiek en mag variabele tijd hebben; een
//! geheime sleutel hoort in een constant-time ondertekenaar van de
//! aanroeper). Sleuteluitwisseling is X25519, en P-256 als de identiteit dat
//! via [`Identity::agree_p256`] aanbiedt. De serverrol kwam uit Stulp
//! (03-10), dat hem tot dan in een eigen kopie van deze crate droeg.
use crate::crypto::ct::Secret;
use crate::{
    AsyncRead, AsyncWrite, ChainVerifier, Conn, ConnError, Entropy, Error, Result, Roots,
    VerifyPeer,
};
use crate::{
    crypto::{
        ct,
        x25519::{BASEPOINT, x25519},
    },
    record::REC_HANDSHAKE,
    schedule::{self, Direction, TrafficKeys},
    wire::{Builder, Reader},
};
use alloc::vec::Vec;

/// Een reeds geladen keten en signer. Implementaties moeten de sleutel aan het blad binden.
pub trait Identity {
    /// DER-certificaten, blad eerst; een lege keten is ongeldig.
    fn certificates(&self) -> &[Vec<u8>];
    /// TLS SignatureScheme van de private sleutel.
    fn signature_scheme(&self) -> u16;
    /// Tekent de volledige, domeingescheiden CertificateVerify-inhoud; seed is verse OS-entropy.
    fn sign(&self, message: &[u8], seed: [u8; 32]) -> Result<Vec<u8>>;
    /// Optioneel P-256-ECDH voor clients die geen X25519 aanbieden: met het
    /// efemere geheim `seed` en het ongecomprimeerde punt van de peer, het
    /// eigen ongecomprimeerde punt en het gedeelde geheim. `None` (de
    /// standaard) betekent: alleen X25519.
    fn agree_p256(&self, seed: &[u8; 32], peer: &[u8; 65]) -> Option<Result<([u8; 65], [u8; 32])>> {
        let _ = (seed, peer);
        None
    }
    /// Of [`Identity::agree_p256`] werkt; alleen dan kiest de server P-256.
    fn offers_p256(&self) -> bool {
        false
    }
}

/// Controleert ketengrootte en sleutelbinding. Dit controleert niet de geldigheid voor een client;
/// die blijft diens eigen CA-, naam- en datumcontrole uitvoeren.
pub fn validate_identity(identity: &impl Identity) -> Result {
    let leaf = identity
        .certificates()
        .first()
        .ok_or(Error::EmptyCertificateList)?;
    certificate(identity)?;
    let challenge = b"leantls server identity validation";
    let signature = identity.sign(challenge, [0; 32])?;
    ChainVerifier::new(Roots::from_list(&[leaf])?, 0).verify_signature(
        leaf,
        identity.signature_scheme(),
        challenge,
        &signature,
    )
}

enum Share {
    X25519([u8; 32]),
    P256([u8; 65]),
}
impl Share {
    fn group(&self) -> u16 {
        match self {
            Self::X25519(_) => 0x001d,
            Self::P256(_) => 0x0017,
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::X25519(b) => b,
            Self::P256(b) => b,
        }
    }
    fn exchange(&self, seed: &[u8; 32], identity: &impl Identity) -> Result<(Self, Secret<32>)> {
        match self {
            Self::X25519(peer) => Ok((
                Self::X25519(x25519(seed, &BASEPOINT)),
                Secret::new(x25519(seed, peer)),
            )),
            Self::P256(peer) => {
                let (public, shared) = identity
                    .agree_p256(seed, peer)
                    .ok_or(Error::Group(0x0017))??;
                Ok((Self::P256(public), Secret::new(shared)))
            }
        }
    }
}
struct Hello<'a> {
    session: &'a [u8],
    share: Share,
    http: bool,
}
fn invalid(why: &'static str) -> Error {
    Error::PeerRejected(why)
}
fn list_has(mut list: Reader<'_>, wanted: u16) -> Result<bool> {
    if list.is_empty() {
        return Err(invalid("empty ClientHello algorithm list"));
    }
    let mut found = false;
    while !list.is_empty() {
        found |= list.u16()? == wanted;
    }
    Ok(found)
}
fn hello(bytes: &[u8], scheme: u16, http: bool, p256: bool) -> Result<Hello<'_>> {
    let mut r = Reader::new(bytes);
    if r.u16()? != 0x0303 {
        return Err(Error::NotTls13);
    }
    r.take(32)?;
    let session = r.vec8()?.rest();
    if session.len() > 32 {
        return Err(invalid("ClientHello session ID exceeds 32 bytes"));
    }
    if !list_has(r.vec16()?, 0x1301)? {
        return Err(Error::CipherSuite(0x1301));
    }
    if r.vec8()?.rest() != [0] {
        return Err(invalid("invalid ClientHello compression methods"));
    }
    let mut extensions = r.vec16()?;
    if !r.is_empty() {
        return Err(invalid("trailing ClientHello bytes"));
    }
    let mut seen = Vec::new();
    let (mut version, mut signature, mut group, mut p256_group) = (false, false, false, false);
    let mut share = None;
    let mut selected_http = false;
    while !extensions.is_empty() {
        let typ = extensions.u16()?;
        let mut ext = extensions.vec16()?;
        if seen.contains(&typ) || seen.len() == 256 {
            return Err(invalid("duplicate or excessive ClientHello extensions"));
        }
        seen.try_reserve(1).map_err(|_| Error::Alloc)?;
        seen.push(typ);
        match typ {
            43 => version = list_has(ext.vec8()?, 0x0304)?,
            13 => signature = list_has(ext.vec16()?, scheme)?,
            10 => {
                let groups = ext.vec16()?;
                group = list_has(groups, 0x001d)?;
                p256_group = p256 && list_has(groups, 0x0017)?;
            }
            51 => {
                let mut keys = ext.vec16()?;
                let mut groups = Vec::new();
                while !keys.is_empty() {
                    let id = keys.u16()?;
                    let key = keys.vec16()?;
                    if groups.contains(&id) || groups.len() == 256 {
                        return Err(invalid("duplicate or excessive ClientHello key shares"));
                    }
                    groups.try_reserve(1).map_err(|_| Error::Alloc)?;
                    groups.push(id);
                    if id == 0x001d {
                        share = Some(Share::X25519(
                            key.rest().try_into().map_err(|_| Error::KeyShare)?,
                        ));
                    } else if id == 0x0017 && p256 {
                        let point: [u8; 65] = key.rest().try_into().map_err(|_| Error::KeyShare)?;
                        if point[0] != 4 {
                            return Err(Error::KeyShare);
                        }
                        if share.is_none() {
                            share = Some(Share::P256(point));
                        }
                    }
                }
            }
            16 => {
                let mut names = ext.vec16()?;
                if names.is_empty() {
                    return Err(invalid("empty ALPN list"));
                }
                let mut offered_http = false;
                while !names.is_empty() {
                    let name = names.vec8()?;
                    if name.is_empty() {
                        return Err(invalid("empty ALPN protocol"));
                    }
                    offered_http |= name.rest() == b"http/1.1";
                }
                if http && !offered_http {
                    return Err(invalid("no common ALPN protocol"));
                }
                selected_http = http && offered_http;
            }
            // No SNI-based virtual hosts or session resumption. Unknown offers do not select features.
            _ => {
                ext.take(ext.rest().len())?;
            }
        }
        if !ext.is_empty() {
            return Err(invalid("trailing ClientHello extension bytes"));
        }
    }
    if !version {
        return Err(Error::NotTls13);
    }
    if !signature {
        return Err(Error::SignatureAlgorithm(scheme));
    }
    let share = share.ok_or(Error::NoKeyShare)?;
    if !(match share {
        Share::X25519(_) => group,
        Share::P256(_) => p256_group,
    }) {
        return Err(Error::Group(share.group()));
    }
    Ok(Hello {
        session,
        share,
        http: selected_http,
    })
}
fn server_hello(h: &Hello<'_>, random: &[u8], share: &Share) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(2)?;
    let body = b.open(3)?;
    b.u16(0x0303)?;
    b.bytes(random)?;
    let id = b.open(1)?;
    b.bytes(h.session)?;
    b.close(id)?;
    b.u16(0x1301)?;
    b.u8(0)?;
    let exts = b.open(2)?;
    b.u16(43)?;
    b.u16(2)?;
    b.u16(0x0304)?;
    b.u16(51)?;
    let key = b.open(2)?;
    b.u16(share.group())?;
    let value = b.open(2)?;
    b.bytes(share.bytes())?;
    b.close(value)?;
    b.close(key)?;
    b.close(exts)?;
    b.close(body)?;
    Ok(b.finish())
}
fn encrypted_extensions(http: bool) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(8)?;
    let body = b.open(3)?;
    let exts = b.open(2)?;
    if http {
        b.u16(16)?;
        b.u16(11)?;
        b.u16(9)?;
        b.u8(8)?;
        b.bytes(b"http/1.1")?;
    }
    b.close(exts)?;
    b.close(body)?;
    Ok(b.finish())
}
fn certificate(identity: &impl Identity) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(11)?;
    let body = b.open(3)?;
    b.u8(0)?;
    let certs = b.open(3)?;
    let mut total = 8usize;
    if identity.certificates().is_empty() {
        return Err(Error::EmptyCertificateList);
    }
    for cert in identity.certificates() {
        if cert.is_empty() {
            return Err(Error::EmptyCertificate);
        }
        total = total
            .checked_add(cert.len())
            .and_then(|n| n.checked_add(5))
            .ok_or(Error::HandshakeTooLarge(65536))?;
        if total > 65536 {
            return Err(Error::HandshakeTooLarge(total));
        }
        let entry = b.open(3)?;
        b.bytes(cert)?;
        b.close(entry)?;
        b.u16(0)?;
    }
    b.close(certs)?;
    b.close(body)?;
    Ok(b.finish())
}
impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    async fn server_message(&mut self, message: &[u8]) -> Result<(), ConnError<E>> {
        self.transcript.update(message);
        for part in message.chunks(16384) {
            self.queue_record(REC_HANDSHAKE, part)?;
            self.flush().await?;
        }
        Ok(())
    }
}
/// Accepteert TLS 1.3 met X25519 of P-256 en AES-128-GCM. `http` onderhandelt uitsluitend HTTP/1.1.
/// De identiteit moet vooraf met [`validate_identity`] gecontroleerd zijn. Annuleren sluit `io`.
/// Een scheduler moet iedere verbinding een absolute deadline geven (Stulp gebruikt tien seconden).
pub async fn accept<T, E>(
    io: T,
    identity: &impl Identity,
    entropy: Entropy,
    http: bool,
) -> Result<Conn<T>, ConnError<E>>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    let mut conn = Conn::new(io)?;
    if let Err(error) = handshake(&mut conn, identity, entropy, http).await {
        if let ConnError::Tls(tls) = &error {
            let code = match tls {
                Error::Alert { .. } | Error::CloseNotify | Error::Eof => None,
                Error::NotTls13 | Error::Version(_) => Some(70),
                Error::CipherSuite(_)
                | Error::Group(_)
                | Error::NoKeyShare
                | Error::SignatureAlgorithm(_) => Some(40),
                Error::Truncated | Error::HandshakeTooLarge(_) => Some(50),
                Error::KeyShare | Error::PeerRejected(_) => Some(47),
                Error::FinishedMismatch => Some(51),
                Error::Decrypt(_) => Some(20),
                Error::UnexpectedMessage { .. } | Error::UnexpectedRecord(_) => Some(10),
                _ => Some(80),
            };
            if let Some(code) = code {
                let code = if matches!(tls, Error::PeerRejected("no common ALPN protocol")) {
                    120
                } else {
                    code
                };
                if conn
                    .queue_record(crate::record::REC_ALERT, &[2, code])
                    .is_ok()
                {
                    let _ = conn.flush().await;
                }
            }
        }
        return Err(error);
    }
    Ok(conn)
}
async fn handshake<T, E>(
    conn: &mut Conn<T>,
    identity: &impl Identity,
    entropy: Entropy,
    http: bool,
) -> Result<(), ConnError<E>>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    conn.server = true;
    let len = conn.expect(1).await?;
    let ch = hello(
        conn.body(len),
        identity.signature_scheme(),
        http,
        identity.offers_p256(),
    )?;
    let http = ch.http;
    let mut private = Secret::new([0u8; 32]);
    private.copy_from_slice(&entropy.bytes[..32]);
    let (share, shared) = ch.share.exchange(&private, identity)?;
    drop(private);
    let sh = server_hello(&ch, &entropy.bytes[32..64], &share)?;
    let mut signing_seed = Secret::new([0u8; 32]);
    signing_seed.copy_from_slice(&entropy.bytes[64..]);
    drop(entropy);
    conn.consume(len);
    conn.require_boundary()?;
    if ct::eq(&shared[..], &[0u8; 32]) {
        return Err(Error::KeyShare.into());
    }
    let secrets = schedule::new_secrets(&shared)?;
    drop(shared);
    conn.server_message(&sh).await?;
    let hash = conn.transcript.clone().finish();
    let c_hs = schedule::derive_secret(&secrets.handshake, b"c hs traffic", &hash)?;
    let s_hs = schedule::derive_secret(&secrets.handshake, b"s hs traffic", &hash)?;
    conn.read = Some(Direction::new(TrafficKeys::from_secret(c_hs)?));
    conn.write = Some(Direction::new(TrafficKeys::from_secret(s_hs)?));
    conn.queue_raw(&[20, 3, 3, 0, 1, 1])?;
    conn.server_message(&encrypted_extensions(http)?).await?;
    conn.server_message(&certificate(identity)?).await?;
    let signature = identity.sign(
        &schedule::cert_verify_content(&conn.transcript.clone().finish()),
        *signing_seed,
    )?;
    let mut b = Builder::new();
    b.u8(15)?;
    let body = b.open(3)?;
    b.u16(identity.signature_scheme())?;
    let sig = b.open(2)?;
    b.bytes(&signature)?;
    b.close(sig)?;
    b.close(body)?;
    conn.server_message(&b.finish()).await?;
    let fin = schedule::finished_data(
        &conn
            .write
            .as_ref()
            .ok_or(Error::Internal("server write keys"))?
            .keys
            .secret,
        &conn.transcript.clone().finish(),
    )?;
    let mut message = [0u8; 36];
    message[..4].copy_from_slice(&[20, 0, 0, 32]);
    message[4..].copy_from_slice(&fin);
    conn.server_message(&message).await?;
    let hash = conn.transcript.clone().finish();
    let c_ap = schedule::derive_secret(&secrets.master, b"c ap traffic", &hash)?;
    let s_ap = schedule::derive_secret(&secrets.master, b"s ap traffic", &hash)?;
    // Server application keys start after server Finished, including failure alerts.
    conn.write = Some(Direction::new(TrafficKeys::from_secret(s_ap)?));
    let expected = schedule::finished_data(
        &conn
            .read
            .as_ref()
            .ok_or(Error::Internal("server read keys"))?
            .keys
            .secret,
        &hash,
    )?;
    let len = conn.expect(20).await?;
    if !ct::eq(conn.body(len), &expected) {
        return Err(Error::FinishedMismatch.into());
    }
    conn.consume(len);
    conn.require_boundary()?;
    conn.read = Some(Direction::new(TrafficKeys::from_secret(c_ap)?));
    conn.hs = Vec::new();
    Ok(())
}
