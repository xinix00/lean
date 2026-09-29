//! Het sleutelschema van TLS 1.3 (RFC 8446 §7.1), los getest tegen de
//! uitgewerkte handshake van RFC 8448.
//!
//! Een verkeerd label of een verkeerd transcript-moment levert stil
//! verkeerde sleutels op en valt pas bij Finished op; daarom volgt elke stap
//! het RFC-diagram letterlijk. SHA-256 en AES-128-GCM leggen de maten vast:
//! een geheim van 32 bytes, een sleutel van 16 en een IV van 12.

use crate::crypto::ct::wipe;
use crate::crypto::gcm::Gcm;
use crate::crypto::hmac::{self, HmacSha256};
use crate::crypto::sha256::{self, Sha256};
use crate::error::{Error, Result};

/// Lengte van een hash en van elk geheim.
pub(crate) const HASH_LEN: usize = sha256::LEN;
/// Lengte van een AES-128-sleutel.
pub(crate) const KEY_LEN: usize = 16;
/// Lengte van de AEAD-nonce.
pub(crate) const IV_LEN: usize = 12;

/// Een geheim van 32 bytes dat zichzelf wist.
pub(crate) struct Secret(pub(crate) [u8; HASH_LEN]);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// HKDF-Expand-Label (§7.1):
///
/// ```text
/// HkdfLabel = { uint16 length; opaque label<7..255>; opaque context<0..255> }
/// ```
///
/// met "tls13 " voor elk label. De lengte staat zowel in de info als in de
/// uitvoer, voor domeinscheiding.
pub(crate) fn expand_label(secret: &[u8], label: &[u8], ctx: &[u8], out: &mut [u8]) -> Result {
    let len = u16::try_from(out.len()).map_err(|_| Error::Internal("HKDF output length"))?;
    let label_len = u8::try_from(6 + label.len()).map_err(|_| Error::Internal("HKDF label"))?;
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::Internal("HKDF context"))?;
    let parts: [&[u8]; 6] = [
        &len.to_be_bytes(),
        &[label_len],
        b"tls13 ",
        label,
        &[ctx_len],
        ctx,
    ];
    if hmac::expand(secret, &parts, out) {
        Ok(())
    } else {
        Err(Error::Internal("HKDF-Expand length"))
    }
}

/// Derive-Secret (§7.1) over een transcript-hash.
pub(crate) fn derive_secret(
    secret: &Secret,
    label: &[u8],
    transcript: &[u8; HASH_LEN],
) -> Result<Secret> {
    let mut out = Secret([0; HASH_LEN]);
    expand_label(&secret.0, label, transcript, &mut out.0)?;
    Ok(out)
}

/// HKDF-Extract in de volgorde van het RFC-diagram: zout, dan IKM.
pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> Secret {
    Secret(hmac::extract(salt, ikm))
}

/// Transcript-Hash("") voor de twee "derived"-stappen.
pub(crate) fn empty_hash() -> [u8; HASH_LEN] {
    Sha256::new().finish()
}

/// De takken van het schema die later nog nodig zijn.
pub(crate) struct Secrets {
    /// Handshake Secret.
    pub(crate) handshake: Secret,
    /// Master Secret.
    pub(crate) master: Secret,
}

/// Leidt af tot en met Master Secret vanuit het X25519-geheim. Zonder PSK
/// begint Early Secret bij nullen:
///
/// ```text
///          0 -> HKDF-Extract = Early Secret
/// Derive-Secret(., "derived", "") -> zout
///  (EC)DHE -> HKDF-Extract = Handshake Secret
/// Derive-Secret(., "derived", "") -> zout
///          0 -> HKDF-Extract = Master Secret
/// ```
pub(crate) fn new_secrets(shared: &[u8; 32]) -> Result<Secrets> {
    let zeros = [0u8; HASH_LEN];
    let early = extract(&[], &zeros);
    let salt = derive_secret(&early, b"derived", &empty_hash())?;
    let handshake = extract(&salt.0, shared);
    let salt = derive_secret(&handshake, b"derived", &empty_hash())?;
    let master = extract(&salt.0, &zeros);
    Ok(Secrets { handshake, master })
}

/// Sleutel, IV en het geheim van één richting; het geheim blijft voor
/// Finished en KeyUpdate.
pub(crate) struct TrafficKeys {
    /// Het verkeersgeheim.
    pub(crate) secret: Secret,
    /// De AES-128-sleutel.
    pub(crate) key: [u8; KEY_LEN],
    /// De IV.
    pub(crate) iv: [u8; IV_LEN],
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.iv);
    }
}

impl TrafficKeys {
    /// Leidt sleutel en IV af uit een verkeersgeheim (§7.3).
    pub(crate) fn from_secret(secret: Secret) -> Result<Self> {
        let mut k = Self {
            secret,
            key: [0; KEY_LEN],
            iv: [0; IV_LEN],
        };
        expand_label(&k.secret.0, b"key", &[], &mut k.key)?;
        expand_label(&k.secret.0, b"iv", &[], &mut k.iv)?;
        Ok(k)
    }

    /// De KeyUpdate van §7.2 met het label "traffic upd".
    pub(crate) fn next(&self) -> Result<Self> {
        let mut s = Secret([0; HASH_LEN]);
        expand_label(&self.secret.0, b"traffic upd", &[], &mut s.0)?;
        Self::from_secret(s)
    }
}

/// Eén richting van de recordlaag: sleutels, AEAD en de recordteller die na
/// elke sleutelwissel opnieuw bij nul begint.
pub(crate) struct Direction {
    /// De sleutels.
    pub(crate) keys: TrafficKeys,
    /// De AEAD met die sleutel.
    pub(crate) aead: Gcm,
    /// Het volgende recordnummer.
    pub(crate) seq: u64,
}

impl Direction {
    /// Installeert sleutels met teller nul.
    pub(crate) fn new(keys: TrafficKeys) -> Self {
        let aead = Gcm::new(&keys.key);
        Self { keys, aead, seq: 0 }
    }

    /// De nonce voor het huidige record, en schuift de teller door.
    pub(crate) fn next_nonce(&mut self) -> Result<[u8; IV_LEN]> {
        let n = nonce(&self.keys.iv, self.seq);
        self.seq = self.seq.checked_add(1).ok_or(Error::SequenceExhausted)?;
        Ok(n)
    }
}

/// Finished verify_data (§4.4.4) over het transcript tot dan toe.
pub(crate) fn finished_data(base: &Secret, transcript: &[u8; HASH_LEN]) -> Result<[u8; HASH_LEN]> {
    let mut fk = Secret([0; HASH_LEN]);
    expand_label(&base.0, b"finished", &[], &mut fk.0)?;
    let mut m = HmacSha256::new(&fk.0);
    m.update(transcript);
    Ok(m.finish())
}

/// Lengte van de CertificateVerify-invoer van de server.
pub(crate) const CERT_VERIFY_LEN: usize = 64 + SERVER_CONTEXT.len() + 1 + HASH_LEN;

/// De contextstring voor de server.
const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// De CertificateVerify-invoer van §4.4.3: 64 spaties, de context, een nul
/// en de transcript-hash. Die opbouw scheidt de handtekening van elk ander
/// protocol dat dezelfde sleutel gebruikt. Alleen de serverkant: deze client
/// tekent niets.
pub(crate) fn cert_verify_content(transcript: &[u8; HASH_LEN]) -> [u8; CERT_VERIFY_LEN] {
    let mut out = [0x20u8; CERT_VERIFY_LEN];
    out[64..64 + SERVER_CONTEXT.len()].copy_from_slice(SERVER_CONTEXT);
    out[64 + SERVER_CONTEXT.len()] = 0;
    out[64 + SERVER_CONTEXT.len() + 1..].copy_from_slice(transcript);
    out
}

/// De AEAD-nonce van §5.3: het recordnummer met nullen aangevuld tot de
/// IV-lengte, xor de IV.
pub(crate) fn nonce(iv: &[u8; IV_LEN], seq: u64) -> [u8; IV_LEN] {
    let mut out = *iv;
    for (o, s) in out[IV_LEN - 8..].iter_mut().zip(seq.to_be_bytes()) {
        *o ^= s;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::{arr32, unhex};

    fn want(what: &str, got: &[u8], exp: &str) {
        assert_eq!(got, &unhex(exp)[..], "{what}");
    }

    /// Port van TestScheduleRFC8448: de sleutels uit de eenvoudige
    /// 1-RTT-handshake van RFC 8448 §3.
    #[test]
    fn schedule_rfc8448() {
        let shared = arr32(
            "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
             35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
        );
        let chsh = arr32(
            "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
             d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8",
        );

        let early = extract(&[], &[0u8; HASH_LEN]);
        want(
            "early secret",
            &early.0,
            "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
             e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a",
        );

        let derived = derive_secret(&early, b"derived", &empty_hash()).unwrap();
        want(
            "derive secret for handshake \"tls13 derived\"",
            &derived.0,
            "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
             16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba",
        );

        let s = new_secrets(&shared).unwrap();
        want(
            "handshake secret",
            &s.handshake.0,
            "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
             01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac",
        );
        want(
            "master secret",
            &s.master.0,
            "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
             47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19",
        );

        let chs = derive_secret(&s.handshake, b"c hs traffic", &chsh).unwrap();
        want(
            "derive secret \"tls13 c hs traffic\"",
            &chs.0,
            "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
             2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21",
        );

        let shs = derive_secret(&s.handshake, b"s hs traffic", &chsh).unwrap();
        want(
            "derive secret \"tls13 s hs traffic\"",
            &shs.0,
            "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
             37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38",
        );

        let k = TrafficKeys::from_secret(shs).unwrap();
        want(
            "server handshake key",
            &k.key,
            "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc",
        );
        want(
            "server handshake iv",
            &k.iv,
            "5d 31 3e b2 67 12 76 ee 13 00 0b 30",
        );
    }

    /// Port van TestNonce.
    #[test]
    fn nonce() {
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&unhex("5d 31 3e b2 67 12 76 ee 13 00 0b 30"));
        assert_eq!(
            super::nonce(&iv, 0),
            iv,
            "record 0 hoort de IV zelf te zijn"
        );

        let got = super::nonce(&iv, 1);
        assert!(
            got[..11] == iv[..11] && got[11] == iv[11] ^ 1,
            "record 1: {got:x?}"
        );

        let got = super::nonce(&iv, 1 << 40);
        assert_ne!(
            got[..8],
            iv[..8],
            "hoge recordnummers raken de bovenste bytes niet"
        );
    }
}
