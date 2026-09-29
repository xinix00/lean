//! AWS Signature Version 4 voor verzoeken met een bekende body.
//!
//! Deze module bezit de canonieke vorm en de ondertekening, niets van het
//! transport. Specificatie:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>.
//!
//! De Go-voorganger draaide tegen AWS, Cloudflare R2, MinIO en Hetzner/Ceph RGW
//! in hoplock/s3. De tests bewaken de canonieke vorm, want elke wijziging daarin
//! maakt elke handtekening ongeldig. Streaming-handtekeningen vallen buiten de
//! scope (KAM.md, TLS/S3).

use alloc::string::String;
use alloc::vec::Vec;

use crate::hmac::hmac_sha256;
use crate::sha256;
use crate::{Error, Header, Result, UNSIGNED_PAYLOAD, Url, push_str};

/// Het algoritme in de Authorization-kop.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// De dienst in de credential-scope.
const SERVICE: &str = "s3";
/// Het slot van de credential-scope.
const TERMINATOR: &str = "aws4_request";

/// De hash van de lege body, voor GET, HEAD, DELETE en LIST. Die is veiliger en
/// breder ondersteund dan [`UNSIGNED_PAYLOAD`].
pub(crate) const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// De statische sleutels en de regio waaronder getekend wordt.
pub(crate) struct Credentials<'a> {
    /// De publieke sleutel-id.
    pub(crate) access_key_id: &'a str,
    /// Het geheim; verlaat deze module alleen als HMAC-uitvoer.
    pub(crate) secret_access_key: &'a str,
    /// Het STS-sessietoken, of leeg.
    pub(crate) session_token: &'a str,
    /// De regio van de credential-scope; "auto" voor R2.
    pub(crate) region: &'a str,
}

/// Zet X-Amz-Date, X-Amz-Content-Sha256, eventueel X-Amz-Security-Token en
/// daarna Authorization in `headers`, precies de koppen die over de draad gaan.
///
/// `payload_hash` is de hexadecimale SHA-256 van de body of
/// [`UNSIGNED_PAYLOAD`]; leeg betekent het laatste. `unix` is de tekentijd in
/// seconden sinds 1970.
pub(crate) fn sign_request(
    method: &str,
    url: &Url,
    headers: &mut Vec<Header>,
    creds: &Credentials<'_>,
    payload_hash: &str,
    unix: u64,
) -> Result {
    let payload_hash = if payload_hash.is_empty() {
        UNSIGNED_PAYLOAD
    } else {
        payload_hash
    };
    let stamp = AmzDate::from_unix(unix);
    let amz_date = stamp.as_str();
    let date = amz_date.get(..8).unwrap_or(amz_date);

    set_header(headers, "X-Amz-Date", amz_date)?;
    set_header(headers, "X-Amz-Content-Sha256", payload_hash)?;
    if !creds.session_token.is_empty() {
        set_header(headers, "X-Amz-Security-Token", creds.session_token)?;
    }

    let (canonical, signed) = canonical_request(method, url, headers, payload_hash)?;

    let mut scope = String::new();
    for part in [date, "/", creds.region, "/", SERVICE, "/", TERMINATOR] {
        push_str(&mut scope, part)?;
    }
    let mut to_sign = String::new();
    let canonical_hash = hex(&sha256::digest(canonical.as_bytes()));
    for part in [
        ALGORITHM,
        "\n",
        amz_date,
        "\n",
        scope.as_str(),
        "\n",
        hex_str(&canonical_hash),
    ] {
        push_str(&mut to_sign, part)?;
    }
    let key = derive_signing_key(creds.secret_access_key, date, creds.region);
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));

    let mut auth = String::new();
    for part in [
        ALGORITHM,
        " Credential=",
        creds.access_key_id,
        "/",
        scope.as_str(),
        ", SignedHeaders=",
        signed.as_str(),
        ", Signature=",
        hex_str(&signature),
    ] {
        push_str(&mut auth, part)?;
    }
    set_header_owned(headers, "Authorization", auth)
}

/// Bouwt het canonieke verzoek en de lijst getekende koppen.
///
/// Twee schijnbare weglatingen zijn opzet:
///
/// - `host` komt uit de URL, omdat het transport die kop bezit en schrijft.
/// - Content-Length blijft ongetekend, omdat het transport hem uit de
///   bodylengte afleidt; zo deed de Go-voorganger het ook met net/http.
pub(crate) fn canonical_request(
    method: &str,
    url: &Url,
    headers: &[Header],
    payload_hash: &str,
) -> Result<(String, String)> {
    // Namen in kleine letters, waarden getrimd, gesorteerd op naam.
    let mut lines: Vec<(String, &str)> = Vec::new();
    lines
        .try_reserve(headers.len() + 1)
        .map_err(|_| Error::OutOfMemory)?;
    lines.push((lowercase("host")?, url.host.as_str()));
    for h in headers {
        if h.name.eq_ignore_ascii_case("authorization") || h.name.eq_ignore_ascii_case("host") {
            continue;
        }
        lines.push((lowercase(h.name)?, h.value.trim()));
    }
    lines.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    push_str(&mut out, method)?;
    push_str(&mut out, "\n")?;
    push_str(&mut out, &canonical_uri(&url.path)?)?;
    push_str(&mut out, "\n")?;
    push_str(&mut out, &canonical_query(&url.query)?)?;
    push_str(&mut out, "\n")?;
    let mut signed = String::new();
    for (i, (name, value)) in lines.iter().enumerate() {
        push_str(&mut out, name)?;
        push_str(&mut out, ":")?;
        push_str(&mut out, value)?;
        push_str(&mut out, "\n")?;
        if i > 0 {
            push_str(&mut signed, ";")?;
        }
        push_str(&mut signed, name)?;
    }
    push_str(&mut out, "\n")?;
    push_str(&mut out, &signed)?;
    push_str(&mut out, "\n")?;
    push_str(&mut out, payload_hash)?;
    Ok((out, signed))
}

/// Escapet elk padsegment met de ongereserveerde tekens van RFC 3986 en laat
/// de scheidingstekens staan. Een leeg pad wordt "/".
///
/// Dit is ook de vorm die over de draad gaat: een sleutel met een spatie of een
/// `+` tekent dan precies de string die de server ontvangt. De kleinere
/// Go-kopie in hop/internal/runner liet deze stap weg en tekende daardoor een
/// andere string dan het verzoek droeg.
pub(crate) fn canonical_uri(path: &str) -> Result<String> {
    let mut out = String::new();
    if path.is_empty() {
        push_str(&mut out, "/")?;
        return Ok(out);
    }
    uri_escape(&mut out, path.as_bytes(), false)?;
    Ok(out)
}

/// Escapet de parameters opnieuw volgens SigV4 en sorteert op sleutel, daarna
/// op waarde.
pub(crate) fn canonical_query(raw: &str) -> Result<String> {
    let mut out = String::new();
    if raw.is_empty() {
        return Ok(out);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in raw.split('&') {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let mut ek = String::new();
        uri_escape(&mut ek, &query_unescape(k)?, true)?;
        let mut ev = String::new();
        uri_escape(&mut ev, &query_unescape(v)?, true)?;
        pairs.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        pairs.push((ek, ev));
    }
    pairs.sort_unstable();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            push_str(&mut out, "&")?;
        }
        push_str(&mut out, k)?;
        push_str(&mut out, "=")?;
        push_str(&mut out, v)?;
    }
    Ok(out)
}

/// Procent-codeert alle bytes buiten de ongereserveerde SigV4-set. Met
/// `encode_slash` onwaar blijft `/` als padscheiding staan.
pub(crate) fn uri_escape(out: &mut String, s: &[u8], encode_slash: bool) -> Result {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    out.try_reserve(s.len()).map_err(|_| Error::OutOfMemory)?;
    for &c in s {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            push_char(out, char::from(c))?;
        } else if c == b'/' && !encode_slash {
            push_char(out, '/')?;
        } else {
            push_char(out, '%')?;
            push_char(out, char::from(HEX_UPPER[usize::from(c >> 4)]))?;
            push_char(out, char::from(HEX_UPPER[usize::from(c & 15)]))?;
        }
    }
    Ok(())
}

/// Decodeert een querycomponent zoals Go's `url.QueryUnescape`: `+` is een
/// spatie en `%XX` een byte. Een kapotte escape levert, net als in Go, een lege
/// waarde op; dan faalt de handtekening luid aan de serverkant.
fn query_unescape(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve(s.len()).map_err(|_| Error::OutOfMemory)?;
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = b.get(i + 1).and_then(|&h| hex_val(h));
                let lo = b.get(i + 2).and_then(|&l| hex_val(l));
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    out.clear();
                    return Ok(out);
                };
                out.push(hi << 4 | lo);
                i += 3;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// De waarde van één hexadecimaal cijfer.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Leidt de ondertekeningssleutel af: vier HMAC's over datum, regio, dienst en
/// het slot van de scope.
pub(crate) fn derive_signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    // De eerste sleutel is "AWS4" + geheim, op de stack samengesteld zodat
    // het geheim niet in een heapbuffer achterblijft.
    let k_date = hmac_with_prefixed_key(b"AWS4", secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    hmac_sha256(&k_service, TERMINATOR.as_bytes())
}

/// HMAC met sleutel `prefix + secret`. Een geheim dat samen met het voorvoegsel
/// langer dan een blok is, wordt door [`hmac_sha256`] eerst gehasht; daarom
/// wordt de sleutel hier alleen op de stack samengesteld als hij past.
fn hmac_with_prefixed_key(prefix: &[u8], secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 128];
    let len = prefix.len() + secret.len();
    match key.get_mut(..len) {
        Some(dst) => {
            let (a, b) = dst.split_at_mut(prefix.len());
            a.copy_from_slice(prefix);
            b.copy_from_slice(secret);
            hmac_sha256(dst, data)
        }
        None => {
            // Langer dan 128 bytes: hash eerst, zoals RFC 2104 toch voorschrijft.
            let mut h = sha256::Sha256::new();
            h.update(prefix);
            h.update(secret);
            hmac_sha256(&h.finish(), data)
        }
    }
}

/// Een kop vervangen of toevoegen, hoofdletterongevoelig, zoals Go's `Set`.
pub(crate) fn set_header(headers: &mut Vec<Header>, name: &'static str, value: &str) -> Result {
    let mut owned = String::new();
    push_str(&mut owned, value)?;
    set_header_owned(headers, name, owned)
}

/// Als [`set_header`], met een waarde die al een eigen buffer heeft.
fn set_header_owned(headers: &mut Vec<Header>, name: &'static str, value: String) -> Result {
    if let Some(h) = headers
        .iter_mut()
        .find(|h| h.name.eq_ignore_ascii_case(name))
    {
        h.value = value;
        return Ok(());
    }
    headers.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
    headers.push(Header { name, value });
    Ok(())
}

/// De hexadecimale SHA-256 van `data` in kleine letters, S3's payload-vorm.
pub(crate) fn hex_sha256(data: &[u8]) -> [u8; 64] {
    hex(&sha256::digest(data))
}

/// Hex in kleine letters van een digest.
pub(crate) fn hex(digest: &[u8; 32]) -> [u8; 64] {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (pair, b) in out.chunks_exact_mut(2).zip(digest) {
        pair[0] = HEX_LOWER[usize::from(b >> 4)];
        pair[1] = HEX_LOWER[usize::from(b & 15)];
    }
    out
}

/// De hex-uitvoer als `&str`; hij bestaat per constructie uit ASCII.
pub(crate) fn hex_str(h: &[u8; 64]) -> &str {
    core::str::from_utf8(h).unwrap_or("")
}

/// Een `String` in kleine letters, faalbaar gealloceerd.
fn lowercase(s: &str) -> Result<String> {
    let mut out = String::new();
    push_str(&mut out, s)?;
    out.make_ascii_lowercase();
    Ok(out)
}

/// Eén teken aanvullen, faalbaar gealloceerd.
fn push_char(out: &mut String, c: char) -> Result {
    out.try_reserve(c.len_utf8())
        .map_err(|_| Error::OutOfMemory)?;
    out.push(c);
    Ok(())
}

/// Een tijdstip in de vorm `20060102T150405Z`, zonder klok en zonder
/// tijdzonebibliotheek: de rekenregel is die van Howard Hinnant
/// (`civil_from_days`), exact voor elke datum na 1970.
pub(crate) struct AmzDate([u8; 16]);

impl AmzDate {
    /// Zet Unix-seconden om naar UTC.
    pub(crate) fn from_unix(unix: u64) -> Self {
        let days = unix / 86_400;
        let secs = unix % 86_400;
        let (y, m, d) = civil_from_days(days);
        let mut out = *b"00000000T000000Z";
        put_digits(&mut out[0..4], y);
        put_digits(&mut out[4..6], m);
        put_digits(&mut out[6..8], d);
        put_digits(&mut out[9..11], secs / 3600);
        put_digits(&mut out[11..13], secs / 60 % 60);
        put_digits(&mut out[13..15], secs % 60);
        Self(out)
    }

    /// De tekst, bijvoorbeeld `20260115T120000Z`.
    pub(crate) fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

/// Dagen sinds 1970-01-01 naar (jaar, maand, dag).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// Schrijft `v` rechts uitgelijnd in decimale cijfers; wat niet past valt weg.
fn put_digits(dst: &mut [u8], mut v: u64) {
    for slot in dst.iter_mut().rev() {
        // Het resultaat van `% 10` past altijd in een u8.
        *slot = b'0' + u8::try_from(v % 10).unwrap_or(0);
        v /= 10;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(https: bool, host: &str, path: &str, query: &str) -> Url {
        Url {
            https,
            host: host.into(),
            path: path.into(),
            query: query.into(),
        }
    }

    fn hdr(name: &'static str, value: &str) -> Header {
        Header {
            name,
            value: value.into(),
        }
    }

    fn get<'a>(headers: &'a [Header], name: &str) -> &'a str {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map_or("", |h| h.value.as_str())
    }

    const JAN_15_2026_NOON: u64 = 1_768_478_400;

    #[test]
    fn uri_escape_cases() {
        let cases: [(&str, bool, &str); 9] = [
            ("abc", false, "abc"),
            ("a b", false, "a%20b"),
            ("a/b", false, "a/b"),
            ("a/b", true, "a%2Fb"),
            ("a+b=c", false, "a%2Bb%3Dc"),
            ("~unreserved-_.set", false, "~unreserved-_.set"),
            (
                "path with spaces/and+specials",
                false,
                "path%20with%20spaces/and%2Bspecials",
            ),
            ("", false, ""),
            ("\n", false, "%0A"),
        ];
        for (input, slash, want) in cases {
            let mut got = String::new();
            uri_escape(&mut got, input.as_bytes(), slash).unwrap();
            assert_eq!(got, want, "uri_escape({input:?}, {slash})");
        }
    }

    #[test]
    fn canonical_query_cases() {
        let cases = [
            ("", ""),
            ("a=1", "a=1"),
            ("b=2&a=1", "a=1&b=2"),
            ("a=2&a=1", "a=1&a=2"),
            ("key=val with space", "key=val%20with%20space"),
            ("a", "a="),
            ("with%20encoded=already", "with%20encoded=already"),
        ];
        for (raw, want) in cases {
            assert_eq!(
                canonical_query(raw).unwrap(),
                want,
                "canonical_query({raw:?})"
            );
        }
    }

    #[test]
    fn canonical_uri_cases() {
        let cases = [
            ("", "/"),
            ("/", "/"),
            ("/foo/bar", "/foo/bar"),
            ("/foo bar/baz", "/foo%20bar/baz"),
            ("/foo+bar/baz~q", "/foo%2Bbar/baz~q"),
        ];
        for (input, want) in cases {
            assert_eq!(canonical_uri(input).unwrap(), want);
        }
    }

    #[test]
    fn derive_signing_key_deterministisch() {
        let k1 = derive_signing_key("secret", "20260101", "us-east-1");
        let k2 = derive_signing_key("secret", "20260101", "us-east-1");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        assert_ne!(k1, derive_signing_key("secret", "20260102", "us-east-1"));
        assert_ne!(k1, derive_signing_key("secret", "20260101", "us-west-2"));
    }

    #[test]
    fn sign_request_zet_de_verwachte_headers() {
        let u = url(true, "bucket.s3.us-east-1.amazonaws.com", "/lock.json", "");
        let mut headers = vec![
            hdr("Content-Type", "application/json"),
            hdr("If-None-Match", "*"),
        ];
        let payload = hex_sha256(b"payload");
        sign_request(
            "PUT",
            &u,
            &mut headers,
            &Credentials {
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                session_token: "",
                region: "us-east-1",
            },
            hex_str(&payload),
            JAN_15_2026_NOON,
        )
        .unwrap();
        assert_eq!(get(&headers, "X-Amz-Date"), "20260115T120000Z");
        assert!(!get(&headers, "X-Amz-Content-Sha256").is_empty());
        let auth = get(&headers, "Authorization");
        assert!(
            auth.starts_with(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260115/us-east-1/s3/aws4_request,"
            ),
            "{auth}"
        );
        assert!(auth.contains("SignedHeaders=") && auth.contains("Signature="));
        let signed = extract_signed_headers(auth);
        for want in [
            "content-type",
            "host",
            "if-none-match",
            "x-amz-content-sha256",
            "x-amz-date",
        ] {
            assert!(
                signed.contains(&want),
                "SignedHeaders mist {want}: {signed:?}"
            );
        }
    }

    #[test]
    fn sign_request_sessie_token() {
        let mut headers = Vec::new();
        sign_request(
            "GET",
            &url(true, "bucket.s3.us-east-1.amazonaws.com", "/lock.json", ""),
            &mut headers,
            &Credentials {
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "secret",
                session_token: "session-tok",
                region: "us-east-1",
            },
            EMPTY_PAYLOAD_HASH,
            JAN_15_2026_NOON,
        )
        .unwrap();
        assert_eq!(get(&headers, "X-Amz-Security-Token"), "session-tok");
        assert!(get(&headers, "Authorization").contains("x-amz-security-token"));
    }

    #[test]
    fn sign_request_deterministisch_bij_vaste_klok() {
        let mk = || {
            let mut headers = Vec::new();
            sign_request(
                "GET",
                &url(true, "bucket.s3.us-east-1.amazonaws.com", "/lock.json", ""),
                &mut headers,
                &Credentials {
                    access_key_id: "AKID",
                    secret_access_key: "secret",
                    session_token: "",
                    region: "us-east-1",
                },
                EMPTY_PAYLOAD_HASH,
                JAN_15_2026_NOON,
            )
            .unwrap();
            get(&headers, "Authorization").to_owned()
        };
        assert_eq!(mk(), mk());
    }

    #[test]
    fn canonical_request_gesigneerde_headers() {
        let u = url(true, "bucket.s3.us-east-1.amazonaws.com", "/lock.json", "");
        let headers = [
            hdr("Content-Type", "application/json"),
            hdr("Authorization", "must-not-be-signed"),
            hdr("X-Amz-Date", "20260115T120000Z"),
        ];
        let (canonical, signed) = canonical_request("PUT", &u, &headers, UNSIGNED_PAYLOAD).unwrap();
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert!(canonical.contains("host:bucket.s3.us-east-1.amazonaws.com\n"));
        assert!(!canonical.contains("content-length"));
    }

    #[test]
    fn lege_payload_hash() {
        assert_eq!(hex_str(&hex_sha256(b"")), EMPTY_PAYLOAD_HASH);
    }

    // Het GET-voorbeeld uit de AWS S3-documentatie ("Signature Calculations
    // for the Authorization Header", examplebucket/test.txt met een Range-kop).
    // De Go-tests toetsten alleen vorm en determinisme; dit is de toets die niet
    // meebeweegt met onze eigen aannames.
    #[test]
    fn aws_voorbeeld_get_object() {
        let u = url(true, "examplebucket.s3.amazonaws.com", "/test.txt", "");
        let mut headers = vec![hdr("Range", "bytes=0-9")];
        sign_request(
            "GET",
            &u,
            &mut headers,
            &Credentials {
                access_key_id: "AKIAIOSFODNN7EXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                session_token: "",
                region: "us-east-1",
            },
            EMPTY_PAYLOAD_HASH,
            1_369_353_600, // 2013-05-24T00:00:00Z
        )
        .unwrap();
        assert_eq!(
            get(&headers, "Authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn amz_date_randen() {
        assert_eq!(AmzDate::from_unix(0).as_str(), "19700101T000000Z");
        assert_eq!(AmzDate::from_unix(951_782_400).as_str(), "20000229T000000Z");
        assert_eq!(
            AmzDate::from_unix(4_102_444_799).as_str(),
            "20991231T235959Z"
        );
    }

    fn extract_signed_headers(auth: &str) -> Vec<&str> {
        let Some((_, rest)) = auth.split_once("SignedHeaders=") else {
            return Vec::new();
        };
        rest.split(',').next().unwrap_or("").split(';').collect()
    }
}
