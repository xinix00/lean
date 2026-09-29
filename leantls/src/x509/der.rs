//! Een begrensde DER-lezer: precies de vormen die X.509 nodig heeft.
//!
//! De lezer leent de invoer en kopieert niets; hij alloceert niets, dus een
//! lengte uit de invoer kan nooit een allocatie sturen. Hij recurseert niet:
//! wie een geneste structuur wil, vraagt om een nieuwe [`Der`] over de
//! inhoud, en de diepte staat dan in de code van de aanroeper.
//!
//! Een SET (in namen) wordt nooit uitgepakt: issuer en subject worden als
//! ruwe TLV vergeleken, en [`Der::any`] leest elke tag.
//!
//! Strikt DER, geen BER: geen onbepaalde lengte, geen niet-minimale lengte,
//! geen tagnummers boven 30, INTEGER minimaal gecodeerd, BOOLEAN alleen 00
//! of FF. Een certificaat dat daar niet aan voldoet, is geen DER en dus ook
//! niet ondertekend zoals het gelezen wordt.

use core::fmt;

/// SEQUENCE (constructed).
pub(crate) const SEQUENCE: u8 = 0x30;
/// BOOLEAN.
pub(crate) const BOOLEAN: u8 = 0x01;
/// INTEGER.
pub(crate) const INTEGER: u8 = 0x02;
/// BIT STRING.
pub(crate) const BIT_STRING: u8 = 0x03;
/// OCTET STRING.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// NULL.
pub(crate) const NULL: u8 = 0x05;
/// OBJECT IDENTIFIER.
pub(crate) const OID: u8 = 0x06;
/// UTCTime.
pub(crate) const UTC_TIME: u8 = 0x17;
/// GeneralizedTime.
pub(crate) const GENERALIZED_TIME: u8 = 0x18;

/// `[n]` context-specifiek en constructed, zoals `[0] EXPLICIT`.
pub(crate) const fn explicit(n: u8) -> u8 {
    0xa0 | n
}

/// `[n]` context-specifiek en primitief, zoals `[2] IMPLICIT IA5String`.
pub(crate) const fn implicit(n: u8) -> u8 {
    0x80 | n
}

/// Wat er mis is met de DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerError {
    /// De invoer houdt op midden in een TLV.
    Truncated,
    /// Een onbepaalde, niet-minimale of te grote lengte.
    Length,
    /// Een tag in de meerbyte-vorm (nummer 31 en hoger).
    HighTag,
    /// Een andere tag dan verwacht.
    Tag {
        /// Verwacht.
        want: u8,
        /// Gevonden.
        got: u8,
    },
    /// Bytes na het laatste verwachte veld.
    Trailing,
    /// Een INTEGER die leeg, negatief of niet minimaal is.
    Integer,
    /// Een BOOLEAN die geen 00 of FF is.
    Boolean,
    /// Een BIT STRING met ongeldige opvulling.
    BitString,
    /// Een tijd die geen `YYMMDDHHMMSSZ` of `YYYYMMDDHHMMSSZ` is.
    Time,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DerError::Truncated => f.write_str("truncated"),
            DerError::Length => f.write_str("bad length"),
            DerError::HighTag => f.write_str("high tag number"),
            DerError::Tag { want, got } => write!(f, "tag {got:#04x}, expected {want:#04x}"),
            DerError::Trailing => f.write_str("trailing bytes"),
            DerError::Integer => f.write_str("bad INTEGER"),
            DerError::Boolean => f.write_str("bad BOOLEAN"),
            DerError::BitString => f.write_str("bad BIT STRING"),
            DerError::Time => f.write_str("bad time"),
        }
    }
}

/// Het resultaat van deze module.
pub(crate) type Result<T, E = DerError> = core::result::Result<T, E>;

/// Eén gelezen TLV.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    /// De tag.
    pub(crate) tag: u8,
    /// De inhoud.
    pub(crate) body: &'a [u8],
    /// De hele TLV, met tag en lengte: wat er ondertekend wordt.
    pub(crate) raw: &'a [u8],
}

/// Een cursor over een reeks TLV's.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Der<'a> {
    /// Wat nog niet gelezen is.
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    /// Een cursor over `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Alles gelezen?
    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// De tag van de volgende TLV, zonder te lezen.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Leest de volgende TLV, welke tag ook.
    pub(crate) fn any(&mut self) -> Result<Tlv<'a>> {
        let all = self.rest;
        let [tag, first, rest @ ..] = all else {
            return Err(DerError::Truncated);
        };
        if tag & 0x1f == 0x1f {
            return Err(DerError::HighTag);
        }
        let (len, rest) = match *first {
            n @ 0..0x80 => (usize::from(n), rest),
            // 0x80 is de onbepaalde lengte van BER; DER verbiedt hem. Meer
            // dan vier lengtebytes (4 GiB) is voor een certificaat onzin.
            0x80 | 0x85.. => return Err(DerError::Length),
            long => {
                let count = usize::from(long & 0x7f);
                let (bytes, rest) = rest.split_at_checked(count).ok_or(DerError::Truncated)?;
                // Minimaal: geen voorloopnul, en niet lang als kort had gekund.
                if bytes.first() == Some(&0) {
                    return Err(DerError::Length);
                }
                let n = bytes.iter().fold(0usize, |n, b| n << 8 | usize::from(*b));
                if n < 0x80 {
                    return Err(DerError::Length);
                }
                (n, rest)
            }
        };
        let (body, rest) = rest.split_at_checked(len).ok_or(DerError::Truncated)?;
        let raw = all
            .get(..all.len() - rest.len())
            .ok_or(DerError::Truncated)?;
        self.rest = rest;
        Ok(Tlv {
            tag: *tag,
            body,
            raw,
        })
    }

    /// Leest een TLV met tag `want`.
    pub(crate) fn tlv(&mut self, want: u8) -> Result<Tlv<'a>> {
        let t = self.any()?;
        if t.tag != want {
            return Err(DerError::Tag { want, got: t.tag });
        }
        Ok(t)
    }

    /// Leest de inhoud van een TLV met tag `want`.
    pub(crate) fn read(&mut self, want: u8) -> Result<&'a [u8]> {
        Ok(self.tlv(want)?.body)
    }

    /// Een cursor over de inhoud van een TLV met tag `want`.
    pub(crate) fn nested(&mut self, want: u8) -> Result<Der<'a>> {
        Ok(Der::new(self.read(want)?))
    }

    /// Leest een TLV met tag `want` als die volgt; anders niets.
    pub(crate) fn optional(&mut self, want: u8) -> Result<Option<&'a [u8]>> {
        if self.peek() == Some(want) {
            Ok(Some(self.read(want)?))
        } else {
            Ok(None)
        }
    }

    /// Eist dat alles gelezen is.
    pub(crate) fn end(&self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DerError::Trailing)
        }
    }
}

/// Leest precies één TLV met tag `want` uit `bytes`, zonder rest.
pub(crate) fn single(bytes: &[u8], want: u8) -> Result<Tlv<'_>> {
    let mut d = Der::new(bytes);
    let t = d.tlv(want)?;
    d.end()?;
    Ok(t)
}

/// De grootte van een niet-negatieve INTEGER: de inhoud zonder de
/// tekenbyte. Weigert leeg, negatief en niet-minimaal.
pub(crate) fn uint(body: &[u8]) -> Result<&[u8]> {
    match body {
        [] => Err(DerError::Integer),
        [b, ..] if b & 0x80 != 0 => Err(DerError::Integer),
        [0, next, ..] if next & 0x80 == 0 => Err(DerError::Integer),
        [0, rest @ ..] if !rest.is_empty() => Ok(rest),
        _ => Ok(body),
    }
}

/// Een kleine niet-negatieve INTEGER, zoals `pathLenConstraint`.
pub(crate) fn small_uint(body: &[u8]) -> Result<u32> {
    let mag = uint(body)?;
    if mag.len() > 4 {
        return Err(DerError::Integer);
    }
    Ok(mag.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)))
}

/// Een BOOLEAN: in DER alleen 00 of FF.
pub(crate) fn boolean(body: &[u8]) -> Result<bool> {
    match body {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(DerError::Boolean),
    }
}

/// Een BIT STRING: (bits, aantal ongebruikte bits aan het eind). De
/// ongebruikte bits moeten nul zijn (DER).
pub(crate) fn bit_string(body: &[u8]) -> Result<(&[u8], u8)> {
    let (&unused, bits) = body.split_first().ok_or(DerError::BitString)?;
    if unused > 7 || (bits.is_empty() && unused != 0) {
        return Err(DerError::BitString);
    }
    if let Some(last) = bits.last()
        && last & ((1u8 << unused) - 1) != 0
    {
        return Err(DerError::BitString);
    }
    Ok((bits, unused))
}

/// Een BIT STRING van hele bytes, zoals een sleutel of een handtekening.
pub(crate) fn octets(body: &[u8]) -> Result<&[u8]> {
    match bit_string(body)? {
        (bits, 0) => Ok(bits),
        _ => Err(DerError::BitString),
    }
}

/// Een UTCTime of GeneralizedTime als seconden sinds 1970 (UTC).
///
/// RFC 5280 §4.1.2.5: altijd `Z`, altijd seconden, geen breuk; UTCTime-jaren
/// 50 tot 99 zijn 1950 tot 1999.
pub(crate) fn time(t: Tlv<'_>) -> Result<i64> {
    let digits = |s: &[u8]| -> Result<i64> {
        s.iter().try_fold(0i64, |n, c| match c {
            b'0'..=b'9' => Ok(n * 10 + i64::from(c - b'0')),
            _ => Err(DerError::Time),
        })
    };
    let (year, rest) = match (t.tag, t.body.len()) {
        (UTC_TIME, 13) => {
            let (yy, rest) = t.body.split_at(2);
            let yy = digits(yy)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, rest)
        }
        (GENERALIZED_TIME, 15) => {
            let (yyyy, rest) = t.body.split_at(4);
            (digits(yyyy)?, rest)
        }
        _ => return Err(DerError::Time),
    };
    let [m0, m1, d0, d1, h0, h1, i0, i1, s0, s1, b'Z'] = *rest else {
        return Err(DerError::Time);
    };
    let month = digits(&[m0, m1])?;
    let day = digits(&[d0, d1])?;
    let hour = digits(&[h0, h1])?;
    let min = digits(&[i0, i1])?;
    let sec = digits(&[s0, s1])?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || min > 59
        || sec > 59
    {
        return Err(DerError::Time);
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Dagen in een maand van de proleptische gregoriaanse kalender.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Dagen sinds 1970-01-01 (Howard Hinnant, `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths() {
        let mut d = Der::new(&[0x04, 0x02, 0xaa, 0xbb, 0x05, 0x00]);
        let t = d.tlv(OCTET_STRING).unwrap();
        assert_eq!(t.body, &[0xaa, 0xbb]);
        assert_eq!(t.raw, &[0x04, 0x02, 0xaa, 0xbb]);
        assert_eq!(d.read(NULL).unwrap(), &[] as &[u8]);
        d.end().unwrap();

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        assert_eq!(single(&long, OCTET_STRING).unwrap().body.len(), 0x80);
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([7u8; 0x100]);
        assert_eq!(single(&two, OCTET_STRING).unwrap().body.len(), 0x100);
    }

    #[test]
    fn ber_forms_refused() {
        let cases: [(&[u8], DerError); 8] = [
            (&[0x30, 0x80, 0x00, 0x00], DerError::Length), // onbepaald
            (&[0x04, 0x81, 0x01, 0xaa], DerError::Length), // lang waar kort kon
            (&[0x04, 0x82, 0x00, 0x81], DerError::Length), // voorloopnul
            (&[0x04, 0x85, 1, 0, 0, 0, 0], DerError::Length), // vijf lengtebytes
            (&[0x1f, 0x22, 0x00], DerError::HighTag),
            (&[0x04, 0x03, 0xaa], DerError::Truncated),
            (&[0x04], DerError::Truncated),
            (&[0x04, 0x82, 0x01], DerError::Truncated),
        ];
        for (bytes, want) in cases {
            assert_eq!(Der::new(bytes).any().err(), Some(want), "{bytes:02x?}");
        }
        assert_eq!(
            single(&[0x05, 0x00, 0x05, 0x00], NULL).err(),
            Some(DerError::Trailing)
        );
        assert_eq!(
            Der::new(&[0x05, 0x00]).read(INTEGER).err(),
            Some(DerError::Tag {
                want: INTEGER,
                got: NULL
            })
        );
    }

    #[test]
    fn nested_context_tags() {
        // [3] { SEQUENCE { OID 2.5.29.19, BOOLEAN TRUE, OCTET STRING {} } }
        let b = [
            0xa3, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x00,
        ];
        let mut outer = Der::new(&b);
        let mut ext = outer.nested(explicit(3)).unwrap();
        let mut seq = ext.nested(SEQUENCE).unwrap();
        assert_eq!(seq.read(OID).unwrap(), &[0x55, 0x1d, 0x13]);
        assert!(boolean(seq.read(BOOLEAN).unwrap()).unwrap());
        assert_eq!(seq.optional(implicit(0)).unwrap(), None);
        assert_eq!(seq.read(OCTET_STRING).unwrap(), &[] as &[u8]);
        seq.end().unwrap();
        ext.end().unwrap();
        outer.end().unwrap();
    }

    #[test]
    fn integers() {
        assert_eq!(uint(&[0x01]).unwrap(), &[0x01]);
        assert_eq!(uint(&[0x00]).unwrap(), &[0x00]);
        assert_eq!(uint(&[0x00, 0x80]).unwrap(), &[0x80]);
        assert_eq!(uint(&[]).err(), Some(DerError::Integer));
        assert_eq!(uint(&[0x80]).err(), Some(DerError::Integer), "negatief");
        assert_eq!(
            uint(&[0x00, 0x7f]).err(),
            Some(DerError::Integer),
            "niet minimaal"
        );
        assert_eq!(small_uint(&[0x01, 0x00]).unwrap(), 256);
        assert!(small_uint(&[0x01, 0, 0, 0, 0]).is_err());
        assert!(boolean(&[0x01]).is_err());
        assert!(boolean(&[]).is_err());
    }

    #[test]
    fn bit_strings() {
        assert_eq!(bit_string(&[0x00, 0xaa]).unwrap(), (&[0xaa][..], 0));
        assert_eq!(bit_string(&[0x07, 0x80]).unwrap(), (&[0x80][..], 7));
        assert!(bit_string(&[0x07, 0x81]).is_err(), "ongebruikte bit gezet");
        assert!(bit_string(&[0x08, 0x00]).is_err());
        assert!(bit_string(&[]).is_err());
        assert!(bit_string(&[0x01]).is_err());
        assert!(octets(&[0x01, 0x80]).is_err());
    }

    fn t(tag: u8, s: &str) -> Result<i64> {
        let mut b = vec![tag, s.len() as u8];
        b.extend(s.as_bytes());
        time(single(&b, tag).unwrap())
    }

    #[test]
    fn times() {
        assert_eq!(t(UTC_TIME, "700101000000Z"), Ok(0));
        assert_eq!(t(UTC_TIME, "491231235959Z"), Ok(2_524_607_999));
        assert_eq!(t(UTC_TIME, "500101000000Z"), Ok(-631_152_000));
        assert_eq!(t(GENERALIZED_TIME, "20260929000000Z"), Ok(1_790_640_000));
        assert_eq!(t(GENERALIZED_TIME, "20000229120000Z"), Ok(951_825_600));
        assert_eq!(t(GENERALIZED_TIME, "99991231235959Z"), Ok(253_402_300_799));
        for bad in [
            "19000229000000Z", // geen schrikkeljaar
            "20261301000000Z",
            "20260931000000Z",
            "20260101240000Z",
            "20260101000060Z",
            "20260101000000+",
            "2026010100000Z",
            "2026O101000000Z",
        ] {
            assert!(t(GENERALIZED_TIME, bad).is_err(), "{bad}");
        }
        assert!(
            t(UTC_TIME, "20260101000000Z").is_err(),
            "lengte hoort bij tag"
        );
        assert!(t(UTC_TIME, "2601010000Z").is_err(), "zonder seconden");
    }
}
