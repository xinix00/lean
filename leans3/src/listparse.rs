//! De ListObjectsV2-pagina, met de hand gelezen.
//!
//! Deze module bezit de XML-lezer en de drie velden die [`crate::Client::list`]
//! nodig heeft; verder niets. In Go voegde `encoding/xml` 39.344 bytes aan
//! symbolen toe aan de HopOS-kernel voor arm64 (12-08-2026), voor een
//! reflectieve algemene decoder. Deze lezer maakt één doorgang, vergelijkt
//! lokale elementnamen en decodeert de vijf voorgedefinieerde plus de numerieke
//! entiteiten. Onbekende elementen worden overgeslagen voor voorwaartse
//! compatibiliteit; niet-ondersteunde syntax faalt luid. Elk geopend element
//! en de wortel moeten sluiten, zodat een afgekapte pagina nooit kan doorgaan
//! voor een volledige lijst met minder sleutels.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Maximale nestdiepte. Een geldige pagina heeft er drie nodig; de ruimte
/// daarboven maakt van een kwaadaardige stroom open-tags een fout in plaats
/// van een groeiende stapel.
pub(crate) const MAX_DEPTH: usize = 32;
/// Maximaal aantal sleutels per pagina (S3 levert er hoogstens 1.000).
pub(crate) const MAX_PAGE_KEYS: usize = 1000;
/// Maximale sleutellengte in bytes, de S3-grens.
pub(crate) const MAX_KEY_BYTES: usize = 1024;
/// Maximale lengte van een vervolgtoken.
pub(crate) const MAX_TOKEN_BYTES: usize = 16 << 10;

/// Wat er misging bij het lezen van een pagina; `at` is de byte-positie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// Een `<?`-declaratie zonder `?>`.
    UnterminatedDeclaration,
    /// Een commentaar zonder `-->`.
    UnterminatedComment,
    /// Een CDATA-sectie zonder `]]>`.
    UnterminatedCdata,
    /// Een `<!`-declaratie zonder `>`.
    UnterminatedMarkup,
    /// Een sluit-tag terwijl er niets open is.
    UnopenedClose {
        /// Positie van de tag.
        at: usize,
    },
    /// Een sluit-tag die niet bij het open element hoort.
    MismatchedClose {
        /// Positie van de tag.
        at: usize,
    },
    /// Een start-tag na het sluiten van de wortel.
    ContentAfterRoot {
        /// Positie van de tag.
        at: usize,
    },
    /// Meer dan 32 niveaus nesting.
    TooDeep,
    /// Een element dat nooit sloot: de pagina is afgekapt.
    Truncated,
    /// Geen enkel volledig element.
    NoElement,
    /// `IsTruncated` is geen boolean.
    BadBoolean,
    /// Een vervolgtoken langer dan 16 KiB.
    TokenTooLong,
    /// Een sleutel langer dan 1.024 bytes.
    KeyTooLong,
    /// Meer dan 1.000 sleutels.
    TooManyKeys,
    /// Een attribuutwaarde zonder slot-aanhalingsteken.
    UnterminatedAttribute {
        /// Positie van de tag.
        at: usize,
    },
    /// Een tag zonder `>`.
    UnterminatedTag {
        /// Positie van de tag.
        at: usize,
    },
    /// Iets anders dan witruimte in een sluit-tag.
    JunkInClose {
        /// Positie van de tag.
        at: usize,
    },
    /// Een lege tagnaam.
    EmptyName {
        /// Positie van de tag.
        at: usize,
    },
    /// Een tagnaam die alleen uit een namespace-voorvoegsel bestaat.
    PrefixOnlyName {
        /// Positie van de tag.
        at: usize,
    },
    /// Een entiteit zonder `;`.
    UnterminatedEntity,
    /// Een onbekende entiteit.
    UnknownEntity,
    /// Een numerieke entiteit die geen teken is.
    BadCharacter,
    /// Een waarde die geen UTF-8 is.
    NotUtf8,
    /// De heap weigerde.
    OutOfMemory,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnterminatedDeclaration => f.write_str("unterminated XML declaration"),
            Self::UnterminatedComment => f.write_str("unterminated XML comment"),
            Self::UnterminatedCdata => f.write_str("unterminated CDATA section"),
            Self::UnterminatedMarkup => f.write_str("unterminated markup declaration"),
            Self::UnopenedClose { at } => write!(f, "closing tag at {at} without an open element"),
            Self::MismatchedClose { at } => {
                write!(f, "closing tag at {at} does not match the open element")
            }
            Self::ContentAfterRoot { at } => write!(f, "content after the root element at {at}"),
            Self::TooDeep => write!(f, "XML nested deeper than {MAX_DEPTH} elements"),
            Self::Truncated => f.write_str("truncated XML: an element was never closed"),
            Self::NoElement => f.write_str("no complete XML element in the response"),
            Self::BadBoolean => f.write_str("IsTruncated is not a boolean"),
            Self::TokenTooLong => {
                write!(f, "continuation token exceeds {MAX_TOKEN_BYTES} bytes")
            }
            Self::KeyTooLong => write!(f, "object key exceeds {MAX_KEY_BYTES} bytes"),
            Self::TooManyKeys => write!(f, "LIST page exceeds {MAX_PAGE_KEYS} keys"),
            Self::UnterminatedAttribute { at } => {
                write!(f, "unterminated attribute value in the tag at {at}")
            }
            Self::UnterminatedTag { at } => write!(f, "unterminated tag at {at}"),
            Self::JunkInClose { at } => write!(f, "junk in the closing tag at {at}"),
            Self::EmptyName { at } => write!(f, "empty XML tag name at {at}"),
            Self::PrefixOnlyName { at } => {
                write!(f, "XML tag name at {at} is only a namespace prefix")
            }
            Self::UnterminatedEntity => f.write_str("unterminated XML entity"),
            Self::UnknownEntity => f.write_str("unknown XML entity"),
            Self::BadCharacter => f.write_str("XML entity is not a character"),
            Self::NotUtf8 => f.write_str("XML value is not UTF-8"),
            Self::OutOfMemory => f.write_str("out of memory while parsing a LIST page"),
        }
    }
}

/// Het deel van een ListObjectsV2-pagina dat [`crate::Client::list`] gebruikt.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ListPage {
    /// Of er na deze pagina nog een volgt.
    pub(crate) is_truncated: bool,
    /// Het token voor de volgende pagina, of leeg.
    pub(crate) next_token: String,
    /// De sleutels onder `Contents`, in volgorde.
    pub(crate) keys: Vec<String>,
}

/// Leest de velden die [`crate::Client::list`] nodig heeft. De lezer kijkt naar
/// lokale naam én positie: `IsTruncated` en `NextContinuationToken` direct onder
/// de wortel, `Key` onder `Contents`. Velden met dezelfde naam elders kunnen de
/// uitkomst niet veranderen.
pub(crate) fn parse_list_page(b: &[u8]) -> Result<ListPage, XmlError> {
    let mut out = ListPage::default();
    let mut stack: [&[u8]; MAX_DEPTH] = [&[]; MAX_DEPTH];
    let mut depth = 0usize;
    // Tekst alleen verzamelen voor gewenste velden; de rest meteen weggooien.
    let mut text: Vec<u8> = Vec::new();
    let mut wanted = false;
    let mut saw_root = false;
    let mut root_closed = false;

    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c != b'<' {
            let j = find_byte(b, i, b'<').unwrap_or(b.len());
            if wanted {
                append(&mut text, b.get(i..j).unwrap_or(&[]))?;
            }
            i = j;
            continue;
        }
        if starts_with(b, i, b"<?") {
            i = find(b, i, b"?>").ok_or(XmlError::UnterminatedDeclaration)? + 2;
        } else if starts_with(b, i, b"<!--") {
            i = find(b, i, b"-->").ok_or(XmlError::UnterminatedComment)? + 3;
        } else if starts_with(b, i, b"<![CDATA[") {
            let e = find(b, i, b"]]>").ok_or(XmlError::UnterminatedCdata)?;
            if wanted {
                append(&mut text, b.get(i + 9..e).unwrap_or(&[]))?;
            }
            i = e + 3;
        } else if starts_with(b, i, b"<!") {
            i = find_byte(b, i, b'>').ok_or(XmlError::UnterminatedMarkup)? + 1;
        } else if starts_with(b, i, b"</") {
            let (name, end) = close_tag(b, i)?;
            let top = depth
                .checked_sub(1)
                .and_then(|d| stack.get(d))
                .ok_or(XmlError::UnopenedClose { at: i })?;
            if *top != name {
                return Err(XmlError::MismatchedClose { at: i });
            }
            if wanted {
                let value = unescape(&text)?;
                store(&mut out, &stack[..depth], value)?;
            }
            depth -= 1;
            text.clear();
            wanted = false;
            if depth == 0 {
                root_closed = true;
            }
            i = end;
        } else {
            let (name, end, self_closing) = start_tag(b, i)?;
            if root_closed {
                return Err(XmlError::ContentAfterRoot { at: i });
            }
            if depth == 0 {
                saw_root = true;
            }
            let slot = stack.get_mut(depth).ok_or(XmlError::TooDeep)?;
            *slot = name;
            depth += 1;
            if self_closing {
                // Een zelfsluitend gewenst veld is een lege waarde.
                if is_wanted(&stack[..depth]) {
                    store(&mut out, &stack[..depth], String::new())?;
                }
                depth -= 1;
                if depth == 0 {
                    root_closed = true;
                }
            } else {
                text.clear();
                wanted = is_wanted(&stack[..depth]);
            }
            i = end;
        }
    }

    if depth != 0 {
        return Err(XmlError::Truncated);
    }
    if !saw_root || !root_closed {
        return Err(XmlError::NoElement);
    }
    Ok(out)
}

/// Of `stack` een gewenst veld aanwijst. De wortelnaam blijft vrij, want niet
/// elke S3-implementatie noemt hem `ListBucketResult`.
fn is_wanted(stack: &[&[u8]]) -> bool {
    match stack {
        [_, field] => *field == b"IsTruncated" || *field == b"NextContinuationToken",
        [_, contents, key] => *contents == b"Contents" && *key == b"Key",
        _ => false,
    }
}

/// Bewaart een gelezen veld. Een ongeldige `IsTruncated` is een fout, want
/// onzekere paginering mag nooit als volledig gelden.
fn store(out: &mut ListPage, stack: &[&[u8]], value: String) -> Result<(), XmlError> {
    match stack {
        [_, field] if *field == b"IsTruncated" => {
            out.is_truncated = match value.trim_matches([' ', '\t', '\n', '\r']) {
                "true" | "1" => true,
                "false" | "0" | "" => false,
                _ => return Err(XmlError::BadBoolean),
            };
        }
        [_, field] if *field == b"NextContinuationToken" => {
            if value.len() > MAX_TOKEN_BYTES {
                return Err(XmlError::TokenTooLong);
            }
            out.next_token = value;
        }
        [_, _, _] => {
            if value.len() > MAX_KEY_BYTES {
                return Err(XmlError::KeyTooLong);
            }
            if out.keys.len() == MAX_PAGE_KEYS {
                return Err(XmlError::TooManyKeys);
            }
            out.keys.try_reserve(1).map_err(|_| XmlError::OutOfMemory)?;
            out.keys.push(value);
        }
        _ => {}
    }
    Ok(())
}

/// Leest een start-tag en geeft de lokale naam, de positie erna en of hij
/// zelfsluitend is. Een `>` tussen aanhalingstekens sluit de tag niet.
fn start_tag(b: &[u8], at: usize) -> Result<(&[u8], usize, bool), XmlError> {
    let (name, mut j) = tag_name(b, at + 1, at)?;
    while let Some(&c) = b.get(j) {
        match c {
            b'"' | b'\'' => {
                j = find_byte(b, j + 1, c).ok_or(XmlError::UnterminatedAttribute { at })? + 1;
            }
            b'/' if b.get(j + 1) == Some(&b'>') => return Ok((name, j + 2, true)),
            b'>' => return Ok((name, j + 1, false)),
            _ => j += 1,
        }
    }
    Err(XmlError::UnterminatedTag { at })
}

/// Leest een sluit-tag en geeft de naam en de positie na `>`.
fn close_tag(b: &[u8], at: usize) -> Result<(&[u8], usize), XmlError> {
    let (name, mut j) = tag_name(b, at + 2, at)?;
    loop {
        match b.get(j) {
            None => return Err(XmlError::UnterminatedTag { at }),
            Some(b'>') => return Ok((name, j + 1)),
            Some(&c) if is_space(c) => j += 1,
            Some(_) => return Err(XmlError::JunkInClose { at }),
        }
    }
}

/// Leest een elementnaam vanaf `i` en geeft het deel na de laatste
/// namespace-dubbele-punt.
fn tag_name(b: &[u8], i: usize, at: usize) -> Result<(&[u8], usize), XmlError> {
    let mut j = i;
    while let Some(&c) = b.get(j) {
        if is_space(c) || c == b'>' || c == b'/' {
            break;
        }
        j += 1;
    }
    let full = b.get(i..j).unwrap_or(&[]);
    if full.is_empty() {
        return Err(XmlError::EmptyName { at });
    }
    let local = match full.iter().rposition(|&c| c == b':') {
        Some(k) => full.get(k + 1..).unwrap_or(&[]),
        None => full,
    };
    if local.is_empty() {
        return Err(XmlError::PrefixOnlyName { at });
    }
    Ok((local, j))
}

/// Decodeert de vijf voorgedefinieerde en de numerieke entiteiten. Een
/// onbekende entiteit faalt in plaats van een sleutel stil te beschadigen.
fn unescape(b: &[u8]) -> Result<String, XmlError> {
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(b.len())
        .map_err(|_| XmlError::OutOfMemory)?;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c != b'&' {
            out.push(c);
            i += 1;
            continue;
        }
        // "&#x10FFFF;" is de langste ondersteunde vorm.
        let e = find_byte(b, i, b';')
            .filter(|&e| e - i <= 12)
            .ok_or(XmlError::UnterminatedEntity)?;
        let ent = b.get(i + 1..e).unwrap_or(&[]);
        match ent {
            b"amp" => out.push(b'&'),
            b"lt" => out.push(b'<'),
            b"gt" => out.push(b'>'),
            b"quot" => out.push(b'"'),
            b"apos" => out.push(b'\''),
            [b'#', digits @ ..] => {
                let ch = numeric_entity(digits).ok_or(XmlError::BadCharacter)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            _ => return Err(XmlError::UnknownEntity),
        }
        i = e + 1;
    }
    String::from_utf8(out).map_err(|_| XmlError::NotUtf8)
}

/// Leest `123` of `x1F600` als Unicode-teken; surrogaten en waarden boven
/// U+10FFFF zijn geen teken.
fn numeric_entity(digits: &[u8]) -> Option<char> {
    let (digits, radix) = match digits {
        [b'x' | b'X', rest @ ..] => (rest, 16),
        _ => (digits, 10),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &d in digits {
        let n = char::from(d).to_digit(radix)?;
        v = v.checked_mul(radix)?.checked_add(n)?;
    }
    char::from_u32(v)
}

/// Voegt bytes toe, faalbaar gealloceerd.
fn append(dst: &mut Vec<u8>, src: &[u8]) -> Result<(), XmlError> {
    dst.try_reserve(src.len())
        .map_err(|_| XmlError::OutOfMemory)?;
    dst.extend_from_slice(src);
    Ok(())
}

/// XML-witruimte.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// Of `s` op positie `i` begint.
fn starts_with(b: &[u8], i: usize, s: &[u8]) -> bool {
    b.get(i..).is_some_and(|rest| rest.starts_with(s))
}

/// Zoekt `s` vanaf `i` zonder het antwoord eerst naar een string te kopiëren.
fn find(b: &[u8], i: usize, s: &[u8]) -> Option<usize> {
    b.get(i..)?
        .windows(s.len())
        .position(|w| w == s)
        .map(|p| p + i)
}

/// Zoekt byte `c` vanaf `i`.
fn find_byte(b: &[u8], i: usize, c: u8) -> Option<usize> {
    b.get(i..)?.iter().position(|&x| x == c).map(|p| p + i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(truncated: bool, token: &str, keys: &[&str]) -> ListPage {
        ListPage {
            is_truncated: truncated,
            next_token: token.into(),
            keys: keys.iter().map(|k| (*k).to_owned()).collect(),
        }
    }

    pub(crate) const ECHT_ANTWOORD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>hop-apps</Name>
  <Prefix>apps/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>apps/welcome/welcome.elf</Key>
    <LastModified>2026-08-12T10:00:00.000Z</LastModified>
    <ETag>&quot;9a0364b9e99bb480dd25e1f0284c8555&quot;</ETag>
    <Size>2515083</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>apps/vitals/vitals.elf</Key>
    <Size>2560201</Size>
  </Contents>
</ListBucketResult>"#;

    pub(crate) fn veel_keys(n: usize) -> String {
        let mut b = String::from(
            "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t</NextContinuationToken>",
        );
        for i in 0..n {
            b.push_str(&format!(
                "<Contents><Key>apps/job-{i:04}/image.elf</Key><Size>{}</Size></Contents>",
                i * 1024
            ));
        }
        b.push_str("</ListBucketResult>");
        b
    }

    // In Go was encoding/xml de referentie. Die is hier niet, dus staat wat hij
    // over elk document zei als verwachte uitkomst in de tabel.
    #[test]
    fn parse_gelijk_aan_encoding_xml() {
        let many = veel_keys(1000);
        let many_keys: Vec<String> = (0..1000)
            .map(|i| format!("apps/job-{i:04}/image.elf"))
            .collect();
        let many_refs: Vec<&str> = many_keys.iter().map(String::as_str).collect();
        let cases: Vec<(&str, &str, ListPage)> = vec![
            (
                "echt antwoord",
                ECHT_ANTWOORD,
                page(
                    false,
                    "",
                    &["apps/welcome/welcome.elf", "apps/vitals/vitals.elf"],
                ),
            ),
            (
                "leeg (geen Contents)",
                "<ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>",
                page(false, "", &[]),
            ),
            (
                "afgekapt met token",
                "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken><Contents><Key>a</Key></Contents></ListBucketResult>",
                page(
                    true,
                    "1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=",
                    &["a"],
                ),
            ),
            (
                "namespace-prefix op elk element",
                r#"<s3:ListBucketResult xmlns:s3="http://x/"><s3:IsTruncated>true</s3:IsTruncated><s3:Contents><s3:Key>met/prefix</s3:Key></s3:Contents></s3:ListBucketResult>"#,
                page(true, "", &["met/prefix"]),
            ),
            (
                "entiteiten in de key",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>map/a&amp;b &lt;c&gt; &quot;d&quot; &apos;e&apos;</Key></Contents></ListBucketResult>",
                page(false, "", &["map/a&b <c> \"d\" 'e'"]),
            ),
            (
                "numerieke entiteit",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>caf&#233;/&#x1F600;.txt</Key></Contents></ListBucketResult>",
                page(false, "", &["caf\u{e9}/\u{1F600}.txt"]),
            ),
            (
                "leeg element",
                "<ListBucketResult><IsTruncated/><Contents><Key>x</Key></Contents></ListBucketResult>",
                page(false, "", &["x"]),
            ),
            (
                "lege key",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key></Key></Contents></ListBucketResult>",
                page(false, "", &[""]),
            ),
            (
                "commentaar ertussen",
                "<ListBucketResult><!-- door een proxy --><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents></ListBucketResult>",
                page(false, "", &["a"]),
            ),
            (
                "CDATA in de key",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key><![CDATA[raar>maar>geldig]]></Key></Contents></ListBucketResult>",
                page(false, "", &["raar>maar>geldig"]),
            ),
            (
                "attributen met > erin",
                r#"<ListBucketResult attr="a>b"><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents></ListBucketResult>"#,
                page(false, "", &["a"]),
            ),
            (
                "witruimte en newlines",
                "<ListBucketResult>\n\t<IsTruncated>\n\t\tfalse\n\t</IsTruncated>\n\t<Contents>\n\t\t<Key>a/b</Key>\n\t</Contents>\n</ListBucketResult>\n",
                page(false, "", &["a/b"]),
            ),
            (
                "Key ook ergens anders (mag niet meetellen)",
                "<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Key>niet-van-ons</Key></CommonPrefixes><Contents><Key>wel-van-ons</Key></Contents></ListBucketResult>",
                page(false, "", &["wel-van-ons"]),
            ),
            ("veel keys", many.as_str(), page(true, "t", &many_refs)),
        ];
        for (name, doc, want) in cases {
            let got = parse_list_page(doc.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn parse_weigert() {
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        let cases = [
            ("leeg", ""),
            ("geen XML", "niet eens een tag"),
            (
                "afgekapt midden in een tag",
                "<ListBucketResult><Contents><Key>a</Ke",
            ),
            (
                "afgekapte stream (wortel nooit gesloten)",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents>",
            ),
            (
                "sluit-tag zonder open",
                "<ListBucketResult></Contents></ListBucketResult>",
            ),
            (
                "verkeerde sluit-tag",
                "<ListBucketResult><Contents><Key>a</Contents></Key></ListBucketResult>",
            ),
            (
                "IsTruncated is geen boolean",
                "<ListBucketResult><IsTruncated>misschien</IsTruncated></ListBucketResult>",
            ),
            (
                "onbekende entiteit",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&nbsp;b</Key></Contents></ListBucketResult>",
            ),
            (
                "onafgesloten entiteit",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&amp</Key></Contents></ListBucketResult>",
            ),
            (
                "entiteit is geen teken",
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a&#xD800;</Key></Contents></ListBucketResult>",
            ),
            (
                "onafgesloten commentaar",
                "<ListBucketResult><!-- en dan niets meer",
            ),
            (
                "onafgesloten CDATA",
                "<ListBucketResult><Contents><Key><![CDATA[abc</Key>",
            ),
            ("onafgesloten declaratie", r#"<?xml version="1.0""#),
            ("onafgesloten attribuut", r#"<ListBucketResult attr="abc"#),
            ("lege tagnaam", "<ListBucketResult><></></ListBucketResult>"),
            (
                "alleen een prefix als naam",
                "<ListBucketResult><s3:></s3:></ListBucketResult>",
            ),
            (
                "rommel in de sluit-tag",
                "<ListBucketResult><Contents></Contents rommel></ListBucketResult>",
            ),
            (
                "inhoud na de wortel",
                "<ListBucketResult></ListBucketResult><Extra/>",
            ),
            ("te diep genest", deep.as_str()),
        ];
        for (name, doc) in cases {
            assert!(
                parse_list_page(doc.as_bytes()).is_err(),
                "{name}: geen fout"
            );
        }
    }

    #[test]
    fn parse_weigert_te_veel_keys_en_te_lange_key() {
        let err = parse_list_page(veel_keys(MAX_PAGE_KEYS + 1).as_bytes()).unwrap_err();
        assert!(err.to_string().contains("page exceeds"), "{err}");

        let doc = format!(
            "<ListBucketResult><Contents><Key>{}</Key></Contents></ListBucketResult>",
            "k".repeat(MAX_KEY_BYTES + 1)
        );
        let err = parse_list_page(doc.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("key exceeds"), "{err}");

        let doc = format!(
            "<ListBucketResult><NextContinuationToken>{}</NextContinuationToken></ListBucketResult>",
            "t".repeat(MAX_TOKEN_BYTES + 1)
        );
        let err = parse_list_page(doc.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("token exceeds"), "{err}");
    }

    // Elke echte prefix van een geldige pagina is een fout: een afgekapte
    // stroom mag nooit doorgaan voor een volledige lijst met minder sleutels.
    #[test]
    fn afgekapt_antwoord_is_altijd_een_fout() {
        for i in 1..ECHT_ANTWOORD.len() {
            let half = &ECHT_ANTWOORD.as_bytes()[..i];
            assert!(
                parse_list_page(half).is_err(),
                "afgekapt op {i} bytes gaf geen fout: {:?}",
                String::from_utf8_lossy(half)
            );
        }
    }

    #[test]
    fn is_truncated_varianten() {
        let cases = [
            ("<r><IsTruncated>1</IsTruncated></r>", true),
            ("<r><IsTruncated>0</IsTruncated></r>", false),
            ("<r><IsTruncated>true</IsTruncated></r>", true),
            ("<r><IsTruncated>false</IsTruncated></r>", false),
            ("<r><IsTruncated> true </IsTruncated></r>", true),
            ("<r></r>", false),
        ];
        for (doc, want) in cases {
            assert_eq!(
                parse_list_page(doc.as_bytes()).unwrap().is_truncated,
                want,
                "{doc}"
            );
        }
    }
}
