//! De servernaam tegen de DNS-namen van het blad (RFC 6125 §6.4, zoals Go).
//!
//! Hoofdletterongevoelig in ASCII. Een wildcard mag alleen als heel het
//! linkerlabel (`*.example.com`) en staat dan voor precies één niet-leeg
//! label: `a.example.com` wel, `example.com` en `a.b.example.com` niet.
//! Geen terugval op de CommonName: die is sinds RFC 6125 en Go 1.15 weg, en
//! een certificaat zonder SubjectAltName past dus op geen enkele naam.

/// Grootste servernaam: de grens van DNS (RFC 1035 §2.3.4).
pub(crate) const MAX_NAME: usize = 253;

/// Is `name` een IP-adres (IPv4 met punten of iets met een dubbele punt)?
/// Die worden uitsluitend tegen IP SANs getoetst, nooit tegen DNS-namen.
pub(crate) fn is_ip(name: &str) -> bool {
    name.contains(':')
        || (name.split('.').count() == 4
            && name
                .split('.')
                .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit())))
}

/// IP-SANs zijn 4 of 16 ruwe bytes; IPv4-mapped IPv6 volgt dezelfde canonieke vergelijking als Go.
pub(crate) fn matches_ip(raw: &[u8], host: core::net::IpAddr) -> bool {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let candidate = match raw.len() {
        4 => <[u8; 4]>::try_from(raw)
            .ok()
            .map(|b| IpAddr::V4(Ipv4Addr::from(b))),
        16 => <[u8; 16]>::try_from(raw)
            .ok()
            .map(|b| IpAddr::V6(Ipv6Addr::from(b))),
        _ => None,
    };
    candidate.is_some_and(|ip| ip.to_canonical() == host.to_canonical())
}

/// Is `name` een bruikbare hostnaam: labels van 1 tot 63 tekens uit
/// letters, cijfers, `-` en `_`, samen hooguit [`MAX_NAME`]?
pub(crate) fn is_valid_host(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Past `host` op het patroon `pattern` uit een certificaat?
pub(crate) fn matches(pattern: &[u8], host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
    let pattern = pattern.strip_suffix(b".").unwrap_or(pattern);
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    match pattern.strip_prefix(b"*.") {
        Some(rest) => {
            // Het eerste label van host valt weg; de rest moet exact gelijk
            // zijn, en er mag geen tweede `*` in het patroon staan.
            let Some(dot) = host.iter().position(|b| *b == b'.') else {
                return false;
            };
            dot > 0
                && !rest.is_empty()
                && !rest.contains(&b'*')
                && host
                    .get(dot + 1..)
                    .is_some_and(|h| h.eq_ignore_ascii_case(rest))
        }
        None => !pattern.contains(&b'*') && pattern.eq_ignore_ascii_case(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_case() {
        assert!(matches(b"github.com", "github.com"));
        assert!(matches(b"GitHub.COM", "github.com"));
        assert!(matches(b"github.com", "github.com."));
        assert!(!matches(b"github.com", "api.github.com"));
        assert!(!matches(b"github.com", "github.co"));
        assert!(!matches(b"", "github.com"));
    }

    /// De wildcard-gevallen uit Go's x509verify-test, plus de randen.
    #[test]
    fn wildcards() {
        assert!(matches(b"*.wild.example", "a.wild.example"));
        assert!(matches(b"*.github.com", "API.github.com"));
        assert!(!matches(b"*.wild.example", "a.b.wild.example"), "te diep");
        assert!(!matches(b"*.wild.example", "wild.example"), "de kale naam");
        assert!(!matches(b"*.wild.example", ".wild.example"), "leeg label");
        assert!(
            !matches(b"a*.wild.example", "ab.wild.example"),
            "deel-label"
        );
        assert!(!matches(b"*.*.example", "a.b.example"), "twee sterren");
        assert!(!matches(b"www.*.example", "www.a.example"), "niet links");
        assert!(!matches(b"*", "localhost"));
        assert!(!matches(b"*.", "a."));
    }

    #[test]
    fn host_forms() {
        assert!(is_ip("192.168.1.1"));
        assert!(is_ip("::1"));
        assert!(is_ip("fe80::1%eth0"));
        assert!(!is_ip("1.2.3.example"));
        assert!(!is_ip("github.com"));
        assert!(is_valid_host("objects.githubusercontent.com"));
        assert!(is_valid_host("a_b.example."));
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("a..b"));
        assert!(!is_valid_host("*.example"));
        assert!(!is_valid_host(&"a".repeat(64)));
        assert!(!is_valid_host(&["a"; 128].join(".")), "255 tekens");
    }
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    #[test]
    fn addresses_match_only_binary_ip_sans() {
        let v4 = "127.0.0.1".parse().unwrap();
        let mapped = "::ffff:127.0.0.1".parse().unwrap();
        let v6 = "::1".parse().unwrap();
        assert!(matches_ip(&[127, 0, 0, 1], v4));
        assert!(matches_ip(&[127, 0, 0, 1], mapped));
        assert!(!matches_ip(b"127.0.0.1", v4));
        assert!(!matches_ip(&[127, 0, 0, 2], v4));
        assert!(!matches_ip(&[127, 0, 0, 1], v6));
        assert!(matches_ip(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            v6
        ));
    }
}
