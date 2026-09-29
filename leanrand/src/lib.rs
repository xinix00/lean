//! Random voor een node: bytes, een id, een begrensd getal, jitter op een wachttijd.
//!
//! Deze crate bezit de vier vormen waarin een node toeval nodig heeft, en de
//! drie fouten die daar steeds weer in sluipen: een foutpad voor een fout die
//! niet kan, `% n`-bias, en herhaalpogingen die in de pas lopen. [`below`]
//! trekt met afwijzing, [`jitter`] spreidt een wachttijd over ±50%, en
//! [`Source::fill`] heeft geen foutpad.
//!
//! Wat hij NIET bezit: de bron zelf. Op bare metal is er geen OS-entropie, dus
//! de aanroeper levert een [`Source`] (de RNG van de SoC, een DRBG met een
//! zaad uit de firmware). In Go was dat `crypto/rand`, één bron zonder keuze
//! per aanroep; hier is het één bron per eigenaar, als parameter, zodat een
//! test deterministisch toeval kan geven zonder globale staat.
//!
//! De Go-versie verving `github.com/google/uuid`, dat 3.793 bytes aan
//! symbolen en `database/sql/driver` in de HopOS-kern trok voor twee
//! aanroepen, waarvan één afgekapt op acht tekens (gemeten 12-08-2026). Een
//! eigen generator, een zaad, een reproduceerbare productiestroom en een
//! UUID-vorm zijn er daarom bewust niet.
//!
//! # Examples
//!
//! ```
//! use leanrand::Source;
//!
//! /// Een tellende bron; alleen goed genoeg voor een voorbeeld.
//! struct Counter(u8);
//!
//! impl Source for Counter {
//!     fn fill(&mut self, buf: &mut [u8]) {
//!         for b in buf {
//!             self.0 = self.0.wrapping_add(1);
//!             *b = self.0;
//!         }
//!     }
//! }
//!
//! let mut src = Counter(0);
//! let v = leanrand::below(&mut src, 6);
//! assert!(v < 6);
//! let id = leanrand::id(&mut src, 12)?;
//! assert_eq!(id.len(), 12);
//! # Ok::<(), leanrand::Error>(())
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

/// Het alfabet van [`id`]: Crockford base32 zonder I, L, O en U.
///
/// Twee redenen. Vijf bits per teken zonder bias, want 32 deelt 256. En geen
/// paren die je verkeerd overtypt (1/I/L, 0/O), want een id wordt voorgelezen
/// en overgetikt.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Een bron van toeval die een buffer volledig vult.
///
/// `fill` heeft geen foutpad, net als `Read` in de Go-versie: een bron die
/// half vult of kan falen, levert een halve sleutel op, en dat is erger dan
/// geen sleutel. Een bron die echt kan breken (een hardware-RNG die zijn
/// zelftest verliest) beslist zelf wat er dan gebeurt, bij de eigenaar van
/// het ijzer, niet in elke aanroeper.
pub trait Source {
    /// Vult `buf` volledig met toeval.
    fn fill(&mut self, buf: &mut [u8]);
}

impl<S: Source + ?Sized> Source for &mut S {
    fn fill(&mut self, buf: &mut [u8]) {
        (**self).fill(buf);
    }
}

/// Een fout uit deze crate.
///
/// Toeval zelf faalt niet (zie [`Source`]); alleen de heap kan nee zeggen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// De heap kon `bytes` bytes niet leveren.
    Alloc {
        /// Het gevraagde aantal bytes.
        bytes: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alloc { bytes } => write!(f, "leanrand: cannot allocate {bytes} bytes"),
        }
    }
}

impl core::error::Error for Error {}

/// Het resultaat van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Vult `buf` met toeval uit `src`.
///
/// Een dunne naam rond [`Source::fill`], zodat een aanroeper die alleen deze
/// crate kent niet naar de trait hoeft te grijpen.
pub fn read<S: Source + ?Sized>(src: &mut S, buf: &mut [u8]) {
    src.fill(buf);
}

/// Geeft `n` bytes toeval; leeg bij `n == 0`.
///
/// De allocatie is faalbaar: een gevraagde maat komt vaak van buiten.
pub fn bytes<S: Source + ?Sized>(src: &mut S, n: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if n == 0 {
        return Ok(out);
    }
    out.try_reserve_exact(n)
        .map_err(|_| Error::Alloc { bytes: n })?;
    out.resize(n, 0);
    src.fill(&mut out);
    Ok(out)
}

/// Geeft een `u64` over het volle bereik.
pub fn next_u64<S: Source + ?Sized>(src: &mut S) -> u64 {
    let mut b = [0u8; 8];
    src.fill(&mut b);
    u64::from_le_bytes(b)
}

/// Geeft een getal in `[0, n)` zonder bias, ook als `n` geen macht van twee is.
///
/// Bij `n == 0` en `n == 1` is het antwoord 0, zodat een lengte van nul
/// geldig blijft. `% n` alleen zou de lage getallen vaker geven; daarom wordt
/// een trekking boven het grootste volle veelvoud van `n` weggegooid. Dat
/// kost gemiddeld minder dan twee trekkingen, ook net boven 2^63, het
/// slechtste geval.
pub fn below<S: Source + ?Sized>(src: &mut S, n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    // De grens is het grootste getal waaronder een volledig aantal blokken
    // van n past. `u64::MAX % n + 1` is de rest plus één; nog eens `% n`
    // maakt daar 0 van als u64::MAX + 1 precies deelbaar is door n.
    let limit = u64::MAX - (u64::MAX % n + 1) % n;
    loop {
        let v = next_u64(src);
        if v <= limit {
            return v % n;
        }
    }
}

/// Geeft `2 * n` kleine hexadecimale tekens uit `n` bytes toeval.
pub fn hex<S: Source + ?Sized>(src: &mut S, n: usize) -> Result<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let len = n.checked_mul(2).ok_or(Error::Alloc { bytes: usize::MAX })?;
    let mut out = String::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::Alloc { bytes: len })?;
    let mut chunk = [0u8; 32];
    let mut left = n;
    while left > 0 {
        let take = left.min(chunk.len());
        let part = chunk.get_mut(..take).unwrap_or_default();
        src.fill(part);
        for &c in part.iter() {
            // De capaciteit staat al vast: deze pushes groeien niet.
            out.push(char::from(DIGITS[usize::from(c >> 4)]));
            out.push(char::from(DIGITS[usize::from(c & 0xf)]));
        }
        left -= take;
    }
    Ok(out)
}

/// Vult `out` met een id uit het Crockford-alfabet, vijf bits per teken.
///
/// De allocatievrije vorm van [`id`]: elke byte in `out` wordt een ASCII-teken.
pub fn fill_id<S: Source + ?Sized>(src: &mut S, out: &mut [u8]) {
    src.fill(out);
    for b in out.iter_mut() {
        // 32 deelt 256, dus de onderste vijf bits zijn zonder bias.
        *b = ALPHABET[usize::from(*b & 31)];
    }
}

/// Geeft een id van `n` tekens uit het Crockford-alfabet; leeg bij `n == 0`.
///
/// Twaalf tekens zijn 60 bits, zestien zijn er 80.
pub fn id<S: Source + ?Sized>(src: &mut S, n: usize) -> Result<String> {
    let mut out = String::new();
    if n == 0 {
        return Ok(out);
    }
    out.try_reserve_exact(n)
        .map_err(|_| Error::Alloc { bytes: n })?;
    let mut chunk = [0u8; 32];
    let mut left = n;
    while left > 0 {
        let take = left.min(chunk.len());
        let part = chunk.get_mut(..take).unwrap_or_default();
        fill_id(src, part);
        for &c in part.iter() {
            out.push(char::from(c));
        }
        left -= take;
    }
    Ok(out)
}

/// Spreidt `d` over ±50%: het antwoord ligt in `[d/2, 3d/2)`.
///
/// Zo lopen herhaalpogingen en periodiek werk van veel nodes niet in de pas.
/// Een duur van nul blijft nul. Een negatieve duur, die Go wel kende, bestaat
/// in [`Duration`] niet. De spreiding loopt in nanoseconden; boven de 584
/// jaar (`u64::MAX` ns, verder dan Go's `time.Duration` reikt) is de band
/// `[d/2, d/2 + u64::MAX ns)`.
pub fn jitter<S: Source + ?Sized>(src: &mut S, d: Duration) -> Duration {
    if d.is_zero() {
        return d;
    }
    let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    (d / 2).saturating_add(Duration::from_nanos(below(src, ns)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// SplitMix64, gezaaid uit de klok en een teller: goed genoeg om de
    /// eigenschappen te toetsen, en nooit tweemaal dezelfde stroom.
    struct TestSource(u64);

    impl TestSource {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            Self(t ^ SEQ.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed))
        }

        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl Source for TestSource {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }

    #[test]
    fn test_bytes_lengte() -> Result {
        let mut src = TestSource::new();
        assert_eq!(bytes(&mut src, 32)?.len(), 32);
        assert!(bytes(&mut src, 0)?.is_empty());
        // Go kende ook Bytes(-1); een usize kan niet negatief zijn.
        Ok(())
    }

    #[test]
    fn test_bytes_vult_echt_vol() -> Result {
        let mut src = TestSource::new();
        let a = bytes(&mut src, 64)?;
        let b = bytes(&mut src, 64)?;
        assert_ne!(a, b, "twee trekkingen van 64 bytes waren identiek");
        assert!(a.iter().any(|&c| c != 0), "64 bytes waren allemaal nul");
        Ok(())
    }

    #[test]
    fn test_n_blijft_onder_de_grens() {
        let mut src = TestSource::new();
        for n in [
            2,
            3,
            7,
            10,
            255,
            256,
            1000,
            1 << 32,
            (1 << 63) + 1,
            u64::MAX,
        ] {
            for _ in 0..2000 {
                let v = below(&mut src, n);
                assert!(v < n, "below({n}) = {v}");
            }
        }
    }

    #[test]
    fn test_n_leeg_bereik() {
        let mut src = TestSource::new();
        assert_eq!(below(&mut src, 0), 0);
        assert_eq!(below(&mut src, 1), 0);
    }

    #[test]
    fn test_n_is_redelijk_vlak() {
        const BUCKETS: usize = 6;
        const PER: usize = 10_000;
        let mut src = TestSource::new();
        let mut count = [0usize; BUCKETS];
        for _ in 0..BUCKETS * PER {
            count[below(&mut src, BUCKETS as u64) as usize] += 1;
        }
        for (i, &c) in count.iter().enumerate() {
            assert!(
                (PER * 85 / 100..=PER * 115 / 100).contains(&c),
                "bak {i} kreeg {c} van de {PER} verwachte trekkingen ({count:?})"
            );
        }
    }

    #[test]
    fn test_hex() -> Result {
        let mut src = TestSource::new();
        let s = hex(&mut src, 16)?;
        assert_eq!(s.len(), 32);
        assert!(
            s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "hex gaf iets dat geen hex is: {s:?}"
        );
        assert_eq!(hex(&mut src, 0)?, "");
        // Meer dan één blok van 32 bytes.
        assert_eq!(hex(&mut src, 100)?.len(), 200);
        Ok(())
    }

    #[test]
    fn test_id() -> Result {
        let mut src = TestSource::new();
        let s = id(&mut src, 12)?;
        assert_eq!(s.len(), 12);
        assert!(
            s.bytes().all(|c| ALPHABET.contains(&c)),
            "id gaf een teken buiten het alfabet: {s:?}"
        );
        assert!(
            !s.contains(['I', 'L', 'O', 'U']),
            "id gaf een teken dat je verkeerd overtypt: {s:?}"
        );
        assert_eq!(id(&mut src, 0)?, "");
        assert_eq!(id(&mut src, 70)?.len(), 70);
        Ok(())
    }

    #[test]
    fn test_ids_zijn_uniek() -> Result {
        const N: usize = 20_000;
        let mut src = TestSource::new();
        let mut seen = HashSet::with_capacity(N);
        for i in 0..N {
            let s = id(&mut src, 12)?;
            assert!(
                seen.insert(s.clone()),
                "dubbele id na {i} trekkingen: {s:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_id_alfabet_heeft_geen_dubbels() {
        assert_eq!(ALPHABET.len(), 32, "32 is de reden dat er geen bias is");
        let mut seen = HashSet::new();
        for &c in ALPHABET {
            assert!(
                seen.insert(c),
                "alfabet bevat {:?} twee keer",
                char::from(c)
            );
        }
    }

    #[test]
    fn test_jitter_blijft_in_de_band() {
        let d = Duration::from_millis(100);
        let mut src = TestSource::new();
        let (mut low, mut high) = (false, false);
        for _ in 0..2000 {
            let v = jitter(&mut src, d);
            assert!(
                v >= d / 2 && v < d + d / 2,
                "jitter({d:?}) = {v:?}, buiten [{:?}, {:?})",
                d / 2,
                d + d / 2
            );
            if v < d {
                low = true;
            } else {
                high = true;
            }
        }
        assert!(low && high, "jitter kwam maar aan één kant van d uit");
    }

    #[test]
    fn test_jitter_zonder_wachttijd() {
        let mut src = TestSource::new();
        assert_eq!(jitter(&mut src, Duration::ZERO), Duration::ZERO);
        // Een negatieve duur bestaat in Duration niet; het tweede Go-geval
        // is daarmee een typefout geworden. Wel toetsen: het uiterste.
        let max = jitter(&mut src, Duration::MAX);
        assert!(max >= Duration::MAX / 2);
    }

    #[test]
    fn test_uint64_vult_alle_bits() {
        let mut src = TestSource::new();
        let mut or = 0u64;
        for _ in 0..200 {
            or |= next_u64(&mut src);
        }
        assert_eq!(
            or,
            u64::MAX,
            "na 200 trekkingen stonden niet alle bits ooit aan: {or:#x}"
        );
    }

    #[test]
    fn test_dyn_source() {
        // Een &mut dyn Source is ook een bron: één eigenaar kan hem doorgeven.
        let mut src = TestSource::new();
        let dynsrc: &mut dyn Source = &mut src;
        assert!(below(dynsrc, 10) < 10);
    }
}
