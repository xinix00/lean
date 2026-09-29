//! De Huffman-decoder van HPACK (RFC 7541 §5.2 en bijlage B).
//!
//! Deze module bezit de codetabel en een boom die de compiler er één keer uit
//! bouwt. Een boom is bewust niet de snelste vorm (de Go-standaardbibliotheek
//! gebruikt een tabel per vier bits), maar wel de kleinste die aantoonbaar
//! klopt: hij kan geen code missen die in de tabel staat, en er is geen tweede
//! weergave van dezelfde data die uit de pas kan lopen. Koppen zijn tientallen
//! bytes per verzoek; wat een snellere decoder wint, verdwijnt naast één
//! TLS-record. De encoder-helft bestaat niet: antwoorden gaan zonder Huffman.
//!
//! Symbool 256 (EOS, dertig enen) staat bewust niet in de tabel. EOS in een
//! literal is een fout, en opvulling mag alleen een voorvoegsel ervan zijn.

use alloc::vec::Vec;

use crate::hpack::HpackError;

/// De codes per symbool (RFC 7541 bijlage B), rechts uitgelijnd.
const CODES: [u32; 256] = [
    0x00001ff8, 0x007fffd8, 0x0fffffe2, 0x0fffffe3, 0x0fffffe4, 0x0fffffe5, 0x0fffffe6, 0x0fffffe7,
    0x0fffffe8, 0x00ffffea, 0x3ffffffc, 0x0fffffe9, 0x0fffffea, 0x3ffffffd, 0x0fffffeb, 0x0fffffec,
    0x0fffffed, 0x0fffffee, 0x0fffffef, 0x0ffffff0, 0x0ffffff1, 0x0ffffff2, 0x3ffffffe, 0x0ffffff3,
    0x0ffffff4, 0x0ffffff5, 0x0ffffff6, 0x0ffffff7, 0x0ffffff8, 0x0ffffff9, 0x0ffffffa, 0x0ffffffb,
    0x00000014, 0x000003f8, 0x000003f9, 0x00000ffa, 0x00001ff9, 0x00000015, 0x000000f8, 0x000007fa,
    0x000003fa, 0x000003fb, 0x000000f9, 0x000007fb, 0x000000fa, 0x00000016, 0x00000017, 0x00000018,
    0x00000000, 0x00000001, 0x00000002, 0x00000019, 0x0000001a, 0x0000001b, 0x0000001c, 0x0000001d,
    0x0000001e, 0x0000001f, 0x0000005c, 0x000000fb, 0x00007ffc, 0x00000020, 0x00000ffb, 0x000003fc,
    0x00001ffa, 0x00000021, 0x0000005d, 0x0000005e, 0x0000005f, 0x00000060, 0x00000061, 0x00000062,
    0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068, 0x00000069, 0x0000006a,
    0x0000006b, 0x0000006c, 0x0000006d, 0x0000006e, 0x0000006f, 0x00000070, 0x00000071, 0x00000072,
    0x000000fc, 0x00000073, 0x000000fd, 0x00001ffb, 0x0007fff0, 0x00001ffc, 0x00003ffc, 0x00000022,
    0x00007ffd, 0x00000003, 0x00000023, 0x00000004, 0x00000024, 0x00000005, 0x00000025, 0x00000026,
    0x00000027, 0x00000006, 0x00000074, 0x00000075, 0x00000028, 0x00000029, 0x0000002a, 0x00000007,
    0x0000002b, 0x00000076, 0x0000002c, 0x00000008, 0x00000009, 0x0000002d, 0x00000077, 0x00000078,
    0x00000079, 0x0000007a, 0x0000007b, 0x00007ffe, 0x000007fc, 0x00003ffd, 0x00001ffd, 0x0ffffffc,
    0x000fffe6, 0x003fffd2, 0x000fffe7, 0x000fffe8, 0x003fffd3, 0x003fffd4, 0x003fffd5, 0x007fffd9,
    0x003fffd6, 0x007fffda, 0x007fffdb, 0x007fffdc, 0x007fffdd, 0x007fffde, 0x00ffffeb, 0x007fffdf,
    0x00ffffec, 0x00ffffed, 0x003fffd7, 0x007fffe0, 0x00ffffee, 0x007fffe1, 0x007fffe2, 0x007fffe3,
    0x007fffe4, 0x001fffdc, 0x003fffd8, 0x007fffe5, 0x003fffd9, 0x007fffe6, 0x007fffe7, 0x00ffffef,
    0x003fffda, 0x001fffdd, 0x000fffe9, 0x003fffdb, 0x003fffdc, 0x007fffe8, 0x007fffe9, 0x001fffde,
    0x007fffea, 0x003fffdd, 0x003fffde, 0x00fffff0, 0x001fffdf, 0x003fffdf, 0x007fffeb, 0x007fffec,
    0x001fffe0, 0x001fffe1, 0x003fffe0, 0x001fffe2, 0x007fffed, 0x003fffe1, 0x007fffee, 0x007fffef,
    0x000fffea, 0x003fffe2, 0x003fffe3, 0x003fffe4, 0x007ffff0, 0x003fffe5, 0x003fffe6, 0x007ffff1,
    0x03ffffe0, 0x03ffffe1, 0x000fffeb, 0x0007fff1, 0x003fffe7, 0x007ffff2, 0x003fffe8, 0x01ffffec,
    0x03ffffe2, 0x03ffffe3, 0x03ffffe4, 0x07ffffde, 0x07ffffdf, 0x03ffffe5, 0x00fffff1, 0x01ffffed,
    0x0007fff2, 0x001fffe3, 0x03ffffe6, 0x07ffffe0, 0x07ffffe1, 0x03ffffe7, 0x07ffffe2, 0x00fffff2,
    0x001fffe4, 0x001fffe5, 0x03ffffe8, 0x03ffffe9, 0x0ffffffd, 0x07ffffe3, 0x07ffffe4, 0x07ffffe5,
    0x000fffec, 0x00fffff3, 0x000fffed, 0x001fffe6, 0x003fffe9, 0x001fffe7, 0x001fffe8, 0x007ffff3,
    0x003fffea, 0x003fffeb, 0x01ffffee, 0x01ffffef, 0x00fffff4, 0x00fffff5, 0x03ffffea, 0x007ffff4,
    0x03ffffeb, 0x07ffffe6, 0x03ffffec, 0x03ffffed, 0x07ffffe7, 0x07ffffe8, 0x07ffffe9, 0x07ffffea,
    0x07ffffeb, 0x0ffffffe, 0x07ffffec, 0x07ffffed, 0x07ffffee, 0x07ffffef, 0x07fffff0, 0x03ffffee,
];

/// De codelengte per symbool in bits.
const LENS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

/// Een lege tak in de boom.
const NONE: u16 = u16::MAX;
/// Markeert een blad; de lage acht bits zijn het symbool.
const LEAF: u16 = 0x8000;

/// De boom: per interne knoop twee kinderen. Een volledige prefixcode met 257
/// bladeren heeft precies 256 interne knopen; zonder EOS blijven die allemaal
/// nodig, want EOS heeft een broer (symbool 22). Past de tabel niet, dan faalt
/// de build, niet het programma.
const TREE: [[u16; 2]; 256] = build_tree();

/// Bouwt de boom tijdens het compileren.
const fn build_tree() -> [[u16; 2]; 256] {
    let mut tree = [[NONE; 2]; 256];
    let mut used = 1usize;
    let mut sym = 0usize;
    while sym < 256 {
        let code = CODES[sym];
        let mut bit = LENS[sym] as u32;
        let mut node = 0usize;
        while bit > 1 {
            bit -= 1;
            let b = ((code >> bit) & 1) as usize;
            if tree[node][b] == NONE {
                tree[node][b] = used as u16;
                used += 1;
            }
            node = tree[node][b] as usize;
        }
        tree[node][(code & 1) as usize] = LEAF | sym as u16;
        sym += 1;
    }
    tree
}

/// Decodeert een Huffman-gecodeerde literal en voegt hem aan `out` toe.
///
/// Twee dingen die RFC 7541 §5.2 eist en een naïeve lus overslaat: EOS mag niet
/// in de stroom staan, en de staart mag alleen opvulling zijn, hoogstens zeven
/// bits en allemaal enen. Al het andere is een fout in plaats van iets om stil
/// af te ronden; anders accepteert deze decoder bytes die een andere weigert.
pub(crate) fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<(), HpackError> {
    // Een symbool is minstens vijf bits: meer dan 8/5 byte per byte kan niet.
    out.try_reserve(src.len() * 8 / 5 + 1)
        .map_err(|_| HpackError::OutOfMemory)?;
    let mut node = 0usize;
    let mut depth = 0u32;
    let mut ones = true;
    for &byte in src {
        for i in (0..8).rev() {
            let bit = usize::from((byte >> i) & 1);
            if bit == 0 {
                ones = false;
            }
            let next = TREE
                .get(node)
                .and_then(|kids| kids.get(bit))
                .copied()
                .unwrap_or(NONE);
            if next == NONE {
                // Alleen het pad van EOS loopt hier dood.
                return Err(HpackError::Eos);
            }
            depth += 1;
            if next & LEAF != 0 {
                out.push((next & 0xff) as u8);
                node = 0;
                depth = 0;
                ones = true;
            } else {
                node = usize::from(next);
            }
        }
    }
    if depth > 7 || !ones {
        // Een halve code langer dan de opvulruimte, of opvulling met een nul.
        return Err(HpackError::Eos);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codeert met de tabel, voor de rondgang hieronder.
    fn encode(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut n = 0u32;
        for &s in src {
            acc = (acc << LENS[usize::from(s)]) | u64::from(CODES[usize::from(s)]);
            n += u32::from(LENS[usize::from(s)]);
            while n >= 8 {
                n -= 8;
                out.push((acc >> n) as u8);
            }
        }
        if n > 0 {
            out.push(((acc << (8 - n)) as u8) | (0xff >> n));
        }
        out
    }

    // Elk symbool door de boom: bewijst dat de boom de hele tabel draagt.
    #[test]
    fn elk_symbool_rondgang() {
        let all: Vec<u8> = (0..=255).collect();
        let mut out = Vec::new();
        decode(&encode(&all), &mut out).unwrap();
        assert_eq!(out, all);
    }
}
