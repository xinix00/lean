//! HMAC-SHA256 (RFC 2104), voor de sleutelafleiding en handtekening van SigV4.
//!
//! Deze module bezit alleen de HMAC-constructie; de hash komt uit
//! [`crate::sha256`].

use crate::sha256::{BLOCK_LEN, DIGEST_LEN, Sha256};

/// Berekent HMAC-SHA256 van `data` onder `key`.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
    // Een sleutel langer dan een blok wordt eerst gehasht (RFC 2104 §2).
    let mut k = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let hashed = crate::sha256::digest(key);
        k[..DIGEST_LEN].copy_from_slice(&hashed);
    } else if let Some(dst) = k.get_mut(..key.len()) {
        dst.copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for ((i, o), kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(k) {
        *i ^= kb;
        *o ^= kb;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner = inner.finish();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // RFC 4231 §4, testgevallen 1, 2, 3, 4, 6 en 7 (5 kapt de uitvoer af en
    // zegt dus niets extra over deze code). 6 en 7 hebben een sleutel langer
    // dan een blok.
    #[test]
    fn rfc4231_vectoren() {
        let case1_key = [0x0bu8; 20];
        let case3_key = [0xaau8; 20];
        let case3_data = [0xddu8; 50];
        let case4_key: Vec<u8> = (1..=25).collect();
        let case4_data = [0xcdu8; 50];
        let long_key = [0xaau8; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &case1_key,
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &case3_key,
                &case3_data,
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &case4_key,
                &case4_data,
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &long_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, data, want) in cases {
            assert_eq!(hex(&hmac_sha256(key, data)), want);
        }
    }
}
