//! Constant-time vergelijken en het wissen van geheimen.
//!
//! Deze module bezit de enige `unsafe` van de crate: het vluchtige schrijven
//! waarmee een sleutel uit het geheugen verdwijnt. Wat niet constant-time
//! hoeft (lengtes, publieke sleutels) staat hier niet.

use core::sync::atomic::{Ordering, compiler_fence};

/// Vergelijkt twee byte-reeksen zonder vroeg te stoppen bij het eerste verschil.
///
/// De lengte lekt wel: een MAC of tag heeft een vaste, publieke lengte, dus
/// daar zit geen geheim in. De inhoud wordt altijd helemaal doorlopen.
pub(crate) fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    // Een vergelijking op een u8 compileert zonder sprong die van de inhoud
    // afhangt; de OR hierboven heeft alle bits al verzameld.
    core::hint::black_box(diff) == 0
}

/// Overschrijft een buffer met nullen op een manier die de compiler niet mag
/// weghalen.
///
/// Een gewone `fill(0)` vlak voor een drop is een dode store en verdwijnt
/// onder optimalisatie; daarom vluchtig, per element, met een fence erachter.
/// Generiek, zodat bytes, rondesleutels en veldelementen dezelfde weg gaan.
#[expect(
    unsafe_code,
    reason = "vluchtig schrijven is de enige manier om een wis te garanderen"
)]
pub(crate) fn wipe<T: Copy + Default>(buf: &mut [T]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is een geldige, uitgelijnde, exclusieve verwijzing naar
        // één element uit `buf`; een vluchtige write daarheen kan niet buiten
        // de slice komen en er leest niemand tegelijk. `T: Copy` heeft geen
        // Drop, dus overschrijven zonder drop lekt niets.
        unsafe { core::ptr::write_volatile(b, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Een geheim van `N` bytes dat zichzelf bij `Drop` wist (via [`wipe`]); de
/// vervanger van `zeroize::Zeroizing` zonder externe crate.
pub(crate) struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Neemt `bytes` in bewaring.
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> core::ops::Deref for Secret<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for Secret<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_compares_content_and_length() {
        assert!(eq(b"abc", b"abc"));
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"ab"));
        assert!(eq(b"", b""));
    }

    #[test]
    fn wipe_zeroes() {
        let mut k = [0xa5u8; 19];
        wipe(&mut k);
        assert_eq!(k, [0u8; 19]);
    }
}
