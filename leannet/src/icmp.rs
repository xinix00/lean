//! Toestandsloze ICMPv4-echo (RFC 792): genoeg voor een diagnostische ping.
//!
//! Deze module bezit alleen het omzetten van een echo-verzoek in een antwoord.
//! Wachtrijen en routering zijn van de stack.

use crate::wire::checksum;

/// ICMP-type van een echo-antwoord.
pub(crate) const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP-type van een echo-verzoek.
pub(crate) const ICMP_ECHO_REQUEST: u8 = 8;
/// Het vaste deel: type, code, checksum, id, volgnummer.
pub(crate) const SIZE_ICMP_ECHO: usize = 8;

/// Bouwt een echo-antwoord in `reply`: code, id, volgnummer en payload blijven,
/// type en checksum veranderen. Weigert misvormde of corrupte verzoeken en te
/// kleine uitvoerbuffers met `None`.
pub(crate) fn icmp_echo(req: &[u8], reply: &mut [u8]) -> Option<usize> {
    if req.len() < SIZE_ICMP_ECHO {
        return None;
    }
    if req.first() != Some(&ICMP_ECHO_REQUEST) || req.get(1) != Some(&0) {
        return None;
    }
    if checksum(req) != 0 {
        return None;
    }
    let out = reply.get_mut(..req.len())?;
    out.copy_from_slice(req);
    if let Some(t) = out.first_mut() {
        *t = ICMP_ECHO_REPLY;
    }
    if let Some(c) = out.get_mut(2..4) {
        c.copy_from_slice(&[0, 0]);
    }
    let sum = checksum(out);
    if let Some(c) = out.get_mut(2..4) {
        c.copy_from_slice(&sum.to_be_bytes());
    }
    Some(req.len())
}

#[cfg(test)]
mod tests;
