//! Eén pure TCP-machine per verbinding (RFC 9293 en 6298), plus de
//! ACK-geklokte congestiecontrole voor fysieke routes.
//!
//! `recv` en `emit` krijgen monotone nanoseconden, zodat verlies- en
//! tijdsscenario's in tests deterministisch zijn zonder taken of klokken.
//!
//! Hertransmissie werkt op de volgnummerruimte, niet alleen op data. SYN en
//! FIN doen dus mee aan go-back-N: een RTO spoelt `nxt` terug naar `una` en
//! `emit` maakt data en stuurvlaggen samen opnieuw. Drie ernstige bevindingen
//! in lneto (review 11-08-2026) leefden in precies de klasse "een aparte
//! vlaggenrij raakt leeg terwijl zijn segment verdween"; die rij bestaat hier
//! niet.
//!
//! Alleen invoer in volgorde wordt aangenomen; een gat krijgt meteen een
//! duplicate ACK zodat de peer fast-retransmit doet (KAM: ADAPT). Window
//! scaling wel, SACK en timestamps niet.
//!
//! Deze module bezit de toestand van één verbinding en haar ringen. De pot
//! zelf is van de stack en komt als parameter binnen; `budgeted` zegt of deze
//! verbinding er nog aan gekoppeld is.

use core::fmt;

use crate::ring::{Budget, Ring, TxRing};
use crate::wire::TcpFlags;
use crate::{Error, MS, Result, SEC};

// ---- volgnummerrekenkunde modulo 2^32 ----

/// `a < b` in volgnummerruimte.
pub(crate) fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a <= b` in volgnummerruimte.
pub(crate) fn seq_leq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// `a - b` als getal met teken, voor kleine afstanden.
pub(crate) fn seq_diff(a: u32, b: u32) -> i64 {
    i64::from(a.wrapping_sub(b) as i32)
}

/// Een bytegrootte als `u32` voor volgnummerrekenkunde; buffers zijn ver onder 4 GiB.
fn seq_len(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Een bytegrootte als `i64`.
fn ilen(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Een niet-negatieve `i64` als `usize`; negatief wordt nul.
fn ulen(n: i64) -> usize {
    usize::try_from(n).unwrap_or(0)
}

// ---- toestanden ----

/// De RFC 9293-toestanden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TcpState {
    /// Geen verbinding (of een listener-embryo dat op een SYN wacht).
    #[default]
    Closed,
    /// SYN verstuurd, wacht op SYN|ACK.
    SynSent,
    /// SYN ontvangen, SYN|ACK verstuurd.
    SynRcvd,
    /// Data in beide richtingen.
    Established,
    /// Onze FIN is verstuurd.
    FinWait1,
    /// Onze FIN is bevestigd; wacht op die van de peer.
    FinWait2,
    /// De peer is klaar met zenden.
    CloseWait,
    /// Onze FIN na die van de peer; wacht op de bevestiging.
    LastAck,
    /// Gelijktijdig sluiten.
    Closing,
    /// Kort wachten op herhaalde FINs.
    TimeWait,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpState::Closed => "CLOSED",
            TcpState::SynSent => "SYN-SENT",
            TcpState::SynRcvd => "SYN-RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN-WAIT-1",
            TcpState::FinWait2 => "FIN-WAIT-2",
            TcpState::CloseWait => "CLOSE-WAIT",
            TcpState::LastAck => "LAST-ACK",
            TcpState::Closing => "CLOSING",
            TcpState::TimeWait => "TIME-WAIT",
        })
    }
}

// ---- RTO-parameters (RFC 6298) en levensloopgrenzen ----

/// Begin-RTO.
pub(crate) const TCP_RTO_INITIAL: u64 = SEC;
/// RFC 6298 §2.4 raadt 1 s aan; ingebedde LANs gebruiken een lagere vloer.
pub(crate) const TCP_RTO_MIN: u64 = 200 * MS;
/// Plafond van de RTO.
pub(crate) const TCP_RTO_MAX: u64 = 60 * SEC;
/// Plafond op het verdubbelen; een vastgelopen peer blijft op `TCP_RTO_MAX` peilen.
const TCP_BACKOFF_MAX: u8 = 12;
/// TIME-WAIT: ingebedde doelen kunnen geen vier minuten 2MSL betalen.
pub(crate) const TCP_TIME_WAIT_DUR: u64 = SEC;
/// Een volledige socket-close krijgt één absolute termijn voor wachtende data,
/// FIN en TIME-WAIT samen. ACKs en vensterupdates kunnen hem bewust niet
/// verlengen: nadat de eigenaar de socket losliet is een coöperatieve close
/// nuttig, maar het tupel en de buffers eeuwig vasthouden niet.
pub(crate) const TCP_FULL_CLOSE_DUR: u64 = 20 * SEC;
/// FIN-WAIT-2 krijgt dezelfde grens voor gebruikers die alleen half sluiten.
pub(crate) const TCP_FIN_WAIT2_DUR: u64 = 20 * SEC;
/// CLOSE-WAIT: de peer is klaar. Staartlezen en antwoorden blijven mogelijk,
/// maar een vergeten verbinding wordt na twee minuten zonder echte
/// applicatie-I/O of ACK-voortgang opgeruimd.
pub(crate) const TCP_CLOSE_WAIT_DUR: u64 = 120 * SEC;
/// De klassieke MSS zonder optie.
pub(crate) const TCP_DEFAULT_MSS: usize = 536;
/// De MSS-klem zonder geadverteerde MSS: MTU 1500 min IP- en TCP-header.
const TCP_CLASSIC_MSS: usize = crate::MTU - 40;
/// RTOs zonder geldige ACK tijdens de handshake: ongeveer zes seconden.
pub(crate) const TCP_MAX_RETRIES_HANDSHAKE: u8 = 5;
/// RTOs zonder geldige ACK met data: minuten voor een verdwenen peer. Elke
/// geldige ACK zet de teller terug, dus een levende zero-window-peer blijft.
pub(crate) const TCP_MAX_RETRIES_DATA: u8 = 12;
/// Plafond van het congestievenster.
pub(crate) const MAX_CONGESTION_WINDOW: usize = 1 << 30;

/// Een segmentkop in machinevorm; de stack vertaalt van en naar de draad. De
/// payload reist apart (bij `recv` als slice, bij `emit` in de buffer).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Seg {
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: TcpFlags,
    /// Draadwaarde vóór schaling.
    pub(crate) wnd: u16,
    /// Lengte van de payload (alleen bij `emit` ingevuld).
    pub(crate) len: usize,
    /// Alleen betekenisvol op SYN-segmenten.
    pub(crate) mss: u16,
    /// Window-scale-optie aanwezig.
    pub(crate) ws_ok: bool,
    /// Aangeboden shift.
    pub(crate) ws: u8,
}

/// Hoogstens één wachtende reset en zijn exacte vorm. Een abort gebruikt
/// RST|ACK; een ACK die onze SYN niet bevestigt krijgt kaal `<SEQ=SEG.ACK>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PendingRst {
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) with_ack: bool,
    pub(crate) set: bool,
}

/// Tellers per verbinding, opgeteld in [`crate::Stats`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpCounters {
    /// RTO-hertransmissies (go-back-N).
    pub(crate) retrans: usize,
    /// Drie duplicate ACKs.
    pub(crate) fast_retrans: usize,
    /// Verstuurde zero-window-probes.
    pub(crate) persist: usize,
    /// De peer adverteerde een nulvenster.
    pub(crate) zero_wnd: usize,
    /// Verstuurde datasegmenten, hertransmissies inbegrepen.
    pub(crate) segs_out: usize,
    pub(crate) bytes_out: usize,
    /// Ontvangen datasegmenten.
    pub(crate) segs_in: usize,
    pub(crate) bytes_in: usize,
}

/// Eén verbinding.
#[derive(Debug, Default)]
pub(crate) struct TcpConn {
    pub(crate) cnt: TcpCounters,
    pub(crate) state: TcpState,
    /// Passieve kant: een SYN op `Closed` opent naar SYN-RCVD.
    pub(crate) listen: bool,

    // Zendkant. `data_base` verankert de kop van de zendring in de
    // volgnummerruimte, zodat hertransmissie een herlezing is. `close` zet
    // `fin_seq` vast en weigert latere writes.
    pub(crate) iss: u32,
    /// Hoogste door de peer bevestigde volgnummer.
    pub(crate) una: u32,
    /// Volgende te versturen volgnummer.
    pub(crate) nxt: u32,
    pub(crate) data_base: u32,
    pub(crate) closing: bool,
    pub(crate) fin_seq: u32,
    /// Venster van de peer in octetten, na schaling.
    pub(crate) snd_wnd: u32,
    /// Segment van de laatste vensterupdate (RFC 9293 §3.10.7.4).
    pub(crate) wl1: u32,
    pub(crate) wl2: u32,
    pub(crate) peer_mss: usize,
    /// Shift voor binnenkomende vensteradvertenties van de peer.
    pub(crate) snd_ws: u8,

    // Ontvangstkant.
    pub(crate) irs: u32,
    pub(crate) rcv_nxt: u32,
    pub(crate) fin_rcvd: bool,
    /// Shift voor onze vensteradvertenties.
    pub(crate) rcv_ws: u8,
    /// Beide kanten boden window scaling aan.
    pub(crate) ws_on: bool,

    // Waarden op onze SYN.
    pub(crate) adv_mss: u16,
    pub(crate) adv_ws: u8,

    pub(crate) rx: Ring,
    pub(crate) tx: TxRing,

    /// Ringen beginnen op hun vloer en verdubbelen onder ontvangst- of
    /// schrijfdruk, begrensd door `max_buf` en de pot. Zonder koppeling aan
    /// de pot groeit niets. Gegroeide capaciteit leeft tot de close: krimpen
    /// tussen reads of ACKs zou één bulkstroom in een cyclus van groeien,
    /// alloceren en krimpen veranderen.
    pub(crate) budgeted: bool,
    pub(crate) max_buf: usize,

    /// Data, FIN, een duplicaat of een challenge vraagt om een ACK.
    pub(crate) need_ack: bool,
    /// Volledige socket-close. Beloofde binnenkomende data wordt geteld en
    /// weggegooid, zodat ACK en FIN verder kunnen nadat de ontvangstring
    /// terug is.
    pub(crate) app_closed: bool,
    /// Vernieuwbaar zolang een applicatie een CLOSE-WAIT-socket bezit; een
    /// volledige close overschrijft hem met één absolute grens. Nul is "geen".
    pub(crate) close_deadline: u64,
    /// De wachtende reset; `emit` stuurt hem eerst en reap bewaart hem als de
    /// verbinding sterft voordat de pomp langskwam.
    pub(crate) rst: PendingRst,
    /// De verste geadverteerde ontvangstrand. `adv_set` kan geen nul als
    /// schildwacht gebruiken, want door wrap is nul geldig. Hij voorkomt ook
    /// krimpen onder een al belooft venster (RFC 9293 §3.8.6.2.1).
    pub(crate) adv_edge: u32,
    pub(crate) adv_set: bool,
    /// De belofte van de actieve SYN, tot de ISS van de peer `rcv_nxt` vastlegt.
    pub(crate) syn_wnd: u16,

    // RTO en Karn. `max_sent` voorkomt dat hertransmitteerde ruimte wordt bemeten.
    pub(crate) srtt: i64,
    pub(crate) rttvar: i64,
    pub(crate) rto: u64,
    pub(crate) have_rtt: bool,
    pub(crate) timer_on: bool,
    pub(crate) deadline: u64,
    pub(crate) backoff: u8,
    pub(crate) timing: bool,
    pub(crate) timed_seq: u32,
    pub(crate) timed_at: u64,
    pub(crate) max_sent: u32,

    /// Zero-window-probes hebben een eigen backoff, zodat ze RTT en RTO niet
    /// vergiftigen.
    pub(crate) persist_backoff: u8,
    /// Fast retransmit: drie vergrendelt het herstel tot cumulatieve voortgang.
    pub(crate) dupacks: u8,

    /// Fysieke routes gebruiken ACK-geklokte congestiecontrole; geheugenlinks niet.
    pub(crate) congestion: bool,
    pub(crate) cwnd: usize,
    pub(crate) ssthresh: usize,
    pub(crate) cwnd_acked: usize,
    pub(crate) last_data_sent: u64,

    /// RTOs sinds de laatste geldige ACK.
    pub(crate) retries: u8,
    /// Onderscheidt een SYN-reset van opgeraakte pogingen.
    pub(crate) refused: bool,
    /// Bewaart een onnet einde, zodat I/O een fout meldt en geen EOF.
    pub(crate) reset: bool,
    /// De timer staat één zero-window-probe van één byte toe.
    pub(crate) probe: bool,

    pub(crate) tw_deadline: u64,
}

impl TcpConn {
    /// Een verbinding met eigen ringen van de gegeven maten, zonder pot.
    pub(crate) fn with_rings(rx: usize, tx: usize) -> Result<TcpConn> {
        Ok(TcpConn {
            rx: Ring::with_size(rx)?,
            tx: TxRing::with_size(tx)?,
            ..TcpConn::default()
        })
    }

    /// Zet alles terug behalve wat de eigenaar leverde: ringen, potkoppeling,
    /// groeiplafond en congestiebeleid.
    fn reset_to(&mut self, state: TcpState, iss: u32, adv_mss: u16, adv_ws: u8) {
        let rx = core::mem::take(&mut self.rx);
        let tx = core::mem::take(&mut self.tx);
        *self = TcpConn {
            state,
            iss,
            max_sent: iss,
            adv_mss,
            adv_ws,
            rto: TCP_RTO_INITIAL,
            peer_mss: TCP_DEFAULT_MSS,
            rx,
            tx,
            budgeted: self.budgeted,
            max_buf: self.max_buf,
            congestion: self.congestion,
            ..TcpConn::default()
        };
    }

    /// Start een uitgaande verbinding; de volgende `emit` stuurt de SYN.
    pub(crate) fn open_active(&mut self, iss: u32, adv_mss: u16, adv_ws: u8) {
        self.reset_to(TcpState::SynSent, iss, adv_mss, adv_ws);
        self.una = iss;
        self.nxt = iss;
        self.data_base = iss.wrapping_add(1);
    }

    /// Maakt een listener-embryo dat een binnenkomende SYN naar SYN-RCVD opent.
    pub(crate) fn open_passive(&mut self, iss: u32, adv_mss: u16, adv_ws: u8) {
        self.reset_to(TcpState::Closed, iss, adv_mss, adv_ws);
        self.listen = true;
    }

    /// Zet de FIN vast na de laatste databyte en weigert latere writes.
    pub(crate) fn close(&mut self) -> Result {
        if self.closing {
            return Err(Error::TcpClosing);
        }
        match self.state {
            TcpState::Closed | TcpState::TimeWait => return Err(Error::TcpClosed),
            TcpState::SynSent => {
                // Nog niets gesynchroniseerd: laat de poging vallen.
                self.state = TcpState::Closed;
                return Ok(());
            }
            _ => {}
        }
        self.closing = true;
        self.fin_seq = self.data_base.wrapping_add(seq_len(self.tx.buffered()));
        Ok(())
    }

    /// De volgnummerruimte die de peer nog niet bevestigde: de hele zendring
    /// (onverzonden plus onderweg) en één voor een FIN die nog niet bevestigd is.
    ///
    /// De FIN telt als één, net als in de volgnummerruimte: zo is nul precies
    /// "de peer heeft alles, einde inbegrepen", en heeft een flush na een close
    /// één getal om op te wachten in plaats van een tweede vraag.
    pub(crate) fn unacked(&self) -> usize {
        // Alleen `ack == fin_seq + 1` bevestigt de FIN (zie `process_ack`), dus
        // zolang `una <= fin_seq` staat hij nog open.
        let fin_open = self.closing && seq_leq(self.una, self.fin_seq);
        self.tx.buffered() + usize::from(fin_open)
    }

    /// Markeert een volledige socket-close, anders dan de half-close van
    /// `close`. Geeft ongelezen ontvangstopslag vrij terwijl `app_closed`
    /// binnenkomende data blijft opschuiven en bevestigen, zodat de peer zijn
    /// FIN kwijt kan.
    pub(crate) fn abandon_read(&mut self, now: u64, pot: &mut Budget) {
        // Een dubbele close mag de absolute opruimgrens niet oprekken.
        if !self.app_closed {
            self.app_closed = true;
            self.close_deadline = now + TCP_FULL_CLOSE_DUR;
        }
        if self.budgeted {
            pot.release(self.rx.size());
            self.rx = Ring::default();
        }
    }

    /// Houdt een legitiem actieve half-gesloten verbinding in leven en begrenst
    /// een vergetene. Een volledige close heeft een eigen absolute deadline.
    pub(crate) fn touch_close_wait(&mut self, now: u64) {
        if self.state == TcpState::CloseWait && !self.app_closed {
            self.close_deadline = now + TCP_CLOSE_WAIT_DUR;
        }
    }

    /// Staat los van `emit`, zodat de stack een eigenaarloze verbinding kan
    /// opruimen ook als de buurresolutie geen route voor zijn RST heeft.
    pub(crate) fn lifecycle_expired(&self, now: u64) -> bool {
        if self.state == TcpState::Closed {
            return false;
        }
        (self.app_closed || self.state == TcpState::CloseWait)
            && self.close_deadline != 0
            && now >= self.close_deadline
    }

    /// Beëindigt de verbinding en zet één reset klaar.
    pub(crate) fn abort(&mut self) {
        if self.state != TcpState::Closed && self.state != TcpState::SynSent {
            self.rst = PendingRst {
                seq: self.nxt,
                ack: self.rcv_nxt,
                with_ack: true,
                set: true,
            };
            self.reset = true; // Een abort is geen net einde; I/O moet falen.
        }
        self.state = TcpState::Closed;
        self.timer_on = false;
    }

    /// Buffert applicatiedata. Een volle ring terwijl de peer meer venster
    /// biedt, is het signaal om de zendring te laten groeien.
    pub(crate) fn write(&mut self, p: &[u8], pot: &mut Budget) -> Result<usize> {
        if self.reset {
            return Err(Error::Reset);
        }
        if self.closing || !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(Error::TcpClosed);
        }
        let mut n = self.tx.write_app(p);
        while n < p.len() && self.snd_wnd as usize > self.tx.size() && self.grow_tx(pot) {
            n += self.tx.write_app(p.get(n..).unwrap_or(&[]));
        }
        Ok(n)
    }

    /// De volgende maat voor een ring van `cur` bytes, binnen `max_buf`.
    ///
    /// `max_buf` klemt elke ring apart. Gecombineerd nam de zendring van een
    /// verbinding die om beurten grote stukken schrijft en leest de hele
    /// ruimte, en bleef de ontvangstring op zijn vloer: de peer mocht dan
    /// 4 KiB per ronde sturen (256 rondes per MiB, gemeten 04-09-2026).
    fn grown_size(&self, cur: usize) -> Option<usize> {
        if !self.budgeted {
            return None;
        }
        let headroom = self.max_buf.checked_sub(cur).filter(|h| *h > 0)?;
        let mut new = cur.saturating_mul(2);
        if new - cur > headroom {
            new = cur + headroom;
        }
        (new > cur).then_some(new)
    }

    /// Verdubbelt de ontvangstring binnen `max_buf` en de pot.
    pub(crate) fn grow_rx(&mut self, pot: &mut Budget) -> bool {
        let old = self.rx.size();
        let Some(new) = self.grown_size(old) else {
            return false;
        };
        // De piek (oud plus nieuw) wordt geboekt: eerst de hele nieuwe buffer
        // reserveren, dan pas de oude teruggeven. Kan de pot de piek niet
        // dragen, dan blijft de ring gewoon klein.
        if !pot.reserve(new) {
            return false;
        }
        if self.rx.grow(new).is_err() {
            pot.release(new);
            return false;
        }
        pot.release(old);
        true
    }

    /// Verdubbelt de zendring binnen `max_buf` en de pot.
    pub(crate) fn grow_tx(&mut self, pot: &mut Budget) -> bool {
        let old = self.tx.size();
        let Some(new) = self.grown_size(old) else {
            return false;
        };
        if !pot.reserve(new) {
            return false;
        }
        if self.tx.grow(new).is_err() {
            pot.release(new);
            return false;
        }
        pot.release(old);
        true
    }

    /// Geeft ontvangen bytes. `Ok(0)` is "nog niets"; [`Error::TcpClosed`] is
    /// EOF na de FIN van de peer; [`Error::Reset`] is nooit een EOF.
    ///
    /// Een bijna dicht venster dat weer opengaat, zet één update klaar zodra
    /// minstens één MSS vrij is, zodat de peer niet seconden op zijn
    /// zero-window-probe wacht.
    pub(crate) fn read(&mut self, p: &mut [u8]) -> Result<usize> {
        if self.reset {
            // Een reset maakt gebufferde staartdata ongeldig: een fout, geen
            // schijnbaar complete stroom.
            return Err(Error::Reset);
        }
        let was_free = self.rx.free();
        let n = self.rx.read(p);
        if n == 0 && (self.fin_rcvd || self.state == TcpState::Closed) {
            return Err(Error::TcpClosed);
        }
        // De drempel is min(MSS, halve ring), minstens één.
        let thresh = self.peer_mss.min(self.rx.size() / 2).max(1);
        if was_free < thresh && self.rx.free() >= thresh {
            self.need_ack = true;
        }
        // Het venster van de PEER is wat wij hem het laatst beloofden
        // (adv_edge − rcv_nxt), niet onze lokale vrije ruimte. Een snelle
        // lezer houdt de ring leeg (was_free blijft hoog en de conditie
        // hierboven vuurt nooit) terwijl de zender zijn belofte allang heeft
        // opgemaakt en wacht. Zonder deze check kwam de vensterupdate pas mee
        // op de persist-probe van de peer: gemeten 18-08-2026 (LicheeRV,
        // zenderzijdig) 194 stalls die samen 43,047 van de 43,049 s besloegen,
        // mediaan 165 ms per vensterronde.
        if self.adv_set {
            let out = seq_diff(self.adv_edge, self.rcv_nxt);
            let t = ilen(thresh);
            if out >= 0 && out < t && ilen(self.rx.free()) - out >= t {
                self.need_ack = true;
            }
        }
        Ok(n)
    }

    /// Legt een geadverteerd venster vast zonder de rechterrand naar links te
    /// schuiven (RFC 9293 §3.8.6.2.1). SYN en gewone advertenties delen dit pad.
    pub(crate) fn promise_edge(&mut self, wnd: u32) {
        let edge = self.rcv_nxt.wrapping_add(wnd);
        if !self.adv_set || seq_lt(self.adv_edge, edge) {
            self.adv_edge = edge;
            self.adv_set = true;
        }
    }

    /// De geschaalde vrije ontvangstruimte. Belooft nooit ongealloceerde capaciteit.
    pub(crate) fn advertised_wnd(&mut self) -> u16 {
        let mut w = self.rx.free();
        if self.ws_on {
            w >>= self.rcv_ws;
        }
        let w = u16::try_from(w).unwrap_or(u16::MAX);
        // Leg de werkelijk geklemde draadbelofte vast, niet alle vrije
        // capaciteit. Zonder schaling belooft een ring van 128 KiB er maar
        // 65.535 en mag daarheen krimpen.
        let mut promised = u32::from(w);
        if self.ws_on {
            promised <<= self.rcv_ws;
        }
        self.promise_edge(promised);
        w
    }

    // ---- ontvangen ----

    /// Verwerkt een gechecksumd, gedemultiplexed segment door de RFC-machine.
    pub(crate) fn recv(&mut self, seg: &Seg, data: &[u8], now: u64, pot: &mut Budget) {
        if self.state == TcpState::Closed {
            // ACK en RST apart toetsen: has(ACK|RST) eist beide en liet een
            // SYN|RST een embryo alloceren. LISTEN negeert RST (RFC 9293 §3.10.7.2).
            if self.listen
                && seg.flags.has(TcpFlags::SYN)
                && !seg.flags.has(TcpFlags::ACK)
                && !seg.flags.has(TcpFlags::RST)
            {
                self.accept_syn(seg);
            }
            return;
        }
        if self.state == TcpState::SynSent {
            self.recv_syn_sent(seg);
            return;
        }

        // Een RST vereist een exacte volgnummermatch; een mismatch binnen het
        // venster krijgt een challenge-ACK tegen blinde resets (RFC 5961 §3.2).
        if seg.flags.has(TcpFlags::RST) {
            if seg.seq == self.rcv_nxt {
                self.state = TcpState::Closed;
                self.timer_on = false;
                self.reset = true; // Een reset van de peer is geen EOF.
            } else if self.in_rcv_window(seg.seq) {
                self.need_ack = true;
            }
            return;
        }
        // Een SYN op een gesynchroniseerde verbinding krijgt een challenge-ACK
        // (RFC 5961 §4.2).
        if seg.flags.has(TcpFlags::SYN) {
            if self.state == TcpState::SynRcvd && seg.seq == self.irs {
                // Een dubbele SYN: onze SYN|ACK ging verloren; opnieuw sturen.
                self.nxt = self.iss;
                return;
            }
            self.need_ack = true;
            return;
        }
        if !seg.flags.has(TcpFlags::ACK) {
            return; // Elk segment na de SYN draagt ACK (RFC 9293 §3.10.7.4).
        }
        // Aanvaardbaarheid gaat vóór ACK-verwerking, vensterupdates en het
        // terugzetten van pogingen. Invoer buiten het venster krijgt alleen
        // een verse ACK: dat dekt probes en herhaalde FINs zonder dat
        // verdwaalde invoer de zendtoestand verandert.
        if !self.seg_acceptable(seg, data.len()) {
            // Een exact dubbele FIN in TIME-WAIT herstart 2MSL, zodat nog een
            // verloren ACK herstelbaar is. Andere FINs rekken niets op.
            if self.state == TcpState::TimeWait
                && seg.flags.has(TcpFlags::FIN)
                && seg.seq.wrapping_add(seq_len(data.len())) == self.rcv_nxt.wrapping_sub(1)
            {
                self.tw_deadline = now + TCP_TIME_WAIT_DUR;
            }
            self.need_ack = true;
            return;
        }

        if !self.process_ack(seg, data.len(), now, pot) {
            // Een ongeldige ACK weigert het hele segment, data en FIN inbegrepen.
            return;
        }

        // Data en FIN alleen in ontvangende toestanden; anders duplicaten
        // bevestigen zodat de peer niet eeuwig hertransmitteert.
        match self.state {
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                self.process_data(seg, data, now, pot);
            }
            _ => {
                if !data.is_empty() || seg.flags.has(TcpFlags::FIN) {
                    self.need_ack = true;
                }
            }
        }
    }

    /// Brengt een listener-embryo van SYN naar SYN-RCVD.
    fn accept_syn(&mut self, seg: &Seg) {
        self.state = TcpState::SynRcvd;
        self.listen = false;
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.una = self.iss;
        self.nxt = self.iss;
        self.data_base = self.iss.wrapping_add(1);
        self.take_syn_options(seg);
        // SYN-vensters worden nooit geschaald (RFC 7323 §2.2).
        self.snd_wnd = u32::from(seg.wnd);
        self.wl1 = seg.seq;
        self.wl2 = 0;
    }

    /// SYN-SENT: wacht op SYN|ACK of een weigering.
    fn recv_syn_sent(&mut self, seg: &Seg) {
        if seg.flags.has(TcpFlags::RST) {
            if seg.flags.has(TcpFlags::ACK) && seg.ack == self.iss.wrapping_add(1) {
                self.state = TcpState::Closed; // Verbinding geweigerd.
                self.refused = true;
                self.timer_on = false;
            }
            return;
        }
        // Een ACK zonder RST die onze SYN niet bevestigt krijgt
        // <SEQ=SEG.ACK><CTL=RST> terwijl SYN-SENT doorgaat (RFC 9293
        // §3.10.7.3). Dat ruimt een oude verbinding bij de peer op zodat de
        // volgende SYN zijn listener bereikt.
        if seg.flags.has(TcpFlags::ACK) && seg.ack != self.iss.wrapping_add(1) {
            self.rst = PendingRst {
                seq: seg.ack,
                set: true,
                ..PendingRst::default()
            };
            return;
        }
        if !seg.flags.has(TcpFlags::SYN) || !seg.flags.has(TcpFlags::ACK) {
            return; // Gelijktijdig openen hoort niet bij het profiel.
        }
        self.enter_established();
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.una = seg.ack;
        self.need_ack = true;
        // Veranker de vensterbelofte van onze SYN nu `rcv_nxt` bekend is.
        self.promise_edge(u32::from(self.syn_wnd));
        self.take_syn_options(seg);
        // SYN-vensters zijn ongeschaald; dit is de beginwaarde.
        self.snd_wnd = u32::from(seg.wnd);
        self.wl1 = seg.seq;
        self.wl2 = seg.ack;
    }

    /// Deelt de handshake-afronding tussen actief en passief openen.
    fn enter_established(&mut self) {
        self.state = TcpState::Established;
        self.timer_on = false;
        self.timing = false;
        self.backoff = 0;
        // Zet de handshake-backoff terug, zodat het eerste dataverlies niet
        // tot een minuut van eerder SYN-verlies erft. Een latere RTT-meting
        // kalibreert opnieuw.
        self.rto = TCP_RTO_INITIAL;
        self.retries = 0;
        // Een wachtende reset voor een ongeldige ACK vervalt zodra een latere
        // geldige ACK de handshake afmaakt.
        self.rst = PendingRst::default();
    }

    /// Neemt de MSS van de peer over en zet schaling alleen aan als beide
    /// kanten hem aanboden (RFC 7323 §2.2).
    pub(crate) fn take_syn_options(&mut self, seg: &Seg) {
        if seg.mss != 0 {
            self.peer_mss = usize::from(seg.mss);
            // De MSS van de peer is een bovengrens; klem hem op wat wij
            // adverteerden, dat al de link naar deze peer volgt. Zonder
            // geadverteerde MSS geldt de klassieke klem.
            let limit = usize::from(self.adv_mss);
            if limit > 0 && self.peer_mss > limit {
                self.peer_mss = limit;
            } else if limit == 0 && self.peer_mss > TCP_CLASSIC_MSS {
                self.peer_mss = TCP_CLASSIC_MSS;
            }
        }
        if seg.ws_ok {
            self.ws_on = true;
            // RFC 7323 §2.3 kapt de shift op 14.
            self.snd_ws = seg.ws.min(14);
            self.rcv_ws = self.adv_ws;
        }
        self.init_congestion();
    }

    /// Het beloofde venster voor aanvaardbaarheid en RST-validatie, niet vers
    /// vrijgekomen ruimte die nog niet geadverteerd is.
    pub(crate) fn rcv_wnd(&self) -> u32 {
        if self.adv_set {
            let d = seq_diff(self.adv_edge, self.rcv_nxt);
            return u32::try_from(d).unwrap_or(0);
        }
        seq_len(self.rx.free())
    }

    /// Of `seq` binnen het ontvangstvenster valt.
    fn in_rcv_window(&self, seq: u32) -> bool {
        seq_leq(self.rcv_nxt, seq) && seq_lt(seq, self.rcv_nxt.wrapping_add(self.rcv_wnd()))
    }

    /// De vier gevallen van RFC 9293 §3.10.7.4 tegen het beloofde venster.
    /// SEG.LEN telt de FIN mee; de SYN is al eerder afgehandeld.
    fn seg_acceptable(&self, seg: &Seg, data_len: usize) -> bool {
        let mut seg_len = seq_len(data_len);
        if seg.flags.has(TcpFlags::FIN) {
            seg_len = seg_len.wrapping_add(1);
        }
        let wnd = self.rcv_wnd();
        match (seg_len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => self.in_rcv_window(seg.seq),
            (_, 0) => false, // Data op een vol venster krijgt een nulvenster-ACK.
            _ => {
                // Hetzelfde vensterpredicaat voor beide uiteinden.
                self.in_rcv_window(seg.seq) || self.in_rcv_window(seg.seq.wrapping_add(seg_len - 1))
            }
        }
    }

    /// Schuift volgnummers en ring op, werkt vensters en RTT bij, telt
    /// duplicaten en drijft sluitovergangen. Alleen `ack == fin_seq + 1`
    /// bevestigt de FIN.
    fn process_ack(&mut self, seg: &Seg, data_len: usize, now: u64, pot: &mut Budget) -> bool {
        let ack = seg.ack;
        // SYN-RCVD aanvaardt alleen SND.UNA < ACK ≤ SND.NXT (RFC 9293
        // §3.10.7.4). Ongeldige ACKs krijgen <SEQ=SEG.ACK><RST> en houden geen
        // embryo in leven. Vergelijk met `max_sent`, want een dubbele SYN kan
        // `nxt` terugspoelen terwijl een geldige finale ACK al onderweg is.
        if self.state == TcpState::SynRcvd
            && !(seq_lt(self.una, ack) && seq_leq(ack, self.max_sent))
        {
            self.rst = PendingRst {
                seq: ack,
                set: true,
                ..PendingRst::default()
            };
            return false;
        }
        if seq_lt(self.max_sent, ack) {
            // Een ACK voorbij alles wat ooit verstuurd is: meld onze toestand en
            // laat het segment vallen. `max_sent` spoelt, anders dan de
            // hertransmissiecursor `nxt`, nooit terug.
            self.need_ack = true;
            return false;
        }
        if seq_lt(ack, self.una) {
            // Een oude ACK breekt de duplicaatreeks, maar kan het herstel voor
            // dezelfde onbevestigde data niet opnieuw wapenen. Drie blijft
            // vergrendeld tot voortgang.
            if self.dupacks < 3 {
                self.dupacks = 0;
            }
            return true; // Negeer de oude ACK maar laat de data door.
        }

        if self.state == TcpState::SynRcvd {
            // De toets hierboven maakt dit de enige geldige SYN-RCVD-ACK.
            self.enter_established();
        }

        // Vensterupdates alleen van segmenten die niet ouder zijn dan de laatste.
        let mut wnd = u32::from(seg.wnd);
        if self.ws_on {
            wnd <<= self.snd_ws;
        }
        // Een duplicate ACK vereist een ongewijzigd venster (RFC 5681 §2).
        let same_wnd = wnd == self.snd_wnd;
        if seq_lt(self.wl1, seg.seq) || (self.wl1 == seg.seq && seq_leq(self.wl2, ack)) {
            let was_closed = self.snd_wnd == 0;
            self.snd_wnd = wnd;
            if wnd == 0 && !was_closed {
                self.cnt.zero_wnd += 1;
            }
            self.wl1 = seg.seq;
            self.wl2 = ack;
            // Een geldige nulvensterupdate bewijst dat de peer in persist leeft
            // en zet de pogingen terug. Oude nuladvertenties doen dat niet.
            if self.snd_wnd == 0 {
                self.retries = 0;
            }
            // Gaat een nulvenster open zonder ACK-voortgang, spoel dan terug
            // naar `una`, want de probe kan verloren zijn. Eén byte opnieuw
            // sturen is veilig als hij wel aankwam.
            if was_closed && wnd > 0 {
                // Einde van de persist-backoff; `post_tx` wapent een schone RTO.
                self.persist_backoff = 0;
                self.timer_on = false;
                if ack == self.una && self.una != self.nxt {
                    self.go_back_n();
                }
            }
        }

        if ack == self.una {
            // RFC 5681-duplicaat: geen data of FIN, zelfde ACK en venster, met
            // data onderweg. Vergrendel op drie tot cumulatieve voortgang:
            // wachtende duplicaten, vensterupdates en de teruggespoelde `nxt`
            // mogen hetzelfde go-back-N-herstel niet herstarten. De RTO dekt
            // een verloren hertransmissie.
            if data_len == 0 && !seg.flags.has(TcpFlags::FIN) && same_wnd && self.una != self.nxt {
                if self.dupacks < 3 {
                    self.dupacks += 1;
                    if self.dupacks == 3 {
                        self.cnt.fast_retrans += 1;
                        self.congestion_loss();
                        self.go_back_n();
                    }
                }
            } else if self.dupacks < 3 {
                self.dupacks = 0;
            }
            return true;
        }

        // ack > una is echte voortgang.
        let data_acked = seq_diff(ack, self.data_base);
        if data_acked > 0 {
            // SYN- en FIN-ruimte zijn geen ringdata.
            let data_acked = ulen(data_acked).min(self.tx.buffered());
            self.congestion_ack(data_acked);
            // Een cumulatieve ACK kan de hertransmissie na go-back-N inhalen;
            // herstel de zendcursor vóór het vrijgeven.
            self.tx.force_sent(data_acked);
            self.tx.ack(data_acked);
            self.data_base = self.data_base.wrapping_add(seq_len(data_acked));
        }
        self.una = ack;
        if seq_lt(self.nxt, ack) {
            // Trek de teruggespoelde cursor bij tot de cumulatieve ACK.
            self.nxt = ack;
        }
        self.dupacks = 0;
        self.retries = 0; // Echte voortgang bewijst leven.
        self.persist_backoff = 0;
        self.touch_close_wait(now); // Voortgang is activiteit; duplicaten niet.

        // Karn: alleen niet-hertransmitteerde ruimte mag bemeten worden.
        if self.timing && seq_leq(self.timed_seq, ack) {
            self.update_rtt(i64::try_from(now.saturating_sub(self.timed_at)).unwrap_or(i64::MAX));
            self.timing = false;
            self.backoff = 0;
        }

        // RFC 6298: stop de timer als alles bevestigd is, herstart hem anders.
        if self.una == self.nxt {
            self.timer_on = false;
        } else {
            self.timer_on = true;
            self.deadline = now + self.current_rto();
        }

        // Sluitovergangen die een exacte FIN-bevestiging eisen.
        if self.closing && ack == self.fin_seq.wrapping_add(1) {
            match self.state {
                TcpState::FinWait1 => {
                    self.state = TcpState::FinWait2;
                    self.tw_deadline = now + TCP_FIN_WAIT2_DUR;
                }
                TcpState::Closing => {
                    self.state = TcpState::TimeWait;
                    self.tw_deadline = now + TCP_TIME_WAIT_DUR;
                }
                TcpState::LastAck => {
                    self.state = TcpState::Closed;
                    self.timer_on = false;
                }
                _ => {}
            }
            // Een bevestigde FIN betekent dat alle zenddata bevestigd is: geef
            // de ring vrij in plaats van hem door FIN-WAIT-2 of TIME-WAIT te dragen.
            if self.budgeted && self.tx.buffered() == 0 {
                pot.release(self.tx.size());
                self.tx = TxRing::default();
            }
        }
        true
    }

    /// Verwerkt payload en FIN in volgorde. Een gat valt weg met een directe
    /// duplicate ACK, zodat de peer snel herstelt zonder lokale reassemblage.
    fn process_data(&mut self, seg: &Seg, data: &[u8], now: u64, pot: &mut Budget) {
        let mut data = data;
        let mut seq = seg.seq;
        let mut has_fin = seg.flags.has(TcpFlags::FIN);
        let mut seg_end = seq.wrapping_add(seq_len(data.len()));

        // Knip een al ontvangen prefix af en houd een nieuwe hertransmitteerde
        // staart (RFC 9293 §3.10.7.4).
        let d = seq_diff(self.rcv_nxt, seq);
        if d > 0 && !data.is_empty() {
            data = data.get(ulen(d)..).unwrap_or(&[]); // Alles gezien; de FIN kan nog tellen.
            seq = self.rcv_nxt;
            seg_end = seq.wrapping_add(seq_len(data.len()));
        }

        // Knip op de geadverteerde rand. Een peer mag geen ringgroei afdwingen
        // door voorbij onze belofte te sturen; hij hertransmitteert de staart
        // binnen een later venster.
        if self.adv_set {
            let allowed = seq_diff(self.adv_edge, seq);
            // De FIN neemt één positie na de data en heeft resterend venster nodig.
            if has_fin && allowed <= ilen(data.len()) {
                has_fin = false;
                self.need_ack = true; // De peer herhaalt de FIN als ons venster opengaat.
            }
            if allowed < ilen(data.len()) {
                // `seg_acceptable` garandeert hier een positieve overlap voor data.
                data = data.get(..ulen(allowed)).unwrap_or(&[]);
                seg_end = seq.wrapping_add(seq_len(data.len()));
            }
        }

        if !data.is_empty() {
            if seq != self.rcv_nxt {
                self.need_ack = true; // Een duplicate ACK meldt het gat.
                return;
            }
            if self.app_closed {
                // Na een volledige close: beloofde data opschuiven en weggooien,
                // zodat ACK en FIN nog kunnen afronden.
                self.rcv_nxt = self.rcv_nxt.wrapping_add(seq_len(data.len()));
                self.need_ack = true;
                if has_fin {
                    seg_end = self.rcv_nxt;
                }
            } else if !self.accept_data(data, pot) {
                // De peer hertransmitteert de staart en een volgende FIN.
                return;
            }
        }
        if has_fin {
            if seg_end != self.rcv_nxt {
                self.need_ack = true; // Een FIN buiten volgorde neemt het duplicaatpad.
                return;
            }
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.fin_rcvd = true;
            self.need_ack = true;
            match self.state {
                TcpState::Established => {
                    self.state = TcpState::CloseWait;
                    self.close_deadline = now + TCP_CLOSE_WAIT_DUR;
                }
                // Onze FIN is nog onbevestigd: gelijktijdig sluiten.
                TcpState::FinWait1 => self.state = TcpState::Closing,
                TcpState::FinWait2 => {
                    self.state = TcpState::TimeWait;
                    self.tw_deadline = now + TCP_TIME_WAIT_DUR;
                }
                _ => {}
            }
        }
    }

    /// Schrijft data in volgorde in de ring en laat hem groeien. `true` als
    /// alles paste.
    fn accept_data(&mut self, data: &[u8], pot: &mut Budget) -> bool {
        self.cnt.segs_in += 1;
        self.cnt.bytes_in += data.len();
        let mut n = self.rx.write(data);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(seq_len(n));
        self.need_ack = true;
        // Ontvangstgroei, verankerd aan de eerste gewone rand. Twee signalen,
        // elk laat de ring groeien:
        //   - het beloofde venster is vol (free == 0): een trage lezer tegen
        //     een snelle zender;
        //   - er kwam een VOL segment (len == adv_mss): de zender is
        //     venster-beperkt terwijl de lezer bijhoudt. Een snelle lezer
        //     draint tussen twee pollrondes, dus de ring wordt nooit vol, en
        //     een alleen-vol-trigger hield elke bulkoverdracht voorgoed op de
        //     16 KiB-vloer: gemeten 18-08-2026 op de LicheeRV, beeldstromen op
        //     ~170 KB/s (één vloervenster per ~90 ms) terwijl de pot leeg
        //     stond. Chatverkeer stuurt nooit volle segmenten en blijft op de
        //     vloer.
        if self.adv_set
            && (self.rx.free() == 0 || data.len() >= usize::from(self.adv_mss))
            && self.grow_rx(pot)
            && n < data.len()
        {
            let m = self.rx.write(data.get(n..).unwrap_or(&[]));
            self.rcv_nxt = self.rcv_nxt.wrapping_add(seq_len(m));
            n += m;
        }
        n >= data.len()
    }

    // ---- zenden ----

    /// Maakt één segment met payload in `buf[..seg.len]`. Herhaal tot `None`:
    /// één verbinding kan een burst of data plus FIN klaar hebben.
    pub(crate) fn emit(&mut self, buf: &mut [u8], now: u64) -> Option<Seg> {
        if let Some(seg) = self.take_rst() {
            // Een wachtende abort- of ongeldige-ACK-reset gaat voor alles.
            return Some(seg);
        }
        // Een volledige close is een eigendomsgrens, geen levensteken. Geen
        // persist-ACK en geen latere sluitovergang mag deze deadline verzetten.
        if self.lifecycle_expired(now) {
            return self.abort_with_rst();
        }
        match self.state {
            TcpState::Closed => return None,
            TcpState::FinWait2 if now >= self.tw_deadline => {
                // De peer bevestigde onze FIN maar sloot nooit: expliciet afbreken.
                return self.abort_with_rst();
            }
            TcpState::TimeWait => {
                if now >= self.tw_deadline {
                    self.state = TcpState::Closed;
                    return None;
                }
                if self.need_ack {
                    self.need_ack = false;
                    return Some(self.bare_ack());
                }
                return None;
            }
            _ => {}
        }

        // Werk achter een nulvenster houdt een persist-timer gewapend, want de
        // venster-openende ACK van de peer kan verloren gaan.
        if !self.timer_on && self.snd_wnd == 0 && (self.tx.unsent() > 0 || self.fin_pending()) {
            self.arm_timer(now);
        }

        // RFC 6298-hertransmissie dekt alle volgnummerruimte onderweg, SYN en
        // FIN inbegrepen.
        if self.timer_on
            && now >= self.deadline
            && let Some(seg) = self.on_timer(now)
        {
            return Some(seg);
        }

        // `nxt` op `iss` betekent: SYN of SYN|ACK (ook opnieuw) moet eruit.
        let handshaking = matches!(self.state, TcpState::SynSent | TcpState::SynRcvd);
        if handshaking && self.nxt == self.iss {
            return Some(self.emit_syn(now));
        }
        if handshaking {
            return None; // SYN onderweg; wacht op antwoord of timer.
        }
        self.emit_data(buf, now)
    }

    /// De RTO of persist-timer liep af. Geeft een reset als de pogingen op zijn.
    fn on_timer(&mut self, now: u64) -> Option<Seg> {
        self.retries = self.retries.saturating_add(1);
        let limit = if matches!(self.state, TcpState::SynSent | TcpState::SynRcvd) {
            TCP_MAX_RETRIES_HANDSHAKE
        } else {
            TCP_MAX_RETRIES_DATA
        };
        if self.retries > limit {
            // De peer bleef stil over de hele backoff-ladder.
            return self.abort_with_rst();
        }
        if self.snd_wnd == 0
            && seq_diff(self.nxt, self.una) <= 1
            && (self.tx.buffered() > 0 || self.fin_pending())
        {
            // Persist-probes hebben een eigen backoff (RFC 9293 §3.8.6.1), zodat
            // een lange nulvensterepisode de gewone RTO niet opblaast.
            if self.persist_backoff < TCP_BACKOFF_MAX {
                self.persist_backoff += 1;
            }
            let wait = self
                .current_rto()
                .saturating_mul(1 << self.persist_backoff)
                .min(TCP_RTO_MAX);
            self.deadline = now + wait;
            if self.una != self.nxt {
                self.go_back_n(); // Stuur de vorige probe-byte opnieuw.
            }
            self.cnt.persist += 1;
            self.probe = true; // Eén byte voorbij het nulvenster mag.
        } else {
            if self.una != self.nxt && !matches!(self.state, TcpState::SynSent | TcpState::SynRcvd)
            {
                self.congestion_loss();
            }
            if self.backoff < TCP_BACKOFF_MAX {
                self.backoff += 1;
                self.rto = self.current_rto().saturating_mul(2).min(TCP_RTO_MAX);
            }
            self.deadline = now + self.current_rto();
            if self.una != self.nxt {
                self.cnt.retrans += 1;
                self.go_back_n();
            }
        }
        None
    }

    /// Stuurt de SYN of SYN|ACK (ook als hertransmissie).
    fn emit_syn(&mut self, now: u64) -> Seg {
        self.nxt = self.iss.wrapping_add(1);
        if seq_lt(self.max_sent, self.nxt) {
            self.max_sent = self.nxt; // De SYN neemt volgnummerruimte.
        }
        self.arm_timer(now);
        // SYN-vensters zijn ongeschaald; een SYN|ACK biedt WS alleen als de peer dat deed.
        let mut seg = Seg {
            seq: self.iss,
            flags: TcpFlags::SYN,
            wnd: self.raw_wnd(),
            mss: self.adv_mss,
            ws_ok: true,
            ws: self.adv_ws,
            ..Seg::default()
        };
        if self.state == TcpState::SynRcvd {
            seg.flags |= TcpFlags::ACK;
            seg.ack = self.rcv_nxt;
            seg.ws_ok = self.ws_on;
            // Leg de ongeschaalde SYN|ACK-belofte vast voordat een snelle peer data stuurt.
            self.promise_edge(u32::from(seg.wnd));
        } else {
            self.syn_wnd = seg.wnd; // Actief openen verankert dit na de SYN|ACK.
        }
        seg
    }

    /// Het datapad: data binnen het venster, dan een kale FIN, dan een kale ACK.
    fn emit_data(&mut self, buf: &mut [u8], now: u64) -> Option<Seg> {
        // Het datapad gebruikt de ruimte in het zendvenster; een gewapende probe
        // mag één byte voorbij nul.
        self.restart_congestion_after_idle(now);
        let in_flight = seq_diff(self.nxt, self.una);
        let mut avail = ulen(i64::from(self.snd_wnd) - in_flight);
        avail = avail.min(self.congestion_available());
        if self.probe && avail == 0 {
            avail = 1;
        }
        let n = self
            .tx
            .unsent()
            .min(avail)
            .min(self.peer_mss)
            .min(buf.len());
        if n > 0 {
            self.cnt.segs_out += 1;
            self.cnt.bytes_out += n;
            self.probe = false;
            let got = self.tx.next_send(buf.get_mut(..n).unwrap_or(&mut []));
            let mut seg = Seg {
                seq: self.nxt,
                ack: self.rcv_nxt,
                flags: TcpFlags::ACK | TcpFlags::PSH,
                wnd: self.advertised_wnd(),
                len: got,
                ..Seg::default()
            };
            self.nxt = self.nxt.wrapping_add(seq_len(got));
            self.post_tx(seg.seq.wrapping_add(seq_len(got)), now);
            self.last_data_sent = now;
            // Liften de FIN mee op de laatste data als het venster het toelaat.
            if self.fin_pending()
                && self.nxt == self.fin_seq
                && in_flight + ilen(got) < i64::from(self.snd_wnd)
            {
                seg.flags |= TcpFlags::FIN;
                self.send_fin_bookkeeping(now);
            }
            self.need_ack = false;
            return Some(seg);
        }

        // Een kale FIN neemt volgnummerruimte en gehoorzaamt het zendvenster. Een
        // gewapende probe mag die ene positie gebruiken en wordt door de FIN verbruikt.
        if self.fin_pending()
            && self.nxt == self.fin_seq
            && (in_flight < i64::from(self.snd_wnd) || self.probe)
        {
            self.probe = false;
            let seg = Seg {
                seq: self.nxt,
                ack: self.rcv_nxt,
                flags: TcpFlags::FIN | TcpFlags::ACK,
                wnd: self.advertised_wnd(),
                ..Seg::default()
            };
            self.send_fin_bookkeeping(now);
            self.need_ack = false;
            return Some(seg);
        }

        if self.need_ack {
            self.need_ack = false;
            return Some(self.bare_ack());
        }
        None
    }

    /// Breekt af en geeft de reset in dezelfde emit-reeks terug.
    fn abort_with_rst(&mut self) -> Option<Seg> {
        self.abort();
        self.take_rst()
    }

    /// De enige encoder en verbruiker van een wachtende reset.
    pub(crate) fn take_rst(&mut self) -> Option<Seg> {
        if !self.rst.set {
            return None;
        }
        let r = core::mem::take(&mut self.rst);
        let mut seg = Seg {
            seq: r.seq,
            flags: TcpFlags::RST,
            ..Seg::default()
        };
        if r.with_ack {
            seg.flags |= TcpFlags::ACK;
            seg.ack = r.ack;
        }
        Some(seg)
    }

    /// Of de FIN nog (of na een terugspoeling opnieuw) moet.
    fn fin_pending(&self) -> bool {
        self.closing
            && seq_leq(self.nxt, self.fin_seq)
            && matches!(
                self.state,
                TcpState::Established
                    | TcpState::CloseWait
                    | TcpState::FinWait1
                    | TcpState::Closing
                    | TcpState::LastAck
            )
    }

    /// Schuift `nxt` over de FIN en doet de toestandsovergang.
    fn send_fin_bookkeeping(&mut self, now: u64) {
        self.nxt = self.fin_seq.wrapping_add(1);
        if seq_lt(self.max_sent, self.nxt) {
            self.max_sent = self.nxt; // De FIN neemt ruimte voor latere ACK-validatie.
        }
        self.arm_timer(now);
        match self.state {
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            _ => {}
        }
    }

    /// Een kale ACK draagt SND.NXT (RFC 9293 §3.9), hier de nooit teruggespoelde
    /// `max_sent` en niet de tijdelijke hertransmissiecursor `nxt`.
    fn bare_ack(&mut self) -> Seg {
        Seg {
            seq: self.max_sent,
            ack: self.rcv_nxt,
            flags: TcpFlags::ACK,
            wnd: self.advertised_wnd(),
            ..Seg::default()
        }
    }

    /// Het ongeschaalde SYN-venster.
    fn raw_wnd(&self) -> u16 {
        u16::try_from(self.rx.free()).unwrap_or(u16::MAX)
    }

    /// Spoelt ringcursor en `nxt` terug naar `una`, zodat `emit` alle
    /// onbevestigde data, SYN en FIN opnieuw maakt.
    pub(crate) fn go_back_n(&mut self) {
        self.tx.rewind();
        // De ringkop is `data_base`; `una` kan ervoor liggen zolang de SYN onderweg is.
        if seq_diff(self.data_base, self.una) > 0 {
            self.nxt = self.iss; // Handshake opnieuw.
        } else {
            // Bevestigde bytes zijn al uit de ring, dus zijn kop is `una`.
            self.nxt = self.una;
        }
        self.timing = false; // Karn sluit hertransmissies uit van RTT-meting.
    }

    /// Legt nieuw verstuurde ruimte vast en start RTT-meting (RFC 6298 §5.1).
    fn post_tx(&mut self, seg_end: u32, now: u64) {
        // Karn: meet alleen voorbij `max_sent`. ACKs van hertransmitteerde
        // ruimte zijn dubbelzinnig en mogen de RTO niet laten instorten.
        if !self.timing && seq_lt(self.max_sent, seg_end) {
            self.timing = true;
            self.timed_seq = seg_end;
            self.timed_at = now;
        }
        if seq_lt(self.max_sent, seg_end) {
            self.max_sent = seg_end;
        }
        self.arm_timer(now);
    }

    /// Wapent de timer als hij nog niet loopt.
    fn arm_timer(&mut self, now: u64) {
        if !self.timer_on {
            self.timer_on = true;
            self.deadline = now + self.current_rto();
        }
    }

    /// De vroegste hertransmissie- of levensloopdeadline.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        let mut d: Option<u64> = None;
        let mut add = |t: u64| {
            if t != 0 && d.is_none_or(|cur| t < cur) {
                d = Some(t);
            }
        };
        if self.timer_on {
            add(self.deadline);
        }
        if matches!(self.state, TcpState::TimeWait | TcpState::FinWait2) {
            add(self.tw_deadline);
        }
        if (self.state == TcpState::CloseWait || self.app_closed) && self.state != TcpState::Closed
        {
            add(self.close_deadline);
        }
        d
    }

    /// De RTO binnen vloer en plafond.
    pub(crate) fn current_rto(&self) -> u64 {
        self.rto.clamp(TCP_RTO_MIN, TCP_RTO_MAX)
    }

    /// Vouwt een meting in SRTT, RTTVAR en RTO (RFC 6298 §2.2/§2.3).
    fn update_rtt(&mut self, sample: i64) {
        if sample <= 0 {
            return;
        }
        if !self.have_rtt {
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.have_rtt = true;
        } else {
            let diff = (self.srtt - sample).abs();
            self.rttvar += (diff - self.rttvar) / 4;
            self.srtt += (sample - self.srtt) / 8;
        }
        self.rto = u64::try_from(self.srtt + 4 * self.rttvar).unwrap_or(TCP_RTO_INITIAL);
    }

    // ---- congestiecontrole (alleen fysieke routes) ----
    //
    // Toepassing-naar-toepassing-bulk maakte de aanname ongeldig dat deze stack
    // alleen kleine uploads stuurt: een ontvangstvenster beschrijft de socket,
    // niet de wachtrij van een fysieke NIC. Een onbegrensde zender overspoelt
    // die rij en speelt steeds een heel venster opnieuw af (DESIGN.md).
    // Vertrouwde geheugenroutes houden hun pad met alleen het ontvangstvenster.
    // ACKs en de RTO drijven alles; er is geen pacing-taak of extra timer.

    /// RFC 6928-beginvenster met de onderhandelde MSS.
    fn init_congestion(&mut self) {
        if !self.congestion {
            return;
        }
        self.cwnd = self.initial_congestion_window();
        self.ssthresh = MAX_CONGESTION_WINDOW;
        self.cwnd_acked = 0;
    }

    /// Groei op nieuw bevestigde bytes.
    pub(crate) fn congestion_ack(&mut self, acked: usize) {
        if !self.congestion || acked == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            // RFC 5681 slow start: hoogstens één MSS per ACK, ook cumulatief.
            self.cwnd = MAX_CONGESTION_WINDOW.min(self.cwnd + acked.min(self.peer_mss));
            return;
        }
        // Congestion avoidance: één MSS per venster nieuw bevestigde bytes.
        self.cwnd_acked += acked;
        if self.cwnd_acked >= self.cwnd {
            self.cwnd_acked -= self.cwnd;
            self.cwnd = MAX_CONGESTION_WINDOW.min(self.cwnd + self.peer_mss);
        }
    }

    /// Verlies: drempel naar de helft van de vlucht, venster naar één MSS.
    pub(crate) fn congestion_loss(&mut self) {
        if !self.congestion {
            return;
        }
        // De vlucht mag niet krimpen alleen omdat de hertransmissiecursor terugspoelt.
        self.ssthresh = (ulen(seq_diff(self.max_sent, self.una)) / 2).max(2 * self.peer_mss);
        // Conservatief Tahoe-herstel; gedeeltelijke ACKs klokken de rest.
        self.cwnd = self.peer_mss;
        self.cwnd_acked = 0;
    }

    /// Hoeveel het congestievenster nu toelaat.
    pub(crate) fn congestion_available(&self) -> usize {
        if !self.congestion {
            return MAX_CONGESTION_WINDOW;
        }
        let cwnd = ilen(self.cwnd);
        if seq_lt(self.nxt, self.max_sent) {
            // Een verkleind venster staat herstel van al verstuurde bytes toe,
            // maar geen volledige go-back-N-burst. Elke ACK laat de volgende toe.
            let room = cwnd - seq_diff(self.nxt, self.una);
            return ulen(room.min(seq_diff(self.max_sent, self.nxt)));
        }
        ulen(cwnd - seq_diff(self.max_sent, self.una))
    }

    /// Het RFC 6928-beginvenster.
    pub(crate) fn initial_congestion_window(&self) -> usize {
        (10 * self.peer_mss).min((2 * self.peer_mss).max(14600))
    }

    /// Een stille verbinding herstart voorzichtig, zonder extra timer. Data
    /// onderweg houdt haar herstelvenster; alleen volledig bevestigde vluchten
    /// herstarten.
    pub(crate) fn restart_congestion_after_idle(&mut self, now: u64) {
        if self.congestion
            && self.tx.unsent() > 0
            && self.max_sent == self.una
            && self.last_data_sent != 0
            && now.saturating_sub(self.last_data_sent) >= self.current_rto()
        {
            self.cwnd = self.cwnd.min(self.initial_congestion_window());
            self.cwnd_acked = 0;
        }
    }
}

#[cfg(test)]
mod tests;
