//! De socket-API: handvatten voor TCP-verbindingen, listeners en UDP-sockets.
//!
//! De Go-versie leverde `net.Conn`, `net.Listener` en `net.PacketConn`, met
//! blokkerende calls die op een notificatie of deadline wachtten. Hier is elke
//! call synchroon en blokkeert nooit: "nog niet" is [`Error::WouldBlock`], en
//! wie wil wachten registreert een waker op het handvat en probeert opnieuw
//! als hij gewekt wordt. Een kleine wrapper elders maakt daar een `Future`
//! van. De semantiek volgt `net.Conn` verder precies:
//!
//! - een verstreken deadline weigert ook klare I/O ([`Error::DeadlineExceeded`]);
//! - een gesloten handvat gaat vóór een verstreken deadline ([`Error::Closed`]);
//! - een lege leesbuffer keert meteen terug met `Ok(0)`;
//! - EOF na de FIN van de peer is `Ok(0)` bij een niet-lege buffer, een reset
//!   is [`Error::Reset`] en nooit EOF;
//! - `close` deblokkeert wachters: hun volgende poging geeft [`Error::Closed`].
//!
//! Deze module bezit geen toestand; alles staat in [`Stack`].

use core::task::Waker;

use crate::multicast::{is_link_local_multicast, is_multicast_ip};
use crate::stack::{
    ConnKey, DIAL_TIMEOUT_DEFAULT, Dial, ListenHandle, Listener, MTU, TCP_BACKLOG, TCP_FLOOR_RX,
    TCP_FLOOR_TX, TcpHandle, UdpHandle,
};
use crate::tcp::TcpState;
use crate::wire::{SIZE_IPV4, SIZE_UDP};
use crate::{Error, Result, Stack};

/// UDP-rijbytes per socket: genoeg voor DNS, SNTP en QUIC-transport.
pub(crate) const UDP_QUEUE_CAP: usize = 32 << 10;

/// Het grootste UDP-datagram dat in één 1500-byte-frame past.
pub const UDP_MAX_PAYLOAD: usize = MTU - SIZE_IPV4 - SIZE_UDP;

/// Een lokaal of extern eindpunt: IPv4-adres en poort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// Het adres.
    pub ip: [u8; 4],
    /// De poort.
    pub port: u16,
}

impl Stack {
    /// De verbinding achter `h`, of [`Error::Closed`] als het handvat niet meer
    /// geldt of de applicatie het al sloot.
    fn sock(&mut self, h: TcpHandle) -> Result<&mut crate::stack::Conn> {
        self.conns
            .get_mut(h.idx)
            .and_then(Option::as_mut)
            .filter(|c| c.generation == h.generation && c.app_owned)
            .ok_or(Error::Closed)
    }

    /// De verbinding achter `h` zolang de stack er nog iets voor bewaart: ook
    /// na [`Stack::tcp_close`], tot TIME-WAIT verstreek of de verbinding
    /// anders uit de demux ging.
    ///
    /// Een losgelaten verbinding die de demux verlaat, geeft in `reap` meteen
    /// haar plek vrij; de generatie houdt een later hergebruik van die plek
    /// buiten dit handvat.
    fn tracked(&self, h: TcpHandle) -> Result<&crate::stack::Conn> {
        self.conn(h.idx)
            .filter(|c| c.generation == h.generation && (c.app_owned || c.live))
            .ok_or(Error::Closed)
    }

    /// Hetzelfde als [`Stack::tracked`], veranderbaar.
    fn tracked_mut(&mut self, h: TcpHandle) -> Result<&mut crate::stack::Conn> {
        self.conn_mut(h.idx)
            .filter(|c| c.generation == h.generation && (c.app_owned || c.live))
            .ok_or(Error::Closed)
    }

    // ---- TCP-listener ----

    /// Opent een TCP-listener; poort nul kiest een efemere poort. Alleen
    /// verbindingen kosten budget, een listener niet.
    pub fn tcp_listen(&mut self, port: u16) -> Result<ListenHandle> {
        if self.closed {
            return Err(Error::StackClosed);
        }
        let port = if port == 0 {
            self.ephemeral_port(Stack::tcp_port_in_use)?
        } else if self.tcp_port_in_use(port) {
            return Err(Error::TcpPortInUse { port });
        } else {
            port
        };
        let l = Listener {
            generation: self.new_generation(),
            port,
            backlog: [None; TCP_BACKLOG],
            len: 0,
            waker: Default::default(),
        };
        let generation = l.generation;
        if let Some(idx) = self.listeners.iter().position(Option::is_none) {
            if let Some(slot) = self.listeners.get_mut(idx) {
                *slot = Some(l);
            }
            return Ok(ListenHandle { idx, generation });
        }
        crate::try_push(&mut self.listeners, Some(l))?;
        Ok(ListenHandle {
            idx: self.listeners.len() - 1,
            generation,
        })
    }

    /// De poort van een listener.
    pub fn listen_port(&mut self, h: ListenHandle) -> Result<u16> {
        self.listener_mut(h).map(|l| l.port).ok_or(Error::Closed)
    }

    /// Neemt een voltooide handshake aan. [`Error::WouldBlock`] als de backlog
    /// leeg is; registreer dan [`Stack::listen_register_waker`].
    ///
    /// Een peer kan resetten, of een CLOSE-WAIT-timer kan de verbinding
    /// opruimen terwijl ze in de rij staat; zo'n verouderde entry komt nooit
    /// bij de applicatie.
    pub fn tcp_accept(&mut self, h: ListenHandle, now: u64) -> Result<TcpHandle> {
        loop {
            let c = self.listener_mut(h).ok_or(Error::Closed)?.pop();
            let Some(c) = c else {
                return Err(Error::WouldBlock);
            };
            if !self.is_live(c) {
                continue;
            }
            if let Some(conn) = self.conn_mut(c.idx) {
                conn.handoff_deadline = 0;
                conn.listener = None;
                conn.app_owned = true;
                conn.tcp.touch_close_wait(now);
            }
            // Herbereken de protocoltimer nu de overdrachtsgrens weg is.
            self.notify();
            return Ok(c);
        }
    }

    /// Registreert wie op `tcp_accept` wacht.
    pub fn listen_register_waker(&mut self, h: ListenHandle, w: &Waker) -> Result {
        self.listener_mut(h).ok_or(Error::Closed)?.waker.register(w);
        Ok(())
    }

    /// Sluit een listener. De backlog wordt afgebroken en lopende embryo's
    /// worden meteen opgeruimd in plaats van hun budget door de
    /// handshake-backoff tegen een gesloten listener te dragen. Idempotent
    /// voor een al gesloten handvat.
    pub fn tcp_listen_close(&mut self, h: ListenHandle) {
        if self.listener_mut(h).is_none() {
            return;
        }
        let Some(mut l) = self.listeners.get_mut(h.idx).and_then(Option::take) else {
            return;
        };
        l.waker.wake();
        while let Some(c) = l.pop() {
            if self.is_live(c) {
                self.abort_and_reap(c.idx);
            }
        }
        for i in 0..self.conns.len() {
            let embryo = self
                .conn(i)
                .is_some_and(|c| c.live && c.listener == Some(h) && c.handoff_deadline == 0);
            if embryo {
                self.abort_and_reap(i);
            }
        }
        self.notify();
    }

    // ---- TCP-verbinding ----

    /// Opent actief een verbinding en geeft meteen een handvat; de SYN gaat
    /// bij de volgende pomp. Vraag [`Stack::tcp_poll_connect`] tot hij `Ok`
    /// of een fout geeft. `deadline` (monotone nanoseconden) begrenst de
    /// dial; zonder is dat 30 seconden, tegen stille hosts.
    pub fn tcp_connect(
        &mut self,
        ip: [u8; 4],
        port: u16,
        deadline: Option<u64>,
        now: u64,
    ) -> Result<TcpHandle> {
        // TCP naar multicast is betekenisloos: ingress laat multicast-TCP per
        // contract vallen, dus een SYN zou alleen draad en ~20 KiB verbrand
        // tot de handshake opgeeft. Weiger voordat er iets bestaat.
        if is_multicast_ip(ip) {
            return Err(Error::MulticastTcp { ip });
        }
        if port == 0 {
            return Err(Error::InvalidPort);
        }
        if self.closed {
            return Err(Error::StackClosed);
        }
        // Faal meteen als een off-subnet-bestemming geen gateway heeft; geen
        // ARP-query zou ooit voortgang maken.
        let (hop, via_arp) = self.next_hop(ip);
        if via_arp && hop == [0; 4] {
            return Err(Error::NoRoute { ip });
        }
        let lport = self.ephemeral_port(Stack::tcp_port_in_use)?;
        let key = ConnKey {
            lport,
            rip: ip,
            rport: port,
        };
        let i = self.new_conn(key)?;
        let iss = self.next_iss();
        let adv_mss = self.adv_mss(ip);
        let adv_ws = self.cfg.adv_ws;
        let c = self.conn_mut(i).ok_or(Error::Closed)?;
        c.tcp.open_active(iss, adv_mss, adv_ws);
        c.app_owned = true;
        c.dial = Some(Dial {
            deadline: deadline.unwrap_or(now + DIAL_TIMEOUT_DEFAULT),
            hop,
            via_arp,
        });
        let h = TcpHandle {
            idx: i,
            generation: c.generation,
        };
        self.notify(); // Pomp de SYN, eerst ARP als dat nodig is.
        Ok(h)
    }

    /// De uitkomst van een dial: `Ok` als de verbinding staat,
    /// [`Error::WouldBlock`] zolang de handshake loopt, anders de fout. Bij een
    /// fout is de verbinding opgeruimd en het handvat ongeldig.
    ///
    /// Registreer tijdens het wachten [`Stack::tcp_register_write_waker`].
    pub fn tcp_poll_connect(&mut self, h: TcpHandle, now: u64) -> Result {
        let closed = self.closed;
        let c = self.sock(h)?;
        let Some(dial) = c.dial else {
            return Ok(()); // Al gevestigd, of geaccepteerd.
        };
        let key = c.key;
        let state = c.tcp.state;
        let refused = c.tcp.refused;
        let reset = c.tcp.reset;
        let outcome = if now >= dial.deadline {
            Err(Error::DeadlineExceeded)
        } else if closed {
            Err(Error::StackClosed)
        } else if matches!(state, TcpState::Established | TcpState::CloseWait) {
            // Een peer kan data en FIN sturen voordat deze wachter wakker wordt,
            // en zo door ESTABLISHED naar een nog bruikbare CLOSE-WAIT gaan.
            c.tcp.touch_close_wait(now);
            c.dial = None;
            return Ok(());
        } else if dial.via_arp && self.arp.no_answer(dial.hop, now) {
            // Alleen ARP-routes kunnen hier falen. Vóór de Closed-toets, want
            // de pomp kan de verbinding om dezelfde reden al hebben afgebroken:
            // meld dan geen route in plaats van een timeout.
            Err(Error::Unreachable { hop: dial.hop })
        } else if state == TcpState::Closed {
            if reset {
                // Gevestigd en daarna gereset voordat de dialer keek (een
                // overvolle backlog aan de overkant): een reset, geen timeout.
                Err(Error::Reset)
            } else if refused {
                Err(Error::Refused {
                    ip: key.rip,
                    port: key.rport,
                })
            } else {
                // Geen RST en geen antwoord: de handshakepogingen zijn op.
                Err(Error::ConnectTimeout {
                    ip: key.rip,
                    port: key.rport,
                })
            }
        } else {
            return Err(Error::WouldBlock);
        };
        // Eén idempotent opruimpad voor toestandsfouten, deadlines en annulering.
        self.abort_and_reap(h.idx);
        self.release_handle(h);
        outcome
    }

    /// Laat de applicatie-eigendom van `h` los en geeft de plek vrij als de
    /// verbinding al uit de demux is.
    fn release_handle(&mut self, h: TcpHandle) {
        let Some(slot) = self.conns.get_mut(h.idx) else {
            return;
        };
        if let Some(c) = slot.as_mut().filter(|c| c.generation == h.generation) {
            c.app_owned = false;
            c.dial = None;
            c.wake();
            if !c.live {
                *slot = None;
            }
        }
    }

    /// Leest ontvangen bytes zonder te blokkeren.
    ///
    /// `Ok(0)` bij een lege `buf`, of bij EOF na de FIN van de peer.
    /// [`Error::WouldBlock`] als er nog niets is; registreer dan
    /// [`Stack::tcp_register_read_waker`].
    pub fn tcp_read(&mut self, h: TcpHandle, buf: &mut [u8], now: u64) -> Result<usize> {
        let c = self.sock(h)?;
        if buf.is_empty() {
            // `net.Conn` eist dat een lege read meteen terugkeert.
            return Ok(0);
        }
        if c.rd_deadline.is_some_and(|d| now >= d) {
            // Een verstreken deadline weigert ook klare I/O; anders zou een late
            // read nog wachtende data verbruiken.
            return Err(Error::DeadlineExceeded);
        }
        match c.tcp.read(buf) {
            Ok(0) => Err(Error::WouldBlock),
            Ok(n) => {
                c.tcp.touch_close_wait(now);
                self.notify(); // Lezen kan het ontvangstvenster hebben geopend.
                Ok(n)
            }
            Err(Error::TcpClosed) => Ok(0), // FIN is EOF; een reset blijft een fout.
            Err(e) => Err(e),
        }
    }

    /// Of een read nu zonder [`Error::WouldBlock`] zou terugkeren: er staan
    /// ontvangen bytes klaar, of de peer sloot (FIN of reset), zodat de read
    /// EOF of de fout meldt. Verbruikt niets.
    ///
    /// De niet-consumerende vraag voor een eigenaar die op meerdere
    /// verbindingen tegelijk wacht: hij registreert
    /// [`Stack::tcp_register_read_waker`] en leest pas als dit `true` zegt,
    /// in plaats van elke verbinding rond te pollen met een lege read.
    pub fn tcp_readable(&mut self, h: TcpHandle) -> Result<bool> {
        let c = self.sock(h)?;
        Ok(c.tcp.rx.buffered() > 0
            || c.tcp.reset
            || c.tcp.fin_rcvd
            || c.tcp.state == TcpState::Closed)
    }

    /// Buffert bytes om te versturen zonder te blokkeren en geeft het aantal.
    ///
    /// [`Error::WouldBlock`] als de zendring vol is en niet kan groeien;
    /// registreer dan [`Stack::tcp_register_write_waker`] en wacht op ACK-ruimte.
    pub fn tcp_write(&mut self, h: TcpHandle, data: &[u8], now: u64) -> Result<usize> {
        let pot = &mut self.pot;
        let c = self
            .conns
            .get_mut(h.idx)
            .and_then(Option::as_mut)
            .filter(|c| c.generation == h.generation && c.app_owned)
            .ok_or(Error::Closed)?;
        if c.wr_deadline.is_some_and(|d| now >= d) {
            return Err(Error::DeadlineExceeded);
        }
        let n = c.tcp.write(data, pot)?;
        if n > 0 {
            c.tcp.touch_close_wait(now);
            self.notify(); // Laat de pomp versturen.
            return Ok(n);
        }
        if data.is_empty() {
            return Ok(0);
        }
        Err(Error::WouldBlock)
    }

    /// Sluit de socket volledig: FIN na de gebufferde data, ongelezen
    /// ontvangstbudget meteen terug, en één absolute opruimgrens van 20
    /// seconden die ACKs en nulvensterupdates niet verlengen. Zendbudget komt
    /// terug als de FIN bevestigd is of de verbinding wordt opgeruimd.
    ///
    /// Dit is geen abort: gebufferde data gaat nog uit en wordt hertransmitteerd,
    /// de FIN volgt erachter. Op de draad is het een half-close; wat de peer
    /// daarna nog stuurt wordt bevestigd en weggegooid, zodat zijn FIN kan
    /// afronden. Pas als de 20 seconden verstrijken zonder net einde volgt een
    /// RST.
    ///
    /// Na `close` is het handvat ongeldig voor I/O; wachters worden gewekt.
    /// [`Stack::tcp_unacked`] en [`Stack::tcp_register_write_waker`] blijven
    /// werken tot de stack de verbinding loslaat, zodat een flush kan zien
    /// wanneer de peer alles heeft.
    pub fn tcp_close(&mut self, h: TcpHandle, now: u64) -> Result {
        let pot = &mut self.pot;
        let c = self
            .conns
            .get_mut(h.idx)
            .and_then(Option::as_mut)
            .filter(|c| c.generation == h.generation && c.app_owned)
            .ok_or(Error::Closed)?;
        let _ = c.tcp.close(); // Een tweede close op machineniveau is geen fout.
        c.tcp.abandon_read(now, pot);
        self.release_handle(h);
        self.notify(); // Stuur de FIN.
        Ok(())
    }

    /// Of de ringen van deze verbinding boven hun vloer groeiden.
    ///
    /// Dat is de verbinding die zichzelf indeelt: alleen bulkoverdrachten
    /// groeien (een vol segment is het groeisignaal), praatzieke lange stromen
    /// blijven op de vloer. Een gegroeide ontvangstring draagt een
    /// vensterbelofte die budget vastpint zolang de verbinding open staat (de
    /// belofte mag niet naar links, RFC 9293). "Snel heeft altijd een eind":
    /// een pool hoort een gegroeide verbinding te sluiten in plaats van haar
    /// stil open te houden. leanhttp doet dat aan beide kanten.
    pub fn tcp_grown(&mut self, h: TcpHandle) -> Result<bool> {
        let c = self.sock(h)?;
        Ok(c.tcp.rx.size() > TCP_FLOOR_RX || c.tcp.tx.size() > TCP_FLOOR_TX)
    }

    /// De toestand van de verbinding.
    pub fn tcp_state(&mut self, h: TcpHandle) -> Result<TcpState> {
        Ok(self.sock(h)?.tcp.state)
    }

    /// Het lokale eindpunt.
    pub fn tcp_local(&mut self, h: TcpHandle) -> Result<Endpoint> {
        let ip = self.cfg.ip;
        let c = self.sock(h)?;
        Ok(Endpoint {
            ip,
            port: c.key.lport,
        })
    }

    /// Het externe eindpunt.
    pub fn tcp_remote(&mut self, h: TcpHandle) -> Result<Endpoint> {
        let c = self.sock(h)?;
        Ok(Endpoint {
            ip: c.key.rip,
            port: c.key.rport,
        })
    }

    /// Zet de leesdeadline (monotone nanoseconden); `None` wist hem. Een
    /// wachtende lezer wordt gewekt om de nieuwe deadline te zien.
    pub fn tcp_set_read_deadline(&mut self, h: TcpHandle, deadline: Option<u64>) -> Result {
        let c = self.sock(h)?;
        c.rd_deadline = deadline;
        c.read_waker.wake();
        Ok(())
    }

    /// Zet de schrijfdeadline; `None` wist hem.
    pub fn tcp_set_write_deadline(&mut self, h: TcpHandle, deadline: Option<u64>) -> Result {
        let c = self.sock(h)?;
        c.wr_deadline = deadline;
        c.write_waker.wake();
        Ok(())
    }

    /// Zet beide deadlines.
    pub fn tcp_set_deadline(&mut self, h: TcpHandle, deadline: Option<u64>) -> Result {
        self.tcp_set_read_deadline(h, deadline)?;
        self.tcp_set_write_deadline(h, deadline)
    }

    /// Registreert wie op leesbare data (of EOF, reset, close, deadline) wacht.
    pub fn tcp_register_read_waker(&mut self, h: TcpHandle, w: &Waker) -> Result {
        self.sock(h)?.read_waker.register(w);
        Ok(())
    }

    /// Registreert wie op schrijfruimte, de uitkomst van een dial of een
    /// bevestiging wacht.
    ///
    /// De waker gaat af bij elk segment dat de verbinding binnenkrijgt (dus
    /// bij elke ACK, ook een die niets vrijgeeft), bij een deadline, en als de
    /// stack de verbinding opruimt. Daarmee is hij ook de waker voor een flush
    /// op [`Stack::tcp_unacked`]: registreren, opnieuw kijken, wachten. Een
    /// wek is een reden om te kijken, geen belofte van voortgang.
    ///
    /// Anders dan de andere calls werkt hij ook na [`Stack::tcp_close`], tot de
    /// verbinding weg is; daarna [`Error::Closed`].
    pub fn tcp_register_write_waker(&mut self, h: TcpHandle, w: &Waker) -> Result {
        self.tracked_mut(h)?.write_waker.register(w);
        Ok(())
    }

    /// Het aantal volgnummers dat de peer nog niet bevestigde: bytes in de
    /// zendring (onverzonden plus onderweg), plus één zolang een FIN van
    /// [`Stack::tcp_close`] onbevestigd is. `Ok(0)` betekent dat de peer
    /// alles heeft, einde inbegrepen.
    ///
    /// Het handvat blijft na [`Stack::tcp_close`] bevraagbaar zolang de stack
    /// de verbinding bewaart: in FIN-WAIT, CLOSING, LAST-ACK en TIME-WAIT (daar
    /// altijd `Ok(0)`, want TIME-WAIT volgt pas op de ACK van onze FIN).
    /// Daarna geeft het [`Error::Closed`], ook als een latere verbinding de
    /// plek hergebruikt.
    ///
    /// Let op: [`Error::Closed`] na een close zegt "hier valt niets meer te
    /// wachten", niet "alles kwam aan". LAST-ACK gaat bij de ACK op de FIN
    /// meteen naar gesloten en wordt direct opgeruimd, dus die flush ziet
    /// `Closed` in plaats van `0`; een verbinding die de 20-secondengrens of
    /// de hertransmissieladder niet overleefde evengoed. Wie het verschil
    /// moet weten, wacht vóór de close op `0` en sluit daarna.
    ///
    /// [`Error::Reset`] als de verbinding gereset is terwijl de applicatie het
    /// handvat nog houdt: die bytes komen nooit meer aan.
    ///
    /// Wie wil wachten registreert [`Stack::tcp_register_write_waker`]: die
    /// gaat bij elke ACK af.
    pub fn tcp_unacked(&self, h: TcpHandle) -> Result<usize> {
        let c = self.tracked(h)?;
        if c.tcp.reset {
            return Err(Error::Reset);
        }
        Ok(c.tcp.unacked())
    }

    // ---- UDP ----

    /// De poort achter `h`.
    fn udp_port(&mut self, h: UdpHandle) -> Result<&mut crate::udp::UdpPort> {
        self.udp
            .get_mut(h.idx)
            .filter(|u| u.generation == h.generation)
            .ok_or(Error::Closed)
    }

    /// Bindt een UDP-poort; nul kiest een efemere.
    pub fn udp_bind(&mut self, port: u16) -> Result<UdpHandle> {
        if self.closed {
            return Err(Error::StackClosed);
        }
        let port = if port == 0 {
            self.ephemeral_port(|s, p| s.udp.bound(p))?
        } else {
            port
        };
        let generation = self.new_generation();
        let idx = self
            .udp
            .bind(port, UDP_QUEUE_CAP, &mut self.pot, generation)?;
        Ok(UdpHandle { idx, generation })
    }

    /// Bindt een efemere poort aan één peer voor `udp_send` en `udp_recv`.
    /// Datagrammen van anderen komen de rij niet in.
    pub fn udp_connect(&mut self, ip: [u8; 4], port: u16) -> Result<UdpHandle> {
        if port == 0 {
            return Err(Error::InvalidPort);
        }
        let h = self.udp_bind(0)?;
        self.udp_port(h)?.peer = Some((ip, port));
        Ok(h)
    }

    /// De lokale poort.
    pub fn udp_local(&mut self, h: UdpHandle) -> Result<Endpoint> {
        let ip = self.cfg.ip;
        let port = self.udp_port(h)?.port;
        Ok(Endpoint { ip, port })
    }

    /// De peer van een verbonden socket, of `None`.
    pub fn udp_remote(&mut self, h: UdpHandle) -> Result<Option<Endpoint>> {
        Ok(self
            .udp_port(h)?
            .peer
            .map(|(ip, port)| Endpoint { ip, port }))
    }

    /// Haalt het oudste datagram op: lengte en afzender. Is `buf` te klein,
    /// dan valt de rest weg (UDP-semantiek).
    pub fn udp_recv_from(
        &mut self,
        h: UdpHandle,
        buf: &mut [u8],
        now: u64,
    ) -> Result<(usize, Endpoint)> {
        let u = self.udp_port(h)?;
        if u.rd_deadline.is_some_and(|d| now >= d) {
            return Err(Error::DeadlineExceeded);
        }
        let (n, ip, port) = u.recv_from(buf).ok_or(Error::WouldBlock)?;
        Ok((n, Endpoint { ip, port }))
    }

    /// Leest van een verbonden socket.
    pub fn udp_recv(&mut self, h: UdpHandle, buf: &mut [u8], now: u64) -> Result<usize> {
        self.udp_recv_from(h, buf, now).map(|(n, _)| n)
    }

    /// Of er een datagram klaarligt.
    pub fn udp_readable(&mut self, h: UdpHandle) -> Result<bool> {
        Ok(self.udp_port(h)?.has_data())
    }

    /// Verstuurt één datagram naar `to`. Een onopgeloste ARP-route geeft
    /// [`Error::WouldBlock`] (de query loopt dan); een route die opgaf geeft
    /// [`Error::Unreachable`], en geen gateway meteen [`Error::NoRoute`].
    pub fn udp_send_to(
        &mut self,
        h: UdpHandle,
        to: Endpoint,
        data: &[u8],
        now: u64,
    ) -> Result<usize> {
        let u = self.udp_port(h)?;
        if u.peer.is_some() {
            // Een verbonden UDP-socket schrijft alleen naar zijn peer.
            return Err(Error::WriteToConnected);
        }
        self.udp_send_inner(h, to, data, now)
    }

    /// Verstuurt één datagram naar de peer van een verbonden socket.
    pub fn udp_send(&mut self, h: UdpHandle, data: &[u8], now: u64) -> Result<usize> {
        let (ip, port) = self.udp_port(h)?.peer.ok_or(Error::NotConnected)?;
        self.udp_send_inner(h, Endpoint { ip, port }, data, now)
    }

    /// Het gedeelde zendpad.
    fn udp_send_inner(
        &mut self,
        h: UdpHandle,
        to: Endpoint,
        data: &[u8],
        now: u64,
    ) -> Result<usize> {
        let u = self.udp_port(h)?;
        let sport = u.port;
        if u.wr_deadline.is_some_and(|d| now >= d) {
            return Err(Error::DeadlineExceeded);
        }
        if to.port == 0 {
            return Err(Error::InvalidPort);
        }
        // Alleen het link-local blok is verstuurbaar multicast: bredere groepen
        // kan een multicastrouter voorbij het LAN dragen (RFC 2365). Een
        // expliciete weigering is beter dan een ARP-timeout.
        if is_multicast_ip(to.ip) && !is_link_local_multicast(to.ip) {
            return Err(Error::NotLinkLocalMulticast { ip: to.ip });
        }
        if data.len() > UDP_MAX_PAYLOAD {
            return Err(Error::DatagramTooLarge {
                len: data.len(),
                max: UDP_MAX_PAYLOAD,
            });
        }
        if let Some(mac) = self.route(to.ip, now, true) {
            if mac != self.cfg.mac && !self.udp_out_has_room() {
                return Err(Error::WouldBlock);
            }
            // UDP kan een geweigerde transmissie niet hertransmitteren; de fout
            // gaat terug naar de schrijver.
            self.send_udp_frame(mac, sport, to.ip, to.port, data)?;
            return Ok(data.len());
        }
        let (hop, via_arp) = self.next_hop(to.ip);
        if via_arp && hop == [0; 4] {
            // Geen gateway is een direct antwoord, geen reden om te wachten.
            return Err(Error::NoRoute { ip: to.ip });
        }
        if via_arp && self.arp.no_answer(hop, now) {
            return Err(Error::Unreachable { hop });
        }
        self.notify(); // Pomp de ARP-query.
        Err(Error::WouldBlock)
    }

    /// Sluit de socket en geeft zijn hele rijreservering terug. Wachters worden
    /// gewekt; hun volgende poging geeft [`Error::Closed`].
    pub fn udp_close(&mut self, h: UdpHandle) {
        if self.udp_port(h).is_err() {
            return;
        }
        if let Some(mut u) = self.udp.close(h.idx, &mut self.pot) {
            u.read_waker.wake();
            u.write_waker.wake();
        }
        self.notify();
    }

    /// Zet de leesdeadline; `None` wist hem.
    pub fn udp_set_read_deadline(&mut self, h: UdpHandle, deadline: Option<u64>) -> Result {
        let u = self.udp_port(h)?;
        u.rd_deadline = deadline;
        u.read_waker.wake();
        Ok(())
    }

    /// Zet de schrijfdeadline; `None` wist hem.
    pub fn udp_set_write_deadline(&mut self, h: UdpHandle, deadline: Option<u64>) -> Result {
        let u = self.udp_port(h)?;
        u.wr_deadline = deadline;
        u.write_waker.wake();
        Ok(())
    }

    /// Zet beide deadlines.
    pub fn udp_set_deadline(&mut self, h: UdpHandle, deadline: Option<u64>) -> Result {
        self.udp_set_read_deadline(h, deadline)?;
        self.udp_set_write_deadline(h, deadline)
    }

    /// Registreert wie op een datagram wacht.
    pub fn udp_register_read_waker(&mut self, h: UdpHandle, w: &Waker) -> Result {
        self.udp_port(h)?.read_waker.register(w);
        Ok(())
    }

    /// Registreert wie op een route of zendruimte wacht.
    pub fn udp_register_write_waker(&mut self, h: UdpHandle, w: &Waker) -> Result {
        self.udp_port(h)?.write_waker.register(w);
        Ok(())
    }
}
