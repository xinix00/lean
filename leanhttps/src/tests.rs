//! De tests uit leanhttps_test.go die zonder TLS-server kunnen.
//!
//! Een kale verbinding in het geheugen legt vast wat leantls schrijft. De
//! ClientHello draagt SNI in klare tekst, dus "SNI volgt de dial-host" is te
//! zien zonder dat er een server antwoordt; de handshake eindigt daarna op het
//! einde van de stroom.

use super::*;
use leanhttp::Dial;
use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::task::Waker;

/// Een kale verbinding die alles bewaart en dan eindigt.
struct Raw {
    written: Rc<RefCell<Vec<u8>>>,
    timeouts: Rc<RefCell<Vec<Option<Duration>>>>,
    closed: Rc<RefCell<u32>>,
}

impl leanhttp::AsyncRead for Raw {
    fn poll_read(
        &mut self,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        Poll::Ready(Ok(0))
    }

    fn set_read_timeout(&mut self, t: Option<Duration>) -> core::result::Result<(), IoError> {
        self.timeouts.borrow_mut().push(t);
        Ok(())
    }
}

impl leanhttp::AsyncWrite for Raw {
    fn poll_write(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        self.written.borrow_mut().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
}

impl Close for Raw {
    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        *self.closed.borrow_mut() += 1;
        Poll::Ready(Ok(()))
    }
}

/// De kale dialer: telt en bewaart per dial wat er geschreven werd.
#[derive(Default)]
struct Tcp {
    dials: Vec<(String, u16)>,
    written: Vec<Rc<RefCell<Vec<u8>>>>,
    timeouts: Vec<Rc<RefCell<Vec<Option<Duration>>>>>,
}

impl Dial for Tcp {
    type Conn = Raw;

    async fn dial(&mut self, target: Target<'_>) -> leanhttp::Result<Raw> {
        self.dials.push((target.host.to_owned(), target.port));
        let written = Rc::new(RefCell::new(Vec::new()));
        self.written.push(written.clone());
        let timeouts = Rc::new(RefCell::new(Vec::new()));
        self.timeouts.push(timeouts.clone());
        Ok(Raw {
            written,
            timeouts,
            closed: Rc::default(),
        })
    }
}

/// Een ketenverificatie die alles goedkeurt; hier telt alleen dat hij bestaat.
struct AnyChain;

impl leantls::VerifyPeer for AnyChain {
    fn signature_algorithms(&self) -> &[u16] {
        &[]
    }
    fn verify_chain(&self, _: leantls::CertChain<'_>, _: &str) -> leantls::Result {
        Ok(())
    }
    fn verify_signature(&self, _: &[u8], _: u16, _: &[u8], _: &[u8]) -> leantls::Result {
        Ok(())
    }
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("future hangs");
}

fn target(host: &str) -> Target<'_> {
    Target {
        https: true,
        host,
        port: 443,
    }
}

fn pinned() -> Trust<'static> {
    Trust::Pinned(leantls::PeerKey::new([7; 32]))
}

fn entropy() -> Entropy {
    Entropy::new([1; Entropy::LEN])
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// In Go weigerde een lege Client omdat er geen vertrouwensmodel was. Hier heeft
// `Trust` geen standaardwaarde: de weigering is een compile_fail-doctest in de
// crate-doc. Wat hier te toetsen blijft: de dialer zegt dat hij versleutelt,
// want alleen dan staat leanhttp `https://` toe.
#[test]
fn zonder_vertrouwensmodel() {
    let d = TlsDial::new(Tcp::default(), pinned(), entropy);
    assert!(d.is_encrypted());
}

// ServerName is in Go een veld dat leeg moest blijven. Hier bestaat het niet:
// SNI komt per dial uit de host, dus twee hops naar twee hosts dragen elk hun
// eigen naam, en een punt aan het eind valt weg.
#[test]
fn server_name_weigert() {
    let mut d = TlsDial::new(Tcp::default(), pinned(), entropy);
    assert!(block_on(d.dial(target("eerste.example"))).is_err());
    assert!(block_on(d.dial(target("tweede.example."))).is_err());
    let hello1 = d.inner.written[0].borrow().clone();
    let hello2 = d.inner.written[1].borrow().clone();
    assert!(
        contains(&hello1, b"eerste.example"),
        "SNI van de eerste hop ontbreekt"
    );
    assert!(
        contains(&hello2, b"tweede.example"),
        "SNI van de tweede hop ontbreekt"
    );
    assert!(
        !contains(&hello2, b"tweede.example."),
        "de slotpunt ging mee in SNI"
    );
    assert!(
        !contains(&hello2, b"eerste.example"),
        "de eerste naam bleef hangen"
    );
    // De handshake eindigde op het einde van de stroom; de reden staat klaar.
    assert!(matches!(d.last_error(), Some(Error::Tls(_))));
}

#[test]
fn ip_zonder_pin() {
    let chain = AnyChain;
    let mut d = TlsDial::new(Tcp::default(), Trust::Chain(&chain), entropy);
    for ip in ["10.0.0.5", "::1", "fe80::1"] {
        assert_eq!(
            block_on(d.dial(target(ip))).err(),
            Some(leanhttp::Error::NoHost)
        );
        assert_eq!(d.last_error(), Some(Error::ChainWithoutName));
        assert!(d.last_error().unwrap().to_string().contains("IP address"));
    }
    assert!(
        d.inner.dials.is_empty(),
        "een keten tegen een IP werd toch gedialed"
    );

    // Een pin levert de identiteit zelf; een IP is dan geen reden tot weigeren.
    let mut p = TlsDial::new(Tcp::default(), pinned(), entropy);
    let _ = block_on(p.dial(target("127.0.0.1")));
    assert_eq!(p.inner.dials.len(), 1);
    assert_ne!(p.last_error(), Some(Error::ChainWithoutName));
}

// Het vertrouwensmodel wordt geleend en is `Copy`: de dialer kan hem niet
// veranderen. Twee dials met hetzelfde model geven elk hun eigen SNI (zie
// hierboven), en het model is daarna gelijk aan het begin.
#[test]
fn config_niet_gemuteerd() {
    let key = [9; 32];
    let trust = Trust::Pinned(leantls::PeerKey::new(key));
    let mut d = TlsDial::new(Tcp::default(), trust, entropy);
    let _ = block_on(d.dial(target("eerste.example")));
    let Trust::Pinned(after) = d.trust else {
        panic!("het model veranderde van soort");
    };
    assert_eq!(after, leantls::PeerKey::new(key));
}

// In Go toetste deze test de importgraaf van leanhttp. Hier is dat de
// afhankelijkhedenlijst: leanhttp noemt leantls niet.
#[test]
fn leanhttp_blijft_tls_vrij() {
    let manifest = include_str!("../../leanhttp/Cargo.toml");
    assert!(
        !manifest.contains("leantls"),
        "leanhttp hangt af van leantls"
    );
}

// En deze crate hangt van precies twee crates af: de compositie.
#[test]
fn geen_ecdsa_in_pin() {
    let manifest = include_str!("../Cargo.toml");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split('[')
        .next()
        .unwrap();
    let names: Vec<&str> = deps
        .lines()
        .filter_map(|l| l.split('=').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    assert_eq!(names, ["leanhttp", "leantls"]);
}

// De termijnen van leanhttp moeten het kale transport onder TLS bereiken, ook
// al geeft leantls geen `get_mut`.
#[test]
fn termijnen_bereiken_het_transport() {
    let timeouts: Rc<RefCell<Vec<Option<Duration>>>> = Rc::default();
    let raw = Raw {
        written: Rc::default(),
        timeouts: timeouts.clone(),
        closed: Rc::default(),
    };
    let wire = Wire {
        conn: raw,
        pending: Cell::new(Pending::default()),
    };
    wire.pending.set(Pending {
        read: Some(Some(Duration::from_secs(5))),
        write: None,
    });
    let mut wire = wire;
    let mut buf = [0u8; 4];
    let mut cx = Context::from_waker(Waker::noop());
    let _ = leantls::AsyncRead::poll_read(Pin::new(&mut wire), &mut cx, &mut buf);
    assert_eq!(&*timeouts.borrow(), &[Some(Duration::from_secs(5))]);
    // Eén keer toegepast, niet bij elke read opnieuw.
    let _ = leantls::AsyncRead::poll_read(Pin::new(&mut wire), &mut cx, &mut buf);
    assert_eq!(timeouts.borrow().len(), 1);
}

#[test]
fn is_ip_randen() {
    for (host, want) in [
        ("10.0.0.5", true),
        ("255.255.255.255", true),
        ("256.1.1.1", false),
        ("1.2.3", false),
        ("::1", true),
        ("leader.internal", false),
        ("123.example", false),
        ("1.2.3.4.5", false),
    ] {
        assert_eq!(is_ip(host), want, "{host}");
    }
}

/// Een lege, geldige wortelset: de keten faalt toch al op het einde van de stroom.
const NO_ROOTS: &[u8] = &[];

#[test]
fn web_dial_is_plain_for_http_and_refuses_https_without_name_clock_or_entropy() {
    let clock = || Some(1_790_000_000);
    let fresh = || Some(entropy());
    let mut web = WebDial::new(Tcp::default(), NO_ROOTS, clock, fresh);
    let plain = Target {
        https: false,
        host: "minio.lan",
        port: 9000,
    };
    assert!(matches!(block_on(web.dial(plain)), Ok(Link::Plain(_))));
    assert!(matches!(
        block_on(web.dial(target("10.0.0.1"))),
        Err(leanhttp::Error::NoHost)
    ));
    assert_eq!(web.last_error(), Some(Error::ChainWithoutName));
    let mut no_clock = WebDial::new(Tcp::default(), NO_ROOTS, || None, fresh);
    assert!(matches!(
        block_on(no_clock.dial(target("s3.example.test"))),
        Err(leanhttp::Error::Connect)
    ));
    let mut no_entropy = WebDial::new(Tcp::default(), NO_ROOTS, clock, || None);
    assert!(matches!(
        block_on(no_entropy.dial(target("s3.example.test"))),
        Err(leanhttp::Error::Connect)
    ));
    // Alleen de http-dial raakte de netstack.
    assert_eq!(web.inner.dials.len(), 1);
    assert!(no_clock.inner.dials.is_empty() && no_entropy.inner.dials.is_empty());
}

#[test]
fn web_dial_sends_sni_under_a_handshake_deadline() {
    let mut web = WebDial::new(
        Tcp::default(),
        leantls::MOZILLA_ROOTS,
        || Some(1_790_000_000),
        || Some(entropy()),
    );
    // De peer zwijgt en sluit: de handshake faalt, maar de ClientHello ging uit.
    assert!(block_on(web.dial(target("s3.example.test"))).is_err());
    assert!(web.last_error().is_some());
    assert!(contains(&web.inner.written[0].borrow(), b"s3.example.test"));
    assert_eq!(
        web.inner.timeouts[0].borrow().first(),
        Some(&Some(Duration::from_secs(20)))
    );
}
