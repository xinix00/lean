//! De tests van de Go-versie, geport met dezelfde namen en bedoeling, plus
//! tests van de recordlaag tegen een nep-transport.
//!
//! De interop-tests praten met Go's `crypto/tls` (testdata/goserver): een
//! onafhankelijke implementatie is de enige echte toets van transcript en
//! recordlaag. Zonder `go` op het pad worden alleen die tests overgeslagen,
//! met een regel op stderr.

use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use crate::conn::Conn;
use crate::record::{MAX_PLAIN, REC_ALERT, REC_APP_DATA, REC_CCS, REC_HANDSHAKE};
use crate::schedule::{Direction, Secret, TrafficKeys};
use crate::spki::peer_key_from_cert;
use crate::*;

// --- Gereedschap ------------------------------------------------------------

/// Draait een future die nooit `Pending` blijft (blokkerende std-sockets).
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// Een blokkerende TCP-socket achter de twee traits.
struct Tcp(TcpStream);

impl AsyncRead for Tcp {
    type Error = std::io::Error;
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        Poll::Ready(self.get_mut().0.read(buf))
    }
}

impl AsyncWrite for Tcp {
    type Error = std::io::Error;
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        Poll::Ready(self.get_mut().0.write(buf))
    }
}

/// 96 bytes uit het OS.
fn entropy() -> Entropy {
    let mut b = [0u8; Entropy::LEN];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    Entropy::new(b)
}

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, mut buf: &[u8]) -> Result<(), W::Error> {
    while !buf.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *w).poll_write(cx, buf)).await?;
        buf = &buf[n..];
    }
    Ok(())
}

async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, mut buf: &mut [u8]) -> Result<(), R::Error> {
    while !buf.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, buf)).await?;
        assert!(n > 0, "stroom eindigde te vroeg");
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Bouwt de Go-helper één keer per testproces.
fn go_binary() -> Option<&'static PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/goserver/main.go");
        let out = std::env::temp_dir().join(format!("leantls-goserver-{}", std::process::id()));
        match Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .status()
        {
            Ok(s) if s.success() => Some(out),
            other => {
                eprintln!("SKIP interop: go build faalde of go ontbreekt: {other:?}");
                None
            }
        }
    })
    .as_ref()
}

/// Een draaiende crypto/tls-server.
struct GoServer {
    child: Child,
    addr: String,
    key: [u8; 32],
    out: Option<BufReader<ChildStdout>>,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn go_server(mode: &str) -> Option<GoServer> {
    go_server_with(mode, &[])
}

/// Als [`go_server`], met extra argumenten (de ketenmap van de x509-modi).
fn go_server_with(mode: &str, args: &[&str]) -> Option<GoServer> {
    let bin = go_binary()?;
    let mut child = Command::new(bin)
        .arg(mode)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let addr = parts.next().unwrap().to_string();
    let key = crate::crypto::testutil::arr32(parts.next().unwrap());
    Some(GoServer {
        child,
        addr,
        key,
        out: Some(out),
    })
}

fn dial(srv: &GoServer) -> Tcp {
    let s = TcpStream::connect(&srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    Tcp(s)
}

fn pinned(srv: &GoServer) -> Trust<'static> {
    Trust::Pinned(PeerKey::new(srv.key))
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut k)
        .unwrap();
    k
}

// --- Interop met crypto/tls -------------------------------------------------

#[test]
fn client_against_stdlib_server() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    assert_eq!(conn.peer_key(), Some(&PeerKey::new(srv.key)));

    let msg = b"hallo van leantls";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 17];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");
}

#[test]
fn client_without_sni() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()));
    assert!(conn.is_ok(), "handshake: {:?}", conn.err());
}

#[test]
fn large_transfer() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();

    // 300 KiB in stukken van 40 KiB (drie records per schrijf); één eigenaar
    // schrijft en leest om beurten, zodat de echo nooit vastloopt.
    const N: usize = 300 << 10;
    const CHUNK: usize = 40 << 10;
    let mut send = vec![0u8; N];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut send)
        .unwrap();
    let mut got = vec![0u8; N];
    for (s, g) in send.chunks(CHUNK).zip(got.chunks_mut(CHUNK)) {
        block_on(write_all(&mut conn, s)).unwrap();
        block_on(read_exact(&mut conn, g)).unwrap();
    }
    if let Some(i) = (0..N).find(|&i| send[i] != got[i]) {
        panic!("byte {i} verschilt: {:#x} != {:#x}", got[i], send[i]);
    }
}

#[test]
fn wrong_pin_refused() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let other = Trust::Pinned(PeerKey::new(random_key()));
    let err = block_on(connect(dial(&srv), &other, "", entropy()))
        .err()
        .expect("een verkeerde pin werd geaccepteerd");
    assert!(
        err.to_string().contains("does not match the pin"),
        "melding zegt niet wat er mis is: {err}"
    );
}

#[test]
fn no_pin_refused() {
    // Go testte nil, een lege Config en een pin van 5 bytes. De eerste twee
    // compileren hier niet (zie de compile_fail-voorbeelden bij `Trust`); de
    // derde is een fout bij het maken van de pin.
    for n in [0usize, 5, 31, 33] {
        assert!(
            PeerKey::from_slice(&vec![0u8; n]).is_err(),
            "pin van {n} bytes geaccepteerd"
        );
    }
}

#[test]
fn tls12_server_refused() {
    let Some(srv) = go_server("echo12") else {
        return;
    };
    let err = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()))
        .err()
        .expect("een TLS 1.2-server werd geaccepteerd");
    assert!(!err.to_string().is_empty(), "lege foutmelding");
    eprintln!("TLS 1.2-server: {err}");
}

#[test]
fn non_ed25519_cert_refused() {
    let der = include_bytes!("../testdata/ecdsa-p256-cert.der");
    let err = peer_key_from_cert(der).expect_err("een ECDSA-certificaat werd geaccepteerd");
    assert!(
        err.to_string().contains("Ed25519"),
        "melding noemt Ed25519 niet: {err}"
    );

    // En aan de lijn: een ECDSA-server kan niet tekenen met het enige
    // aangeboden algoritme (Ed25519) en breekt zelf af met
    // handshake_failure. Geweigerd is geweigerd.
    let Some(srv) = go_server("ecdsa13") else {
        return;
    };
    let err = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()))
        .err()
        .expect("ECDSA-peer geaccepteerd");
    assert!(err.to_string().contains("handshake_failure"), "{err}");
}

#[test]
fn peer_key_from_cert_extracts_key() {
    // Go: TestPeerKeyFromCert. De tweede bron (daar crypto/x509) is hier
    // OpenSSL, dat bij het maken van de testdata de ruwe sleutel schreef.
    let der = include_bytes!("../testdata/ed25519-cert.der");
    let want = include_bytes!("../testdata/ed25519-pub.raw");
    let got = peer_key_from_cert(der).unwrap();
    assert_eq!(&got, want, "sleutel wijkt af");
}

#[test]
fn truncated_cert_never_panics() {
    let der = include_bytes!("../testdata/ed25519-cert.der");
    for i in 0..der.len() {
        assert!(
            peer_key_from_cert(&der[..i]).is_err(),
            "afgekapt op {i} bytes werd geaccepteerd"
        );
    }
}

#[test]
fn close_sends_close_notify() {
    let Some(mut srv) = go_server("discard13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();
    block_on(write_all(&mut conn, b"tot ziens")).unwrap();
    block_on(conn.close_notify()).unwrap_or_else(|e| panic!("close: {e}"));
    drop(conn);

    let mut out = srv.out.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = out.read_line(&mut line);
        let _ = tx.send(line);
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => assert_eq!(
            line.trim(),
            "result: EOF",
            "server zag geen nette afsluiting"
        ),
        Err(_) => panic!("server zag helemaal niets"),
    }
}

#[test]
fn concurrent_writes() {
    // Go liet acht goroutines tegelijk schrijven om te bewijzen dat records
    // niet door elkaar lopen. Met één eigenaar kan dat niet eens compileren;
    // wat overblijft is de bedoeling: acht schrijvers na elkaar over één
    // verbinding, elk byte komt precies één keer aan.
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();
    const WRITERS: u8 = 8;
    const EACH: usize = 4 << 10;
    let mut got = vec![0u8; usize::from(WRITERS) * EACH];
    for i in 0..WRITERS {
        block_on(write_all(&mut conn, &[b'a' + i; EACH])).unwrap();
    }
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    for i in 0..WRITERS {
        let n = got.iter().filter(|b| **b == b'a' + i).count();
        assert_eq!(n, EACH, "schrijver {i}: {n} van {EACH} bytes aangekomen");
    }
}

/// Een ketenverificatie voor de test: blad ondertekend door een bekende
/// Ed25519-CA, met de naam in het blad. Niet voor productie (geen datums,
/// geen naamregels); alleen om de haak aan de lijn te bewijzen.
struct TestChain {
    ca: [u8; 32],
}

/// Splitst een certificaat in (tbs als ruwe TLV, handtekening).
fn split_cert(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let (_, cert, _) = crate::spki::der_value(der)?;
    let (_, _, after_tbs) = crate::spki::der_value(cert)?;
    let tbs = &cert[..cert.len() - after_tbs.len()];
    let (_, _, after_alg) = crate::spki::der_value(after_tbs)?;
    let (_, sig, _) = crate::spki::der_value(after_alg)?;
    Ok((tbs, sig.get(1..).ok_or(Error::Der)?))
}

impl VerifyPeer for TestChain {
    fn signature_algorithms(&self) -> &[u16] {
        &[0x0807]
    }

    fn verify_chain(&self, chain: CertChain<'_>, server_name: &str) -> Result {
        let (tbs, sig) = split_cert(chain.leaf())?;
        let sig: &[u8; 64] = sig
            .try_into()
            .map_err(|_| Error::PeerRejected("signature size"))?;
        if !crate::crypto::ed25519::verify(&self.ca, tbs, sig) {
            return Err(Error::PeerRejected("leaf not signed by the trusted CA"));
        }
        if !tbs
            .windows(server_name.len())
            .any(|w| w == server_name.as_bytes())
        {
            return Err(Error::PeerRejected("name not in leaf"));
        }
        assert_eq!(chain.iter().count(), 2, "blad plus CA");
        Ok(())
    }

    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result {
        if alg != 0x0807 {
            return Err(Error::SignatureAlgorithm(alg));
        }
        let key = peer_key_from_cert(leaf)?;
        let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
        if crate::crypto::ed25519::verify(&key, signed, sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

#[test]
fn verify_peer_mode_against_stdlib_server() {
    // De haak zelf, aan de lijn getest met een Ed25519-keten van twee
    // certificaten; de echte ketenverificatie (ECDSA en RSA) staat in
    // `chain_verifier_against_stdlib_server`.
    let Some(srv) = go_server("chain13") else {
        return;
    };
    let v = TestChain { ca: srv.key };
    let mut conn = block_on(connect(
        dial(&srv),
        &Trust::Chain(&v),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    let msg = b"https zonder crypto/tls";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 23];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");

    let untrusted = TestChain { ca: random_key() };
    let err = block_on(connect(
        dial(&srv),
        &Trust::Chain(&untrusted),
        "leantls.test",
        entropy(),
    ))
    .err()
    .expect("een keten zonder vertrouwd anker werd geaccepteerd");
    assert!(err.to_string().contains("peer rejected"), "{err}");

    let err = block_on(connect(
        dial(&srv),
        &Trust::Chain(&v),
        "other.test",
        entropy(),
    ))
    .err()
    .expect("een keten voor een andere naam werd geaccepteerd");
    assert!(err.to_string().contains("name"), "{err}");
}

/// De echte ketenverificatie tegen crypto/tls: een P-256- en een
/// RSA-2048-keten uit `testdata/chain`, zodat de CertificateVerify met
/// ECDSA (0x0403) en met RSA-PSS (0x0804) over de lijn gaat.
#[test]
fn chain_verifier_against_stdlib_server() {
    use crate::{ChainVerifier, Roots};
    // 2026-09-29: binnen de vaste geldigheid van de testketens, zodat de test
    // niet afhangt van de klok van de machine.
    const NOW: u64 = 1_790_640_000;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
    let dir = dir.to_str().unwrap();
    let ecdsa_root: &[u8] = include_bytes!("../testdata/chain/ecdsa-root.der");
    let rsa_root: &[u8] = include_bytes!("../testdata/chain/rsa-root.der");
    for (mode, root, other) in [
        ("x509ecdsa", ecdsa_root, rsa_root),
        ("x509rsa", rsa_root, ecdsa_root),
    ] {
        let Some(srv) = go_server_with(mode, &[dir]) else {
            return;
        };
        let roots = [root];
        let v = ChainVerifier::new(Roots::from_list(&roots).unwrap(), NOW);
        let mut conn = block_on(connect(
            dial(&srv),
            &Trust::Chain(&v),
            "leantls.test",
            entropy(),
        ))
        .unwrap_or_else(|e| panic!("{mode}: handshake: {e}"));
        let msg = b"https met een echte keten";
        block_on(write_all(&mut conn, msg)).unwrap();
        let mut got = [0u8; 25];
        block_on(read_exact(&mut conn, &mut got)).unwrap();
        assert_eq!(&got, msg, "{mode}: echo");

        let err = block_on(connect(
            dial(&srv),
            &Trust::Chain(&v),
            "other.test",
            entropy(),
        ))
        .err()
        .expect("een keten voor een andere naam werd geaccepteerd");
        assert!(err.to_string().contains("valid for"), "{mode}: {err}");

        let wrong = [other];
        let untrusted = ChainVerifier::new(Roots::from_list(&wrong).unwrap(), NOW);
        let err = block_on(connect(
            dial(&srv),
            &Trust::Chain(&untrusted),
            "leantls.test",
            entropy(),
        ))
        .err()
        .expect("een keten zonder vertrouwde wortel werd geaccepteerd");
        assert!(
            err.to_string().contains("unknown authority"),
            "{mode}: {err}"
        );
    }
}

// --- Nep-transport ------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct MockErr;

impl std::fmt::Display for MockErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mock transport error")
    }
}

#[derive(Default)]
struct MockState {
    input: Vec<u8>,
    pos: usize,
    output: Vec<u8>,
    writes: usize,
    fail_write_at: Option<usize>,
    block_writes: bool,
    block_reads: bool,
    /// Leeg na de laatste byte: `Pending` in plaats van EOF (een peer die wacht).
    pending_at_eof: bool,
    dropped: usize,
    touched: bool,
}

struct Mock(Rc<RefCell<MockState>>);

impl Drop for Mock {
    fn drop(&mut self) {
        self.0.borrow_mut().dropped += 1;
    }
}

impl AsyncRead for Mock {
    type Error = MockErr;
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut s = self.0.borrow_mut();
        s.touched = true;
        if s.block_reads || (s.pending_at_eof && s.pos == s.input.len()) {
            return Poll::Pending;
        }
        let n = buf.len().min(s.input.len() - s.pos);
        buf[..n].copy_from_slice(&s.input[s.pos..s.pos + n]);
        s.pos += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for Mock {
    type Error = MockErr;
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut s = self.0.borrow_mut();
        s.touched = true;
        if s.block_writes {
            return Poll::Pending;
        }
        s.writes += 1;
        if s.fail_write_at == Some(s.writes) {
            return Poll::Ready(Err(MockErr));
        }
        s.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
}

fn mock() -> (Mock, Rc<RefCell<MockState>>) {
    let s = Rc::new(RefCell::new(MockState::default()));
    (Mock(s.clone()), s)
}

fn zero_keys() -> TrafficKeys {
    TrafficKeys {
        secret: Secret([0; 32]),
        key: [0; 16],
        iv: [0; 12],
    }
}

/// Go: encryptedConnForCloseTest. Een verbinding met nul-sleutels in beide
/// richtingen, zonder handshake.
fn encrypted_conn_for_close_test(raw: Mock) -> Conn<Mock> {
    let mut c = Conn::new(raw).unwrap();
    c.write = Some(Direction::new(zero_keys()));
    c.read = Some(Direction::new(zero_keys()));
    c
}

/// De peer-kant: versleutelt records met dezelfde nul-sleutels.
struct Peer {
    conn: Conn<Mock>,
}

impl Peer {
    fn new() -> Self {
        Self {
            conn: encrypted_conn_for_close_test(mock().0),
        }
    }

    fn record(&mut self, typ: u8, data: &[u8]) -> Vec<u8> {
        self.conn.queue_record(typ, data).unwrap();
        let out = self.conn.wbuf[self.conn.wstart..self.conn.wend].to_vec();
        self.conn.wstart = 0;
        self.conn.wend = 0;
        out
    }

    fn rekey(&mut self) {
        let next = self.conn.write.as_ref().unwrap().keys.next().unwrap();
        self.conn.write = Some(Direction::new(next));
    }
}

fn poll_once<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn record_write_error_is_permanent_across_application_retry() {
    let (raw, state) = mock();
    state.borrow_mut().fail_write_at = Some(2);
    let mut c = encrypted_conn_for_close_test(raw);
    let payload = vec![0u8; MAX_PLAIN + 1]; // twee TLS-records

    // Het eerste record gaat, het tweede faalt.
    let n = block_on(poll_fn(|cx| Pin::new(&mut c).poll_write(cx, &payload))).unwrap();
    assert_eq!(n, MAX_PLAIN);
    let err = block_on(poll_fn(|cx| {
        Pin::new(&mut c).poll_write(cx, &payload[MAX_PLAIN..])
    }))
    .unwrap_err();
    assert!(matches!(err, ConnError::Transport(MockErr)), "{err:?}");

    let seq_after_failure = c.write.as_ref().unwrap().seq;
    let err = block_on(poll_fn(|cx| {
        Pin::new(&mut c).poll_write(cx, &payload[MAX_PLAIN..])
    }))
    .unwrap_err();
    assert!(err == Error::WriteBroken, "retry na recordfout: {err:?}");
    assert_eq!(
        c.write.as_ref().unwrap().seq,
        seq_after_failure,
        "retry verbruikte een recordnummer"
    );
    assert_eq!(
        state.borrow().writes,
        2,
        "retry schreef een derde record naar de corrupte stroom"
    );

    // Close na een permanente schrijffout: geen close_notify meer, wel het
    // transport dicht.
    assert!(block_on(c.close_notify()).is_err());
    drop(c);
    let s = state.borrow();
    assert_eq!(
        (s.writes, s.dropped),
        (2, 1),
        "close na permanente schrijffout"
    );
}

#[test]
fn close_unblocks_concurrent_write() {
    // Go: Close mag niet wachten achter een vastzittende Write. Hier: de
    // eigenaar laat de vastzittende schrijf-future vallen en daarna de
    // verbinding; het transport gaat precies één keer dicht.
    let (raw, state) = mock();
    state.borrow_mut().block_writes = true;
    let mut c = encrypted_conn_for_close_test(raw);
    {
        let mut w = pin!(write_all(&mut c, b"peer leest dit niet"));
        assert!(poll_once(w.as_mut()).is_pending(), "Write begon niet");
        assert!(state.borrow().touched);
    }
    drop(c);
    assert_eq!(
        state.borrow().dropped,
        1,
        "onderliggende close niet precies een keer"
    );
}

#[test]
fn blocked_close_notify_still_closes_transport() {
    let (raw, state) = mock();
    state.borrow_mut().block_writes = true;
    let mut c = encrypted_conn_for_close_test(raw);
    {
        let mut f = pin!(c.close_notify());
        assert!(
            poll_once(f.as_mut()).is_pending(),
            "close_notify werd niet geprobeerd"
        );
    }
    assert!(state.borrow().touched, "close_notify werd niet geprobeerd");
    // De begrenzing is de timer van de aanroeper: die laat de future vallen
    // en daarna de verbinding.
    drop(c);
    assert_eq!(state.borrow().dropped, 1);
}

#[test]
fn trust_model_required() {
    // "niets" en "beide" compileren niet (compile_fail bij `Trust`).
    let v = TestChain { ca: [0; 32] };
    let (raw, state) = mock();
    let err = block_on(connect(raw, &Trust::Chain(&v), "", entropy()))
        .err()
        .expect("geaccepteerd");
    assert!(
        err.to_string().contains("ServerName is required"),
        "haak zonder naam: {err}"
    );
    assert!(
        !state.borrow().touched,
        "er ging iets over het transport voor de weigering"
    );

    let err = PeerKey::from_slice(&[0u8; 8]).expect_err("pin van de verkeerde maat");
    assert!(
        err.to_string().contains("an Ed25519 public key is"),
        "{err}"
    );

    let (raw, _) = mock();
    let long = "a".repeat(256);
    let err = block_on(connect(
        raw,
        &Trust::Pinned(PeerKey::new([0; 32])),
        &long,
        entropy(),
    ))
    .err()
    .unwrap();
    assert!(err == Error::ServerNameTooLong(256), "{err:?}");
}

#[test]
fn handshake_respecteert_de_conn_deadline() {
    // Go: een zwijgende peer mag de goroutine niet gijzelen voorbij de
    // deadline. Hier is de deadline de aanroeper die de future laat vallen;
    // daarna is het transport weg en blijft er niets hangen.
    let (raw, state) = mock();
    state.borrow_mut().block_reads = true;
    let trust = Trust::Pinned(PeerKey::new([0; 32]));
    {
        let mut f = pin!(connect(raw, &trust, "", entropy()));
        for _ in 0..10 {
            assert!(
                poll_once(f.as_mut()).is_pending(),
                "een handshake tegen een zwijgende peer slaagde?!"
            );
        }
        assert!(
            !state.borrow().output.is_empty(),
            "ClientHello niet verstuurd"
        );
    }
    assert_eq!(
        state.borrow().dropped,
        1,
        "de afgebroken handshake hield het transport vast"
    );
}

// --- Recordlaag en berichten na de handshake ------------------------------------

fn read_all(c: &mut Conn<Mock>) -> (Vec<u8>, Option<ConnError<MockErr>>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 100];
    loop {
        match block_on(poll_fn(|cx| Pin::new(&mut *c).poll_read(cx, &mut buf))) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e)),
        }
    }
}

#[test]
fn key_update_rotates_keys_and_answers() {
    let mut peer = Peer::new();
    let mut wire = peer.record(REC_APP_DATA, b"voor ");
    wire.extend(peer.record(REC_HANDSHAKE, &[24, 0, 0, 1, 1])); // update_requested
    peer.rekey();
    wire.extend(peer.record(REC_APP_DATA, b"na"));
    wire.extend(peer.record(REC_ALERT, &[1, 0]));

    let (raw, state) = mock();
    state.borrow_mut().input = wire;
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(got, b"voor na");

    // Ons antwoord: een KeyUpdate zonder verzoek, met de oude sleutels, en
    // daarna schrijven we met de nieuwe.
    block_on(write_all(&mut c, b"x")).unwrap();
    let out = state.borrow().output.clone();
    let mut reader = encrypted_conn_for_close_test(mock().0);
    let (r2, s2) = mock();
    drop(r2);
    s2.borrow_mut().input = out;
    reader.io = Mock(s2);
    let rec = block_on(poll_fn(|cx| reader.poll_record(cx))).unwrap();
    assert_eq!(
        (rec.0, &reader.rbuf[rec.1..rec.2]),
        (REC_HANDSHAKE, &[24u8, 0, 0, 1, 0][..])
    );
    let next = reader.read.as_ref().unwrap().keys.next().unwrap();
    reader.read = Some(Direction::new(next));
    let rec = block_on(poll_fn(|cx| reader.poll_record(cx))).unwrap();
    assert_eq!(
        (rec.0, &reader.rbuf[rec.1..rec.2]),
        (REC_APP_DATA, &b"x"[..])
    );
}

#[test]
fn post_handshake_noise_is_ignored() {
    // Een klaartekst-CCS, een NewSessionTicket en daarna data: alleen de data
    // komt boven, en close_notify is een net einde.
    let mut peer = Peer::new();
    let mut wire = vec![REC_CCS, 3, 3, 0, 1, 1];
    wire.extend(peer.record(REC_HANDSHAKE, &[4, 0, 0, 3, 9, 9, 9]));
    wire.extend(peer.record(REC_APP_DATA, b"data"));
    wire.extend(peer.record(REC_ALERT, &[1, 0]));
    let (raw, state) = mock();
    state.borrow_mut().input = wire;
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(got, b"data");
}

#[test]
fn record_padding_is_stripped() {
    // Een peer mag nullen achter het inhoudstype zetten (§5.4).
    let mut peer = Peer::new();
    let mut inner = b"opgevuld".to_vec();
    inner.push(REC_APP_DATA);
    inner.extend([0u8; 7]);
    // queue_record zet zelf het type erachter; gebruik type 0 voor de
    // laatste opvulbyte, zodat de klaartekst `inner` plus een nul wordt.
    let rec = peer.record(0, &inner);
    let (raw, state) = mock();
    state.borrow_mut().input = rec;
    let mut c = encrypted_conn_for_close_test(raw);
    let mut buf = [0u8; 32];
    let n = block_on(poll_fn(|cx| Pin::new(&mut c).poll_read(cx, &mut buf))).unwrap();
    assert_eq!(&buf[..n], b"opgevuld");
}

#[test]
fn alerts_and_truncation_are_errors() {
    // Een fatale alert wordt een leesbare fout.
    let mut peer = Peer::new();
    let (raw, state) = mock();
    state.borrow_mut().input = peer.record(REC_ALERT, &[2, 40]);
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    let err = err.unwrap();
    assert!(err.to_string().contains("handshake_failure"), "{err}");
    // En plakt.
    let (_, again) = read_all(&mut c);
    assert!(again.unwrap() == Error::Alert { level: 2, code: 40 });

    // Transport dicht zonder close_notify: mogelijk afgekapt, dus een fout.
    let mut peer = Peer::new();
    let (raw, state) = mock();
    state.borrow_mut().input = peer.record(REC_APP_DATA, b"half");
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert_eq!(got, b"half");
    assert!(err.unwrap() == Error::Eof);
}

#[test]
fn tampered_record_is_fatal() {
    let mut peer = Peer::new();
    let mut rec = peer.record(REC_APP_DATA, b"geheim");
    let last = rec.len() - 1;
    rec[last] ^= 1;
    let (raw, state) = mock();
    state.borrow_mut().input = rec;
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    assert!(err.unwrap() == Error::Decrypt(0));
}

#[test]
fn oversized_record_refused_before_reading() {
    let (raw, state) = mock();
    state.borrow_mut().input = vec![REC_APP_DATA, 3, 3, 0xff, 0xff];
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    assert!(err.unwrap() == Error::RecordTooLarge(0xffff));
}

#[test]
fn write_after_close_notify_is_refused() {
    let (raw, state) = mock();
    let mut c = encrypted_conn_for_close_test(raw);
    block_on(c.close_notify()).unwrap();
    assert_eq!(state.borrow().writes, 1);
    let err = block_on(write_all(&mut c, b"te laat")).unwrap_err();
    assert!(err == Error::Closed);
}

#[test]
fn server_hello_choices_are_checked() {
    use crate::handshake::parse_server_hello;
    let sid = [7u8; 32];
    let hello = |suite: u16, exts: &[u8]| {
        let mut b = vec![3, 3];
        b.extend([1u8; 32]);
        b.push(32);
        b.extend(sid);
        b.extend(suite.to_be_bytes());
        b.push(0);
        b.extend((exts.len() as u16).to_be_bytes());
        b.extend(exts);
        b
    };
    let versions = [0, 43, 0, 2, 3, 4];
    let mut share = vec![0, 51, 0, 36, 0, 0x1d, 0, 32];
    share.extend([5u8; 32]);
    let good: Vec<u8> = versions.iter().chain(share.iter()).copied().collect();
    assert_eq!(
        parse_server_hello(&hello(0x1301, &good), &sid),
        Ok([5u8; 32])
    );
    assert_eq!(
        parse_server_hello(&hello(0x1302, &good), &sid),
        Err(Error::CipherSuite(0x1302))
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &share), &sid),
        Err(Error::NotTls13)
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &versions), &sid),
        Err(Error::NoKeyShare)
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &good), &[8u8; 32]),
        Err(Error::SessionIdMismatch)
    );
    let mut hrr = hello(0x1301, &good);
    hrr[2..34].copy_from_slice(&crate::handshake::HELLO_RETRY_RANDOM);
    assert_eq!(
        parse_server_hello(&hrr, &sid),
        Err(Error::HelloRetryRequest)
    );
    let good = hello(0x1301, &good);
    for i in 0..good.len() {
        assert!(
            parse_server_hello(&good[..i], &sid).is_err(),
            "afgekapt op {i} geaccepteerd"
        );
    }
}

#[test]
fn certificate_list_structure() {
    // Leeg certificaat en lege lijst worden geweigerd.
    assert_eq!(
        CertChain::parse(&[0, 0, 0, 0]).err(),
        Some(Error::EmptyCertificateList)
    );
    assert_eq!(
        CertChain::parse(&[0, 0, 0, 5, 0, 0, 0, 0, 0]).err(),
        Some(Error::EmptyCertificate)
    );
    let c =
        CertChain::parse(&[0, 0, 0, 13, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 0, 1, 0xcc, 0, 0]).unwrap();
    assert_eq!(c.leaf(), &[0xaa, 0xbb]);
    assert_eq!(
        c.iter().collect::<Vec<_>>(),
        vec![&[0xaa, 0xbb][..], &[0xcc][..]]
    );
}

// --- Server -----------------------------------------------------------------

/// Een identiteit zonder privésleutel: de handtekening is onzin, maar de
/// test hieronder komt niet verder dan de client-Finished.
struct Unsigned(Vec<Vec<u8>>);

impl crate::server::Identity for Unsigned {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.0
    }
    fn signature_scheme(&self) -> u16 {
        0x0403
    }
    fn sign(&self, _: &[u8], _: [u8; 32]) -> Result<Vec<u8>> {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }
}

/// Geen applicatiebyte voordat de client-Finished klopt: een vervalste
/// Finished, applicatiedata in plaats van Finished en een kapot record falen
/// alle drie, en de server laat het transport niet lekken.
#[test]
fn server_refuses_a_client_without_a_valid_finished() {
    let cert = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ecdsa-p256-cert.der"),
    )
    .unwrap();
    refuses_unproven_client(&Unsigned(vec![cert]));
}

fn refuses_unproven_client(identity: &impl crate::server::Identity) {
    use crate::crypto::x25519::{BASEPOINT, x25519};
    let private = [3; 32];
    let session = [9; 32];
    let ch = crate::handshake::client_hello(
        &[8; 32],
        &session,
        &x25519(&private, &BASEPOINT),
        "leantls.test",
        &[identity.signature_scheme()],
    )
    .unwrap();
    for attack in [0, 1, 2] {
        let (raw, state) = mock();
        {
            let mut s = state.borrow_mut();
            s.input.extend_from_slice(&[22, 3, 1]);
            s.input.extend_from_slice(&(ch.len() as u16).to_be_bytes());
            s.input.extend_from_slice(&ch);
            s.pending_at_eof = true;
        }
        let mut accepting = Box::pin(crate::server::accept(raw, identity, entropy(), false));
        assert!(
            poll_once(accepting.as_mut()).is_pending(),
            "server exposed connection without client Finished"
        );
        let output = state.borrow().output.clone();
        let n = usize::from(u16::from_be_bytes([output[3], output[4]]));
        let sh = &output[5..5 + n];
        let share = crate::handshake::parse_server_hello(&sh[4..], &session).unwrap();
        let secrets = crate::schedule::new_secrets(&x25519(&private, &share)).unwrap();
        let mut hash = crate::crypto::sha256::Sha256::new();
        hash.update(&ch);
        hash.update(sh);
        let keys = TrafficKeys::from_secret(
            crate::schedule::derive_secret(&secrets.handshake, b"c hs traffic", &hash.finish())
                .unwrap(),
        )
        .unwrap();
        let mut sender = Conn::new(mock().0).unwrap();
        sender.write = Some(Direction::new(keys));
        let mut finished = [0; 36];
        finished[..4].copy_from_slice(&[20, 0, 0, 32]);
        sender
            .queue_record(
                if attack == 1 {
                    REC_APP_DATA
                } else {
                    REC_HANDSHAKE
                },
                &finished,
            )
            .unwrap();
        let mut record = sender.wbuf[sender.wstart..sender.wend].to_vec();
        if attack == 2 {
            *record.last_mut().unwrap() ^= 1;
        }
        state.borrow_mut().input.extend_from_slice(&record);
        let Poll::Ready(Err(error)) = poll_once(accepting.as_mut()) else {
            panic!("forged client accepted or hung")
        };
        match attack {
            0 => assert!(error == Error::FinishedMismatch),
            1 => assert!(error == Error::UnexpectedRecord(REC_APP_DATA)),
            _ => assert!(matches!(error, ConnError::Tls(Error::Decrypt(_)))),
        }
        drop(accepting);
        assert_eq!(
            state.borrow().dropped,
            1,
            "failed handshake leaked transport"
        );
    }
}
