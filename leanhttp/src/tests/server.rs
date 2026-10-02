//! Servertests: serve_test.go, de serverkant van review13_test.go, en
//! TestServerSluitGegroeideVerbindingNaRequest uit client_test.go.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use super::support::*;
use super::{h, split};
use crate::AsyncRead as _;
use crate::{
    BODY_TIMEOUT, BUF_SIZE, Error, MAX_BODY_BYTES, Outcome, Result, read, serve, write_all,
};

const GET_CLOSE: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

fn ok2() -> Handler {
    h!(ex => {
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    })
}

fn drain_ok2() -> Handler {
    h!(ex => {
        let _ = ex.read_body_to_end().await;
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    })
}

#[test]
fn serve_gewoon_antwoord() {
    let seen = Rc::new(RefCell::new(String::new()));
    let s = seen.clone();
    let srv = h!(ex => {
        *s.borrow_mut() = format!("{} {} {}", ex.req.method, ex.req.path, ex.req.header.get("host").unwrap_or(""));
        ex.header_mut().set("Content-Type", "text/plain")?;
        ex.write(b"dag").await?;
    });
    let got = rt(
        &srv,
        "GET /hallo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = split(&got);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{got}");
    assert_eq!(body, "dag");
    assert!(head.contains("Content-Length: 3"), "{head}");
    assert!(head.contains("Content-Type: text/plain"), "{head}");
    assert_eq!(*seen.borrow(), "GET /hallo x");
}

#[test]
fn serve_eigen_content_length() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "300000")?;
        ex.write(&vec![b'x'; 300_000]).await?;
    });
    let got = rt(&srv, GET_CLOSE);
    let (head, body) = split(&got);
    assert!(head.contains("Content-Length: 300000"), "{head}");
    assert_eq!(body.len(), 300_000);
}

#[test]
fn serve_status_en_zonder_body() {
    let srv = h!(ex => { ex.write_header(204)?; });
    let got = rt(&srv, GET_CLOSE);
    let (head, body) = split(&got);
    assert!(head.starts_with("HTTP/1.1 204"), "{got}");
    assert_eq!(body, "");
    assert!(
        !head.contains("Content-Length"),
        "204 hoort geen Content-Length te hebben: {head}"
    );
}

#[test]
fn serve_flush_streamt() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Type", "application/octet-stream")?;
        for i in 0..3 {
            ex.write(format!("frame {i}\n").as_bytes()).await?;
            ex.flush().await?;
        }
        // Blijf hangen: de frames moeten er al zijn vóór het einde.
        sleep(Duration::from_secs(3600)).await;
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut c).await.unwrap();
        assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
        assert!(!head.contains("Content-Length"), "{head}");
        for i in 0..3 {
            let size = read_line(&mut c).await.unwrap();
            assert_eq!(size, "8\r\n");
            let data = read_line(&mut c).await.unwrap();
            assert_eq!(data, format!("frame {i}\n"));
            assert_eq!(read_line(&mut c).await.unwrap(), "\r\n");
        }
    });
}

#[test]
fn serve_done_bij_wegvallende_client() {
    let noticed = Rc::new(Cell::new(false));
    let n = noticed.clone();
    let srv = h!(ex => {
        ex.claim_done().await?;
        ex.write(b"hoi\n").await?;
        ex.flush().await?;
        ex.done().await?;
        n.set(true);
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut c).await.unwrap();
        assert!(head.contains("Connection: close"), "{head}");
        let mut buf = [0u8; 16];
        read(&mut c, &mut buf).await.unwrap();
        drop(c);
        sleep(Duration::from_secs(1)).await;
    });
    assert!(noticed.get(), "done sloot niet toen de client verdween");
}

#[test]
fn serve_post_met_body() {
    let srv = h!(ex => {
        if ex.req.method != "POST" {
            return ex.error(405, "POST only").await;
        }
        let body = ex.read_body_to_end().await?;
        let text = String::from_utf8(body).unwrap();
        let n = text.trim_start_matches("{\"n\":").trim_end_matches('}');
        ex.write(n.as_bytes()).await?;
    });
    let got = rt(
        &srv,
        "POST /tel HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 8\r\nConnection: close\r\n\r\n{\"n\":42}",
    );
    assert_eq!(split(&got).1, "42");
    let got = rt(
        &srv,
        "GET /tel HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.starts_with("HTTP/1.1 405"), "{got}");
}

#[test]
fn serve_chunked_verzoek_body_is_een501() {
    let srv = h!(ex => {
        let b = ex.read_body_to_end().await?;
        ex.write(&b).await?;
    });
    let got = rt(
        &srv,
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nd\r\nhallo chunked\r\n0\r\n\r\n",
    );
    assert!(got.starts_with("HTTP/1.1 501"), "{got}");
    let got = rt(
        &srv,
        "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\nConnection: close\r\n\r\nhallo lengte",
    );
    assert_eq!(split(&got).1, "hallo lengte");
}

#[test]
fn serve_keep_alive() {
    let srv = h!(ex => {
        let p = ex.req.path.clone();
        ex.write(p.as_bytes()).await?;
    });
    let got = rt(
        &srv,
        "GET /een HTTP/1.1\r\nHost: x\r\n\r\nGET /twee HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    assert_eq!(got.matches("HTTP/1.1 200").count(), 2, "{got}");
    let (_, rest) = split(&got);
    assert!(rest.starts_with("/een"), "{got}");
    assert!(
        got.ends_with("/twee"),
        "verbinding werd niet hergebruikt: {got}"
    );
}

#[test]
fn serve_verkeerde_content_length_sluit_de_verbinding() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "10")?;
        ex.write(b"abc").await?;
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // Zonder termijn aan de clientkant: alleen een sluitende server laat
        // dit eindigen.
        let got = read_all(&mut c).await;
        assert!(String::from_utf8_lossy(&got).ends_with("abc"));
    });
}

#[test]
fn serve_hijack() {
    let srv = h!(ex => {
        if ex.req.header.get("Upgrade") != Some("websocket") {
            return ex.error(400, "geen upgrade").await;
        }
        let mut raw = ex.hijack()?;
        write_all(&mut raw, b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n").await?;
        let mut buf = [0u8; 64];
        let n = read(&mut raw, &mut buf).await?;
        write_all(&mut raw, b"echo: ").await?;
        write_all(&mut raw, &buf[..n]).await?;
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(
            &mut c,
            b"GET /input HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();
        let head = read_head(&mut c).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        write_all(&mut c, b"ping\n").await.unwrap();
        assert_eq!(read_line(&mut c).await.unwrap(), "echo: ping\n");
    });
}

#[test]
fn serve_hijack_geeft_de_verbinding_terug() {
    // Rust-toevoeging: na de handler is de aanroeper eigenaar, met de bytes
    // die al gebufferd waren.
    block_on(async {
        let (mut c, s) = pipe();
        write_all(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\nrest")
            .await
            .unwrap();
        let out = serve(s, async |ex: &mut crate::Exchange<'_, End>| -> Result {
            ex.hijack()?;
            Ok(())
        })
        .await
        .unwrap();
        match out {
            Outcome::Hijacked(h) => assert_eq!(h.buffered, b"rest"),
            Outcome::Closed => panic!("verbinding niet teruggegeven"),
        }
    });
}

#[test]
fn serve_query() {
    let srv = h!(ex => {
        let z = ex.req.query("z")?.unwrap_or_default();
        let body = format!("{z}|{}", ex.req.path);
        ex.write(body.as_bytes()).await?;
    });
    let got = rt(
        &srv,
        "GET /stream?z=1&a=2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(split(&got).1, "1|/stream");
}

#[test]
fn serve_redirect() {
    let srv = h!(ex => {
        if ex.req.path == "/" {
            return ex.redirect("/kvm", 302).await;
        }
        ex.write(b"de pagina").await?;
    });
    let got = rt(&srv, GET_CLOSE);
    assert!(got.starts_with("HTTP/1.1 302"), "{got}");
    assert!(got.contains("Location: /kvm"), "{got}");
    let got = rt(
        &srv,
        "GET /kvm HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(split(&got).1, "de pagina");
}

fn never() -> Handler {
    h!(ex => { panic!("handler had niet mogen draaien: {}", ex.req.path); })
}

#[test]
fn serve_kapot_verzoek() {
    let got = rt(&never(), "ik ben geen http\r\n\r\n");
    assert!(got.starts_with("HTTP/1.1 400"), "{got}");
}

#[test]
fn serve_te_grote_body_weigert() {
    let got = rt(
        &never(),
        &format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\nxxx",
            MAX_BODY_BYTES + 1
        ),
    );
    assert!(got.starts_with("HTTP/1.1 413"), "{got}");
}

#[test]
fn serve_te_lange_headerregel_weigert() {
    let got = rt(
        &never(),
        &format!(
            "GET / HTTP/1.1\r\nHost: x\r\nX-Groot: {}\r\n\r\n",
            "A".repeat(BUF_SIZE + 1)
        ),
    );
    assert!(got.starts_with("HTTP/1.1 400"), "{got}");
}

#[test]
fn serve_geen_response_splitting() {
    let srv = h!(ex => {
        ex.header_mut().set("X-Echo", "goed\r\nX-Gesmokkeld: fout")?;
        ex.write(b"ok").await?;
    });
    let got = rt(&srv, GET_CLOSE);
    assert!(
        !got.contains("X-Gesmokkeld"),
        "gesmokkelde header kwam door: {got}"
    );
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
}

#[test]
fn server_sluit_gegroeide_verbinding_na_request() {
    let srv = h!(ex => { ex.write(b"ok").await?; });
    block_on(async {
        let (mut c, mut s) = pipe();
        s.grown = true;
        srv(s);
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_all(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let got = String::from_utf8(read_all(&mut c).await).unwrap();
        assert!(
            got.contains("Connection: close\r\n") && got.ends_with("\r\n\r\nok"),
            "{got}"
        );
        assert!(!c.is_closed());
    });
}

#[test]
fn server_weigert_spatie_voor_dubbele_punt() {
    let got = rt(
        &drain_ok2(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nAAAAA",
    );
    assert!(got.contains("400"), "{got}");
}

#[test]
fn server_weigert_te_plus_content_length() {
    let got = rt(
        &drain_ok2(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
    );
    assert!(got.contains("400"), "{got}");
}

#[test]
fn server_weigert_vreemde_te() {
    let got = rt(
        &drain_ok2(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    );
    assert!(got.contains("501"), "{got}");
}

#[test]
fn server_upload_boven_limiet_is_fout() {
    let got = rt(
        &never(),
        &format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_BODY_BYTES + 1
        ),
    );
    assert!(got.contains("413"), "{got}");
}

#[test]
fn server_upload_van_exact_de_limiet_is_geldig() {
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    let srv = h!(ex => {
        let r = ex.read_body_to_end().await.map(|b| b.len());
        *g.borrow_mut() = Some(r);
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    block_on(async {
        let (mut c, s) = pipe_cap(64 << 10);
        srv(s);
        write_all(
            &mut c,
            format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let chunk = vec![b'A'; 64 << 10];
        for _ in 0..(MAX_BODY_BYTES as usize / chunk.len()) {
            write_all(&mut c, &chunk).await.unwrap();
        }
        let head = read_head(&mut c).await.unwrap();
        assert!(head.contains(" 200 "), "{head}");
    });
    assert_eq!(*got.borrow(), Some(Ok(MAX_BODY_BYTES as usize)));
}

#[test]
fn server_ziet_afgebroken_content_length() {
    let got = Rc::new(Cell::new(None));
    let g = got.clone();
    let srv = h!(ex => {
        g.set(Some(ex.read_body_to_end().await.map(|b| b.len())));
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(
            &mut c,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhalf!",
        )
        .await
        .unwrap();
        drop(c);
        sleep(Duration::from_secs(1)).await;
    });
    assert_eq!(got.get(), Some(Err(Error::UnexpectedEof)));
}

#[test]
fn server_weigert_te_identity() {
    let got = rt(
        &drain_ok2(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\nsmokkel",
    );
    assert!(got.contains("501"), "{got}");
}

#[test]
fn dot_segmenten_worden_geweigerd() {
    for pad in ["/admin/.", "/admin/x/..", "/../admin", "/veilig/a/../b"] {
        let got = rt(
            &ok2(),
            &format!("GET {pad} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains("400"), "{pad}: {got}");
    }
}

#[test]
fn writer_is_eigenaar_van_de_framing() {
    let srv = h!(ex => {
        if ex.req.path == "/te" {
            ex.header_mut().set("Transfer-Encoding", "chunked")?;
            ex.write(b"body").await?;
            return Ok(());
        }
        ex.header_mut().set("Content-Length", "5")?;
        ex.write_header(204)?;
    });
    let got = rt(
        &srv,
        "GET /te HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let head = split(&got).0.to_lowercase();
    assert!(
        !(head.contains("transfer-encoding") && head.contains("content-length")),
        "antwoord draagt TE en Content-Length: {head}"
    );
    let got = rt(
        &srv,
        "GET /204 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = split(&got);
    assert!(
        !head.to_lowercase().contains("content-length") && body.is_empty(),
        "{got}"
    );
}

#[test]
fn handler_kan_content_length_niet_overschrijden() {
    let err = Rc::new(Cell::new(None));
    let e = err.clone();
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "5")?;
        ex.write(b"12345").await?;
        e.set(Some(ex.write(b"SMOKKEL").await));
    });
    let got = rt(&srv, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(split(&got).1, "12345");
    assert_eq!(err.get(), Some(Err(Error::WroteTooMuch { declared: 5 })));
}

#[test]
fn content_length_mutatie_omzeilt_de_controle_niet() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "10")?;
        ex.write(b"12345").await?;
        ex.header_mut().set("Content-Length", "5")?;
    });
    let got = rt(
        &srv,
        "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    assert_eq!(got.matches("HTTP/1.1 200").count(), 1, "{got}");
}

#[test]
fn overrun_laat_de_verbinding_leven() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "5")?;
        ex.write(b"12345").await?;
        let _ = ex.write(b"SMOKKEL").await;
    });
    let got = rt(
        &srv,
        "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(got.matches("HTTP/1.1 200").count(), 2, "{got}");
    assert!(!got.contains("SMOKKEL"), "{got}");
}

#[test]
fn trage_body_gijzelt_geen_goroutine() {
    let got = Rc::new(Cell::new(None));
    let g = got.clone();
    let srv = h!(ex => {
        g.set(Some(ex.read_body_to_end().await.map(|b| b.len())));
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(
            &mut c,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nhalf",
        )
        .await
        .unwrap();
        sleep(BODY_TIMEOUT + Duration::from_secs(3)).await;
        drop(c);
    });
    assert!(
        matches!(got.get(), Some(Err(Error::Io(crate::IoError::TimedOut)))),
        "{:?}",
        got.get()
    );
}

#[test]
fn done_overleeft_de_body_timeout() {
    let verdict = Rc::new(Cell::new(None));
    let v = verdict.clone();
    let srv = h!(ex => {
        ex.read_body_to_end().await?;
        let fired = matches!(select(ex.done(), sleep(BODY_TIMEOUT + Duration::from_secs(1))).await, Either::Left(_));
        v.set(Some(fired));
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(
            &mut c,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nping",
        )
        .await
        .unwrap();
        read_head(&mut c).await.unwrap();
    });
    assert_eq!(
        verdict.get(),
        Some(false),
        "done vuurde terwijl de client er nog is"
    );
}

#[test]
fn server_eist_een_geldige_host() {
    for (name, req) in [
        ("zonder Host", "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
        (
            "lege Host",
            "GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n",
        ),
        (
            "dubbele Host",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n",
        ),
        (
            "rare methode",
            "B@D / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ),
    ] {
        let got = rt(&ok2(), req);
        assert!(got.contains("400"), "{name}: {got}");
    }
    assert!(rt(&ok2(), "GET / HTTP/1.0\r\n\r\n").contains("505"));
}

#[test]
fn grote_write_wapent_de_schrijftermijn() {
    let big = 3 * BUF_SIZE;
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", &(big + 2).to_string())?;
        ex.write(b"hi").await?;
        ex.flush().await?;
        ex.write(&vec![0u8; big]).await?;
    });
    block_on(async {
        let (mut c, s) = pipe();
        let stats = s.stats.clone();
        srv(s);
        write_all(&mut c, GET_CLOSE.as_bytes()).await.unwrap();
        read_all(&mut c).await;
        let st = stats.borrow();
        assert_eq!(st.unarmed_writes, 0, "socketwrites zonder schrijftermijn");
    });
}

#[test]
fn kale_lf_is_geen_regel() {
    let got = rt(
        &ok2(),
        "GET / HTTP/1.1\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.contains("400"), "{got}");
}

#[test]
fn control_byte_in_header_is_fout() {
    for (name, req) in [
        (
            "CTL in waarde",
            "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x01b\r\nConnection: close\r\n\r\n",
        ),
        (
            "losse CR",
            "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\nConnection: close\r\n\r\n",
        ),
    ] {
        let got = rt(&ok2(), req);
        assert!(got.contains("400"), "{name}: {got}");
    }
}

#[test]
fn spill_laat_geen_termijn_achter() {
    let big = 3 * BUF_SIZE;
    let armed_after = Rc::new(Cell::new(true));
    let a = armed_after.clone();
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", &big.to_string())?;
        ex.write(&vec![0u8; big]).await?;
        // Nu rekent de handler; de termijn mag niet stil doorlopen.
        a.set(STATS.with(|s| s.borrow().as_ref().unwrap().borrow().write_armed));
    });
    thread_local! {
        static STATS: RefCell<Option<Rc<RefCell<Stats>>>> = const { RefCell::new(None) };
    }
    block_on(async {
        let (mut c, s) = pipe();
        STATS.with(|st| *st.borrow_mut() = Some(s.stats.clone()));
        srv(s);
        write_all(&mut c, GET_CLOSE.as_bytes()).await.unwrap();
        read_all(&mut c).await;
    });
    assert!(
        !armed_after.get(),
        "na de write staat de schrijftermijn nog"
    );
}

#[test]
fn syntaxfout_draint_niet() {
    block_on(async {
        let got = round_trip(&ok2(), "GET / HTTP/1.1\nHost: x\r\n\r\n").await;
        assert!(got.contains("400"), "{got}");
        assert!(
            now() < Duration::from_secs(1),
            "de 400 hield de verbinding {:?} vast",
            now()
        );
    });
}

#[test]
fn head_valt_terug_op_get() {
    let mut m = crate::Mux::new();
    m.handle("GET /x", ()).unwrap();
    let m = Rc::new(m);
    let srv = h!(ex => {
        if m.dispatch(ex).await?.is_some() {
            ex.header_mut().set("Content-Length", "5")?;
            ex.write(b"hallo").await?;
        }
    });
    let got = rt(
        &srv,
        "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        got.contains("200") && got.contains("Content-Length: 5"),
        "{got}"
    );
    assert!(
        !got.contains("hallo"),
        "het HEAD-antwoord draagt body-bytes"
    );
}

fn tagged_mux(patterns: &[(&str, &'static str)]) -> Handler {
    let mut m = crate::Mux::new();
    for (p, tag) in patterns {
        m.handle(p, *tag).unwrap();
    }
    let m = Rc::new(m);
    h!(ex => {
        if let Some(tag) = m.dispatch(ex).await? {
            ex.header_mut().set("X-Handler", tag)?;
        }
    })
}

#[test]
fn exacte_head_route_gaat_voor_de_terugval() {
    for get_first in [true, false] {
        let srv = if get_first {
            tagged_mux(&[("GET /x", "get"), ("HEAD /x", "head")])
        } else {
            tagged_mux(&[("HEAD /x", "head"), ("GET /x", "get")])
        };
        let got = rt(
            &srv,
            "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(
            got.contains("X-Handler: head"),
            "GET eerst={get_first}: {got}"
        );
    }
}

#[test]
fn ongeldige_content_length_gaat_de_draad_niet_op() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "abc")?;
        ex.write(b"ok").await?;
    });
    let got = rt(&srv, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(!got.contains("abc"), "{got}");
    assert!(
        got.contains("Connection: close") && got.ends_with("ok"),
        "{got}"
    );
    let got = rt(&srv, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(!got.contains("abc"), "{got}");
}

#[test]
fn terugval_wint_van_generieke_route() {
    for get_first in [true, false] {
        let srv = if get_first {
            tagged_mux(&[("GET /x", "get"), ("/x", "elk")])
        } else {
            tagged_mux(&[("/x", "elk"), ("GET /x", "get")])
        };
        let got = rt(
            &srv,
            "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(
            got.contains("X-Handler: get"),
            "GET eerst={get_first}: {got}"
        );
    }
}

#[test]
fn mux_slash_is_een_ander_pad() {
    let srv = tagged_mux(&[("/admin", "publiek"), ("/admin/", "beveiligd")]);
    for (pad, want) in [
        ("/admin", "X-Handler: publiek"),
        ("/admin/", "X-Handler: beveiligd"),
        ("/admin/x", "X-Handler: beveiligd"),
    ] {
        let got = rt(
            &srv,
            &format!("GET {pad} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains(want), "{pad}: {got}");
    }
    let srv = tagged_mux(&[("GET /health", "gezond")]);
    let got = rt(
        &srv,
        "GET /health/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.contains("404"), "{got}");
}

#[test]
fn ambigue_escapes_worden_geweigerd() {
    let mut m = crate::Mux::new();
    m.handle("GET /objects/{key}", "key").unwrap();
    m.handle("GET /admin", "admin").unwrap();
    let m = Rc::new(m);
    let srv = h!(ex => {
        match m.dispatch(ex).await? {
            Some(&"key") => {
                let k = ex.req.path_value("key").unwrap_or("").to_string();
                ex.header_mut().set("X-Key", &k)?;
            }
            Some(tag) => ex.header_mut().set("X-Handler", tag)?,
            None => {}
        }
    });
    for (name, pad) in [
        ("escaped slash", "/objects/secret%2Fmetadata"),
        ("escaped dots", "/objects/%2E%2E"),
        ("dots plus pad", "/objects/%2e%2e%2fgeheim"),
    ] {
        let got = rt(
            &srv,
            &format!("GET {pad} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains("400"), "{name}: {got}");
    }
    let got = rt(
        &srv,
        "GET /%61dmin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.contains("X-Handler: admin"), "{got}");
}

#[test]
fn middleware_en_mux_zien_hetzelfde_pad() {
    let mut m = crate::Mux::new();
    m.handle("/admin", "admin").unwrap();
    m.handle("/intern", "intern").unwrap();
    let m = Rc::new(m);
    let saw = Rc::new(RefCell::new(String::new()));
    let s = saw.clone();
    let srv = h!(ex => {
        *s.borrow_mut() = ex.req.path.clone();
        if ex.req.path == "/admin" {
            ex.req.path = "/intern".to_string();
        }
        if let Some(tag) = m.dispatch(ex).await? {
            ex.header_mut().set("X-Handler", tag)?;
        }
    });
    let got = rt(
        &srv,
        "GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(*saw.borrow(), "/admin");
    assert!(got.contains("X-Handler: intern"), "{got}");
}

#[test]
fn lege_framingheader_verdwijnt_niet() {
    for (name, req) in [
        (
            "lege plus echte CL",
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\r\nContent-Length: 5\r\n\r\nAAAAA",
        ),
        (
            "dubbele TE",
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ),
    ] {
        let got = rt(&drain_ok2(), req);
        assert!(got.contains("400"), "{name}: {got}");
    }
}

#[test]
fn een_regel_per_headernaam() {
    let srv = h!(ex => {
        ex.header_mut().append("content-length", "2")?;
        ex.header_mut().append("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    let got = rt(&srv, GET_CLOSE);
    assert_eq!(
        got.to_lowercase().matches("content-length:").count(),
        1,
        "{got}"
    );
}

#[test]
fn hijack_na_gebufferde_write_weigert() {
    let res = Rc::new(Cell::new(None));
    let r = res.clone();
    let srv = h!(ex => {
        ex.write(b"x").await?;
        r.set(Some(ex.hijack().err()));
    });
    rt(&srv, GET_CLOSE);
    assert_eq!(res.get(), Some(Some(Error::ResponseStarted)));
}

#[test]
fn handler_connection_close_wint() {
    let srv = h!(ex => {
        ex.header_mut().set("Connection", "close")?;
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    let got = rt(&srv, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        got.contains("Connection: close") && !got.contains("keep-alive"),
        "{got}"
    );
}

#[test]
fn expect_is_een417() {
    for expect in ["100-continue", "iets-anders"] {
        let got = rt(
            &never(),
            &format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: {expect}\r\n\r\n"),
        );
        assert!(
            got.contains("417") && got.contains("Connection: close"),
            "{expect}: {got}"
        );
    }
}

#[test]
fn head_houdt_expliciete_lengte() {
    let srv = h!(ex => { ex.header_mut().set("Content-Length", "1234")?; });
    let got = rt(
        &srv,
        "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.contains("Content-Length: 1234"), "{got}");
}

#[test]
fn rest_houdt_sluitende_slash() {
    let mut m = crate::Mux::new();
    m.handle("GET /files/{p...}", ()).unwrap();
    let m = Rc::new(m);
    let srv = h!(ex => {
        if m.dispatch(ex).await?.is_some() {
            let p = format!("[{}]", ex.req.path_value("p").unwrap_or(""));
            ex.header_mut().set("X-P", &p)?;
        }
    });
    for (pad, want) in [
        ("/files/a/", "X-P: [a/]"),
        ("/files/a", "X-P: [a]"),
        ("/files/", "X-P: []"),
    ] {
        let got = rt(
            &srv,
            &format!("GET {pad} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains(want), "{pad}: {got}");
    }
}

#[test]
fn alleen_origin_form() {
    for (name, req) in [
        (
            "absolute-form (vreemde host)",
            "GET http://evil/ HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n",
        ),
        (
            "absolute-form (zelfde host)",
            "GET http://goed/pad HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n",
        ),
        (
            "asterisk-form (OPTIONS *)",
            "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ),
    ] {
        let got = rt(&ok2(), req);
        assert!(got.contains("400"), "{name}: {got}");
    }
    for req in [
        "CONNECT ergens:443 HTTP/1.1\r\nHost: ergens\r\nConnection: close\r\n\r\n",
        "CONNECT / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ] {
        assert!(rt(&ok2(), req).contains("501"));
    }
    assert!(
        rt(
            &ok2(),
            "GET /pad HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n"
        )
        .contains("200")
    );
}

#[test]
fn specifiek_wint_ongeacht_volgorde() {
    for general_first in [true, false] {
        let srv = if general_first {
            tagged_mux(&[("/", "wortel"), ("/{x}/{rest...}", "diep")])
        } else {
            tagged_mux(&[("/{x}/{rest...}", "diep"), ("/", "wortel")])
        };
        let got = rt(
            &srv,
            "GET /a/b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(
            got.contains("X-Handler: diep"),
            "algemeen eerst={general_first}: {got}"
        );
    }
}

#[test]
fn conflicterende_casevarianten_sluiten() {
    let srv = h!(ex => {
        ex.header_mut().append("Content-Length", "2")?;
        ex.header_mut().append("content-length", "5")?;
        ex.write(b"ok").await?;
    });
    let got = rt(&srv, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        got.to_lowercase().matches("content-length:").count(),
        0,
        "{got}"
    );
    assert!(
        got.contains("Connection: close") && got.ends_with("ok"),
        "{got}"
    );
}

#[test]
fn write_is_een_commit() {
    let srv = h!(ex => {
        ex.write(b"ok").await?;
        ex.write_header(500)?;
    });
    assert!(rt(&srv, GET_CLOSE).contains(" 200 "));
    let res = Rc::new(Cell::new(None));
    let r = res.clone();
    let srv = h!(ex => {
        ex.write_header(200)?;
        r.set(Some(ex.hijack().err()));
    });
    rt(&srv, GET_CLOSE);
    assert_eq!(res.get(), Some(Some(Error::ResponseStarted)));
}

#[test]
fn http10_wordt_geweigerd() {
    assert!(rt(&ok2(), "GET / HTTP/1.0\r\n\r\n").contains("505"));
}

#[test]
fn server_randvormen() {
    let mut m = crate::Mux::new();
    m.handle("GET /x", ()).unwrap();
    m.handle("PUT /x", ()).unwrap();
    let m = Rc::new(m);
    let srv = h!(ex => {
        if m.dispatch(ex).await?.is_some() {
            ex.header_mut().set("Content-Length", "2")?;
            ex.write(b"ok").await?;
        }
    });
    let got = rt(
        &srv,
        "DELETE /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    );
    assert!(
        got.contains("405") && got.contains("Allow: GET, HEAD, PUT"),
        "{got}"
    );
    for host in ["h.example:8080", "[::1]:80", "10.0.0.1", "a,b"] {
        let got = rt(
            &srv,
            &format!("GET /x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains("200"), "{host}: {got}");
    }
    assert!(
        rt(
            &srv,
            "OPTIONS * HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"
        )
        .contains("400")
    );
}

#[test]
fn write_header_panickt_op_onzin() {
    // In Go een panic; hier een fout, want bibliotheekcode panict niet.
    let res = Rc::new(RefCell::new(Vec::new()));
    let r = res.clone();
    let srv = h!(ex => {
        for status in [0u16, 1000, 100, 101, 103, 199, 600] {
            r.borrow_mut().push(ex.write_header(status));
        }
    });
    rt(&srv, GET_CLOSE);
    let res = res.borrow();
    assert_eq!(res.len(), 7);
    for (r, s) in res.iter().zip([0u16, 1000, 100, 101, 103, 199, 600]) {
        assert_eq!(*r, Err(Error::InvalidStatus(s)));
    }
}

#[test]
fn drain_voor_nette_close() {
    block_on(async {
        let (mut c, s) = pipe();
        ok2()(s);
        write_all(
            &mut c,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nha",
        )
        .await
        .unwrap();
        let mut got = String::new();
        let mut buf = [0u8; 512];
        while !got.ends_with("ok") {
            let n = read(&mut c, &mut buf).await.unwrap();
            assert!(n > 0, "antwoord afgebroken na {got:?}");
            got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        assert!(got.contains(" 200 "), "{got}");
        write_all(&mut c, b"lf")
            .await
            .expect("de server sloot zonder de body te drainen");
        assert_eq!(
            read(&mut c, &mut buf).await,
            Ok(0),
            "verwachtte de close na de drain"
        );
    });
}

#[test]
fn chunked_gooit_content_length_weg() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "")?;
        ex.write(b"stuk1").await?;
        ex.flush().await?;
        ex.write(b"stuk2").await?;
    });
    let got = rt(&srv, GET_CLOSE);
    assert!(got.contains("Transfer-Encoding: chunked"), "{got}");
    assert!(!got.to_lowercase().contains("content-length"), "{got}");
}

#[test]
fn done_en_hijack_sluiten_elkaar_uit() {
    let res = Rc::new(RefCell::new(Vec::new()));
    let r = res.clone();
    let srv = h!(ex => {
        if ex.req.path == "/done" {
            ex.claim_done().await?;
            r.borrow_mut().push(ex.hijack().err());
        } else {
            ex.hijack()?;
            let v = ex.claim_done().await.err();
            r.borrow_mut().push(v);
        }
    });
    rt(&srv, "GET /done HTTP/1.1\r\nHost: x\r\n\r\n");
    rt(&srv, "GET /hijack HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        *res.borrow(),
        vec![Some(Error::DoneClaimed), Some(Error::Hijacked)]
    );
}

#[test]
fn done_claimt_voor_de_start() {
    let res = Rc::new(RefCell::new(Vec::new()));
    let r = res.clone();
    let srv = h!(ex => {
        match ex.req.path.as_str() {
            "/kop" => {
                ex.write_header(200)?;
                ex.flush().await?;
                let v = ex.claim_done().await;
                r.borrow_mut().push(("kop al verstuurd", v));
            }
            "/body" => {
                // Een ongelezen body wordt weggeveegd, niet geweigerd.
                let v = ex.claim_done().await;
                r.borrow_mut().push(("ongelezen body", v));
                let v = ex.read_body(&mut [0u8; 4]).await.map(|_| ());
                r.borrow_mut().push(("body leeg", v));
            }
            _ => {
                ex.claim_done().await?;
                ex.flush().await?;
                let v = ex.claim_done().await;
                r.borrow_mut().push(("herhaald", v));
            }
        }
    });
    rt(&srv, "GET /kop HTTP/1.1\r\nHost: x\r\n\r\n");
    rt(
        &srv,
        "POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nxx",
    );
    rt(&srv, "GET /herhaal HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        *res.borrow(),
        vec![
            ("kop al verstuurd", Err(Error::DoneAfterStart)),
            ("ongelezen body", Ok(())),
            ("body leeg", Ok(())),
            ("herhaald", Ok(())),
        ]
    );
}

#[test]
fn niet_canoniek_is_een400() {
    for pad in ["//admin", "/a//b", "/a//"] {
        let got = rt(
            &ok2(),
            &format!("GET {pad} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(got.contains("400"), "{pad}: {got}");
    }
    assert!(
        rt(
            &ok2(),
            "GET /a/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .contains("200")
    );
}

#[test]
fn done_overleeft_een_body_van_buiten() {
    let srv = h!(ex => {
        ex.claim_done().await?;
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    let got = rt(
        &srv,
        "GET /stream HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nX",
    );
    assert!(got.contains(" 200 "), "{got}");
}

#[test]
fn request_context() {
    // Go's Request.Context is in Rust het wachten op done(): hij eindigt
    // wanneer de client weggaat, en niet eerder.
    let ended = Rc::new(Cell::new(false));
    let e = ended.clone();
    let srv = h!(ex => {
        ex.claim_done().await?;
        ex.flush().await?;
        ex.done().await?;
        e.set(true);
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        sleep(Duration::from_millis(50)).await;
        assert!(
            !e_get(&ended),
            "de lifetime eindigde terwijl de client er nog is"
        );
        drop(c);
        sleep(Duration::from_secs(2)).await;
    });
    assert!(ended.get(), "done eindigde niet toen de client wegging");
}

fn e_get(c: &Rc<Cell<bool>>) -> bool {
    c.get()
}

#[test]
fn handler_fout_is_een500() {
    // Rust-toevoeging: een handler die faalt vóór het antwoord, levert een
    // 500 en een gesloten verbinding.
    let srv = h!(ex => {
        let _ = &ex.req;
        return Err(Error::Alloc { bytes: 1 });
    });
    let got = rt(&srv, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        got.starts_with("HTTP/1.1 500") && got.contains("Connection: close"),
        "{got}"
    );
}

#[test]
fn drain_voor_hergebruik() {
    // Rust-toevoeging: een ongelezen body wordt weggeveegd vóór het volgende
    // verzoek, zodat dat op zijn eigen regel begint.
    let srv = h!(ex => {
        let p = ex.req.path.clone();
        ex.write(p.as_bytes()).await?;
    });
    let got = rt(
        &srv,
        "POST /een HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nGET /\
         GET /twee HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(got.matches("HTTP/1.1 200").count(), 2, "{got}");
    assert!(got.ends_with("/twee"), "{got}");
}

#[test]
fn onbekende_lengte_boven_64k_wordt_chunked() {
    // Rust-toevoeging: KAM zegt tot 64 KiB bufferen, daarna chunked.
    let srv = h!(ex => {
        let n: usize = ex.req.path[1..].parse().unwrap();
        ex.write(&vec![b'x'; n]).await?;
    });
    let got = rt(
        &srv,
        &format!(
            "GET /{} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            crate::AUTO_CHUNK_BYTES
        ),
    );
    assert!(
        got.contains(&format!("Content-Length: {}", crate::AUTO_CHUNK_BYTES)),
        "{}",
        split(&got).0
    );
    let got = rt(
        &srv,
        &format!(
            "GET /{} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            crate::AUTO_CHUNK_BYTES + 1
        ),
    );
    let head = split(&got).0;
    assert!(
        head.contains("Transfer-Encoding: chunked") && !head.contains("Content-Length"),
        "{head}"
    );
    assert!(got.ends_with("0\r\n\r\n"));
}

#[test]
fn recorder() {
    // Go's Recorder bestaat hier niet (een handlertest draait serve over een
    // testpijp); de helft over NewRequest wel: Request::new bouwt alleen wat
    // de server ook zou aannemen.
    let r = crate::Request::new("POST", "/caf%C3%A9?x=2").unwrap();
    assert_eq!(r.path, "/café");
    assert_eq!(r.query("x").unwrap().as_deref(), Some("2"));
    let mut r = r;
    r.set_path_values(vec![("id".to_string(), "b".to_string())]);
    assert_eq!(r.path_value("id"), Some("b"));
    for target in ["/a//b", "/a%2Fb"] {
        assert!(crate::Request::new("GET", target).is_err(), "{target}");
    }
}

// ---- reader_gone en stream: een lange response en een lezer die weggaat ----

/// Een bron met een vast script; is het op, dan "niets". Telt de dutjes.
struct Script {
    steps: Vec<crate::Next>,
    naps: u32,
}

impl crate::Source for Script {
    async fn next(&mut self) -> crate::Next {
        if self.steps.is_empty() {
            crate::Next::Nothing
        } else {
            self.steps.remove(0)
        }
    }

    async fn nap(&mut self) {
        self.naps += 1;
        sleep(Duration::from_millis(500)).await;
    }
}

/// Een bron die altijd iets heeft en nooit ophoudt.
struct Forever {
    sent: u32,
}

impl crate::Source for Forever {
    async fn next(&mut self) -> crate::Next {
        self.sent += 1;
        crate::Next::Data(b"data: tik\n\n".to_vec())
    }

    async fn nap(&mut self) {}
}

/// Leest tot de server sluit.
async fn read_rest(c: &mut End) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match read(c, &mut buf).await {
            Ok(0) | Err(_) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

#[test]
fn reader_gone_ziet_de_client_vertrekken_en_niets_anders() {
    let rounds = Rc::new(Cell::new(0u32));
    let r = rounds.clone();
    let srv = h!(ex => {
        ex.claim_done().await?;
        ex.write(b"hoi\n").await?;
        ex.flush().await?;
        while !ex.reader_gone().await {
            r.set(r.get() + 1);
            sleep(Duration::from_millis(500)).await;
        }
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut c).await.unwrap();
        assert!(head.contains("Connection: close"), "{head}");
        let mut buf = [0u8; 16];
        read(&mut c, &mut buf).await.unwrap();
        // De lezer blijft even stil, stuurt dan iets (geen vertrek), en
        // gaat daarna pas weg.
        sleep(Duration::from_secs(2)).await;
        write_all(&mut c, b"nog hier").await.unwrap();
        sleep(Duration::from_secs(1)).await;
        drop(c);
        sleep(Duration::from_secs(2)).await;
    });
    // Drie seconden aanwezig, een ronde per halve seconde: stilte noch
    // bytes golden als vertrek.
    assert!((5..=8).contains(&rounds.get()), "{} rondes", rounds.get());
}

#[test]
fn reader_gone_zonder_wachter_is_nooit_weg() {
    let saw = Rc::new(Cell::new(None));
    let s2 = saw.clone();
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
        s2.set(Some(ex.reader_gone().await));
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, GET_CLOSE.as_bytes()).await.unwrap();
        drop(c);
        sleep(Duration::from_secs(1)).await;
    });
    assert_eq!(saw.get(), Some(false));
}

#[test]
fn stream_pompt_elk_stuk_meteen_tot_het_einde() {
    let naps = Rc::new(Cell::new(0u32));
    let n = naps.clone();
    let srv = h!(ex => {
        ex.header_mut().set("Content-Type", "text/event-stream")?;
        let mut src = Script {
            steps: vec![
                crate::Next::Data(b"data: 1\n\n".to_vec()),
                crate::Next::Nothing,
                crate::Next::Data(b"data: 2\n\n".to_vec()),
                crate::Next::End,
            ],
            naps: 0,
        };
        ex.stream(200, &mut src).await?;
        n.set(src.naps);
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut c).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("Connection: close"), "{head}");
        assert!(head.contains("text/event-stream"), "{head}");
        assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
        let body = String::from_utf8(read_rest(&mut c).await).unwrap();
        let one = body.find("data: 1\n\n").expect("eerste stuk");
        assert!(body[one..].contains("data: 2\n\n"), "{body}");
        // Het einde van de bron sluit de stroom netjes af.
        assert!(body.ends_with("0\r\n\r\n"), "{body}");
    });
    assert_eq!(naps.get(), 1);
}

#[test]
fn stream_stopt_zodra_de_lezer_weggaat() {
    let outcome = Rc::new(Cell::new(None));
    let o = outcome.clone();
    let srv = h!(ex => {
        let mut src = Forever { sent: 0 };
        let r = ex.stream(200, &mut src).await;
        o.set(Some((r.is_ok(), src.sent)));
    });
    block_on(async {
        let (mut c, s) = pipe();
        srv(s);
        write_all(&mut c, b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        read_head(&mut c).await.unwrap();
        let mut buf = [0u8; 64];
        read(&mut c, &mut buf).await.unwrap();
        drop(c);
        sleep(Duration::from_secs(1)).await;
    });
    let (ok, sent) = outcome.get().expect("de stroom eindigde niet");
    // Een vertrokken lezer is geen fout, en de bron is niet leeggepompt.
    assert!(ok);
    assert!(sent < 100, "{sent} stukken naar een lezer die weg was");
}
