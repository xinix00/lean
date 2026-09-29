//! Clienttests: leanhttp_test.go en de clientkant van review13_test.go.
//!
//! Go's `Call.Context` en `Call.Timeout` zijn hier een `select` met een timer
//! rond de future; een test die in Go een annulering bewees, bewijst hier dat
//! de gevallen future zijn verbinding of dial meeneemt.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use super::h;
use super::support::*;
use crate::{
    AsyncRead, Call, Dial, Error, Header, IoError, Response, Target, fetch, get, read, send,
    write_all,
};

fn net(addr: &str, h: Handler) -> Net {
    let n = Net::new();
    n.add(addr, h);
    n
}

async fn body(resp: &mut Response<End>) -> Result<Vec<u8>, Error> {
    resp.read_to_end(1 << 24).await
}

fn call(url: &str) -> Call<'_> {
    Call {
        url,
        ..Call::default()
    }
}

/// Een body-stroom uit een slice.
struct Bytes<'a>(&'a [u8]);

impl AsyncRead for Bytes<'_> {
    fn poll_read(&mut self, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, IoError>> {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Poll::Ready(Ok(n))
    }
}

/// Een stroom die niet gelezen mag worden: de server had al afgewezen.
struct NoRead;

impl AsyncRead for NoRead {
    fn poll_read(&mut self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, IoError>> {
        panic!("de stroom werd gelezen terwijl de server al had afgewezen");
    }
}

/// Zet een vlag als hij valt: bewijs dat een future geannuleerd is.
struct DropFlag(Rc<Cell<bool>>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

/// Een dialer die nooit klaar is; zijn future meldt het als hij valt.
struct BlackHole(Rc<Cell<bool>>);

impl Dial for BlackHole {
    type Conn = End;

    async fn dial(&mut self, _: Target<'_>) -> crate::Result<End> {
        let _flag = DropFlag(self.0.clone());
        sleep(Duration::from_secs(1 << 20)).await;
        Err(Error::Io(IoError::TimedOut))
    }
}

#[test]
fn call_context_annuleert_dial() {
    let dropped = Rc::new(Cell::new(false));
    let mut d = BlackHole(dropped.clone());
    block_on(async {
        let r = select(
            fetch(&mut d, call("http://cancel-dial.test/")),
            sleep(Duration::from_secs(1)),
        )
        .await;
        assert!(matches!(r, Either::Right(())));
    });
    assert!(dropped.get(), "de annulering bereikte de dial niet");
}

#[test]
fn call_context_annuleert_actieve_io() {
    let closed = Rc::new(Cell::new(false));
    let c = closed.clone();
    let n = net(
        "context.test:80",
        script(move |mut conn| {
            let c = c.clone();
            async move {
                read_head(&mut conn).await;
                read_all(&mut conn).await;
                c.set(true);
            }
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let r = select(
            fetch(&mut d, call("http://context.test/")),
            sleep(Duration::from_secs(1)),
        )
        .await;
        assert!(matches!(r, Either::Right(())));
        sleep(Duration::from_millis(10)).await;
    });
    assert!(closed.get(), "de gevallen call sloot zijn verbinding niet");
}

#[test]
fn call_context_stopt_callback_voor_pool_reuse() {
    let n = net(
        "pool.test:80",
        script(|mut conn| async move {
            for _ in 0..2 {
                if read_head(&mut conn).await.is_none() {
                    return;
                }
                let _ = write_all(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
            }
            read_all(&mut conn).await;
        }),
    );
    block_on(async {
        let mut cl = crate::Client::new(n.clone());
        let r = cl.send(call("http://pool.test/een"), now()).await.unwrap();
        cl.finish(r, now()).await;
        let r = cl.send(call("http://pool.test/twee"), now()).await.unwrap();
        assert_eq!(r.status, 200);
        cl.finish(r, now()).await;
    });
    assert_eq!(
        n.accepted("pool.test:80"),
        1,
        "wil één hergebruikte verbinding"
    );
}

#[test]
fn call_context_annuleert_response_body() {
    let closed = Rc::new(Cell::new(false));
    let c = closed.clone();
    let n = net(
        "body.test:80",
        script(move |mut conn| {
            let c = c.clone();
            async move {
                read_head(&mut conn).await;
                let _ =
                    write_all(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx").await;
                read_all(&mut conn).await;
                c.set(true);
            }
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://body.test/")).await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(resp.read(&mut buf).await, Ok(1));
        let r = select(resp.read(&mut buf), sleep(Duration::from_secs(1))).await;
        assert!(matches!(r, Either::Right(())));
        assert!(resp.release().await.is_none());
        sleep(Duration::from_millis(10)).await;
    });
    assert!(closed.get());
}

#[test]
fn gewone_get() {
    let n = net(
        "srv:80",
        h!(ex => {
            assert_eq!(ex.req.method, "GET");
            assert!(ex.req.header.get("Host").is_some());
            ex.write(b"hallo").await?;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = get(&mut d, "http://srv/").await.unwrap();
        assert_eq!(resp.length, Some(5));
        assert_eq!(body(&mut resp).await.unwrap(), b"hallo");
    });
}

#[test]
fn grote_body_wordt_niet_afgekapt() {
    let want: Vec<u8> = b"0123456789abcdef".repeat(20_000);
    let w = want.clone();
    let n = net(
        "srv:80",
        h!(ex => {
            ex.header_mut().set("Content-Length", &w.len().to_string())?;
            ex.write(&w).await?;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = get(&mut d, "http://srv/").await.unwrap();
        assert_eq!(resp.length, Some(want.len() as u64));
        assert_eq!(body(&mut resp).await.unwrap(), want);
    });
}

#[test]
fn redirect_wordt_gevolgd() {
    let n = net(
        "doel:80",
        h!(ex => {
            match ex.req.path.as_str() {
                "/een" => ex.redirect("http://doel/twee", 302).await?,
                "/twee" => ex.redirect("/drie", 301).await?,
                "/drie" => { ex.write(b"aangekomen").await?; }
                p => panic!("onverwacht pad {p}"),
            }
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = get(&mut d, "http://doel/een").await.unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"aangekomen");
    });
}

#[test]
fn redirect_lus_stopt() {
    let n = net("srv:80", h!(ex => { ex.redirect("/rond", 302).await?; }));
    block_on(async {
        let mut d = n.clone();
        let err = get(&mut d, "http://srv/").await.unwrap_err();
        assert_eq!(err, Error::TooManyRedirects { max: 10 });
        assert!(err.to_string().contains("too many redirects"));
    });
}

#[test]
fn https_weigert_luid() {
    block_on(async {
        let err = get(&mut NoDial, "https://example.com/app.elf")
            .await
            .unwrap_err();
        assert_eq!(err, Error::HttpsNeedsTls);
        for want in ["TLS", "Dial", "leanhttps"] {
            assert!(err.to_string().contains(want), "{err} moet {want} noemen");
        }
    });
}

#[test]
fn dial_hook_stuurt_om() {
    let mut n = net(
        "artifacts.example:443",
        h!(ex => {
            assert_eq!(ex.req.header.get("Host"), Some("artifacts.example"));
            ex.write(b"payload").await?;
        }),
    );
    n.tls = true;
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("https://artifacts.example/app.elf"))
            .await
            .unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"payload");
    });
    assert_eq!(*n.last.borrow(), "artifacts.example:443");
}

fn raw_get(answer: &'static str) -> Result<Response<End>, Error> {
    let n = net("srv:80", raw(answer));
    block_on(async move {
        let mut d = n.clone();
        get(&mut d, "http://srv/").await
    })
}

/// Status en lengte, of de fout van de kop.
type Head = Result<(u16, Option<u64>), Error>;

fn raw_fetch(answer: &'static str, method: &'static str) -> (Head, Result<Vec<u8>, Error>) {
    let n = net("srv:80", raw(answer));
    block_on(async move {
        let mut d = n.clone();
        match fetch(
            &mut d,
            Call {
                method,
                ..call("http://srv/")
            },
        )
        .await
        {
            Ok(mut r) => {
                let b = body(&mut r).await;
                (Ok((r.status, r.length)), b)
            }
            Err(e) => (Err(e), Ok(Vec::new())),
        }
    })
}

#[test]
fn chunked_weigert() {
    let err =
        raw_get("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n0\r\n\r\n")
            .unwrap_err();
    assert_eq!(err, Error::ChunkedNotAllowed);
    assert!(err.to_string().contains("chunked"));
}

#[test]
fn zonder_content_length_weigert() {
    let err = raw_get("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nhallo")
        .unwrap_err();
    assert_eq!(err, Error::NoContentLength);
}

#[test]
fn dubbele_content_length_weigert() {
    let err = raw_get("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhallo")
        .unwrap_err();
    assert_eq!(err, Error::DuplicateContentLength);
}

#[test]
fn foutstatus_geeft_fout() {
    let n = net("srv:80", h!(ex => { ex.error(404, "weg").await?; }));
    block_on(async {
        let mut d = n.clone();
        let err = get(&mut d, "http://srv/").await.unwrap_err();
        assert_eq!(err, Error::Status(404));
        assert!(err.to_string().contains("404"));
    });
}

#[test]
fn kromge_statusregel_weigert() {
    assert_eq!(
        raw_get("ik ben geen http\r\n\r\n").unwrap_err(),
        Error::MalformedStatusLine
    );
}

#[test]
fn te_lange_headerregel_weigert() {
    let answer: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nX-Groot: {}\r\nContent-Length: 1\r\n\r\nx",
            "A".repeat(crate::BUF_SIZE + 1)
        )
        .into_boxed_str(),
    );
    assert_eq!(
        raw_get(answer).unwrap_err(),
        Error::LineTooLong {
            limit: crate::BUF_SIZE
        }
    );
}

#[test]
fn te_veel_headerbytes_weigert() {
    let mut b = String::from("HTTP/1.1 200 OK\r\n");
    let mut i = 0;
    while b.len() < crate::MAX_HEADER_BYTES + 1024 {
        b.push_str(&format!("X-Vul-{i}: {}\r\n", "v".repeat(200)));
        i += 1;
    }
    b.push_str("Content-Length: 1\r\n\r\nx");
    let answer: &'static str = Box::leak(b.into_boxed_str());
    assert_eq!(
        raw_get(answer).unwrap_err(),
        Error::HeadersTooLarge {
            limit: crate::MAX_HEADER_BYTES
        }
    );
}

#[test]
fn geen_host_weigert() {
    block_on(async {
        assert_eq!(
            get(&mut NoDial, "http:///app.elf").await.unwrap_err(),
            Error::NoHost
        );
    });
}

#[test]
fn do_post() {
    let n = net(
        "srv:80",
        h!(ex => {
            let b = ex.read_body_to_end().await?;
            assert_eq!((ex.req.method.as_str(), b.as_slice()), ("POST", &b"{\"n\":1}"[..]));
            assert_eq!(ex.req.header.get("X-Hop-Auth"), Some("abc"));
            assert_eq!(ex.req.header.get("Content-Type"), Some("application/json"));
            assert_eq!(ex.req.content_length, Some(7));
            ex.error(409, "job locked").await?;
        }),
    );
    block_on(async {
        let mut header = Header::new();
        header.set("Content-Type", "application/json").unwrap();
        header.set("X-Hop-Auth", "abc").unwrap();
        let mut d = n.clone();
        let mut resp = fetch(
            &mut d,
            Call {
                method: "POST",
                url: "http://srv/v1/jobs",
                header,
                body: Some(b"{\"n\":1}"),
                ..Call::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 409, "een foutstatus is geen transportfout");
        assert!(
            String::from_utf8(body(&mut resp).await.unwrap())
                .unwrap()
                .contains("job locked")
        );
    });
}

#[test]
fn do_leest_chunked() {
    let n = net(
        "srv:80",
        h!(ex => {
            for i in 0..3 {
                ex.write(format!("data: regel {i}\n").as_bytes()).await?;
                ex.flush().await?;
            }
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        assert_eq!(resp.length, None);
        assert_eq!(
            body(&mut resp).await.unwrap(),
            b"data: regel 0\ndata: regel 1\ndata: regel 2\n"
        );
    });
}

#[test]
fn do_stream_stopt_op_close() {
    let gone = Rc::new(Cell::new(false));
    let g = gone.clone();
    let n = net(
        "srv:80",
        h!(ex => {
            ex.claim_done().await?;
            ex.write(b"eerste\n").await?;
            ex.flush().await?;
            ex.done().await?;
            g.set(true);
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        let mut buf = [0u8; 7];
        let got = resp.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..got], b"eerste\n");
        assert!(resp.release().await.is_none());
        sleep(Duration::from_secs(1)).await;
    });
    assert!(gone.get(), "de server merkte niet dat de client ophing");
}

#[test]
fn do_timeout() {
    let n = net("srv:80", h!(ex => { ex.done().await?; }));
    block_on(async {
        let mut d = n.clone();
        let r = select(
            fetch(&mut d, call("http://srv/")),
            sleep(Duration::from_millis(300)),
        )
        .await;
        assert!(
            matches!(r, Either::Right(())),
            "een zwijgende server hoort op de termijn te stuiten"
        );
        assert!(now() < Duration::from_secs(5));
    });
}

#[test]
fn do_weigert_gesmokkelde_headers() {
    for (name, k, v) in [
        ("eigen Host", "Host", "elders"),
        ("eigen lengte", "Content-Length", "0"),
        ("CRLF in waarde", "X-Iets", "a\r\nX-Gesmokkeld: b"),
    ] {
        let mut header = Header::new();
        header.set(k, v).unwrap();
        let r = block_on(fetch(
            &mut NoDial,
            Call {
                header,
                ..call("http://127.0.0.1:1/")
            },
        ));
        assert!(r.is_err(), "{name}: werd geaccepteerd");
    }
}

#[test]
fn response_url_na_redirect() {
    let n = net(
        "srv:80",
        h!(ex => {
            if ex.req.path == "/start" {
                return ex.redirect("/hier/", 302).await;
            }
            ex.write(b"aangekomen").await?;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let resp = fetch(&mut d, call("http://srv/start")).await.unwrap();
        assert_eq!(resp.url, "http://srv/hier/");
    });
}

#[test]
fn no_follow_geeft_de3xx() {
    let n = net(
        "srv:80",
        raw(
            "HTTP/1.1 302 Found\r\nSet-Cookie: consent=1; Path=/\r\nLocation: /verder\r\nContent-Length: 0\r\n\r\n",
        ),
    );
    block_on(async {
        let mut d = n.clone();
        let resp = fetch(
            &mut d,
            Call {
                no_follow: true,
                ..call("http://srv/start")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 302, "no_follow volgde alsnog");
        assert_eq!(resp.header.get("Location"), Some("/verder"));
        assert_eq!(resp.set_cookie.len(), 1);
        assert_eq!(resp.url, "http://srv/start");
    });
}

/// Een server die op `Expect` een 100 geeft, de body leest en `status` stuurt.
fn continue_server(status: u16, seen: Rc<RefCell<(String, Vec<u8>)>>) -> Handler {
    script(move |mut conn| {
        let seen = seen.clone();
        async move {
            let Some(head) = read_head(&mut conn).await else {
                return;
            };
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let _ = write_all(&mut conn, b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while got.len() < len {
                match read(&mut conn, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            *seen.borrow_mut() = (head, got);
            let answer = if status == 302 {
                "HTTP/1.1 302 Found\r\nLocation: /nieuw\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n")
            };
            let _ = write_all(&mut conn, answer.as_bytes()).await;
            read_all(&mut conn).await;
        }
    })
}

#[test]
fn body_reader_streamt() {
    const PAYLOAD: &[u8] = b"dit-zijn-de-bytes-van-een-artifact";
    let seen = Rc::new(RefCell::new((String::new(), Vec::new())));
    let n = net("srv:80", continue_server(201, seen.clone()));
    block_on(async {
        let mut d = n.clone();
        let mut src = Bytes(PAYLOAD);
        let resp = fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: PAYLOAD.len() as u64,
                ..call("http://srv/object")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 201);
    });
    let (head, got) = seen.borrow().clone();
    assert_eq!(got, PAYLOAD);
    assert!(
        head.contains(&format!("Content-Length: {}", PAYLOAD.len())),
        "{head}"
    );
    assert!(head.contains("Expect: 100-continue"), "{head}");
}

#[test]
fn body_reader_te_kort() {
    let seen = Rc::new(RefCell::new((String::new(), Vec::new())));
    let n = net("srv:80", continue_server(200, seen));
    block_on(async {
        let mut d = n.clone();
        let mut src = Bytes(b"kort");
        let err = fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: 100,
                ..call("http://srv/object")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, Error::StreamBody { sent: 4, want: 100 });
        assert!(err.to_string().contains("stream body"));
    });
}

#[test]
fn body_reader_en_body_samen() {
    let mut src = Bytes(b"b");
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            method: "PUT",
            body: Some(b"a"),
            body_reader: Some(&mut src),
            body_len: 1,
            ..call("http://127.0.0.1:1/x")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::BodyConflict);
    assert!(err.to_string().contains("not both"));
}

#[test]
fn body_reader_volgt_geen_redirect() {
    let seen = Rc::new(RefCell::new((String::new(), Vec::new())));
    let n = net("srv:80", continue_server(302, seen));
    block_on(async {
        let mut d = n.clone();
        let mut src = Bytes(b"data");
        let resp = fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: 4,
                ..call("http://srv/oud")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 302);
    });
    assert_eq!(n.accepted("srv:80"), 1);
}

#[test]
fn header_timeout_raakt_body_niet() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            read_head(&mut conn).await;
            let _ = write_all(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n").await;
            sleep(Duration::from_millis(400)).await;
            let _ = write_all(&mut conn, b"data").await;
            read_all(&mut conn).await;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(
            &mut d,
            Call {
                header_timeout: Some(Duration::from_millis(150)),
                ..call("http://srv/")
            },
        )
        .await
        .unwrap();
        assert_eq!(
            body(&mut resp)
                .await
                .expect("de body liep op de kop-grens stuk"),
            b"data"
        );
    });
}

#[test]
fn header_timeout_slaat_toe() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            sleep(Duration::from_secs(5)).await;
            drop(read_all(&mut conn));
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let err = fetch(
            &mut d,
            Call {
                header_timeout: Some(Duration::from_millis(200)),
                ..call("http://srv/")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, Error::Io(IoError::TimedOut));
        assert!(
            now() < Duration::from_secs(3),
            "wachtte {:?} op een kop-grens van 200ms",
            now()
        );
    });
}

#[test]
fn bodyless_status_blokkeert_niet() {
    for (code, answer, want) in [
        (
            204,
            "HTTP/1.1 204 Geen\r\nConnection: keep-alive\r\n\r\n",
            Some(0),
        ),
        (
            304,
            "HTTP/1.1 304 Geen\r\nConnection: keep-alive\r\n\r\n",
            None,
        ),
    ] {
        let n = net(
            "srv:80",
            script(move |mut conn| async move {
                read_line(&mut conn).await;
                let _ = write_all(&mut conn, answer.as_bytes()).await;
                sleep(Duration::from_secs(3)).await;
            }),
        );
        block_on(async {
            let mut d = n.clone();
            let r = select(
                async {
                    let mut resp = fetch(
                        &mut d,
                        Call {
                            method: "DELETE",
                            ..call("http://srv/x")
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(resp.status, code);
                    assert!(body(&mut resp).await.unwrap().is_empty());
                    assert_eq!(resp.length, want);
                },
                sleep(Duration::from_secs(2)),
            )
            .await;
            assert!(
                matches!(r, Either::Left(())),
                "status {code}: de body bleef hangen"
            );
        });
    }
}

#[test]
fn body_korter_dan_content_length_is_geen_eof() {
    let (_, b) = raw_fetch("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf!", "");
    assert_eq!(b, Err(Error::UnexpectedEof));
}

#[test]
fn chunked_zonder_nulchunk_is_geen_eof() {
    let n = net(
        "srv:80",
        raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n"),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(resp.read(&mut buf).await, Ok(5));
        assert_eq!(&buf[..5], b"hallo");
        assert_eq!(resp.read(&mut buf).await, Err(Error::UnexpectedEof));
    });
}

#[test]
fn interim_antwoorden_worden_overgeslagen() {
    let (head, b) = raw_fetch(
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
         HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\necht",
        "",
    );
    assert_eq!(head.unwrap().0, 200);
    assert_eq!(b.unwrap(), b"echt");
}

#[test]
fn head_leest_geen_body() {
    let (head, b) = raw_fetch("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", "HEAD");
    assert_eq!(b.unwrap(), b"");
    assert_eq!(
        head.unwrap().1,
        Some(1234),
        "de geadverteerde lengte is informatief"
    );
}

#[test]
fn redirect_stript_authorization_cross_origin() {
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    let n = net(
        "hop:80",
        h!(ex => { ex.redirect("http://localhost:8080/", 302).await?; }),
    );
    n.add(
        "localhost:8080",
        h!(ex => {
            *g.borrow_mut() = Some((
                ex.req.header.get("Authorization").map(str::to_string),
                ex.req.header.get("X-Api-Key").map(str::to_string),
            ));
            ex.write(b"einde").await?;
        }),
    );
    block_on(async {
        let mut header = Header::new();
        header.set("Authorization", "Bearer geheim").unwrap();
        header.set("X-Api-Key", "ook-geheim").unwrap();
        let mut d = n.clone();
        let mut resp = fetch(
            &mut d,
            Call {
                header,
                ..call("http://hop/")
            },
        )
        .await
        .unwrap();
        body(&mut resp).await.unwrap();
    });
    assert_eq!(
        *got.borrow(),
        Some((None, None)),
        "headers kwamen mee naar de andere origin"
    );
}

#[test]
fn redirect_stript_ook_bij_andere_poort() {
    let got = Rc::new(RefCell::new(Some(String::new())));
    let g = got.clone();
    let n = net(
        "h:80",
        h!(ex => { ex.redirect("http://h:81/", 302).await?; }),
    );
    n.add(
        "h:81",
        h!(ex => {
            *g.borrow_mut() = ex.req.header.get("Authorization").map(str::to_string);
            ex.write(b"ok").await?;
        }),
    );
    block_on(async {
        let mut header = Header::new();
        header.set("Authorization", "Bearer geheim").unwrap();
        let mut d = n.clone();
        let mut resp = fetch(
            &mut d,
            Call {
                header,
                ..call("http://h/")
            },
        )
        .await
        .unwrap();
        body(&mut resp).await.unwrap();
    });
    assert_eq!(
        *got.borrow(),
        None,
        "Authorization reisde mee naar een andere poort"
    );
}

#[test]
fn redirect_behoudt_headers_binnen_de_origin() {
    // Rust-toevoeging: de tegenhanger van de twee strip-tests.
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    let n = net(
        "h:80",
        h!(ex => {
            if ex.req.path == "/" {
                return ex.redirect("//h:80/doel", 302).await;
            }
            *g.borrow_mut() = ex.req.header.get("Authorization").map(str::to_string);
            ex.write(b"ok").await?;
        }),
    );
    block_on(async {
        let mut header = Header::new();
        header.set("Authorization", "Bearer x").unwrap();
        let mut d = n.clone();
        let mut resp = fetch(
            &mut d,
            Call {
                header,
                ..call("http://h/")
            },
        )
        .await
        .unwrap();
        body(&mut resp).await.unwrap();
    });
    assert_eq!(got.borrow().as_deref(), Some("Bearer x"));
}

#[test]
fn client_weigert_vreemde_te_in_respons() {
    let (head, _) = raw_fetch(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nrommel",
        "",
    );
    let err = head.unwrap_err();
    assert_eq!(err, Error::UnsupportedTransferEncoding);
    assert!(err.to_string().contains("Transfer-Encoding"));
}

#[test]
fn redirect_naar_https_gaat_nooit_plaintext() {
    let leaked = Rc::new(Cell::new(false));
    let l = leaked.clone();
    let n = net(
        "hop:80",
        h!(ex => { ex.redirect("https://secure:443/", 301).await?; }),
    );
    n.add(
        "secure:443",
        script(move |_| {
            let l = l.clone();
            async move { l.set(true) }
        }),
    );
    block_on(async {
        let mut header = Header::new();
        header.set("Authorization", "Bearer geheim").unwrap();
        let mut d = n.clone();
        let err = fetch(
            &mut d,
            Call {
                header,
                ..call("http://hop/")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, Error::HttpsNeedsTls);
    });
    assert!(!leaked.get(), "plaintext op de https-poort");
}

#[test]
fn call_method_injectie_geweigerd() {
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            method: "GET / HTTP/1.1\r\nX-Evil: 1\r\n\r\nGET",
            ..call("http://127.0.0.1:1/")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::InvalidMethod);
}

#[test]
fn uitgaande_headernaam_strikt() {
    let mut header = Header::new();
    header.set("X-Bad\theader", "v").unwrap();
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            header,
            ..call("http://127.0.0.1:1/")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::IllegalHeaderName);
    let (head, _) = raw_fetch(
        "HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 2\r\n\r\nok",
        "",
    );
    assert_eq!(head.unwrap_err(), Error::InvalidHeaderName);
}

#[test]
fn header_timeout_loopt_niet_tijdens_de_upload() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            let _ = write_all(&mut conn, b"HTTP/1.1 100 Continue\r\n\r\n").await;
            sleep(Duration::from_millis(400)).await;
            read_all(&mut conn).await;
        }),
    );
    let payload = vec![b'A'; 4 << 20];
    let err = block_on(async {
        let mut d = n.clone();
        let mut src = Bytes(&payload);
        fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: payload.len() as u64,
                header_timeout: Some(Duration::from_millis(150)),
                ..call("http://srv/")
            },
        )
        .await
        .unwrap_err()
    });
    assert!(
        !matches!(err, Error::StreamBody { .. }),
        "de upload sneuvelde op de header-termijn: {err}"
    );
}

#[test]
fn vreemde_protocolversie_wordt_geweigerd() {
    let (head, _) = raw_fetch("HTTP/9.9 200 OK\r\nContent-Length: 2\r\n\r\nok", "");
    let err = head.unwrap_err();
    assert_eq!(err, Error::UnsupportedProtocol);
    let srv = h!(ex => { ex.write(b"ok").await?; });
    assert!(
        rt(
            &srv,
            "GET / HTTP/1.9\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .contains("505")
    );
}

#[test]
fn timeout_dekt_de_hele_redirect_keten() {
    let n = net(
        "hop:80",
        h!(ex => {
            sleep(Duration::from_millis(400)).await;
            ex.redirect("http://slow/", 302).await?;
        }),
    );
    n.add(
        "slow:80",
        h!(ex => {
            sleep(Duration::from_millis(400)).await;
            ex.write(b"ok").await?;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let r = select(
            fetch(&mut d, call("http://hop/")),
            sleep(Duration::from_millis(600)),
        )
        .await;
        assert!(
            matches!(r, Either::Right(())),
            "twee hops van 400ms binnen 600ms hoort te falen"
        );
        assert!(now() <= Duration::from_millis(1200));
    });
}

#[test]
fn content_length_alleen_cijfers() {
    let srv = h!(ex => {
        let _ = ex.read_body_to_end().await;
        ex.write(b"ok").await?;
    });
    let got = rt(
        &srv,
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\nConnection: close\r\n\r\nAAAAA",
    );
    assert!(got.contains("400"), "{got}");
    let (head, _) = raw_fetch("HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok", "");
    assert_eq!(head.unwrap_err(), Error::BadContentLength);
}

#[test]
fn chunkgrootte_alleen_hex() {
    for answer in [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+3\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 3\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3 \r\nabc\r\n0\r\n\r\n",
    ] {
        let (head, b) = raw_fetch(answer, "");
        head.unwrap();
        assert_eq!(b, Err(Error::MalformedChunkSize), "{answer:?}");
    }
}

#[test]
fn statuscode_exact_drie_cijfers() {
    for status in ["+200", "+20", "20", "2000", "0200", "2O0"] {
        let answer: &'static str = Box::leak(
            format!("HTTP/1.1 {status} OK\r\nContent-Length: 2\r\n\r\nok").into_boxed_str(),
        );
        assert!(
            raw_fetch(answer, "").0.is_err(),
            "statuscode {status} werd geaccepteerd"
        );
    }
}

#[test]
fn uitgaande_headerwaarde_strikt() {
    let mut header = Header::new();
    header.set("X-A", "a\x00b").unwrap();
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            header,
            ..call("http://127.0.0.1:1/")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::IllegalHeaderValue);
    let srv = h!(ex => {
        ex.header_mut().set("X-A", "a\x00b")?;
        ex.header_mut().set("Content-Length", "2")?;
        ex.write(b"ok").await?;
    });
    let got = rt(
        &srv,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(got.contains("200") && !got.contains("X-A"), "{got}");
}

#[test]
fn dial_context_wordt_geannuleerd() {
    let dropped = Rc::new(Cell::new(false));
    let mut d = BlackHole(dropped.clone());
    block_on(async {
        let r = select(
            fetch(&mut d, call("http://x/")),
            sleep(Duration::from_millis(150)),
        )
        .await;
        assert!(matches!(r, Either::Right(())));
        assert!(now() < Duration::from_secs(1));
    });
    assert!(dropped.get(), "de dialer zag de annulering nooit");
}

#[test]
fn response_met_dubbele_framing_is_fout() {
    for (name, answer, want) in [
        (
            "TE plus CL",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            Error::BothFramings,
        ),
        (
            "dubbele TE",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            Error::DuplicateTransferEncoding,
        ),
    ] {
        assert_eq!(raw_fetch(answer, "").0.unwrap_err(), want, "{name}");
    }
}

#[test]
fn chunk_extensie_en_trailer_strikt() {
    for (name, b, want) in [
        (
            "extensie (weigeren wij volledig)",
            "3;ext=foo\r\nabc\r\n0\r\n\r\n",
            Error::ChunkExtension,
        ),
        (
            "lege extensienaam",
            "3;=x\r\nabc\r\n0\r\n\r\n",
            Error::ChunkExtension,
        ),
        (
            "kale puntkomma",
            "3;\r\nabc\r\n0\r\n\r\n",
            Error::ChunkExtension,
        ),
        (
            "trailer zonder :",
            "3\r\nabc\r\n0\r\nkapotteregel\r\n\r\n",
            Error::MalformedTrailer,
        ),
        (
            "framing in trailer",
            "3\r\nabc\r\n0\r\nContent-Length: 5\r\n\r\n",
            Error::ForbiddenTrailer,
        ),
        (
            "auth in trailer",
            "3\r\nabc\r\n0\r\nSet-Cookie: a=b\r\n\r\n",
            Error::ForbiddenTrailer,
        ),
    ] {
        let answer: &'static str = Box::leak(
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{b}").into_boxed_str(),
        );
        assert_eq!(raw_fetch(answer, "").1, Err(want), "{name}");
    }
    let (_, b) = raw_fetch(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: ok\r\n\r\n",
        "",
    );
    assert_eq!(b.unwrap(), b"abc");
}

#[test]
fn redirect_alleen_voor_get_en_head() {
    let mut m = crate::Mux::new();
    m.handle("/van", "van").unwrap();
    m.handle("/doel", "doel").unwrap();
    let m = Rc::new(m);
    let n = net(
        "srv:80",
        h!(ex => {
            match m.dispatch(ex).await? {
                Some(&"van") => ex.redirect("/doel", 302).await?,
                Some(_) => {
                    ex.header_mut().set("Content-Length", "4")?;
                    ex.write(b"doel").await?;
                }
                None => {}
            }
        }),
    );
    n.add(
        "x304:80",
        raw("HTTP/1.1 304 Not Modified\r\nLocation: http://x/\r\n\r\n"),
    );
    block_on(async {
        let mut d = n.clone();
        let resp = fetch(
            &mut d,
            Call {
                method: "DELETE",
                ..call("http://srv/van")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 302, "de 3xx hoort bij de aanroeper te landen");
        let mut resp = fetch(&mut d, call("http://srv/van")).await.unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"doel");
        let resp = fetch(&mut d, call("http://x304/")).await.unwrap();
        assert_eq!(resp.status, 304, "304 werd gevolgd");
    });
}

#[test]
fn methode_is_hoofdlettergevoelig() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "5")?;
        ex.write(b"hallo").await?;
    });
    let got = rt(
        &srv,
        "head / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        got.contains("hallo"),
        "antwoord op 'head' mist de body: {got}"
    );
    let (_, b) = raw_fetch("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "head");
    assert_eq!(b.unwrap(), b"ok");
}

#[test]
fn close_breekt_geblokkeerde_read() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            read_line(&mut conn).await;
            let _ = write_all(
                &mut conn,
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf",
            )
            .await;
            sleep(Duration::from_secs(2)).await;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(resp.read(&mut buf).await, Ok(4));
        let r = select(resp.read(&mut buf), sleep(Duration::from_millis(50))).await;
        assert!(matches!(r, Either::Right(())));
        assert!(resp.release().await.is_none());
        assert!(
            now() < Duration::from_secs(1),
            "de geblokkeerde read hield de close op"
        );
    });
}

#[test]
fn origin_normaliseert_default_poort() {
    use crate::url::{Url, same_origin};
    for (a, b) in [
        ("http://h/a", "http://h:80/b"),
        ("https://h/a", "https://h:443/b"),
        ("http://H/a", "http://h/b"),
    ] {
        assert!(
            same_origin(&Url::parse(a).unwrap(), &Url::parse(b).unwrap()),
            "{a} en {b}"
        );
    }
    assert!(!same_origin(
        &Url::parse("http://h/a").unwrap(),
        &Url::parse("http://h:8080/b").unwrap()
    ));
}

#[test]
fn test304_houdt_informatieve_lengte() {
    let srv = h!(ex => {
        ex.header_mut().set("Content-Length", "1234")?;
        ex.write_header(304)?;
    });
    assert!(
        rt(
            &srv,
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .contains("Content-Length: 1234")
    );
    let n = net("srv:80", srv);
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        assert_eq!((resp.status, resp.length), (304, Some(1234)));
        assert!(body(&mut resp).await.unwrap().is_empty());
    });
}

#[test]
fn stroom_wacht_op_continue() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            read_head(&mut conn).await;
            let _ = write_all(&mut conn, b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let mut body = Vec::new();
            let mut buf = [0u8; 4];
            while body.len() < 4 {
                let n = read(&mut conn, &mut buf).await.unwrap();
                body.extend_from_slice(&buf[..n]);
            }
            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{}",
                String::from_utf8(body).unwrap()
            );
            let _ = write_all(&mut conn, answer.as_bytes()).await;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut src = Bytes(b"ping");
        let mut resp = fetch(
            &mut d,
            Call {
                method: "POST",
                body_reader: Some(&mut src),
                body_len: 4,
                ..call("http://srv/")
            },
        )
        .await
        .unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"ping");
    });
}

#[test]
fn stilte_op_expect_is_fout() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            read_all(&mut conn).await;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut src = NoRead;
        let err = fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: 4,
                header_timeout: Some(Duration::from_millis(200)),
                ..call("http://srv/")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, Error::NoVerdict);
        assert!(err.to_string().contains("no verdict"));
    });
}

#[test]
fn vroege_afwijzing_spaart_de_stroom() {
    let n = net("srv:80", h!(ex => { let _ = &ex.req; }));
    block_on(async {
        let mut d = n.clone();
        let mut src = NoRead;
        let resp = fetch(
            &mut d,
            Call {
                method: "POST",
                body_reader: Some(&mut src),
                body_len: 2 << 20,
                ..call("http://srv/")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 417);
    });
}

#[test]
fn redirect_weigert_https_downgrade() {
    let mut n = net(
        "srv:443",
        raw(
            "HTTP/1.1 302 Found\r\nLocation: http://elders.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    );
    n.tls = true;
    block_on(async {
        let mut d = n.clone();
        let err = fetch(&mut d, call("https://srv/pad?token=geheim"))
            .await
            .unwrap_err();
        assert_eq!(err, Error::HttpsDowngrade);
        assert!(err.to_string().contains("degrade"));
    });
}

#[test]
fn expect_oordeel_is_een_termijn() {
    let n = net(
        "srv:80",
        script(|mut conn| async move {
            sleep(Duration::from_millis(350)).await;
            let _ = write_all(&mut conn, b"HTTP/1.1 ").await;
            sleep(Duration::from_millis(350)).await;
            let _ = write_all(&mut conn, b"100 Continue\r\n\r\n").await;
            read_all(&mut conn).await;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        let mut src = NoRead;
        let err = fetch(
            &mut d,
            Call {
                method: "PUT",
                body_reader: Some(&mut src),
                body_len: 4,
                header_timeout: Some(Duration::from_millis(500)),
                ..call("http://srv/")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            Error::NoVerdict,
            "een getreuzeld oordeel hoort binnen de ene termijn te falen"
        );
    });
}

#[test]
fn expect_hoort_bij_het_pakket() {
    let mut header = Header::new();
    header.set("Expect", "100-continue").unwrap();
    let mut src = Bytes(b"x");
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            method: "PUT",
            header,
            body_reader: Some(&mut src),
            body_len: 1,
            ..call("http://127.0.0.1:1/")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::PackageOwnedHeader);
    assert!(err.to_string().contains("set by the package"));
}

#[test]
fn client_weigert_connect() {
    let err = block_on(fetch(
        &mut NoDial,
        Call {
            method: "CONNECT",
            ..call("http://127.0.0.1:1/")
        },
    ))
    .unwrap_err();
    assert_eq!(err, Error::Connect);
    assert!(err.to_string().contains("CONNECT"));
}

#[test]
fn write_header205_blijft_bodyloos205() {
    let srv = h!(ex => {
        ex.write_header(205)?;
        ex.write(b"mag er niet uit").await?;
    });
    let got = rt(
        &srv,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        got.contains(" 205 ")
            && got.contains("Content-Length: 0")
            && !got.contains("mag er niet uit"),
        "{got}"
    );
    let n = net("srv:80", srv);
    block_on(async {
        let mut d = n.clone();
        let mut resp = fetch(&mut d, call("http://srv/")).await.unwrap();
        assert_eq!((resp.status, resp.length), (205, Some(0)));
        assert!(body(&mut resp).await.unwrap().is_empty());
    });
}

#[test]
fn send_op_een_eigen_verbinding() {
    // Rust-toevoeging: één hop op een gegeven verbinding, en daarna dezelfde
    // verbinding voor het volgende verzoek.
    let srv = h!(ex => {
        let p = ex.req.path.clone();
        ex.write(p.as_bytes()).await?;
    });
    block_on(async {
        let (c, s) = pipe();
        srv(s);
        let mut resp = send(c, call("http://x/een")).await.unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"/een");
        let c = resp
            .release()
            .await
            .expect("verbinding hoort herbruikbaar te zijn");
        let mut resp = send(c, call("http://x/twee")).await.unwrap();
        assert_eq!(body(&mut resp).await.unwrap(), b"/twee");
    });
}

#[test]
fn pool_dial_valt_onder_de_totaaltermijn() {
    // De totaaltermijn is een select van de aanroeper; hij dekt ook de dial
    // op het pool-pad (een pool-miss).
    let dropped = Rc::new(Cell::new(false));
    block_on(async {
        let mut cl = crate::Client::new(BlackHole(dropped.clone()));
        let r = select(
            cl.send(call("http://203.0.113.1:81/"), now()),
            sleep(Duration::from_millis(300)),
        )
        .await;
        assert!(matches!(r, Either::Right(())));
        assert!(now() < Duration::from_secs(3));
    });
    assert!(dropped.get(), "de totaaltermijn mist het pool-pad");
}
