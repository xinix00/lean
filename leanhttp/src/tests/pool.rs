//! Pooltests: client_test.go en de keep-alive-tests uit review13_test.go en
//! serve_test.go. `now` komt uit de virtuele klok, zoals een echte aanroeper
//! hem uit zijn eigen klok haalt.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::h;
use super::support::*;
use crate::{Call, Client, Error, Pool, write_all};

fn net(addr: &str, h: Handler) -> Net {
    let n = Net::new();
    n.add(addr, h);
    n
}

fn call(url: &str) -> Call<'_> {
    Call {
        url,
        ..Call::default()
    }
}

fn ok() -> Handler {
    h!(ex => { ex.write(b"ok").await?; })
}

/// Haalt `url` via de pool, leest de body helemaal en geeft hem terug.
async fn fetch_all(cl: &mut Client<Net>, url: &str) -> Vec<u8> {
    let mut resp = cl.get(url, now()).await.unwrap();
    let b = resp.read_to_end(1 << 20).await.unwrap();
    cl.finish(resp, now()).await;
    b
}

#[test]
fn keep_alive_hergebruikt() {
    let n = net("srv:80", h!(ex => { ex.write(b"hallo").await?; }));
    block_on(async {
        let mut cl = Client::new(n.clone());
        for _ in 0..10 {
            assert_eq!(fetch_all(&mut cl, "http://srv/x").await, b"hallo");
        }
    });
    assert_eq!(n.accepted("srv:80"), 1, "verbindingen voor 10 verzoeken");
}

#[test]
fn grown_verbinding_komt_niet_in_pool() {
    let mut n = net("srv:80", ok());
    n.grown = true;
    block_on(async {
        let mut cl = Client::new(n.clone());
        fetch_all(&mut cl, "http://srv/").await;
        assert_eq!(cl.pool.idle_count(), 0);
    });
}

#[test]
fn context_cancel_en_body_close_poolen_niet_tijdens_callback() {
    // Go: een geannuleerde call mag nooit in de pool belanden. Hier is
    // annuleren een antwoord laten vallen: de verbinding gaat dicht, en de
    // pool ziet hem nooit.
    let closed = Rc::new(Cell::new(false));
    let c = closed.clone();
    let n = net(
        "srv:80",
        script(move |mut conn| {
            let c = c.clone();
            async move {
                read_head(&mut conn).await;
                let _ = write_all(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
                read_all(&mut conn).await;
                c.set(true);
            }
        }),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        let resp = cl.send(call("http://srv/"), now()).await.unwrap();
        drop(resp);
        assert_eq!(cl.pool.idle_count(), 0);
        sleep(Duration::from_millis(10)).await;
    });
    assert!(closed.get());
}

#[test]
fn keep_alive_niet_bij_halve_body() {
    let n = net("srv:80", h!(ex => { ex.write(&[b'x'; 4096]).await?; }));
    block_on(async {
        let mut cl = Client::new(n.clone());
        for _ in 0..3 {
            let mut resp = cl.send(call("http://srv/x"), now()).await.unwrap();
            let mut buf = [0u8; 10];
            resp.read(&mut buf).await.unwrap();
            cl.finish(resp, now()).await;
        }
        assert_eq!(
            n.accepted("srv:80"),
            3,
            "een half gelezen body werd hergebruikt"
        );
        let mut resp = cl.send(call("http://srv/x"), now()).await.unwrap();
        assert_eq!(
            resp.read_to_end(1 << 20).await.unwrap().len(),
            4096,
            "protocol-desync"
        );
    });
}

#[test]
fn keep_alive_server_sluit() {
    let n = net(
        "srv:80",
        h!(ex => {
            ex.header_mut().set("Connection", "close")?;
            ex.write(b"eenmalig").await?;
        }),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        for _ in 0..3 {
            fetch_all(&mut cl, "http://srv/x").await;
        }
    });
    assert_eq!(
        n.accepted("srv:80"),
        3,
        "een server die close zegt werd toch hergebruikt"
    );
}

#[test]
fn keep_alive_idle_timeout() {
    let n = net("srv:80", ok());
    block_on(async {
        let mut cl = Client::new(n.clone());
        cl.pool.idle_timeout = Duration::from_millis(20);
        for _ in 0..2 {
            fetch_all(&mut cl, "http://srv/x").await;
            sleep(Duration::from_millis(40)).await;
        }
    });
    assert_eq!(
        n.accepted("srv:80"),
        2,
        "een verlopen verbinding werd hergebruikt"
    );
}

#[test]
fn keep_alive_max_idle() {
    let n = net("srv:80", ok());
    block_on(async {
        let mut cl = Client::new(n.clone());
        cl.pool.max_idle_per_host = 1;
        let mut r1 = cl.get("http://srv/a", now()).await.unwrap();
        let mut r2 = cl.get("http://srv/b", now()).await.unwrap();
        r1.read_to_end(64).await.unwrap();
        r2.read_to_end(64).await.unwrap();
        cl.finish(r1, now()).await;
        cl.finish(r2, now()).await;
        assert_eq!(cl.pool.idle_for("srv:80"), 1);
    });
}

#[test]
fn gzip_doorlaat() {
    let n = net(
        "srv:80",
        h!(ex => {
            assert_eq!(ex.req.header.get("Accept-Encoding"), Some("gzip"));
            ex.header_mut().set("Content-Encoding", "gzip")?;
            ex.header_mut().set("Content-Length", "3")?;
            ex.write(b"abc").await?;
        }),
    );
    block_on(async {
        let mut header = crate::Header::new();
        header.set("Accept-Encoding", "gzip").unwrap();
        let mut d = n.clone();
        let resp = crate::fetch(
            &mut d,
            Call {
                header,
                ..call("http://srv/x")
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.encoding(), Some("gzip"));
    });
}

#[test]
fn default_blijft_identity() {
    let n = net(
        "srv:80",
        h!(ex => {
            assert_eq!(ex.req.header.get("Accept-Encoding"), Some("identity"));
            ex.write(b"ok").await?;
        }),
    );
    block_on(async {
        let mut d = n.clone();
        assert_eq!(
            crate::fetch(&mut d, call("http://srv/x"))
                .await
                .unwrap()
                .status,
            200
        );
    });
}

#[test]
fn set_cookie_niet_gevouwen() {
    let n = net(
        "srv:80",
        raw(
            "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/; Expires=Mon, 02 Jan 2027 15:04:05 GMT\r\n\
             Set-Cookie: theme=dark; Path=/\r\nContent-Length: 2\r\n\r\nok",
        ),
    );
    block_on(async {
        let mut d = n.clone();
        let resp = crate::fetch(&mut d, call("http://srv/x")).await.unwrap();
        assert_eq!(resp.set_cookie.len(), 2, "{:?}", resp.set_cookie);
        assert!(resp.set_cookie[0].contains("Expires=Mon, 02 Jan 2027"));
        assert_eq!(resp.set_cookie[1], "theme=dark; Path=/");
        assert_eq!(
            resp.header.get("Set-Cookie"),
            None,
            "Set-Cookie staat ook in header"
        );
    });
}

#[test]
fn pool_negeert_http10() {
    for (name, status, extra, want) in [
        ("1.0 zonder Connection", "HTTP/1.0 200 OK", "", 3),
        (
            "1.0 met keep-alive",
            "HTTP/1.0 200 OK",
            "Connection: keep-alive\r\n",
            1,
        ),
        ("1.1 zonder Connection", "HTTP/1.1 200 OK", "", 1),
    ] {
        let n = net(
            "srv:80",
            script(move |mut conn| async move {
                loop {
                    if read_head(&mut conn).await.is_none() {
                        return;
                    }
                    let answer = format!("{status}\r\nContent-Length: 2\r\n{extra}\r\nok");
                    if write_all(&mut conn, answer.as_bytes()).await.is_err() || want > 1 {
                        return;
                    }
                }
            }),
        );
        block_on(async {
            let mut cl = Client::new(n.clone());
            for i in 0..3 {
                let mut resp = cl.send(call("http://srv/x"), now()).await.unwrap();
                assert_eq!(
                    resp.read_to_end(64).await.unwrap(),
                    b"ok",
                    "{name}: verzoek {i}"
                );
                cl.finish(resp, now()).await;
            }
            cl.pool.close_idle().await;
        });
        assert_eq!(n.accepted("srv:80"), want, "{name}");
    }
}

#[test]
fn pool_ruimt_elke_host_op() {
    let n = net("a:80", ok());
    n.add("b:80", ok());
    block_on(async {
        let mut cl = Client::new(n.clone());
        cl.pool.idle_timeout = Duration::from_millis(20);
        fetch_all(&mut cl, "http://a/").await;
        assert_eq!(cl.pool.idle_count(), 1);
        sleep(Duration::from_millis(40)).await;
        fetch_all(&mut cl, "http://b/").await;
        assert_eq!(
            cl.pool.idle_count(),
            1,
            "een verlopen verbinding naar host A blijft staan"
        );
        assert_eq!(cl.pool.idle_for("a:80"), 0);
    });
}

#[test]
fn pool_ruimt_op_voor_de_dial() {
    let n = net("a:80", ok());
    block_on(async {
        let mut cl = Client::new(n.clone());
        cl.pool.idle_timeout = Duration::from_millis(20);
        fetch_all(&mut cl, "http://a/").await;
        assert_eq!(cl.pool.idle_count(), 1);
        sleep(Duration::from_millis(40)).await;
        assert!(
            cl.get("http://dood/", now()).await.is_err(),
            "verwachtte een dial-fout"
        );
        assert_eq!(cl.pool.idle_count(), 0, "de sweep zit achter het verzoek");
    });
}

#[test]
fn serve_done_zegt_geen_keep_alive() {
    for (name, claim, want) in [
        ("zonder done", false, "keep-alive"),
        ("met done", true, "close"),
    ] {
        let n = net(
            "srv:80",
            h!(ex => {
                if claim {
                    ex.claim_done().await?;
                }
                ex.write(b"ok").await?;
            }),
        );
        block_on(async {
            let mut cl = Client::new(n.clone());
            let mut resp = cl.send(call("http://srv/"), now()).await.unwrap();
            resp.read_to_end(64).await.unwrap();
            assert_eq!(resp.header.get("Connection"), Some(want), "{name}");
            cl.finish(resp, now()).await;
            let mut resp = cl.send(call("http://srv/"), now()).await.unwrap();
            assert_eq!(
                resp.read_to_end(64).await.unwrap(),
                b"ok",
                "{name}: tweede ronde"
            );
        });
    }
}

#[test]
fn client_get_gebruikt_de_pool_met_eigen_dial() {
    let n = net(
        "srv:80",
        h!(ex => {
            ex.header_mut().set("Content-Length", "2")?;
            ex.write(b"ok").await?;
        }),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        for _ in 0..3 {
            fetch_all(&mut cl, "http://srv/").await;
        }
    });
    assert_eq!(n.accepted("srv:80"), 1, "de pool wordt omzeild");
}

#[test]
fn client_weigert_https_zonder_tls_dialer() {
    block_on(async {
        let mut cl = Client::new(Net::new());
        assert_eq!(
            cl.get("https://example.invalid/", now()).await.unwrap_err(),
            Error::HttpsNeedsTls
        );
        assert_eq!(
            cl.send(call("https://example.invalid/"), now())
                .await
                .unwrap_err(),
            Error::HttpsNeedsTls
        );
    });
}

#[test]
fn connection_als_tokenlijst() {
    let n = net(
        "srv:80",
        raw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: upgrade, close\r\n\r\nok"),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        fetch_all(&mut cl, "http://srv/").await;
        assert_eq!(cl.pool.idle_count(), 0);
    });
}

#[test]
fn chunk_afgekapt_voor_de_crlf() {
    let n = net(
        "srv:80",
        raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo"),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        let mut resp = cl.send(call("http://srv/"), now()).await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(resp.read(&mut buf).await, Err(Error::UnexpectedEof));
        cl.finish(resp, now()).await;
        assert_eq!(cl.pool.idle_count(), 0, "de dode verbinding is gepoold");
    });
}

#[test]
fn lege_body_poolt_direct() {
    let n = net("srv:80", h!(ex => { ex.write_header(204)?; }));
    block_on(async {
        let mut cl = Client::new(n.clone());
        let resp = cl
            .send(
                Call {
                    method: "DELETE",
                    ..call("http://srv/")
                },
                now(),
            )
            .await
            .unwrap();
        cl.finish(resp, now()).await;
        assert_eq!(cl.pool.idle_for("srv:80"), 1);
    });
}

#[test]
fn geen_pool_met_ongelezen_bytes() {
    let n = net(
        "srv:80",
        raw("HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        let resp = cl.send(call("http://srv/"), now()).await.unwrap();
        assert_eq!(resp.status, 204);
        cl.finish(resp, now()).await;
        assert_eq!(
            cl.pool.idle_count(),
            0,
            "verbinding met voorgeïnjecteerde bytes gepoold"
        );
    });
}

#[test]
fn idle_timeout_ruimt_zelf_op() {
    // Zonder klok in de crate: de timer van de aanroeper roept sweep aan.
    let n = net("srv:80", ok());
    block_on(async {
        let mut cl = Client::new(n.clone());
        cl.pool.idle_timeout = Duration::from_millis(200);
        fetch_all(&mut cl, "http://srv/").await;
        assert_eq!(cl.pool.idle_count(), 1);
        sleep(Duration::from_millis(600)).await;
        cl.pool.sweep(now()).await;
        assert_eq!(cl.pool.idle_count(), 0, "niemand ruimt op");
    });
}

/// Een server die één antwoord geeft en na 50 ms sluit; telt DELETE's.
fn one_shot(deletes: Rc<Cell<usize>>) -> Handler {
    script(move |mut conn| {
        let deletes = deletes.clone();
        async move {
            let line = read_line(&mut conn).await.unwrap_or_default();
            if line.starts_with("DELETE") {
                deletes.set(deletes.get() + 1);
            }
            let _ = write_all(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            sleep(Duration::from_millis(50)).await;
        }
    })
}

#[test]
fn stale_keep_alive_krijgt_een_herkansing() {
    let n = net("srv:80", one_shot(Rc::default()));
    block_on(async {
        let mut cl = Client::new(n.clone());
        for i in 0..2 {
            let mut resp = cl
                .send(call("http://srv/"), now())
                .await
                .unwrap_or_else(|e| panic!("call {i}: {e}: geen herkansing"));
            resp.read_to_end(64).await.unwrap();
            cl.finish(resp, now()).await;
            sleep(Duration::from_millis(120)).await;
        }
    });
    assert_eq!(n.accepted("srv:80"), 2);
}

#[test]
fn stale_retry_alleen_replay_safe() {
    let deletes = Rc::new(Cell::new(0));
    let n = net("srv:80", one_shot(deletes.clone()));
    block_on(async {
        let mut cl = Client::new(n.clone());
        fetch_all(&mut cl, "http://srv/").await;
        sleep(Duration::from_millis(120)).await;
        let r = cl
            .send(
                Call {
                    method: "DELETE",
                    ..call("http://srv/")
                },
                now(),
            )
            .await;
        assert!(
            r.is_err(),
            "een DELETE op een stale verbinding werd stil herhaald"
        );
    });
    assert_eq!(
        deletes.get(),
        0,
        "de herkansing voerde de DELETE alsnog uit"
    );
}

#[test]
fn kapotte_deadline_wis_poolt_niet() {
    block_on(async {
        let mut pool = Pool::new();
        let (mut c, _s) = pipe();
        c.refuse_timeouts = true;
        assert!(!pool.put("x:80", c, now()).await);
    });
}

#[test]
fn pool_totaalcap() {
    block_on(async {
        let mut pool = Pool::new();
        let mut ends = Vec::new();
        for i in 0..12 {
            let (c, s) = pipe();
            ends.push(s);
            let accepted = pool.put(&format!("host{i}:80"), c, now()).await;
            assert!(accepted || i >= 8, "put {i} geweigerd onder de cap");
        }
        assert!(pool.idle_count() <= 8);
    });
}

#[test]
fn finish_now_poolt_alleen_een_hele_body() {
    let n = net(
        "srv:80",
        raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhallo"),
    );
    block_on(async {
        let mut cl = Client::new(n.clone());
        let mut resp = cl.send(call("http://srv/"), now()).await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(resp.read(&mut buf).await, Ok(5));
        assert_eq!(resp.read(&mut buf).await, Ok(0));
        cl.pool.finish_now(resp, now());
        assert_eq!(cl.pool.idle_count(), 1);
        // Half gelezen: de verbinding valt, de pool krijgt hem niet.
        let mut resp = cl.send(call("http://srv/"), now()).await.unwrap();
        assert_eq!(resp.read(&mut buf[..2]).await, Ok(2));
        cl.pool.finish_now(resp, now());
        assert_eq!(cl.pool.idle_count(), 0);
    });
}
