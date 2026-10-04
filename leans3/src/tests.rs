//! De clienttests: de Go-tests uit leans3_test.go, met een geschreven transport
//! in plaats van httptest. Het transport legt elk verzoek vast en speelt een
//! antwoord af; zo toetst elke test wat leans3 zelf belooft, en niets van een
//! HTTP-stapel die hier niet in zit.

use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::task::Waker;

/// Wat het transport van één verzoek zag.
#[derive(Debug, Clone)]
struct Seen {
    method: &'static str,
    host: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    /// `None` voor [`Body::None`].
    body: Option<Vec<u8>>,
    streamed: bool,
}

impl Seen {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }

    fn query(&self, name: &str) -> &str {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// Hoe een antwoordbody zich gedraagt.
enum MockBody {
    Bytes(Vec<u8>),
    /// `n` keer dezelfde byte, zonder die eerst te alloceren.
    Repeat(u8, u64),
    /// Levert nooit iets: lezen blijft hangen.
    Hang,
}

/// Een geschreven antwoord.
struct Canned {
    status: u16,
    reason: &'static str,
    headers: Vec<(&'static str, String)>,
    content_length: Option<u64>,
    body: MockBody,
}

fn ok(body: &[u8]) -> Canned {
    Canned {
        status: 200,
        reason: "OK",
        headers: Vec::new(),
        content_length: Some(body.len() as u64),
        body: MockBody::Bytes(body.to_vec()),
    }
}

fn status(code: u16, reason: &'static str, body: &str) -> Canned {
    Canned {
        status: code,
        reason,
        headers: Vec::new(),
        content_length: Some(body.len() as u64),
        body: MockBody::Bytes(body.as_bytes().to_vec()),
    }
}

impl Canned {
    fn etag(mut self, v: &str) -> Self {
        self.headers.push(("ETag", v.to_owned()));
        self
    }
}

/// Het antwoord zoals de client het leest.
struct MockResponse {
    canned: Canned,
    pos: usize,
    /// Wordt waar zodra de body tot zijn einde gelezen is: dan kan een echt
    /// transport de verbinding hergebruiken.
    drained: Rc<Cell<bool>>,
}

impl AsyncRead for MockResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let pos = self.pos;
        let n = match &mut self.canned.body {
            MockBody::Hang => return Poll::Pending,
            MockBody::Bytes(b) => {
                let rest = &b[pos.min(b.len())..];
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                n
            }
            MockBody::Repeat(byte, left) => {
                let n = (*left).min(buf.len() as u64) as usize;
                buf[..n].fill(*byte);
                *left -= n as u64;
                n
            }
        };
        self.pos += n;
        if n == 0 {
            self.drained.set(true);
        }
        Poll::Ready(Ok(n))
    }
}

impl Response for MockResponse {
    fn status(&self) -> u16 {
        self.canned.status
    }
    fn reason(&self) -> &str {
        self.canned.reason
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.canned
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn content_length(&self) -> Option<u64> {
        self.canned.content_length
    }
}

type Script = Box<dyn FnMut(&Seen) -> Canned>;

/// Het geschreven transport.
struct Mock {
    seen: Rc<RefCell<Vec<Seen>>>,
    script: Script,
    drained: Rc<Cell<bool>>,
    /// Laat `send` eeuwig wachten, en telt hoe vaak een wachtend verzoek werd
    /// losgelaten.
    hang: bool,
    dropped: Rc<Cell<u32>>,
}

fn mock(script: impl FnMut(&Seen) -> Canned + 'static) -> Mock {
    Mock {
        seen: Rc::default(),
        script: Box::new(script),
        drained: Rc::default(),
        hang: false,
        dropped: Rc::default(),
    }
}

/// Telt het loslaten van een wachtend verzoek.
struct DropCount(Rc<Cell<u32>>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

impl Transport for Mock {
    type Response = MockResponse;

    async fn send(&mut self, request: Request<'_, '_>) -> Result<MockResponse, IoError> {
        let (path, query) = request
            .target
            .split_once('?')
            .unwrap_or((request.target, ""));
        let query = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (decode(k), decode(v))
            })
            .collect();
        let mut seen = Seen {
            method: request.method,
            host: request.host.to_owned(),
            path: decode(path),
            query,
            headers: request
                .headers
                .iter()
                .map(|h| (h.name.to_owned(), h.value.clone()))
                .collect(),
            body: None,
            streamed: false,
        };
        match request.body {
            Body::None => {}
            Body::Bytes(b) => seen.body = Some(b.to_vec()),
            Body::Stream { source, len } => {
                // Zoals leanhttp: precies `len` bytes, en een fout van de bron
                // breekt het verzoek af.
                seen.streamed = true;
                let mut body = vec![0u8; len as usize];
                let mut got = 0;
                while got < body.len() {
                    let n = read(source, &mut body[got..]).await?;
                    if n == 0 {
                        return Err(IoError::UnexpectedEof);
                    }
                    got += n;
                }
                seen.body = Some(body);
            }
        }
        self.seen.borrow_mut().push(seen.clone());
        if self.hang {
            let _guard = DropCount(self.dropped.clone());
            poll_fn(|_| Poll::<()>::Pending).await;
        }
        let canned = (self.script)(&seen);
        Ok(MockResponse {
            canned,
            pos: 0,
            drained: self.drained.clone(),
        })
    }
}

/// Een schrijver die alles bewaart.
#[derive(Default)]
struct Buffer(Vec<u8>);

impl AsyncWrite for Buffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.0.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
}

/// Een bron uit het geheugen.
struct Source<'a>(&'a [u8]);

impl AsyncRead for Source<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Poll::Ready(Ok(n))
    }
}

/// Draait een future tot hij klaar is. Het transport hier wacht nergens op, dus
/// een future die na duizend rondes nog wacht, hangt echt.
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

fn klant() -> Client {
    Client {
        endpoint: "http://127.0.0.1:9000".into(),
        bucket: "bkt".into(),
        region: "eu-test-1".into(),
        access_key_id: "AK".into(),
        secret_access_key: "SK".into(),
        path_style: true,
        now: Some(|| 1_768_478_400),
        ..Client::default()
    }
}

fn hex_sum(data: &[u8]) -> String {
    sigv4::hex_str(&sigv4::hex_sha256(data)).to_owned()
}

// De Go-test keek naar de importgraaf: geen net/http, geen crypto/tls. Hier is
// dat de afhankelijkhedenlijst, die leeg moet blijven.
#[test]
fn geen_net_http() {
    let manifest = include_str!("../Cargo.toml");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split('[')
        .next()
        .unwrap();
    assert!(
        deps.trim().is_empty(),
        "leans3 heeft afhankelijkheden: {deps}"
    );
}

#[test]
fn get_leest_object_en_etag() {
    let mut t = mock(|_| ok(br#"{"jobs":[]}"#).etag("\"etag-1\""));
    let (data, etag) = block_on(klant().get(&mut t, "state/cluster")).unwrap();
    assert_eq!(data, br#"{"jobs":[]}"#);
    assert_eq!(etag.as_deref(), Some("\"etag-1\""));
    let seen = &t.seen.borrow()[0];
    assert_eq!(
        (seen.method, seen.path.as_str()),
        ("GET", "/bkt/state/cluster")
    );
    assert!(
        !seen.header("Authorization").is_empty(),
        "GET niet getekend"
    );
    assert_eq!(seen.header("X-Amz-Content-Sha256"), hex_sum(b""));
}

#[test]
fn get_afwezig_is_err_not_found() {
    let mut t = mock(|_| status(404, "Not Found", "no such key"));
    assert_eq!(
        block_on(klant().get(&mut t, "absent")),
        Err(Error::NotFound)
    );
}

#[test]
fn status_fout_draagt_de_body() {
    let mut t = mock(|_| {
        status(
            403,
            "Forbidden",
            "<Error><Code>SignatureDoesNotMatch</Code></Error>\n",
        )
    });
    let err = block_on(klant().get(&mut t, "k")).unwrap_err();
    let Error::Status(se) = &err else {
        panic!("wil een StatusError, kreeg {err:?}");
    };
    assert_eq!(se.code, 403);
    assert!(String::from_utf8_lossy(&se.body).contains("SignatureDoesNotMatch"));
    assert!(err.to_string().contains("403 Forbidden"), "{err}");
}

#[test]
fn get_to_streamt_body() {
    let payload = b"leans3-stream!".repeat(4096);
    let body = payload.clone();
    let mut t = mock(move |_| ok(&body));
    let mut sink = Buffer::default();
    let (n, _) = block_on(klant().get_to(&mut t, "apps/c/j/data.bin", &mut sink)).unwrap();
    assert_eq!(n, payload.len() as u64);
    assert_eq!(sink.0, payload);
    let seen = &t.seen.borrow()[0];
    assert_eq!(seen.path, "/bkt/apps/c/j/data.bin");
    assert!(!seen.header("Authorization").is_empty());
}

#[test]
fn get_to_afwezig_schrijft_niets() {
    let mut t = mock(|_| status(404, "Not Found", "no such key"));
    let mut sink = Buffer::default();
    assert_eq!(
        block_on(klant().get_to(&mut t, "absent", &mut sink)),
        Err(Error::NotFound)
    );
    assert!(sink.0.is_empty());
}

/// Een schrijver die na `limit` bytes vol is.
struct FailAfter {
    limit: usize,
}

impl AsyncWrite for FailAfter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        if buf.len() > self.limit {
            let n = self.limit;
            self.limit = 0;
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            return Poll::Ready(Err(IoError::Other("disk full")));
        }
        self.limit -= buf.len();
        Poll::Ready(Ok(buf.len()))
    }
}

#[test]
fn get_to_schrijffout_breekt_af() {
    let mut t = mock(|_| ok(&vec![0xAB; 64 << 10]));
    let mut sink = FailAfter { limit: 8 << 10 };
    let err = block_on(klant().get_to(&mut t, "big", &mut sink)).unwrap_err();
    assert!(err.to_string().contains("disk full"), "{err}");
    assert!(
        matches!(err, Error::Sink { written: 8192, .. }),
        "een schrijffout moet een Sink-fout zijn, geen ontbrekend object: {err:?}"
    );
}

#[test]
fn put_stuurt_lengte_hash_en_body() {
    let payload = br#"{"jobs":["a"]}"#;
    let mut t = mock(|_| ok(b"").etag("\"etag-7\""));
    let etag = block_on(klant().put(
        &mut t,
        "state/cluster",
        payload,
        &PutOptions {
            content_type: "application/json",
            if_none_match: "*",
            ..PutOptions::default()
        },
    ))
    .unwrap();
    assert_eq!(etag.as_deref(), Some("\"etag-7\""));
    let seen = &t.seen.borrow()[0];
    assert_eq!(
        (seen.method, seen.path.as_str()),
        ("PUT", "/bkt/state/cluster")
    );
    assert_eq!(seen.body.as_deref(), Some(&payload[..]));
    assert_eq!(seen.header("X-Amz-Content-Sha256"), hex_sum(payload));
    assert_eq!(seen.header("Content-Type"), "application/json");
    assert_eq!(seen.header("If-None-Match"), "*");
}

#[test]
fn put_leeg_object_heeft_lengte_nul() {
    let mut t = mock(|_| ok(b""));
    block_on(klant().put(&mut t, "empty", &[], &PutOptions::default())).unwrap();
    // Bytes met een lege slice is Content-Length: 0; None zou geen lengte zijn.
    assert_eq!(t.seen.borrow()[0].body.as_deref(), Some(&[][..]));
}

#[test]
fn put_voorwaarde_faalt() {
    for code in [412, 409] {
        let mut t = mock(move |_| status(code, "Conflict", "exists"));
        let opts = PutOptions {
            if_none_match: "*",
            ..PutOptions::default()
        };
        assert_eq!(
            block_on(klant().put(&mut t, "k", b"x", &opts)),
            Err(Error::PreconditionFailed),
            "status {code}"
        );
    }
}

#[test]
fn put_from_stuurt_lengte_hash_en_body() {
    let payload = b"42".repeat(32 << 10);
    let hash = hex_sum(&payload);
    let mut t = mock(|_| ok(b""));
    let mut src = Source(&payload);
    block_on(klant().put_from(
        &mut t,
        "apps/c/j/out.bin",
        &mut src,
        payload.len() as u64,
        &hash,
        &PutOptions::default(),
    ))
    .unwrap();
    let seen = &t.seen.borrow()[0];
    assert_eq!(
        (seen.method, seen.path.as_str()),
        ("PUT", "/bkt/apps/c/j/out.bin")
    );
    assert!(seen.streamed, "een stroom met bekende lengte, geen buffer");
    assert_eq!(seen.body.as_deref(), Some(&payload[..]));
    assert_eq!(seen.header("X-Amz-Content-Sha256"), hash);
    assert!(!seen.header("Authorization").is_empty());
}

#[test]
fn put_from_korte_bron_faalt_luid() {
    let mut t = mock(|_| ok(b""));
    let mut src = Source(b"0123456789");
    let err = block_on(klant().put_from(
        &mut t,
        "torn",
        &mut src,
        100,
        &hex_sum(b"whatever"),
        &PutOptions::default(),
    ))
    .unwrap_err();
    assert_eq!(
        err,
        Error::Transport {
            op: Op::Put,
            source: IoError::UnexpectedEof
        }
    );
}

#[test]
fn put_from_zonder_hash_weigert() {
    let c = Client {
        endpoint: "https://s3.example.com".into(),
        ..klant()
    };
    let mut t = mock(|_| ok(b""));
    let err = block_on(c.put_from(
        &mut t,
        "k",
        &mut Source(b"x"),
        1,
        "",
        &PutOptions::default(),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("sha256"), "{err}");
    assert!(t.seen.borrow().is_empty());
}

#[test]
fn delete204_blijft_niet_hangen() {
    let mut t = mock(|_| Canned {
        status: 204,
        reason: "No Content",
        headers: Vec::new(),
        content_length: None,
        // Een lezer van deze body zou nooit terugkomen.
        body: MockBody::Hang,
    });
    block_on(klant().delete(
        &mut t,
        "k",
        &DeleteOptions {
            if_match: "\"etag-1\"",
        },
    ))
    .unwrap();
    let seen = &t.seen.borrow()[0];
    assert_eq!(seen.method, "DELETE");
    assert_eq!(seen.header("If-Match"), "\"etag-1\"");
}

#[test]
fn delete_afwezig_en_voorwaarde() {
    let code = Rc::new(Cell::new(404u16));
    let c2 = code.clone();
    let mut t = mock(move |_| status(c2.get(), "", "nope"));
    assert_eq!(
        block_on(klant().delete(&mut t, "k", &DeleteOptions::default())),
        Err(Error::NotFound)
    );
    code.set(412);
    assert_eq!(
        block_on(klant().delete(&mut t, "k", &DeleteOptions { if_match: "x" })),
        Err(Error::PreconditionFailed)
    );
}

#[test]
fn list_pagineert_met_token() {
    let mut t = mock(|seen| {
        if seen.query("continuation-token").is_empty() {
            return ok(br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page2</NextContinuationToken>
  <Contents><Key>apps/c/j/a.txt</Key></Contents>
  <Contents><Key>apps/c/j/b.txt</Key></Contents>
</ListBucketResult>"#);
        }
        ok(br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents><Key>apps/c/j/c.txt</Key></Contents>
</ListBucketResult>"#)
    });
    let (keys, truncated) = block_on(klant().list(&mut t, "apps/c/j/", 10)).unwrap();
    assert!(!truncated, "truncated voor de cap");
    assert_eq!(keys, ["apps/c/j/a.txt", "apps/c/j/b.txt", "apps/c/j/c.txt"]);
    let seen = t.seen.borrow();
    assert_eq!(seen.len(), 2);
    for s in seen.iter() {
        assert_eq!(s.path, "/bkt/");
        assert_eq!(s.query("list-type"), "2");
        assert_eq!(s.query("prefix"), "apps/c/j/");
    }
    assert_eq!(seen[0].query("continuation-token"), "");
    assert_eq!(seen[1].query("continuation-token"), "page2");
}

#[test]
fn list_eist_een_positieve_cap() {
    let mut t = mock(|_| ok(b""));
    let err = block_on(Client::default().list(&mut t, "", 0)).unwrap_err();
    assert!(err.to_string().contains("max must be positive"), "{err}");
}

#[test]
fn directories_page_past_root_objects_and_ignore_data_keys() {
    let mut t = mock(|seen| {
        assert_eq!(seen.query("delimiter"), "/");
        assert_eq!(seen.query("prefix"), "gen/");
        if seen.query("continuation-token").is_empty() {
            ok(b"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>two</NextContinuationToken><Contents><Key>gen/marker</Key></Contents></ListBucketResult>")
        } else {
            ok(b"<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>gen/one&amp;two/</Prefix></CommonPrefixes><Contents><Key>gen/other</Key></Contents></ListBucketResult>")
        }
    });
    assert_eq!(
        block_on(klant().list_directories(&mut t, "gen/", 10)).unwrap(),
        (vec!["gen/one&two/".into()], false)
    );
    assert_eq!(t.seen.borrow().len(), 2);
}

#[test]
fn directories_preserve_caps_and_stuck_token_detection() {
    let mut t = mock(|_| {
        ok(b"<ListBucketResult><CommonPrefixes><Prefix>gen/one/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>gen/two/</Prefix></CommonPrefixes></ListBucketResult>")
    });
    assert!(matches!(
        block_on(Client::default().list_directories(&mut t, "gen/", 0)),
        Err(Error::ListMaxZero)
    ));
    assert_eq!(
        block_on(klant().list_directories(&mut t, "gen/", 1)).unwrap(),
        (vec!["gen/one/".into()], true)
    );
    let mut t = mock(|_| {
        ok(b"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken><CommonPrefixes><Prefix>gen/one/</Prefix></CommonPrefixes></ListBucketResult>")
    });
    assert!(matches!(
        block_on(klant().list_directories(&mut t, "gen/", 10)),
        Err(Error::ListTokenStuck)
    ));
    assert_eq!(t.seen.borrow().len(), 2);
}

#[test]
fn ordinary_list_ignores_common_prefixes() {
    let mut t = mock(|seen| {
        assert_eq!(seen.query("delimiter"), "");
        ok(b"<ListBucketResult><CommonPrefixes><Prefix>gen/child/</Prefix></CommonPrefixes><Contents><Key>gen/item</Key></Contents></ListBucketResult>")
    });
    assert_eq!(
        block_on(klant().list(&mut t, "gen/", 10)).unwrap(),
        (vec!["gen/item".into()], false)
    );
}

#[test]
fn list_weigert_token_zonder_voortgang() {
    let mut t = mock(|_| {
        ok(b"<ListBucketResult><IsTruncated>true</IsTruncated>\
<NextContinuationToken>zelfde</NextContinuationToken>\
<Contents><Key>k</Key></Contents></ListBucketResult>")
    });
    let err = block_on(klant().list(&mut t, "", 10)).unwrap_err();
    assert!(err.to_string().contains("did not advance"), "{err}");
    assert_eq!(t.seen.borrow().len(), 2, "stoppen na twee verzoeken");
}

#[test]
fn list_weigert_lege_afgekapte_pagina() {
    let mut t = mock(|_| {
        ok(b"<ListBucketResult><IsTruncated>true</IsTruncated>\
<NextContinuationToken>volgende</NextContinuationToken></ListBucketResult>")
    });
    let err = block_on(klant().list(&mut t, "", 10)).unwrap_err();
    assert!(err.to_string().contains("no key progress"), "{err}");
}

#[test]
fn get_heeft_een_bufferlimiet() {
    let mut t = mock(|_| Canned {
        status: 200,
        reason: "OK",
        headers: Vec::new(),
        content_length: Some(MAX_BUFFERED_GET + 1),
        body: MockBody::Hang,
    });
    assert!(matches!(
        block_on(klant().get(&mut t, "te-groot")),
        Err(Error::ObjectTooLarge { .. })
    ));
}

#[test]
fn get_begrenst_ook_een_body_zonder_lengte() {
    let mut t = mock(|_| Canned {
        status: 200,
        reason: "OK",
        headers: Vec::new(),
        content_length: None,
        body: MockBody::Repeat(b'x', MAX_BUFFERED_GET + 1),
    });
    let c = klant();
    let fut = c.get(&mut t, "te-groot-chunked");
    // Een body van 4 MiB in brokken van 4 KiB vraagt meer rondes dan block_on
    // geeft, maar elke ronde is klaar; dus geen hang, alleen werk.
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    let got = loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            break v;
        }
    };
    assert!(matches!(got, Err(Error::ObjectTooLarge { .. })), "{got:?}");
}

// In Go brak een context-cancel het lopende verzoek af. Hier is de operatie een
// future: laten vallen is annuleren, en het transport ziet zijn verzoek gaan.
#[test]
fn context_cancel_onderbreekt_actieve_s3_call() {
    let mut t = mock(|_| ok(b""));
    t.hang = true;
    let dropped = t.dropped.clone();
    let seen = t.seen.clone();
    {
        let c = klant();
        let mut fut = std::pin::pin!(c.get(&mut t, "wacht"));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            seen.borrow().len(),
            1,
            "het verzoek bereikte het transport niet"
        );
    }
    assert_eq!(dropped.get(), 1, "het lopende verzoek werd niet losgelaten");
}

#[test]
fn list_cap_meldt_afkapping() {
    let mut t = mock(|_| {
        ok(br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>k1</Key></Contents>
  <Contents><Key>k2</Key></Contents>
  <Contents><Key>k3</Key></Contents>
  <Contents><Key>k4</Key></Contents>
</ListBucketResult>"#)
    });
    let (keys, truncated) = block_on(klant().list(&mut t, "", 2)).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(truncated);
}

#[test]
fn list_exacte_cap_vraagt_geen_extra_pagina() {
    let mut t = mock(|_| {
        ok(b"<ListBucketResult><IsTruncated>true</IsTruncated>\
<NextContinuationToken>onnodig</NextContinuationToken>\
<Contents><Key>k1</Key></Contents><Contents><Key>k2</Key></Contents></ListBucketResult>")
    });
    let (keys, truncated) = block_on(klant().list(&mut t, "", 2)).unwrap();
    assert_eq!((keys.len(), truncated), (2, true));
    assert_eq!(t.seen.borrow().len(), 1);
}

#[test]
fn url_samenstelling() {
    let vhost = Client {
        endpoint: "https://s3.example.com".into(),
        bucket: "bkt".into(),
        ..Client::default()
    };
    let u = vhost.bucket_url().unwrap();
    assert_eq!((u.host(), u.path()), ("bkt.s3.example.com", "/"));
    let ou = vhost.url_for("a/b.txt").unwrap();
    assert_eq!((ou.host(), ou.path()), ("bkt.s3.example.com", "/a/b.txt"));
    assert!(ou.is_https());

    let path = Client {
        path_style: true,
        ..vhost
    };
    let pu = path.url_for("a/b.txt").unwrap();
    assert_eq!((pu.host(), pu.path()), ("s3.example.com", "/bkt/a/b.txt"));
}

#[test]
fn configuratie_faalt_luid() {
    let cases = [
        ("geen endpoint", "", "b", "k", "Endpoint is required"),
        (
            "geen bucket",
            "https://s3.example.com",
            "",
            "k",
            "Bucket is required",
        ),
        (
            "geen key",
            "https://s3.example.com",
            "b",
            "",
            "key is required",
        ),
        (
            "schema",
            "ftp://s3.example.com",
            "b",
            "k",
            "must be http or https",
        ),
        (
            "endpoint zonder schema",
            "s3.example.com",
            "b",
            "k",
            "must include scheme and host",
        ),
    ];
    for (name, endpoint, bucket, key, want) in cases {
        let c = Client {
            endpoint: endpoint.into(),
            bucket: bucket.into(),
            ..klant()
        };
        let mut t = mock(|_| ok(b""));
        let err = block_on(c.get(&mut t, key)).unwrap_err();
        assert!(err.to_string().contains(want), "{name}: {err}");
        assert!(t.seen.borrow().is_empty(), "{name}: toch verstuurd");
    }
}

// Een geannuleerde context deed in Go niets. Een future die nooit gepold wordt,
// doet hier niets: er gaat geen verzoek de deur uit.
#[test]
fn afgebroken_context_doet_niets() {
    let mut t = mock(|_| ok(b""));
    let c = klant();
    drop(c.get(&mut t, "k"));
    assert!(t.seen.borrow().is_empty());
}

#[test]
fn redirect_wordt_nooit_gevolgd() {
    let mut t = mock(|_| {
        let mut r = status(301, "Moved Permanently", "");
        r.headers
            .push(("Location", "http://elders.example/elders".into()));
        r
    });
    let c = Client {
        session_token: "STSGEHEIM".into(),
        ..klant()
    };
    let err = block_on(c.get(&mut t, "sleutel")).unwrap_err();
    assert!(
        matches!(&err, Error::Status(se) if se.code == 301),
        "wil de 301 zelf als StatusError, kreeg {err:?}"
    );
    let seen = t.seen.borrow();
    assert_eq!(seen.len(), 1, "de redirect is gevolgd");
    assert_eq!(seen[0].host, "127.0.0.1:9000");
}

#[test]
fn unsigned_payload_eist_https() {
    let c = Client {
        endpoint: "http://minio.lan:9000".into(),
        ..klant()
    };
    let mut t = mock(|_| ok(b""));
    let err = block_on(c.put_from(
        &mut t,
        "k",
        &mut Source(b"x"),
        1,
        UNSIGNED_PAYLOAD,
        &PutOptions::default(),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");
    assert!(t.seen.borrow().is_empty());
}

#[test]
fn put_from_nul_neemt_het_lengtepad() {
    let mut t = mock(|_| ok(b"").etag("\"leeg\""));
    let etag = block_on(klant().put_from(
        &mut t,
        "k",
        &mut Source(b""),
        0,
        sigv4::EMPTY_PAYLOAD_HASH,
        &PutOptions::default(),
    ))
    .unwrap();
    assert_eq!(etag.as_deref(), Some("\"leeg\""));
    let seen = &t.seen.borrow()[0];
    assert!(
        !seen.streamed,
        "de lege stroom hoort het lengtepad te nemen"
    );
    assert_eq!(seen.body.as_deref(), Some(&[][..]));
}

// De Go-test telde verbindingen; hier telt of de body van de misser tot het
// einde gelezen is, want dat is wat een transport nodig heeft om te hergebruiken.
#[test]
fn sentinel_houdt_de_verbinding() {
    let mut t = mock(|_| status(404, "Not Found", "<Error><Code>NoSuchKey</Code></Error>"));
    for _ in 0..3 {
        t.drained.set(false);
        assert_eq!(
            block_on(klant().get(&mut t, "bestaat-niet")),
            Err(Error::NotFound)
        );
        assert!(t.drained.get(), "de sentinel-body wordt niet gedraind");
    }
}

#[test]
fn head_geeft_alleen_etag() {
    let mut t = mock(|_| Canned {
        status: 200,
        reason: "OK",
        headers: vec![("ETag", "\"etag-7\"".into())],
        // Een HEAD kondigt de body aan die hij niet stuurt.
        content_length: Some(123),
        body: MockBody::Hang,
    });
    let c = klant();
    assert_eq!(block_on(c.head(&mut t, "leases/c")).unwrap(), "\"etag-7\"");
    assert_eq!(block_on(c.head(&mut t, "leases/c")).unwrap(), "\"etag-7\"");
    let seen = &t.seen.borrow()[0];
    assert_eq!((seen.method, seen.path.as_str()), ("HEAD", "/bkt/leases/c"));
    assert!(
        !seen.header("Authorization").is_empty(),
        "HEAD niet getekend"
    );
}

#[test]
fn head_afwezig_is_err_not_found() {
    let mut t = mock(|_| status(404, "Not Found", ""));
    assert_eq!(
        block_on(klant().head(&mut t, "leases/x")),
        Err(Error::NotFound)
    );
}

// De les uit de Go-doc: de kleinste Go-kopie liet URI-escaping weg, zodat een
// sleutel met een spatie of `+` een andere string tekende dan het verzoek
// droeg. Het target op de draad moet precies het getekende pad zijn.
#[test]
fn sleutel_met_spatie_tekent_wat_over_de_draad_gaat() {
    let c = klant();
    let url = c.url_for("map met spatie/a+b.txt").unwrap();
    let target = url.target().unwrap();
    assert_eq!(target, "/bkt/map%20met%20spatie/a%2Bb.txt");
    let mut headers = Vec::new();
    sigv4::set_header(&mut headers, "X-Amz-Date", "20260115T120000Z").unwrap();
    let (canonical, _) =
        sigv4::canonical_request("GET", &url, &headers, sigv4::EMPTY_PAYLOAD_HASH).unwrap();
    assert_eq!(canonical.lines().nth(1), Some(target.as_str()));

    let mut t = mock(|_| ok(b"x"));
    block_on(c.get(&mut t, "map met spatie/a+b.txt")).unwrap();
    assert_eq!(t.seen.borrow()[0].path, "/bkt/map met spatie/a+b.txt");
}

// Een vaste lengte die eerder eindigt is een fout, nooit een kleiner object.
#[test]
fn afgekapte_body_is_een_fout() {
    let mut t = mock(|_| Canned {
        status: 200,
        reason: "OK",
        headers: Vec::new(),
        content_length: Some(10),
        body: MockBody::Bytes(b"kort".to_vec()),
    });
    assert_eq!(
        block_on(klant().get(&mut t, "k")),
        Err(Error::Transport {
            op: Op::Get,
            source: IoError::UnexpectedEof
        })
    );
}

#[test]
fn zonder_klok_faalt_luid() {
    let c = Client {
        now: None,
        ..klant()
    };
    let mut t = mock(|_| ok(b""));
    assert_eq!(block_on(c.get(&mut t, "k")), Err(Error::ClockRequired));
}

#[test]
fn debug_lekt_geen_geheim() {
    let c = Client {
        session_token: "STSGEHEIM".into(),
        ..klant()
    };
    let shown = format!("{c:?}");
    assert!(
        !shown.contains("SK") && !shown.contains("STSGEHEIM"),
        "{shown}"
    );
}
