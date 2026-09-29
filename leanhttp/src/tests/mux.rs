//! Muxtests: mux_test.go en de registratietests uit review13_test.go.
//!
//! In Go paniekte een foute registratie; hier geeft [`Mux::handle`] een fout,
//! dus "verwacht een panic" is "verwacht een `Err`".

use std::rc::Rc;

use super::support::*;
use super::{h, split};
use crate::{Error, Found, Mux, PatternError, Request};

fn req(method: &str, path: &str) -> Request {
    let mut r = Request::new(method, "/").unwrap();
    r.path = path.to_string();
    r
}

fn find<'m>(
    m: &'m Mux<&'static str>,
    method: &str,
    path: &str,
) -> (Found<'m, &'static str>, Request) {
    let mut r = req(method, path);
    let f = m.find(&mut r).unwrap();
    (f, r)
}

#[test]
fn mux_patronen() {
    let patterns = [
        "/health",
        "/logs/",
        "GET /api/devices",
        "POST /api/devices",
        "DELETE /api/devices/",
        "GET /api/devices/{id}",
        "GET /api/devices/{id}/history",
        "GET /app-ui/{app}/settings/{path...}",
        "GET /app-ui/{app}/pair/{driver}/{path...}",
    ];
    let mut m = Mux::new();
    for p in patterns {
        m.handle(p, p).unwrap();
    }
    let mut vals = std::collections::HashMap::new();
    for (method, path, want) in [
        ("GET", "/health", "/health"),
        ("GET", "/logs/abc/def", "/logs/"),
        ("GET", "/api/devices", "GET /api/devices"),
        ("POST", "/api/devices", "POST /api/devices"),
        ("GET", "/api/devices/lamp-1", "GET /api/devices/{id}"),
        (
            "GET",
            "/api/devices/lamp-1/history",
            "GET /api/devices/{id}/history",
        ),
        ("DELETE", "/api/devices/lamp-1", "DELETE /api/devices/"),
        (
            "GET",
            "/app-ui/com.x/settings/",
            "GET /app-ui/{app}/settings/{path...}",
        ),
        (
            "GET",
            "/app-ui/com.x/settings/style.css",
            "GET /app-ui/{app}/settings/{path...}",
        ),
        (
            "GET",
            "/app-ui/com.x/settings/a/b/c.png",
            "GET /app-ui/{app}/settings/{path...}",
        ),
        (
            "GET",
            "/app-ui/com.x/pair/switch/index.html",
            "GET /app-ui/{app}/pair/{driver}/{path...}",
        ),
    ] {
        let (f, r) = find(&m, method, path);
        assert_eq!(f, Found::Route(&want), "{method} {path}");
        for k in ["id", "app", "driver", "path"] {
            if let Some(v) = r.path_value(k).filter(|v| !v.is_empty()) {
                vals.insert(k, v.to_string());
            }
        }
    }
    for (k, want) in [
        ("app", "com.x"),
        ("driver", "switch"),
        ("path", "index.html"),
        ("id", "lamp-1"),
    ] {
        assert_eq!(
            vals.get(k).map(String::as_str),
            Some(want),
            "path_value({k})"
        );
    }
}

#[test]
fn mux_matcht_alleen_canoniek() {
    let mut m = Mux::new();
    m.handle("GET /api/devices", "x").unwrap();
    for pad in [
        "/api//devices",
        "/api/devices/",
        "api/devices",
        "//api/devices",
    ] {
        assert_eq!(find(&m, "GET", pad).0, Found::NotFound, "{pad}");
    }
}

#[test]
fn mux_rest_kan_leeg_zijn() {
    let mut m = Mux::new();
    m.handle("GET /files/{path...}", "files").unwrap();
    let (f, r) = find(&m, "GET", "/files/");
    assert_eq!(
        f,
        Found::Route(&"files"),
        "/files/ raakte de rest-wildcard niet"
    );
    assert_eq!(r.path_value("path"), Some(""));
}

#[test]
fn mux_status() {
    let mut m = Mux::new();
    m.handle("GET /x", "x").unwrap();
    assert_eq!(find(&m, "GET", "/x").0, Found::Route(&"x"));
    assert_eq!(
        find(&m, "POST", "/x").0,
        Found::MethodNotAllowed("GET, HEAD".to_string())
    );
    assert_eq!(find(&m, "GET", "/y").0, Found::NotFound);
}

#[test]
fn mux_weigert_foute_wiring() {
    // Go's nil-handler bestaat hier niet; de overige vormen wel.
    assert_eq!(
        Mux::new().handle("health", ()),
        Err(Error::Pattern(PatternError::NotCanonical))
    );
    let mut m = Mux::new();
    m.handle("/x", ()).unwrap();
    assert!(m.handle("/x", ()).is_err());
    let mut m = Mux::new();
    m.handle("GET /x", ()).unwrap();
    assert!(m.handle("GET /x", ()).is_err());
    let mut m = Mux::new();
    m.handle("GET /x", ()).unwrap();
    m.handle("POST /x", ()).unwrap();
}

#[test]
fn mux_over_de_draad() {
    let mut m = Mux::new();
    m.handle("GET /api/devices/{id}", ()).unwrap();
    let m = Rc::new(m);
    let srv = h!(ex => {
        if m.dispatch(ex).await?.is_some() {
            let body = format!("device {}", ex.req.path_value("id").unwrap_or(""));
            ex.write(body.as_bytes()).await?;
        }
    });
    let got = rt(
        &srv,
        "GET /api/devices/lamp-9 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(split(&got).1, "device lamp-9");
}

#[test]
fn mux_dollar_panickt_met_alternatief() {
    let err = Mux::new().handle("GET /logs/{$}", ()).unwrap_err();
    assert_eq!(err, Error::Pattern(PatternError::Dollar));
    assert!(err.to_string().contains("{$}"), "{err}");
}

#[test]
fn mux_weigert_ambigue_routes() {
    let mut m = Mux::new();
    m.handle("GET /users/{id}", ()).unwrap();
    assert!(m.handle("GET /users/{name}", ()).is_err(), "zelfde vorm");
    let mut m = Mux::new();
    m.handle("GET /a/{x}", ()).unwrap();
    assert!(
        m.handle("GET /{y}/b", ()).is_err(),
        "kruisend met gelijke score"
    );
    let mut m = Mux::new();
    m.handle("GET /a/{x}", ()).unwrap();
    m.handle("GET /a/b", ()).unwrap();
}

#[test]
fn mux_weigert_ongeldige_vormen() {
    for (name, p, want) in [
        (
            "segment na rest",
            "GET /a/{rest...}/b",
            PatternError::SegmentAfterRest,
        ),
        (
            "dubbele wildcardnaam",
            "GET /{x}/{x}",
            PatternError::BadName,
        ),
        (
            "lege accolades",
            "GET /a/{}",
            PatternError::MalformedWildcard,
        ),
        ("naamloze rest", "GET /a/{...}", PatternError::BadName),
        ("segment na {$}", "GET /a/{$}/b", PatternError::Dollar),
    ] {
        assert_eq!(
            Mux::new().handle(p, ()),
            Err(Error::Pattern(want)),
            "{name}"
        );
    }
    let mut m = Mux::new();
    m.handle("GET /files/", ()).unwrap();
    assert!(
        m.handle("GET /files/{rest...}", ()).is_err(),
        "subtree vs rest: zelfde dekking"
    );
}

#[test]
fn mux_kruisende_patronen_conflicteren() {
    for (name, patterns) in [
        ("kruisende wildcards", ["GET /a/{x}/{y}", "GET /{x}/b/c"]),
        ("kruisend met subtree", ["GET /a/{x}/", "GET /{x}/b/"]),
    ] {
        let mut m = Mux::new();
        m.handle(patterns[0], ()).unwrap();
        assert!(m.handle(patterns[1], ()).is_err(), "{name}: geen conflict");
    }
    for (name, patterns) in [
        ("exact onder subtree", ["GET /files/", "GET /files/x"]),
        ("methode onder elk", ["/x", "GET /x"]),
        ("vast naast de subtree", ["GET /logs", "GET /logs/"]),
        ("wildcard onder literal", ["GET /{x}", "GET /a"]),
    ] {
        let mut m = Mux::new();
        for p in patterns {
            m.handle(p, ())
                .unwrap_or_else(|e| panic!("{name}: onterecht conflict: {e}"));
        }
    }
}

#[test]
fn mux_get_kruist_head() {
    let mut m = Mux::new();
    m.handle("GET /a/{x}", ()).unwrap();
    assert!(
        m.handle("HEAD /{x}/b", ()).is_err(),
        "HEAD /a/b matcht beide"
    );
    let mut m = Mux::new();
    m.handle("GET /x", ()).unwrap();
    m.handle("HEAD /x", ()).unwrap();
}

#[test]
fn escaped_literal_in_patroon_panickt() {
    assert_eq!(
        Mux::new().handle("GET /objects/secret%2Fmetadata", ()),
        Err(Error::Pattern(PatternError::EscapedLiteral))
    );
}

#[test]
fn registratie_faalt_vroeg() {
    for (name, p) in [
        ("kromme methode", "GE(T /x"),
        ("dot-patroon", "GET /a/../b"),
        ("dubbele slash", "GET /a//b"),
        ("lege wortel", "//a"),
        ("lege staart", "/a//"),
    ] {
        assert!(Mux::new().handle(p, ()).is_err(), "{name}");
    }
}
