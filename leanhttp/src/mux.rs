//! Routering op methode en pad, alleen in de vormen die de routetabellen van
//! dit project gebruiken, niet het volledige contract van Go's `ServeMux`:
//!
//! ```text
//! "/health"                       exact pad, zonder slash aan het eind
//! "GET /v1/agents"                exact pad en methode; GET bedient ook HEAD
//! "/logs/"                        een subtree: de wortel met slash en alles eronder
//! "/v1/agents/{id}/logs/"         {id} vangt één segment
//! "GET /app-ui/{app}/{path...}"   {path...} vangt de rest van het pad
//! ```
//!
//! Bewust weggelaten: `{$}` (vaste paden en subtrees dekken de tabellen), en
//! routering op escapes (de parser weigert escapes die tot `/`, `.` of `..`
//! decoderen, zodat middleware en de Mux hetzelfde pad zien). Geen scores en
//! geen sortering: de strikte-deelverzamelingsrelatie kiest de specifiekste
//! route, los van de volgorde van registreren.
//!
//! De Mux roept geen handlers aan; hij zegt welke waarde bij het verzoek hoort.
//! Die waarde is wat de aanroeper kiest (een enum, een functiepointer), en de
//! aanroeper `match`t erop. Zo blijft de dispatch statisch, zonder een
//! allocatie per verzoek. De tabel is onveranderlijk zodra de server loopt:
//! registreren gebeurt vooraf, met `&mut`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, PatternError, Result};
use crate::header::{try_string, valid_token};
use crate::io::{Conn, try_extend};
use crate::server::{Exchange, Request};
use crate::url::canonical_path;

/// Een routetabel van patroon naar een waarde van de aanroeper.
#[derive(Debug)]
pub struct Mux<T> {
    routes: Vec<Route<T>>,
}

/// Een voorgeparseerd patroon.
#[derive(Debug)]
struct Route<T> {
    /// Leeg betekent elke methode.
    method: String,
    segs: Vec<Seg>,
    /// Naam van de `{rest...}`-wildcard.
    rest: Option<String>,
    /// Het patroon eindigde op `/`: de wortel met slash en alles eronder.
    subtree: bool,
    value: T,
}

#[derive(Debug)]
enum Seg {
    Lit(String),
    Wild(String),
}

impl Seg {
    fn lit(&self) -> Option<&str> {
        match self {
            Seg::Lit(s) => Some(s),
            Seg::Wild(_) => None,
        }
    }
}

/// Wat [`Mux::find`] bij een verzoek vond.
#[derive(Debug, PartialEq, Eq)]
pub enum Found<'m, T> {
    /// De specifiekste route voor methode en pad.
    Route(&'m T),
    /// Geen enkel pad past.
    NotFound,
    /// Het pad bestaat, maar niet voor deze methode; de waarde is de
    /// `Allow`-lijst.
    MethodNotAllowed(String),
}

impl<T> Default for Mux<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Mux<T> {
    /// Een lege tabel.
    pub const fn new() -> Self {
        Mux { routes: Vec::new() }
    }

    /// Registreert `value` onder `pattern`; de moduledoc noemt de vormen.
    ///
    /// Een kromme methode, een niet-canoniek pad, een foute wildcard of een
    /// patroon dat een ander overlapt zonder strikte deelverzameling te zijn,
    /// is een bedradingsfout: die komt hier terug, vóór het serveren, in
    /// plaats van stil bij de dispatch.
    pub fn handle(&mut self, pattern: &str, value: T) -> Result {
        let (method, path) = match pattern.split_once(' ') {
            Some((m, p)) => (m, p.trim()),
            None => ("", pattern),
        };
        if !method.is_empty() && !valid_token(method) {
            return Err(PatternError::BadMethod.into());
        }
        if !canonical_path(path) {
            // Hetzelfde predicaat als de dispatch; anders vouwt splitsen een
            // pad als /a//b stil tot een route met een andere dekking.
            return Err(PatternError::NotCanonical.into());
        }
        let mut rt = Route {
            method: try_string(method)?,
            segs: Vec::new(),
            rest: None,
            subtree: path.ends_with('/'),
            value,
        };
        for seg in path.trim_matches('/').split('/') {
            rt.push_segment(seg)?;
        }
        // Overlap mag alleen als de een een strikte deelverzameling van de
        // ander is; anders zou de volgorde van registreren beslissen.
        if let Some(with) = self.routes.iter().position(|o| rt.conflicts_with(o)) {
            return Err(PatternError::Conflict { with }.into());
        }
        self.routes
            .try_reserve(1)
            .map_err(|_| Error::Alloc { bytes: 1 })?;
        self.routes.push(rt);
        Ok(())
    }

    /// Zoekt de specifiekste route voor `req` en zet zijn wildcardwaarden.
    ///
    /// Niets wordt genormaliseerd: een niet-canoniek pad (door middleware of
    /// met de hand gebouwd) routeert nergens heen. HEAD valt terug op GET, maar
    /// een expliciete HEAD-route wint en een methodeloze route verliest van GET.
    pub fn find(&self, req: &mut Request) -> Result<Found<'_, T>> {
        if !canonical_path(&req.path) {
            return Ok(Found::NotFound);
        }
        let mut segs: Vec<&str> = Vec::new();
        let trimmed = req.path.trim_matches('/');
        if !trimmed.is_empty() {
            for s in trimmed.split('/') {
                segs.try_reserve(1).map_err(|_| Error::Alloc { bytes: 1 })?;
                segs.push(s);
            }
        }
        let trailing = req.path.ends_with('/');
        let (mut pick, mut fallback): (Option<&Route<T>>, Option<&Route<T>>) = (None, None);
        let mut allow: Vec<&str> = Vec::new();
        for rt in &self.routes {
            if !rt.matches(&segs, trailing) {
                continue;
            }
            if !rt.method.is_empty() && rt.method != req.method {
                if rt.method == "GET" && req.method == "HEAD" {
                    if fallback.is_none_or(|f| rt.more_specific(f)) {
                        fallback = Some(rt);
                    }
                    continue;
                }
                // Het pad bestaat, maar niet voor deze methode. GET bedient
                // HEAD volgens contract, dus Allow noemt die ook.
                for m in [rt.method.as_str(), "HEAD"] {
                    if m == "HEAD" && rt.method != "GET" {
                        continue;
                    }
                    if !allow.contains(&m) {
                        allow
                            .try_reserve(1)
                            .map_err(|_| Error::Alloc { bytes: 1 })?;
                        allow.push(m);
                    }
                }
                continue;
            }
            if pick.is_none_or(|p| rt.more_specific(p)) {
                pick = Some(rt);
            }
        }
        if let Some(f) = fallback
            && pick.is_none_or(|p| f.more_specific(p))
        {
            pick = Some(f);
        }
        if let Some(rt) = pick {
            req.set_path_values(rt.capture(&segs, trailing)?);
            return Ok(Found::Route(&rt.value));
        }
        if allow.is_empty() {
            return Ok(Found::NotFound);
        }
        let mut list = Vec::new();
        for (i, m) in allow.iter().enumerate() {
            if i > 0 {
                try_extend(&mut list, b", ")?;
            }
            try_extend(&mut list, m.as_bytes())?;
        }
        Ok(Found::MethodNotAllowed(
            String::from_utf8(list).unwrap_or_default(),
        ))
    }

    /// Als [`Mux::find`], en antwoordt zelf met 404, of met 405 plus de
    /// verplichte `Allow` (RFC 9110 §15.5.6); `None` betekent dat het antwoord
    /// al verstuurd is.
    pub async fn dispatch<C: Conn>(&self, ex: &mut Exchange<'_, C>) -> Result<Option<&T>> {
        match self.find(&mut ex.req)? {
            Found::Route(v) => Ok(Some(v)),
            Found::NotFound => {
                ex.error(404, "not found").await?;
                Ok(None)
            }
            Found::MethodNotAllowed(allow) => {
                ex.header_mut().set("Allow", &allow)?;
                ex.error(405, "method not allowed").await?;
                Ok(None)
            }
        }
    }
}

impl<T> Route<T> {
    fn push_segment(&mut self, seg: &str) -> Result {
        // Een rest-wildcard slokt alles op; een segment erna matcht nooit.
        if self.rest.is_some() {
            return Err(PatternError::SegmentAfterRest.into());
        }
        if seg.is_empty() {
            // Het wortelpatroon "/" heeft geen segmenten.
            return Ok(());
        }
        if seg == "{$}" {
            return Err(PatternError::Dollar.into());
        }
        if let Some(name) = wild(seg).and_then(|s| s.strip_suffix("...")) {
            if name.is_empty() || self.has_name(name) {
                return Err(PatternError::BadName.into());
            }
            self.rest = Some(try_string(name)?);
            // De rest mag leeg zijn en slashes bevatten.
            self.subtree = true;
            return Ok(());
        }
        let s = match wild(seg) {
            Some(name) if !name.is_empty() => {
                if self.has_name(name) {
                    return Err(PatternError::BadName.into());
                }
                Seg::Wild(try_string(name)?)
            }
            _ if seg.starts_with('{') || seg.ends_with('}') => {
                // Een halve wildcard als literal lezen verstopt een bedradingsfout.
                return Err(PatternError::MalformedWildcard.into());
            }
            // Requestpaden zijn al gedecodeerd, dus een ge-escapete literal kan
            // nooit matchen. Patronen zijn broncode: schrijf het teken zelf.
            _ if seg.contains('%') => return Err(PatternError::EscapedLiteral.into()),
            _ => Seg::Lit(try_string(seg)?),
        };
        self.segs
            .try_reserve(1)
            .map_err(|_| Error::Alloc { bytes: 1 })?;
        self.segs.push(s);
        Ok(())
    }

    fn has_name(&self, name: &str) -> bool {
        self.rest.as_deref() == Some(name)
            || self
                .segs
                .iter()
                .any(|s| matches!(s, Seg::Wild(n) if n == name))
    }

    /// Overlap zonder precies één strikte deelverzamelingsrichting.
    fn conflicts_with(&self, o: &Route<T>) -> bool {
        if !methods_overlap(&self.method, &o.method) || !self.path_overlaps(o) {
            return false;
        }
        let r_sub = method_subset(&self.method, &o.method) && self.path_subset(o);
        let o_sub = method_subset(&o.method, &self.method) && o.path_subset(self);
        r_sub == o_sub
    }

    /// Zegt of een pad bij beide patronen past.
    ///
    /// Vaste patronen matchen exact zonder slash; een subtree matcht zijn
    /// wortel met slash en alles eronder, dus /admin en /admin/ zijn disjunct.
    fn path_overlaps(&self, o: &Route<T>) -> bool {
        let clash = self
            .segs
            .iter()
            .zip(&o.segs)
            .any(|(a, b)| matches!((a.lit(), b.lit()), (Some(x), Some(y)) if x != y));
        if clash {
            return false;
        }
        let (r, n) = (self.segs.len(), o.segs.len());
        match (self.subtree, o.subtree) {
            (true, true) => true,
            (true, false) => n > r,
            (false, true) => r > n,
            (false, false) => r == n,
        }
    }

    /// Zegt of `o` elk pad matcht dat `self` matcht.
    fn path_subset(&self, o: &Route<T>) -> bool {
        for (i, seg) in o.segs.iter().enumerate() {
            let Some(lit) = seg.lit() else {
                continue;
            };
            if self.segs.get(i).and_then(Seg::lit) != Some(lit) {
                return false;
            }
        }
        let (r, n) = (self.segs.len(), o.segs.len());
        if o.subtree {
            // Vaste paden missen de slash: alleen strikt eronder.
            return if self.subtree { r >= n } else { r > n };
        }
        !self.subtree && r == n
    }

    /// Zegt of `self` een strikte deelverzameling van `o` is.
    fn more_specific(&self, o: &Route<T>) -> bool {
        let r_sub = method_subset(&self.method, &o.method) && self.path_subset(o);
        let o_sub = method_subset(&o.method, &self.method) && o.path_subset(self);
        r_sub && !o_sub
    }

    fn matches(&self, segs: &[&str], trailing: bool) -> bool {
        let n = self.segs.len();
        if self.subtree {
            // Afstammelingen altijd; de wortel zelf vraagt de slash.
            if segs.len() < n || (segs.len() == n && !trailing) {
                return false;
            }
        } else if segs.len() != n || trailing {
            return false;
        }
        self.segs
            .iter()
            .zip(segs)
            .all(|(p, s)| p.lit().is_none_or(|l| l == *s))
    }

    fn capture(&self, segs: &[&str], trailing: bool) -> Result<Vec<(String, String)>> {
        let mut vals = Vec::new();
        let mut push = |k: &str, v: &str| -> Result {
            vals.try_reserve(1).map_err(|_| Error::Alloc { bytes: 1 })?;
            vals.push((try_string(k)?, try_string(v)?));
            Ok(())
        };
        for (p, s) in self.segs.iter().zip(segs) {
            if let Seg::Wild(name) = p {
                push(name, s)?;
            }
        }
        if let Some(name) = &self.rest {
            let mut v = Vec::new();
            for (i, s) in segs.iter().skip(self.segs.len()).enumerate() {
                if i > 0 {
                    try_extend(&mut v, b"/")?;
                }
                try_extend(&mut v, s.as_bytes())?;
            }
            if trailing && !v.is_empty() {
                // De slash hoort bij de rest: /files/a/ vangt "a/".
                try_extend(&mut v, b"/")?;
            }
            push(name, core::str::from_utf8(&v).unwrap_or(""))?;
        }
        Ok(vals)
    }
}

/// De naam binnen `{...}`, als het segment zo geschreven is.
fn wild(s: &str) -> Option<&str> {
    s.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
}

/// Methodes als verzamelingen: leeg dekt alles en GET bedient ook HEAD, dus
/// HEAD ⊂ GET ⊂ "".
fn methods_overlap(a: &str, b: &str) -> bool {
    a.is_empty()
        || b.is_empty()
        || a == b
        || (a == "GET" && b == "HEAD")
        || (a == "HEAD" && b == "GET")
}

/// Zegt of `b` elke methode dekt die `a` dekt.
fn method_subset(a: &str, b: &str) -> bool {
    b.is_empty() || a == b || (a == "HEAD" && b == "GET")
}
