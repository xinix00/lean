//! De geporte Go-tests. Elke Go-test is hier een test met dezelfde naam in
//! snake_case en dezelfde bedoeling; waar de Go-machinerie (listener,
//! `context`, absolute deadlines) in Rust niet bestaat, staat bij de test wat
//! er in de plaats kwam.

mod support;

mod client;
mod mux;
mod pool;
mod server;

/// Een handler als async closure over een [`Exchange`](crate::Exchange) op een
/// testpijp, gedeeld over verbindingen.
macro_rules! h {
    ($ex:ident => $body:block) => {
        $crate::tests::support::lean(
            async move |$ex: &mut $crate::Exchange<'_, $crate::tests::support::End>| -> $crate::Result {
                $body
                #[allow(unreachable_code)]
                Ok(())
            },
        )
    };
}
pub(crate) use h;

/// Kop en body van een rauw antwoord.
pub(crate) fn split(resp: &str) -> (&str, &str) {
    resp.split_once("\r\n\r\n").unwrap_or((resp, ""))
}
