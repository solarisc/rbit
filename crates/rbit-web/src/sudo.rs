//! The recent-proof window for changes to credentials ("sudo mode"): a web session may add
//! an SSH key or mint a personal access token only shortly after it proved its identity.
//!
//! Signing in stamps a short-lived cookie: `<issued-at>.<hex SHA-256>`, where the digest
//! covers the session token and the issue time. A stamp is worthless for any other session
//! and expires after [`WINDOW_SECONDS`]. API calls authenticated by a token never consult it,
//! because a token is already a credential.

use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use rbit_core::Timestamp;
use sha2::{Digest, Sha256};

/// The cookie holding the stamp.
pub const COOKIE: &str = "rbit_sudo";
/// How long after proving identity a session may change credentials, in seconds.
pub const WINDOW_SECONDS: i64 = 600;

/// The hex SHA-256 over the session token and the issue time.
fn digest(session: &str, issued_at: i64) -> String {
    let mut hash = Sha256::new();
    hash.update(b"rbit-sudo-v1\0");
    hash.update(session.as_bytes());
    hash.update(b"\0");
    hash.update(issued_at.to_be_bytes());
    hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Stamps `jar` as proof of identity for `session` (its encoded token) at `now`.
pub fn issue(jar: CookieJar, secure: bool, session: &str, now: i64) -> CookieJar {
    let value = format!("{now}.{}", digest(session, now));
    let cookie = Cookie::build((COOKIE, value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(time::Duration::seconds(WINDOW_SECONDS));
    jar.add(cookie)
}

/// Whether `jar` holds a stamp issued to `session` no more than [`WINDOW_SECONDS`] before
/// `now`. The digest is compared in constant time.
pub fn is_fresh(jar: &CookieJar, session: &str, now: i64) -> bool {
    let Some(cookie) = jar.get(COOKIE) else { return false };
    let Some((issued, given)) = cookie.value().split_once('.') else { return false };
    let Ok(issued) = issued.parse::<i64>() else { return false };
    let age = now - issued;
    if !(0..=WINDOW_SECONDS).contains(&age) {
        return false;
    }
    let expected = digest(session, issued);
    given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0_u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The current time in whole seconds, for the window checks.
pub fn now() -> i64 {
    Timestamp::now().seconds()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "session-token-a";

    #[test]
    fn a_stamp_is_fresh_only_within_the_window_for_its_session() {
        let jar = issue(CookieJar::new(), true, SESSION, 1_000);
        assert!(is_fresh(&jar, SESSION, 1_000));
        assert!(is_fresh(&jar, SESSION, 1_000 + WINDOW_SECONDS));
        assert!(!is_fresh(&jar, SESSION, 1_000 + WINDOW_SECONDS + 1), "expired");
        assert!(!is_fresh(&jar, "session-token-b", 1_000), "another session's proof");
        assert!(!is_fresh(&jar, SESSION, 999), "a stamp from the future is refused");
    }

    #[test]
    fn a_tampered_or_missing_stamp_is_refused() {
        assert!(!is_fresh(&CookieJar::new(), SESSION, 1_000));
        let forged = CookieJar::new().add(Cookie::new(COOKIE, "1000.00"));
        assert!(!is_fresh(&forged, SESSION, 1_000));
        let stamped = issue(CookieJar::new(), false, SESSION, 1_000);
        let moved = CookieJar::new().add(Cookie::new(COOKIE, format!("1500.{}", stamped.get(COOKIE).unwrap().value().split_once('.').unwrap().1)));
        assert!(!is_fresh(&moved, SESSION, 1_500), "the digest covers the issue time");
    }
}
