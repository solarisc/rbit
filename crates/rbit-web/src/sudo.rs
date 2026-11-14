//! The recent-proof window for changes to credentials ("sudo mode"): a web session may add
//! an SSH key or mint a personal access token only shortly after it proved its identity.
//!
//! Signing in stamps a short-lived cookie: `<issued-at>.<hex SHA-256>`, where the digest
//! covers the session token and the issue time. A stamp is worthless for any other session
//! and expires after [`WINDOW_SECONDS`]. API calls authenticated by a token never consult it,
//! because a token is already a credential.

use std::{convert::Infallible, fmt::Write};

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use rbit_core::{Timestamp, User};
use rbit_services::ServiceError;
use sha2::{Digest, Sha256};

use crate::{AppState, client_ip::Https};

/// Refusal when a credential change arrives without a password and without a fresh stamp.
const REAUTH_REQUIRED: &str = "confirm your current password to add credentials";
/// Refusal when the password given for a credential change is wrong.
const WRONG_PASSWORD: &str = "the password is wrong";

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
    hash.finalize().iter().fold(String::new(), |mut hex, byte| {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
        hex
    })
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

/// The cookie jar and whether the request arrived over HTTPS: what a credential change needs to
/// stamp the window. One extractor, so handlers stay within the argument limit.
pub struct Stamp {
    pub jar: CookieJar,
    pub secure: bool,
}

impl FromRequestParts<AppState> for Stamp {
    type Rejection = Infallible;

    #[allow(unknown_lints, clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = <CookieJar as FromRequestParts<AppState>>::from_request_parts(parts, state).await?;
        let Https(secure) = <Https as FromRequestParts<AppState>>::from_request_parts(parts, state).await?;
        Ok(Self { jar, secure })
    }
}

/// Lets a credential change through. A fresh stamp passes. Otherwise `password`, the account's
/// current password, is checked the way sign-in checks it, and a correct one stamps the window
/// again. Refusals are `ServiceError::Invalid` with the text the form shows.
pub async fn confirm(
    state: &AppState,
    jar: CookieJar,
    secure: bool,
    session: &str,
    user: &User,
    password: String,
) -> Result<CookieJar, ServiceError> {
    if is_fresh(&jar, session, now()) {
        return Ok(jar);
    }
    if password.is_empty() {
        return Err(ServiceError::Invalid(REAUTH_REQUIRED.to_owned()));
    }
    let login = user.name().to_string();
    match state.services.accounts.authenticate(&login, password).await {
        Ok(account) if account.id() == user.id() => Ok(issue(jar, secure, session, now())),
        Ok(_) | Err(ServiceError::InvalidCredentials) => Err(ServiceError::Invalid(WRONG_PASSWORD.to_owned())),
        Err(error) => Err(error),
    }
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
        let moved =
            CookieJar::new().add(Cookie::new(COOKIE, format!("1500.{}", stamped.get(COOKIE).unwrap().value().split_once('.').unwrap().1)));
        assert!(!is_fresh(&moved, SESSION, 1_500), "the digest covers the issue time");
    }
}
