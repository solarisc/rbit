//! The recent-proof window for credential changes ("sudo mode"): the web layer's side. The
//! stamp is computed and checked by `rbit_services::sudo`, under a server-held key; this
//! module only carries it in a cookie bound to the session.

use std::convert::Infallible;

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use rbit_core::{Timestamp, User};
use rbit_services::{ServiceError, sudo::WINDOW_SECONDS};

use crate::{AppState, client_ip::Https};

/// The cookie holding the stamp.
pub const COOKIE: &str = "rbit_sudo";

/// Refusal when a credential change arrives without a password and without a fresh stamp.
const REAUTH_REQUIRED: &str = "confirm your current password to add credentials";
/// Refusal when the password given for a credential change is wrong.
const WRONG_PASSWORD: &str = "the password is wrong";
/// Refusal for an account without a password, which must sign in again instead.
const SIGN_IN_AGAIN: &str = "sign in again to add credentials";

/// The cookie jar and whether the request arrived over HTTPS. One extractor, so handlers stay
/// within the argument limit.
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

/// Sets the stamp cookie for the window.
pub fn issue(jar: CookieJar, secure: bool, stamp: String) -> CookieJar {
    let cookie = Cookie::build((COOKIE, stamp))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(time::Duration::seconds(WINDOW_SECONDS));
    jar.add(cookie)
}

/// The stamp in `jar`, or an empty string when there is none.
pub fn stamp_value(jar: &CookieJar) -> String {
    jar.get(COOKIE).map_or_else(String::new, |cookie| cookie.value().to_owned())
}

/// The current time in whole seconds.
pub fn now() -> i64 {
    Timestamp::now().seconds()
}

/// Lets a credential change through. A fresh stamp passes. Otherwise `password`, the account's
/// current password, is confirmed (throttled by the service), and a correct one stamps the
/// window again. Accounts without a password are told to sign in again.
pub async fn confirm(state: &AppState, jar: CookieJar, secure: bool, session: &str, user: &User, password: String) -> Result<CookieJar, ServiceError> {
    let sudo = &state.services.sudo;
    if sudo.is_fresh(session, &stamp_value(&jar), now()).await? {
        return Ok(jar);
    }
    if !sudo.has_password(user).await? {
        return Err(ServiceError::Invalid(SIGN_IN_AGAIN.to_owned()));
    }
    if password.is_empty() {
        return Err(ServiceError::Invalid(REAUTH_REQUIRED.to_owned()));
    }
    match sudo.confirm_password(user, password).await {
        Ok(()) => {}
        Err(ServiceError::InvalidCredentials) => return Err(ServiceError::Invalid(WRONG_PASSWORD.to_owned())),
        Err(error) => return Err(error),
    }
    let stamp = sudo.stamp(session, now()).await?;
    Ok(issue(jar, secure, stamp))
}
