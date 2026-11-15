//! The recent-proof window for credential changes ("sudo mode"). Adding a personal access
//! token, an SSH key or a deploy key from the web needs a sign-in, or the current password,
//! within [`WINDOW_SECONDS`].
//!
//! The proof is a stamp `<issued-at>.<hex tag>`. The tag is an HMAC under a server-held key
//! (the `sudo_proof` server secret, which never leaves the server), over a purpose string, the
//! SHA-256 of the session token and the issue time. A stolen session cookie does not let its
//! holder mint a stamp, and signing out ends the session the stamp is bound to.

use std::fmt::Write;

use hmac::{Hmac, KeyInit, Mac};
use rbit_core::User;
use sha2::{Digest, Sha256};

use crate::{AccountService, ServiceContext, ServiceError, ThrottleScope, ThrottleService};

/// The server-secrets row holding the key.
const KEY_NAME: &str = "sudo_proof";
/// Domain separation: changing it invalidates every stamp issued so far.
const PURPOSE: &str = "rbit/sudo-proof/v1";
/// How long after proving identity a session may change credentials, in seconds.
pub const WINDOW_SECONDS: i64 = 600;

type Tag = Hmac<Sha256>;

/// Issues and checks sudo stamps, and confirms current passwords for credential changes.
#[derive(Debug, Clone)]
pub struct SudoService {
    ctx: ServiceContext,
    accounts: AccountService,
    throttle: ThrottleService,
}

impl SudoService {
    pub(crate) fn new(ctx: ServiceContext, accounts: AccountService, throttle: ThrottleService) -> Self {
        Self { ctx, accounts, throttle }
    }

    /// Whether `user` has a password. Accounts that only sign in with a provider do not, and
    /// they prove identity by signing in again instead.
    pub async fn has_password(&self, user: &User) -> Result<bool, ServiceError> {
        Ok(self.ctx.database.external_identities().has_password(user.id()).await?)
    }

    /// The stamp for `session` (its encoded token) issued at `now`.
    pub async fn stamp(&self, session: &str, now: i64) -> Result<String, ServiceError> {
        let key = self.key().await?;
        let tag = tag(&key, session, now)?.finalize().into_bytes();
        Ok(format!("{now}.{}", to_hex(tag.as_slice())))
    }

    /// Whether `stamp` was issued to `session` no more than [`WINDOW_SECONDS`] before `now`.
    /// The tag is compared in constant time.
    pub async fn is_fresh(&self, session: &str, stamp: &str, now: i64) -> Result<bool, ServiceError> {
        let Some((issued, given)) = stamp.split_once('.') else { return Ok(false) };
        let Ok(issued) = issued.parse::<i64>() else { return Ok(false) };
        if !(0..=WINDOW_SECONDS).contains(&(now - issued)) {
            return Ok(false);
        }
        let Some(given) = from_hex(given) else { return Ok(false) };
        let key = self.key().await?;
        Ok(tag(&key, session, issued)?.verify_slice(&given).is_ok())
    }

    /// Checks `password` as the account's current password for a credential change. It spends
    /// the account's password-check budget, as profile changes do, so a stolen session cannot
    /// brute-force the password through these forms. `InvalidCredentials` for a wrong password,
    /// `RateLimited` once the budget is spent.
    pub async fn confirm_password(&self, user: &User, password: String) -> Result<(), ServiceError> {
        let account = user.id().0.to_string();
        self.throttle.check(ThrottleScope::PasswordCheck, &account)?;
        let login = user.name().to_string();
        match self.accounts.authenticate(&login, password).await {
            Ok(verified) if verified.id() == user.id() => {
                self.throttle.reset(ThrottleScope::PasswordCheck, &account);
                Ok(())
            }
            Ok(_) | Err(ServiceError::InvalidCredentials) => {
                self.throttle.record_failure(ThrottleScope::PasswordCheck, &account);
                Err(ServiceError::InvalidCredentials)
            }
            Err(error) => Err(error),
        }
    }

    /// The server's stamp key, created on first use.
    async fn key(&self) -> Result<Vec<u8>, ServiceError> {
        let mut fresh = [0_u8; 32];
        getrandom::fill(&mut fresh).map_err(|error| ServiceError::internal(std::io::Error::other(error.to_string())))?;
        Ok(self.ctx.database.server_secrets().get_or_insert(KEY_NAME, &fresh).await?)
    }
}

/// The keyed tag over the purpose, the session and the issue time.
fn tag(key: &[u8], session: &str, issued_at: i64) -> Result<Tag, ServiceError> {
    let mut tag = Tag::new_from_slice(key).map_err(|error| ServiceError::internal(std::io::Error::other(error.to_string())))?;
    tag.update(PURPOSE.as_bytes());
    tag.update(&[0]);
    tag.update(&Sha256::digest(session.as_bytes()));
    tag.update(&issued_at.to_be_bytes());
    Ok(tag)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok()).collect()
}
