//! Throttle budgets of one password attempt, shared by sign-in and Git HTTP Basic auth.
//!
//! Per typed login and per account, the budgets are kept per client network: wrong guesses
//! from one network spend its own, so a stranger guessing from their network cannot lock the
//! owner out from another. An account-wide failure budget, checked before verification,
//! still bounds guesses spread over many networks.

use super::{ClientInfo, ServiceError, ThrottleScope, account_key, ip_key, login_key};
use crate::ThrottleService;
use rbit_core::AccountId;

/// The budget keys of one attempt; `scope` selects the limits (sign-in or Git).
pub(super) struct PasswordBudget<'a> {
    throttle: &'a ThrottleService,
    scope: ThrottleScope,
    ip: String,
    typed: String,
}

impl<'a> PasswordBudget<'a> {
    /// Admits an attempt for `login` (already trimmed) from `client`, before any verification.
    pub(super) fn start(
        throttle: &'a ThrottleService,
        scope: ThrottleScope,
        client: &ClientInfo,
        login: &str,
    ) -> Result<Self, ServiceError> {
        let ip = ip_key(client);
        // The network comes before the potentially long login: throttle keys are length-capped,
        // so appending the network could merge different networks.
        let typed = format!("{ip}@{}", login_key(login));
        throttle.check_client(scope, &ip)?;
        throttle.check(scope, &typed)?;
        Ok(Self { throttle, scope, ip, typed })
    }

    fn local(&self, account: AccountId) -> String {
        format!("{}@{}", account_key(account), self.ip)
    }

    /// Run before verification. Unknown logins (`None`) have no account budgets.
    pub(super) fn before_verify(&self, account: Option<AccountId>) -> Result<(), ServiceError> {
        account.map_or(Ok(()), |account| {
            self.throttle.check(self.scope, &self.local(account))?;
            self.throttle.check_client_failures(self.scope, &account_key(account))
        })
    }

    /// Charges a rejected password to the network, the typed login and, when the login
    /// named an account, that account's network and account-wide budgets.
    pub(super) fn record_failure(&self, account: Option<AccountId>) {
        self.throttle.record_client_failure(self.scope, &self.ip);
        self.throttle.record_failure(self.scope, &self.typed);
        if let Some(account) = account {
            self.throttle.record_failure(self.scope, &self.local(account));
            self.throttle.record_client_failure(self.scope, &account_key(account));
        }
    }

    /// Clears the typed login and the account's budgets of this network after success.
    pub(super) fn reset(&self, account: AccountId) {
        self.throttle.reset(self.scope, &self.typed);
        self.throttle.reset(self.scope, &self.local(account));
    }
}
