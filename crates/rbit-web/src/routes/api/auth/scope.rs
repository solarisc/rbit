//! The refusal a personal access token gets for a request its scope does not allow.

use rbit_core::{TokenScope, protection::codes};

use super::super::error::ApiError;
use super::Caller;

/// `403` for a token whose scope `granted` does not include `needed`: the code, the scope it has
/// and the scope to create one with.
pub(super) fn refusal(granted: TokenScope, needed: TokenScope) -> ApiError {
    let message = format!("This token's scope ({}) does not allow this; it needs the {} scope", granted.as_str(), needed.as_str());
    let fix = format!("Use a personal access token with the {} scope, created under Settings > Access tokens.", needed.as_str());
    ApiError::forbidden(message).with_code(codes::TOKEN_SCOPE).refused_by(Some(format!("token scope {}", granted.as_str())), fix)
}

impl Caller {
    /// The token scope that stops the caller from `scope`: the scope of a token too narrow
    /// for it. `None` when the caller may do it as far as their token goes.
    pub fn scope_limit(&self, scope: TokenScope) -> Option<TokenScope> {
        self.scope.filter(|granted| !granted.allows(scope))
    }
}
