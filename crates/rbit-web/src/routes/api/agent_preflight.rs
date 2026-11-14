//! Push preflight for agents (agent plan step 3): answers whether the caller's credential
//! may make one proposed branch update, without pushing anything. It runs the same checks a
//! push runs, in the same order (token scope, write access, mirror, then the push gate
//! [`rbit_services::ProtectionService::preview_push`]), so the answer and the refusal a real
//! push gets are one decision.
//!
//! The branch's current head is read on the server, never taken from the caller: `old` is
//! only a claim, and a claim that is not the current head is a `409`.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use rbit_core::{
    RefUpdate, TokenScope,
    protection::{PushActor, PushVerdict, Refusal, codes, reasons},
};
use rbit_services::mirrors;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    ApiMethod::Get,
    ApiRoute,
    auth::Caller,
    error::{ApiError, ApiResult},
    route,
};
use crate::AppState;

/// This area's endpoints, appended to [`super::table`].
pub(super) fn routes() -> Vec<ApiRoute> {
    let repo = |suffix: &str| format!("/repos/{{owner}}/{{repo}}{suffix}");
    vec![route(Get, repo("/agent/preflight/push"), preflight_push)]
}

#[derive(Debug, Deserialize)]
pub struct RepoPath {
    owner: String,
    repo: String,
}

/// `GET /repos/{owner}/{repo}/agent/preflight/push?ref=refs/heads/main&old=<sha>&new=<sha>&force=<bool>`:
/// the caller's push gate for one proposed update of a branch. `old` is the commit the caller
/// believes the branch is at (zeros for a branch that does not exist); it must be the current
/// head. `new` is the commit to move to (zeros for a deletion). `force` says the update is a
/// force push; when `new` is in this repository, the server works that out itself instead.
#[derive(Debug, Deserialize)]
pub struct PreflightQuery {
    #[serde(rename = "ref")]
    reference: String,
    old: String,
    new: String,
    #[serde(default)]
    force: bool,
}

/// An object id as Git writes it: 40 hexadecimal digits (SHA-1) or 64 (SHA-256); all zeros
/// means "no commit". `None` for the zero id.
fn commit(field: &str, value: &str) -> ApiResult<Option<String>> {
    let hex = value.len() == 40 || value.len() == 64;
    if !hex || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::invalid(field, "a full commit id (40 or 64 hexadecimal digits), or zeros for none"));
    }
    Ok((!value.bytes().all(|byte| byte == b'0')).then(|| value.to_ascii_lowercase()))
}

/// The answer as the API documents it: `{allowed, refusals: [{ref, code, message, rule, remediation}]}`.
fn answer(verdict: &PushVerdict) -> Value {
    let refusals: Vec<Value> = verdict
        .refusals
        .iter()
        .map(|refusal| {
            json!({
                "ref": refusal.name,
                "code": refusal.code,
                "message": refusal.reason,
                "rule": refusal.rule,
                "remediation": refusal.remediation,
            })
        })
        .collect();
    json!({ "allowed": !verdict.is_refused(), "refusals": refusals })
}

/// A preflight answer that refuses the update with one refusal.
fn refused(refusal: Refusal) -> Json<Value> {
    Json(answer(&PushVerdict { refusals: vec![refusal], deny_non_fast_forwards: false }))
}

/// `GET /repos/{owner}/{repo}/agent/preflight/push`: read-only; nothing is pushed or recorded.
pub async fn preflight_push(
    State(state): State<AppState>,
    caller: Caller,
    Path(path): Path<RepoPath>,
    Query(query): Query<PreflightQuery>,
) -> ApiResult<Json<Value>> {
    let user = caller.require_user()?;
    if !query.reference.starts_with("refs/heads/") {
        return Err(ApiError::invalid("ref", "a branch, as refs/heads/<name>"));
    }
    let new = commit("new", &query.new)?;
    let claimed = commit("old", &query.old)?;
    let repo = caller.open_repo(&state, &path.owner, &path.repo).await?;

    // The branch's head on the server. A claimed `old` that is not it is a stale answer.
    let current = repo.reader.commit_id(query.reference.clone()).await.ok();
    if claimed != current {
        let head = current.as_deref().unwrap_or("none (the branch does not exist)");
        return Err(ApiError::new(axum::http::StatusCode::CONFLICT, format!("the branch moved: its head is {head}")));
    }

    // Git's checks order: token scope, write access, mirror, then the push gate. A token too
    // narrow to push is answered as a refusal, not a 403: the question is whether a push would be
    // allowed, and that is the answer.
    if let Some(granted) = caller.scope_limit(TokenScope::Write) {
        let rule = format!("token scope {}", granted.as_str());
        let refusal = Refusal::of_text(query.reference.clone(), reasons::TOKEN_SCOPE).with_rule(rule);
        return Ok(refused(refusal));
    }
    if repo.access.can_write() && state.services.mirrors.is_mirror(repo.repo.repo.id).await? {
        let refusal = Refusal::new(query.reference.clone(), codes::REPOSITORY_MIRROR, mirrors::PUSH_REFUSED, mirrors::PUSH_FIX);
        return Ok(refused(refusal));
    }

    // A force push is a new commit that does not contain the old one. With both commits in this
    // repository the server decides; otherwise the caller's declaration stands.
    let force = match (&current, &new) {
        (Some(old), Some(new)) if repo.reader.commit_id(new.clone()).await.is_ok() => {
            !repo.reader.is_ancestor(old.clone(), new.clone()).await.map_err(rbit_services::ServiceError::from)?
        }
        _ => query.force,
    };
    let update = RefUpdate { name: query.reference, before: current, after: new };
    let actor = PushActor { user: Some(user), deploy_key: false, access: repo.access };
    let verdict = state.services.protection.preview_push(&repo, &actor, &[update], force).await?;
    Ok(Json(answer(&verdict)))
}
