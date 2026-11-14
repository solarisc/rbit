//! The refusal texts of the access decisions, with the stable code and the remediation of
//! each (see `docs/error-codes.md`).

/// Refusal texts, as the client shows them (`! [remote rejected] main -> main (…)`). Each
/// text has a stable [`codes`] entry and a remediation sentence (see [`meta`]).
pub mod reasons {
    pub const PULL_REFS: &str = "refs/pull/ is managed by rbit";
    pub const REPLACE_REFS: &str = "refs/replace/ may not override repository objects";
    pub const NAMESPACE_CASE: &str = "use the canonical refs/heads/ namespace";
    pub const DELETION: &str = "protected branch: deleting it is not allowed";
    pub const RESTRICTED: &str = "protected branch: you are not allowed to push to it";
    pub const PULL_REQUEST: &str = "protected branch: changes must go through a pull request";
    pub const NO_WRITE: &str = "you are not allowed to push to this repository";
    pub const TOKEN_SCOPE: &str = "this token's scope does not allow pushing; it needs the write scope";
    pub const ARCHIVED: &str = "This repository is archived and read-only; an administrator can unarchive it in its settings";
    /// The API's wording of the same refusal (its error body keeps GitHub's words).
    pub const ARCHIVED_API: &str = "Repository was archived so is read-only.";
}

/// Stable machine codes of refusals: `code` in API error bodies and `[code]` in the Git
/// report (`ng <ref> [code] reason`). Codes are added, never renamed.
pub mod codes {
    pub const REF_RESERVED: &str = "ref_reserved";
    pub const REF_NOT_CANONICAL: &str = "ref_not_canonical";
    pub const PROTECTED_DELETION: &str = "protected_branch_deletion";
    pub const PROTECTED_RESTRICTED: &str = "protected_branch_restricted";
    pub const PROTECTED_PULL_REQUEST: &str = "protected_branch_requires_pull_request";
    pub const PROTECTED_FORCE_PUSH: &str = "protected_branch_force_push";
    pub const NO_WRITE: &str = "no_write_access";
    pub const TOKEN_SCOPE: &str = "token_scope_insufficient";
    pub const REPOSITORY_ARCHIVED: &str = "repository_archived";
    pub const SCRATCH_OWNER: &str = "scratch_ref_not_owned";
    pub const SCRATCH_LIMIT: &str = "scratch_ref_limit";
    pub const TASK_TAG: &str = "task_tag_moved";
    pub const TASK_WORKFLOW: &str = "task_workflow_files";
    pub const PACK_UNREADABLE: &str = "pack_unreadable";
    pub const REF_REFUSED: &str = "ref_refused";
    /// Every code, so the documentation test covers each one.
    pub const ALL: &[&str] = &[
        REF_RESERVED,
        REF_NOT_CANONICAL,
        PROTECTED_DELETION,
        PROTECTED_RESTRICTED,
        PROTECTED_PULL_REQUEST,
        PROTECTED_FORCE_PUSH,
        NO_WRITE,
        TOKEN_SCOPE,
        REPOSITORY_ARCHIVED,
        SCRATCH_OWNER,
        SCRATCH_LIMIT,
        TASK_TAG,
        TASK_WORKFLOW,
        PACK_UNREADABLE,
        REF_REFUSED,
    ];
}

/// The stable code and the remediation of a refusal `text` from this module.
#[must_use]
pub fn meta(text: &str) -> (&'static str, &'static str) {
    match text {
        reasons::PULL_REFS | reasons::REPLACE_REFS => {
            (codes::REF_RESERVED, "Push to a branch under refs/heads/ instead; rbit manages the other ref namespaces.")
        }
        reasons::NAMESPACE_CASE => (codes::REF_NOT_CANONICAL, "Spell the branch under the canonical refs/heads/ namespace."),
        reasons::DELETION => (codes::PROTECTED_DELETION, "Ask a repository administrator to change the rule, or to delete the branch."),
        reasons::RESTRICTED => {
            (codes::PROTECTED_RESTRICTED, "Ask a repository administrator to allow you, or one of your teams, in this rule.")
        }
        reasons::PULL_REQUEST => (codes::PROTECTED_PULL_REQUEST, "Push a branch and open a pull request into this branch instead."),
        reasons::NO_WRITE => (codes::NO_WRITE, "Ask a repository administrator for write access."),
        reasons::TOKEN_SCOPE => (codes::TOKEN_SCOPE, "Use a personal access token with the write scope."),
        reasons::ARCHIVED | reasons::ARCHIVED_API => {
            (codes::REPOSITORY_ARCHIVED, "Ask a repository administrator to unarchive the repository.")
        }
        _ => (codes::REF_REFUSED, "Ask a repository administrator why this update is refused."),
    }
}
