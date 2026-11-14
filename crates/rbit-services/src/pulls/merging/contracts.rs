//! Pull merge presentation, request and failure contracts; no I/O or policy execution.
use std::fmt;

use rbit_git::merge::MergeError;

use crate::ServiceError;
use rbit_core::{
    issue::MergeStrategy,
    protection::{MergeRules, Refusal},
    pull::{MergeEvaluation, Mergeability, Requirement, ReviewTally},
    status::CommitStatus,
};

/// Stable machine codes of merge refusals (`code` in API error bodies). Protection's own
/// codes are in [`codes`]; these name what a merge or a branch write waits for.
pub mod merge_codes {
    pub const PULL_CLOSED: &str = "pull_closed";
    pub const DRAFT: &str = "merge_draft";
    pub const HEAD_BRANCH_MISSING: &str = "head_branch_missing";
    pub const BASE_BRANCH_MISSING: &str = "base_branch_missing";
    pub const BASE_CHANGED: &str = "base_changed";
    pub const CONFLICTS: &str = "merge_conflicts";
    pub const NOTHING_TO_MERGE: &str = "merge_nothing_to_merge";
    pub const UNRELATED_HISTORY: &str = "merge_unrelated_histories";
    pub const MERGE_FAILED: &str = "merge_failed";
    pub const REQUIRES_APPROVALS: &str = "merge_requires_approvals";
    pub const CHANGES_REQUESTED: &str = "merge_changes_requested";
    pub const RESTRICTED_PUSHER: &str = "merge_restricted_pusher";
    pub const CHECKS_REQUIRED: &str = "merge_checks_required";
    pub const CHECKS_FAILING: &str = "merge_checks_failing";
    pub const BRANCH_EXISTS: &str = "branch_exists";
    pub const HEAD_IN_OTHER_REPOSITORY: &str = "head_in_other_repository";
    /// Every merge code, so the documentation test covers each one.
    pub const ALL: &[&str] = &[
        PULL_CLOSED,
        DRAFT,
        HEAD_BRANCH_MISSING,
        BASE_BRANCH_MISSING,
        BASE_CHANGED,
        CONFLICTS,
        NOTHING_TO_MERGE,
        UNRELATED_HISTORY,
        MERGE_FAILED,
        REQUIRES_APPROVALS,
        CHANGES_REQUESTED,
        RESTRICTED_PUSHER,
        CHECKS_REQUIRED,
        CHECKS_FAILING,
        BRANCH_EXISTS,
        HEAD_IN_OTHER_REPOSITORY,
    ];
}

/// A merge or branch write refused by a requirement or by the state of the branches: its
/// stable `code`, the message for people, the rule that asks (when protection asks) and what
/// would make it pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub code: &'static str,
    pub message: String,
    pub rule: Option<String>,
    pub remediation: &'static str,
}

impl Blocked {
    pub fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self { code, message: message.into(), rule: None, remediation }
    }

    /// The refusal a protection decision gave a branch write.
    pub fn from_refusal(refusal: Refusal) -> Self {
        Self { code: refusal.code, message: refusal.reason, rule: refusal.rule, remediation: refusal.remediation }
    }

    /// The unmet requirement `requirement` of a merge; protection's requirements name the
    /// rules that set them.
    pub fn unmet(requirement: Option<Requirement>, rules: &MergeRules) -> Self {
        let Some(requirement) = requirement else {
            return Self::new(
                merge_codes::MERGE_FAILED,
                "this pull request cannot be merged",
                "Open the merge box to see what the merge waits for.",
            );
        };
        let (code, remediation) = requirement_code(requirement);
        let message = format!("this pull request cannot be merged: {}", requirement.describe(false));
        let rule =
            (requirement.is_protection() && !rules.patterns.is_empty()).then(|| format!("branch protection {}", rules.patterns.join(", ")));
        Self { code, message, rule, remediation }
    }
}

impl Blocked {
    /// The refusal of a merge Git could not make: nothing to merge, or unrelated histories.
    pub fn for_merge_error(error: &MergeError) -> Self {
        let code = if matches!(error, MergeError::Unrelated) { merge_codes::UNRELATED_HISTORY } else { merge_codes::NOTHING_TO_MERGE };
        Self::new(code, error.to_string(), "Push a commit the base does not already have.")
    }

    /// The refusal of a merge of a pull request that is closed.
    pub fn pull_closed() -> Self {
        Self::new(merge_codes::PULL_CLOSED, "the pull request is closed", "Reopen the pull request, or open a new one.")
    }

    /// The refusal of a merge whose base branch moved while it was made.
    pub fn base_changed() -> Self {
        Self::new(merge_codes::BASE_CHANGED, "the base branch changed; try again", "Review the pull request and try again.")
    }

    /// The refusal of a merge with conflicts in `paths`.
    pub fn conflicts(paths: &[String]) -> Self {
        Self::new(merge_codes::CONFLICTS, format!("the merge has conflicts in {}", paths.join(", ")), CONFLICT_FIX)
    }

    /// The refusal of a merge whose base branch does not exist.
    pub fn missing_base() -> Self {
        Self::new(
            merge_codes::BASE_BRANCH_MISSING,
            "the base branch does not exist",
            "Create the base branch, or retarget the pull request.",
        )
    }
}

/// What a merge with conflicts needs.
pub const CONFLICT_FIX: &str = "Update the pull request branch from its base and resolve the conflicts.";

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The stable code and the remediation of an unmet requirement.
fn requirement_code(requirement: Requirement) -> (&'static str, &'static str) {
    match requirement {
        Requirement::Open => (merge_codes::PULL_CLOSED, "Reopen the pull request, or open a new one."),
        Requirement::NotDraft => (merge_codes::DRAFT, "Mark the pull request ready for review."),
        Requirement::HeadBranchExists => (merge_codes::HEAD_BRANCH_MISSING, "Push the head branch again."),
        Requirement::NoConflicts(_) => (merge_codes::CONFLICTS, CONFLICT_FIX),
        Requirement::Approvals { .. } => {
            (merge_codes::REQUIRES_APPROVALS, "Ask a writer other than the author to approve the pull request.")
        }
        Requirement::NoChangesRequested { .. } => {
            (merge_codes::CHANGES_REQUESTED, "Ask the reviewers to approve, or to dismiss their requested changes.")
        }
        Requirement::MergerMayPush => {
            (merge_codes::RESTRICTED_PUSHER, "Ask a repository administrator to allow you in this branch's rule.")
        }
        Requirement::RequiredChecks(_) => (merge_codes::CHECKS_REQUIRED, "Wait for the required checks on the head commit to pass."),
        Requirement::Checks(_) => (merge_codes::CHECKS_FAILING, "Fix the failing checks on the head commit."),
    }
}

/// The merge box as one viewer sees it.
#[derive(Debug, Clone)]
pub struct MergeBox {
    pub evaluation: MergeEvaluation,
    pub rules: MergeRules,
    pub tally: ReviewTally,
    /// The mergeability shown: the stored one, or `Unknown` when it ran on another base.
    pub mergeable: Mergeability,
    pub conflict_paths: Vec<String>,
    /// The latest status of each context on the head commit, by context (milestone 3, S).
    pub statuses: Vec<CommitStatus>,
    /// The contexts required of this head: the rules' ones, without those no workflow will
    /// report for it (agent plan steps 2.2 and 4.2).
    pub required: Vec<String>,
    pub head_branch_exists: bool,
    /// The viewer may press the button (write access to the base repository).
    pub can_merge: bool,
    /// The viewer may delete the head branch after merging.
    pub can_delete_head: bool,
    pub default_title: String,
    pub default_message: String,
    pub default_squash_title: String,
    pub default_squash_message: String,
}

/// Merge policy and status for one observed head and base tip, without display messages.
#[derive(Debug, Clone)]
pub struct MergeReadiness {
    pub evaluation: MergeEvaluation,
    pub rules: MergeRules,
    pub tally: ReviewTally,
    pub mergeable: Mergeability,
    pub conflict_paths: Vec<String>,
    pub statuses: Vec<CommitStatus>,
    pub required: Vec<String>,
    pub head_branch_exists: bool,
    pub base_tip: Option<String>,
}

/// A merge as requested.
#[derive(Debug, Clone)]
pub struct MergeInput {
    pub strategy: MergeStrategy,
    /// Empty: the default for the strategy.
    pub title: String,
    pub message: String,
    /// The head the merger saw; a different current head refuses the merge.
    pub expected_head: Option<String>,
    /// The base branch the merger saw; a different current base refuses the merge.
    pub expected_base: Option<String>,
    pub delete_head_branch: bool,
    /// Merge despite unmet protection rules (only for mergers allowed to bypass).
    pub bypass: bool,
}

/// Why a merge did not happen.
#[derive(Debug, thiserror::Error)]
pub enum MergeFailure {
    /// The head is not the one the merger reviewed (`409`).
    #[error("the head branch was modified; review the new changes and try again")]
    HeadChanged,
    /// The base branch is not the one the merger saw (`409`).
    #[error("the base branch was changed; review the pull request and try again")]
    BaseChanged,
    /// A requirement is unmet, or the branches cannot be merged (`405`); the code says which.
    #[error("{0}")]
    Blocked(Blocked),
    #[error("{0}")]
    Service(#[from] ServiceError),
}

impl From<rbit_storage::StorageError> for MergeFailure {
    fn from(error: rbit_storage::StorageError) -> Self {
        Self::Service(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every merge code is listed in docs/error-codes.md, so a new one cannot ship undocumented.
    #[test]
    fn every_merge_code_is_documented() {
        let docs = include_str!("../../../../../docs/error-codes.md");
        for code in merge_codes::ALL {
            assert!(docs.contains(&format!("`{code}`")), "`{code}` is not in docs/error-codes.md");
        }
    }

    /// A protection requirement names the rule that sets it; a state of the branches does not.
    #[test]
    fn protection_requirements_name_their_rule() {
        let rules = MergeRules { patterns: vec!["main".to_owned()], ..MergeRules::unprotected() };
        let approvals = Requirement::Approvals { have: 0, need: 1 };
        let blocked = Blocked::unmet(Some(approvals), &rules);
        assert_eq!((blocked.code, blocked.rule.as_deref()), (merge_codes::REQUIRES_APPROVALS, Some("branch protection main")));
        let open = Blocked::unmet(Some(Requirement::Open), &rules);
        assert_eq!((open.code, open.rule), (merge_codes::PULL_CLOSED, None));
    }
}
