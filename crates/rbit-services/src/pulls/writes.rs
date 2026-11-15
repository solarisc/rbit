//! Server-side writes for agents (agent plan step 4.4). Each takes the commit the caller
//! expects, goes through write access, the archive guard and branch protection (as a push
//! by the caller would), is made with the merge machinery and handed over by
//! compare-and-swap, and is reported as a push by the caller.
//!
//! * [`PullService::update_branch`] merges the base tip into a pull request's head branch.
//! * [`PullService::revert_commit`] makes `revert-<commit>` from the base tip with one commit
//!   that undoes a commit, and opens a pull request for it (never merged on its own).
//! * [`PullService::set_branch`] moves a branch from the commit the caller saw to another.
//!
//! A conditional change of one file is the web editor's path; it has no API yet.

use rbit_core::{IssueNumber, PushSource, Timestamp, User, pull::CommitIdentity, pull::noreply_domain};
use rbit_git::merge::{MergeError, candidate::land, writes};

use super::{
    Blocked, MergeFailure, NewPullInput, PullContext, PullService,
    merging::{CONFLICT_FIX, merge_codes},
};
use crate::{RepoContext, ServiceError};

impl PullService {
    fn identity(&self, user: &User) -> CommitIdentity {
        let config = &self.ctx().config;
        let domain = noreply_domain(&config.pulls.noreply_domain, &config.server.public_url);
        CommitIdentity::noreply(user.name().as_str(), user.account.display_name.as_deref(), &domain)
    }

    /// Refuses a write of `branch` of `repo` by `actor` that a push would be refused, and
    /// audits an administrator's bypass as a push's.
    async fn may_write(&self, repo: &RepoContext, actor: &User, branch: &str) -> Result<(), MergeFailure> {
        if !repo.can_write_content() {
            return Err(ServiceError::Forbidden.into());
        }
        if let Some(refusal) = self.inner.protection.authorize_branch_write(repo, actor, branch).await? {
            return Err(MergeFailure::Blocked(Blocked::from_refusal(refusal)));
        }
        Ok(())
    }

    /// Merges the base tip into `ctx`'s head branch if it still is `expected_head`; the new
    /// head. Only a head branch in the base repository can be updated.
    pub async fn update_branch(&self, actor: &User, ctx: &PullContext, expected_head: &str) -> Result<String, MergeFailure> {
        if ctx.head_repo.as_ref().is_some_and(|head| head.repo.id != ctx.repo().repo.repo.id) {
            return Err(MergeFailure::Blocked(Blocked::new(
                merge_codes::HEAD_IN_OTHER_REPOSITORY,
                "a head branch in another repository cannot be updated from here",
                "Update the branch in its own repository.",
            )));
        }
        if !ctx.pull.head_sha.starts_with(expected_head) {
            return Err(MergeFailure::HeadChanged);
        }
        self.may_write(ctx.repo(), actor, &ctx.pull.head_branch).await?;
        let base_tip = self.base_tip(ctx).await?.ok_or_else(|| MergeFailure::Blocked(Blocked::missing_base()))?;
        let pending = self.inner.pushes.begin(ctx.repo(), PushSource::User(actor.id())).await;
        let lease = self.ctx().repositories.lease(ctx.repo().repo.repo.id).await;
        let merged = writes::update_branch(
            &self.merge_environment(),
            &ctx.repo().disk_path,
            (&ctx.pull.head_branch, &ctx.pull.head_sha),
            (&ctx.pull.base_branch, &base_tip),
            &self.identity(actor),
            Timestamp::now(),
        )
        .await;
        drop(lease);
        let commit = match merged {
            Ok(merged) => merged.commit,
            Err(MergeError::NothingToMerge) => return Ok(ctx.pull.head_sha.clone()),
            Err(MergeError::BaseMoved) => return Err(MergeFailure::HeadChanged),
            Err(MergeError::Conflict(paths)) => {
                let message = format!("the base conflicts in {}", paths.join(", "));
                return Err(MergeFailure::Blocked(Blocked::new(merge_codes::CONFLICTS, message, CONFLICT_FIX)));
            }
            Err(error) => return Err(ServiceError::internal(error).into()),
        };
        self.inner.pushes.complete(pending).await;
        Ok(commit)
    }

    /// Reverts `commit` on `base` of `repo` in a new branch `revert-<commit>` and opens a
    /// pull request for it; its number.
    pub async fn revert_commit(&self, actor: &User, repo: &RepoContext, commit: &str, base: &str) -> Result<IssueNumber, MergeFailure> {
        let commit = repo.reader.commit_id(commit.to_owned()).await.map_err(ServiceError::from)?;
        let base_tip = repo.reader.commit_id(format!("refs/heads/{base}")).await.map_err(ServiceError::from)?;
        let short = &commit[..commit.len().min(12)];
        let branch = format!("revert-{short}");
        self.may_write(repo, actor, &branch).await?;
        let summary = repo
            .reader
            .history(commit.clone(), 0, 1)
            .await
            .ok()
            .and_then(|found| found.into_iter().next())
            .map(|found| found.summary)
            .unwrap_or_default();
        let pending = self.inner.pushes.begin(repo, PushSource::User(actor.id())).await;
        let lease = self.ctx().repositories.lease(repo.repo.repo.id).await;
        let reverted = writes::revert(
            &self.merge_environment(),
            &repo.disk_path,
            (&base_tip, &commit),
            &branch,
            &self.identity(actor),
            Timestamp::now(),
        )
        .await;
        drop(lease);
        match reverted {
            Ok(_) => {}
            Err(MergeError::BaseMoved) => {
                let message = format!("branch `{branch}` exists already");
                return Err(MergeFailure::Blocked(Blocked::new(merge_codes::BRANCH_EXISTS, message, "Choose another branch name.")));
            }
            Err(MergeError::Conflict(paths)) => {
                let message = format!("the revert conflicts with `{base}` in {}", paths.join(", "));
                return Err(MergeFailure::Blocked(Blocked::new(merge_codes::CONFLICTS, message, CONFLICT_FIX)));
            }
            Err(error @ (MergeError::NothingToMerge | MergeError::Failed(_))) => {
                let code =
                    if matches!(error, MergeError::NothingToMerge) { merge_codes::NOTHING_TO_MERGE } else { merge_codes::MERGE_FAILED };
                return Err(MergeFailure::Blocked(Blocked::new(code, error.to_string(), "Push a commit the base does not already have.")));
            }
            Err(error) => return Err(ServiceError::internal(error).into()),
        }
        self.inner.pushes.complete(pending).await;
        let input = NewPullInput {
            base_branch: base.to_owned(),
            head_branch: branch,
            title: format!("Revert \"{summary}\""),
            body: format!("Reverts {commit}."),
            draft: false,
        };
        let (issue, _) = self.create(actor, repo, repo, input).await?;
        Ok(issue.number)
    }

    /// Moves branch `branch` of `repo` from `expected` to `commit` (both full ids), if a push
    /// by `actor` would be allowed to: a move that drops commits is a force push, refused
    /// where the branch's protection denies those.
    pub async fn set_branch(
        &self,
        actor: &User,
        repo: &RepoContext,
        branch: &str,
        commit: &str,
        expected: &str,
    ) -> Result<(), MergeFailure> {
        if let Some(reason) = crate::protection::ProtectionService::reserved_branch_refusal(branch) {
            return Err(MergeFailure::Blocked(Blocked::new(
                rbit_core::protection::codes::REF_RESERVED,
                reason,
                "Choose a branch name that does not start with refs/ or merge-queue/.",
            )));
        }
        self.may_write(repo, actor, branch).await?;
        let commit = repo.reader.commit_id(commit.to_owned()).await.map_err(ServiceError::from)?;
        let keeps_tip = repo.reader.is_ancestor(expected.to_owned(), commit.clone()).await.unwrap_or(false);
        if !keeps_tip && self.inner.protection.denies_force_push(repo, actor, branch).await? {
            return Err(MergeFailure::Blocked(Blocked::new(
                rbit_core::protection::codes::PROTECTED_FORCE_PUSH,
                "force pushes denied",
                "Merge without rewriting the branch, or ask an administrator to change the rule.",
            )));
        }
        let pending = self.inner.pushes.begin(repo, PushSource::User(actor.id())).await;
        let lease = self.ctx().repositories.lease(repo.repo.repo.id).await;
        let moved = land(&self.merge_environment(), &repo.disk_path, branch, &commit, expected).await;
        drop(lease);
        match moved {
            Ok(()) => {
                self.inner.pushes.complete(pending).await;
                Ok(())
            }
            Err(MergeError::BaseMoved) => Err(MergeFailure::HeadChanged),
            Err(error) => Err(ServiceError::internal(error).into()),
        }
    }
}
