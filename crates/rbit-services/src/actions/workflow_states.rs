//! The workflows of a repository as its pages and API list them, and the warnings of their
//! files: what a file says that rbit accepts but never acts on, such as an `on:` event that
//! never starts a run. Read from the default branch.
use std::collections::BTreeMap;

use rbit_git::GitError;
use rbit_workflow::model::Warning;

use super::browse::WorkflowState;
use super::workflow_files::GitWorkflows;
use super::ActionsService;
use crate::{RepoContext, ServiceError};

impl ActionsService {
    // Actions: disabled workflows.
    /// `repo`'s workflows as GitHub lists them, by path: those that ran and those on the
    /// default branch, each with its name (its newest run's, else its path), whether it is
    /// disabled and its warnings.
    pub async fn workflow_states(&self, repo: &RepoContext) -> Result<Vec<WorkflowState>, ServiceError> {
        let mut named: BTreeMap<String, String> = self.workflows(repo).await?.into_iter().collect();
        let on_default = self.workflow_paths(repo).await?;
        let warnings = self.workflow_warnings(repo, &on_default).await?;
        for path in on_default {
            named.entry(path.clone()).or_insert(path);
        }
        let disabled = self.ctx().database.actions_settings().disabled_workflows(repo.repo.repo.id).await?;
        Ok(named
            .into_iter()
            .map(|(path, name)| WorkflowState {
                disabled: disabled.binary_search(&path).is_ok(),
                warnings: warnings.get(&path).cloned().unwrap_or_default(),
                path,
                name,
            })
            .collect())
    }

    /// The warnings of the workflow files `paths` of the default branch, by path; a file with
    /// none is absent, and so is one that does not parse (its own page reports why).
    pub async fn workflow_warnings(&self, repo: &RepoContext, paths: &[String]) -> Result<BTreeMap<String, Vec<Warning>>, ServiceError> {
        let branch = format!("refs/heads/{}", repo.repo.repo.default_branch);
        let sha = match repo.reader.commit_id(branch).await {
            Ok(sha) => sha,
            Err(GitError::NotFound(_)) => return Ok(BTreeMap::new()),
            Err(error) => return Err(error.into()),
        };
        let (reader, limits, paths) = (repo.reader.clone(), self.limits(), paths.to_vec());
        let found = self
            .evaluate(move |handle, deadline| {
                let mut found = BTreeMap::new();
                for path in paths {
                    if let Ok(workflow) = GitWorkflows::new(handle, &reader, &sha).load(&path, &limits, deadline) {
                        let warnings = workflow.warnings();
                        if !warnings.is_empty() {
                            found.insert(path, warnings);
                        }
                    }
                }
                Ok::<_, GitError>(found)
            })
            .await??;
        Ok(found)
    }
}
