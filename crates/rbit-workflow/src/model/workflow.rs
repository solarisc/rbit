//! Typed workflow workflow records; expression text remains unevaluated.
use super::calls::WorkflowCall;
use super::events::{Dispatch, PullRequestFilters, PushFilters, RepositoryDispatchFilters, Schedule, WorkflowRunFilters};
use super::jobs::{Concurrency, Job, Permissions};
use crate::spec::{Env, RunDefaults};

/// A parsed workflow file.
#[derive(Debug, Clone)]
pub struct Workflow {
    /// `name`; runs show the file path when it is absent.
    pub name: Option<String>,
    /// `run-name`, as written (it may contain expressions).
    pub run_name: Option<String>,
    pub on: On,
    /// Top-level `env`, as templates.
    pub env: Env,
    /// Top-level `defaults.run`.
    pub defaults: RunDefaults,
    /// Top-level `permissions`.
    pub permissions: Option<Permissions>,
    /// Workflow-level `concurrency`.
    pub concurrency: Option<Concurrency>,
    /// The jobs in file order.
    pub jobs: Vec<Job>,
}

impl Workflow {
    pub fn job(&self, id: &str) -> Option<&Job> {
        self.jobs.iter().find(|job| job.id == id)
    }

    /// Warnings about `on:` events that the file names but rbit never starts a run for. The
    /// list is derived from the same parse that decides what starts runs, so it cannot drift.
    pub fn warnings(&self) -> Vec<Warning> {
        self.on.other.iter().map(|event| Warning { code: UNSUPPORTED_EVENT, subject: event.clone() }).collect()
    }
}

/// The code of a warning: an `on:` event that never starts a run on rbit.
pub const UNSUPPORTED_EVENT: &str = "unsupported_event";

/// A problem in a workflow file that does not stop the file from parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// A stable identifier of the kind of problem, such as [`UNSUPPORTED_EVENT`].
    pub code: &'static str,
    /// What the warning is about, as written in the file (the event's name).
    pub subject: String,
}

impl Warning {
    /// The English message for API clients and the CLI; the web UI localizes by `code`.
    pub fn message(&self) -> String {
        format!("{} does not start runs on rbit", self.subject)
    }
}

/// The events a workflow runs on (`on:`).
#[derive(Debug, Clone, Default)]
pub struct On {
    pub push: Option<PushFilters>,
    pub pull_request: Option<PullRequestFilters>,
    pub workflow_dispatch: Option<Dispatch>,
    /// `schedule` entries, in file order.
    pub schedule: Vec<Schedule>,
    // Actions: reusable workflows.
    /// `workflow_call`: other workflows may call this one.
    pub workflow_call: Option<WorkflowCall>,
    // Actions: workflow_run and repository_dispatch.
    pub workflow_run: Option<WorkflowRunFilters>,
    pub repository_dispatch: Option<RepositoryDispatchFilters>,
    /// Other events, by name. rbit starts no runs for them.
    pub other: Vec<String>,
}
