//! How far runs are: their jobs counted by state, for the runs list.
use std::collections::BTreeMap;

use crate::StorageError;
use crate::sqlite::actions_runs::ActionsRunStore;
use rbit_core::Timestamp;
use rbit_core::actions::RunId;

/// A run's jobs by state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunProgress {
    pub total: u64,
    /// Finished, whatever the result: succeeded, failed, cancelled or skipped.
    pub done: u64,
    pub running: u64,
    /// Waiting for a runner.
    pub waiting: u64,
}

impl ActionsRunStore {
    /// The job counts of `runs`, read in one query; a run without jobs is left out.
    pub async fn progress(&self, runs: &[RunId], now: Timestamp) -> Result<BTreeMap<RunId, RunProgress>, StorageError> {
        if runs.is_empty() {
            return Ok(BTreeMap::new());
        }
        let ids = format!("[{}]", runs.iter().map(|run| run.0.to_string()).collect::<Vec<_>>().join(","));
        let rows: Vec<(i64, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT j.run_id, COUNT(*), SUM(j.status IN (1, 2, 3, 4)), SUM(j.status = 6), \
             SUM(j.status = 5 AND (j.environment IS NULL OR NOT EXISTS (SELECT 1 FROM actions_environments e \
                 WHERE e.repo_id = j.repo_id AND e.name = j.environment AND e.wait_timer > 0 AND j.queued_at + e.wait_timer * 60 > ?2))) \
             FROM actions_jobs j WHERE j.run_id IN (SELECT value FROM json_each(?1)) GROUP BY j.run_id",
        )
        .bind(ids)
        .bind(now.0)
        .fetch_all(&self.pool)
        .await?;
        let count = |value: i64| u64::try_from(value).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|(run, total, done, running, waiting)| {
                (RunId(run), RunProgress { total: count(total), done: count(done), running: count(running), waiting: count(waiting) })
            })
            .collect())
    }
}
