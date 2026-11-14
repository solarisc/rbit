-- rbit Actions: a push whose workflows name only events rbit never starts runs for starts no
-- run; its commit is recorded with the reason `unsupported_events`, so its status names the
-- events instead of blaming the branch and path filters.
-- A CHECK constraint cannot be changed in place: the table is rebuilt with every row.
CREATE TABLE actions_commit_decisions_next (
    repo_id     INTEGER NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    sha         TEXT    NOT NULL CHECK (length(sha) BETWEEN 7 AND 64),
    workflows   INTEGER NOT NULL CHECK (workflows >= 0),
    started     INTEGER NOT NULL CHECK (started >= 0),
    reason      TEXT    NOT NULL CHECK (reason IN ('started', 'skip_marker', 'no_workflows', 'filtered', 'too_many_refs', 'no_jobs', 'unsupported_events')),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (repo_id, sha)
) STRICT, WITHOUT ROWID;

INSERT INTO actions_commit_decisions_next (repo_id, sha, workflows, started, reason, recorded_at)
    SELECT repo_id, sha, workflows, started, reason, recorded_at FROM actions_commit_decisions;

DROP TABLE actions_commit_decisions;

ALTER TABLE actions_commit_decisions_next RENAME TO actions_commit_decisions;
