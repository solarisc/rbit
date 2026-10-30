//! Whole-repository lookups for the code and branch pages: every file path at a revision
//! (the "Go to file" finder), the length of a history, and how far branches are ahead of
//! and behind another.

use gix::{ObjectId, objs::tree::EntryKind as GixEntryKind, traverse::tree::Recorder};

use crate::{GitError, RepositoryReader, reader::resolve_commit};

/// How many commits a branch is ahead of and behind a base, each counted up to a cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Divergence {
    pub ahead: usize,
    pub behind: usize,
    /// A count reached the cap, so it is a lower bound.
    pub capped: bool,
}

impl RepositoryReader {
    /// Every file (blob or symbolic link) at `revision`, sorted, at most `limit` of them.
    /// The flag is true when the tree holds more.
    pub async fn file_paths(&self, revision: String, limit: usize) -> Result<(Vec<String>, bool), GitError> {
        self.with_repo(move |repo| {
            let commit = repo.find_commit(resolve_commit(repo, &revision)?).map_err(GitError::backend)?;
            let tree = commit.tree().map_err(GitError::backend)?;
            let mut recorder = Recorder::default();
            tree.traverse().breadthfirst(&mut recorder).map_err(GitError::backend)?;
            let mut paths: Vec<String> = recorder
                .records
                .into_iter()
                .filter(|entry| matches!(entry.mode.kind(), GixEntryKind::Blob | GixEntryKind::BlobExecutable | GixEntryKind::Link))
                .map(|entry| entry.filepath.to_string())
                .collect();
            let truncated = paths.len() > limit;
            paths.sort_unstable();
            paths.truncate(limit);
            Ok((paths, truncated))
        })
        .await
    }

    /// The number of commits reachable from `revision`, counting at most `cap`. The flag is
    /// true when the history is longer.
    pub async fn commit_count(&self, revision: String, cap: usize) -> Result<(usize, bool), GitError> {
        self.with_repo(move |repo| {
            let tip = resolve_commit(repo, &revision)?;
            let mut count = 0;
            for info in repo.rev_walk([tip]).all().map_err(GitError::backend)? {
                info.map_err(GitError::backend)?;
                if count == cap {
                    return Ok((count, true));
                }
                count += 1;
            }
            Ok((count, false))
        })
        .await
    }

    /// How far each of `heads` is ahead of and behind `base`, each side counted up to
    /// `cap`. `None` for a head that does not resolve. Each walk stops at the merge base,
    /// so a branch costs about as much as the commits it differs by.
    pub async fn divergence(&self, base: String, heads: Vec<String>, cap: usize) -> Result<Vec<Option<Divergence>>, GitError> {
        self.with_repo(move |repo| {
            let base_id = resolve_commit(repo, &base)?;
            let only_in = |tip: ObjectId, hidden: ObjectId| -> Result<(usize, bool), GitError> {
                let mut count = 0;
                for info in repo.rev_walk([tip]).with_hidden([hidden]).all().map_err(GitError::backend)? {
                    info.map_err(GitError::backend)?;
                    if count == cap {
                        return Ok((count, true));
                    }
                    count += 1;
                }
                Ok((count, false))
            };
            heads
                .iter()
                .map(|head| {
                    let Ok(head_id) = resolve_commit(repo, head) else { return Ok(None) };
                    if head_id == base_id {
                        return Ok(Some(Divergence::default()));
                    }
                    let (ahead, ahead_capped) = only_in(head_id, base_id)?;
                    let (behind, behind_capped) = only_in(base_id, head_id)?;
                    Ok(Some(Divergence { ahead, behind, capped: ahead_capped || behind_capped }))
                })
                .collect()
        })
        .await
    }
}
