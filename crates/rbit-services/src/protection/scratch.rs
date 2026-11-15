//! Scratch refs: who may push them and how many each person may hold, decided with the push gate.

use rbit_core::{
    RefUpdate, Timestamp, User,
    protection::{PushActor, PushVerdict, Refusal, codes},
};

use super::{ProtectionService, Recording, SCRATCH_REFS_PER_OWNER};
use crate::{RepoContext, ServiceError};

impl ProtectionService {
    /// Scratch refs (`refs/scratch/<owner>/<name>`): only a person may push them, only under
    /// their own name, and a new one only while they have fewer than
    /// [`SCRATCH_REFS_PER_OWNER`] in the repository. Deleting one's own is always allowed.
    /// An allowed update is recorded here (unless previewing), so the sweep expires it even
    /// if Actions is off; a push that then fails leaves a record whose ref the sweep finds gone.
    pub(super) async fn check_scratch(
        &self,
        repo: &RepoContext,
        actor: &PushActor<'_>,
        updates: &[RefUpdate],
        verdict: &mut PushVerdict,
        recording: Recording,
    ) -> Result<(), ServiceError> {
        // Merge-queue candidates are written by the server only: a pushed one would be an
        // untested commit the queue could take for a tested one.
        for update in updates.iter().filter(|update| update.name.starts_with(rbit_git::merge::candidate::CANDIDATE_PREFIX)) {
            verdict.refusals.push(Refusal::new(
                update.name.clone(),
                codes::REF_RESERVED,
                "refs/merge-queue/ is managed by rbit",
                "Push to a branch under refs/heads/ instead; rbit manages the merge queue.",
            ));
        }
        // Branches named like those refs read as them where a name is resolved loosely, and
        // look like candidates to workflows. Deleting one stays possible.
        for update in updates.iter().filter(|update| update.after.is_some() && rbit_git::merge::candidate::reserved_branch(&update.name)) {
            verdict.refusals.push(Refusal::new(
                update.name.clone(),
                codes::REF_RESERVED,
                rbit_git::merge::candidate::RESERVED_BRANCH,
                "Choose a branch name that does not start with refs/ or merge-queue/.",
            ));
        }
        for update in updates.iter().filter(|update| update.name.starts_with(rbit_git::scratch::PREFIX)) {
            let owner = rbit_git::scratch::owner(&update.name);
            let refusal = match actor.user {
                Some(user) if owner == Some(user.name().as_str()) => {
                    let new = update.before.is_none() && update.after.is_some();
                    let held = if new {
                        self.ctx.database.actions_runs().count_scratch(repo.repo.repo.id, user.id(), &update.name).await?
                    } else {
                        0
                    };
                    (held >= SCRATCH_REFS_PER_OWNER).then(|| {
                        Refusal::new(
                            update.name.clone(),
                            codes::SCRATCH_LIMIT,
                            format!("you have {held} scratch refs here; delete one or wait for them to expire"),
                            "Delete one of your scratch refs in this repository, or wait for them to expire.",
                        )
                    })
                }
                _ => Some(Refusal::new(
                    update.name.clone(),
                    codes::SCRATCH_OWNER,
                    "refs/scratch/<you>/… is for your own scratch commits",
                    "Push under refs/scratch/<your name>/… instead.",
                )),
            };
            let store = self.ctx.database.actions_runs();
            match (refusal, &update.after, &update.before) {
                (Some(refusal), _, _) => verdict.refusals.push(refusal),
                (None, Some(after), _) if recording == Recording::Yes => {
                    store.record_scratch(repo.repo.repo.id, &update.name, actor.user.map(User::id), after, Timestamp::now()).await?;
                }
                (None, None, Some(before)) if recording == Recording::Yes => {
                    store.forget_scratch(repo.repo.repo.id, &update.name, before).await?;
                }
                (None, _, _) => {}
            }
        }
        Ok(())
    }
}
