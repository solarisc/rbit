//! `rbit preflight push`: asks the server whether this credential may push one update, before
//! anything is pushed (agent plan step 3). The local side fills in the new commit and whether
//! the update is a force push; the server's branch head is the old one. Exit 0 when the push
//! would be allowed, 3 (not allowed) with each refusal's code, rule and fix when not.

use clap::Subcommand;
use serde_json::json;

use super::{
    Api, Repo, agent,
    commands::Output,
    util::{encode, git, text},
};

/// `rbit preflight`.
#[derive(Debug, Subcommand)]
pub enum PreflightCommand {
    /// Whether this credential may push `--new` to `--ref`: the server runs the push gate a
    /// real push runs and answers; nothing is pushed.
    Push {
        /// The branch to push to.
        #[arg(long = "ref", default_value = "main")]
        branch: String,
        /// The commit to push, as a revision of this checkout.
        #[arg(long, default_value = "HEAD")]
        new: String,
    },
}

/// The all-zero id: no commit (a branch being created).
const ZERO: &str = "0000000000000000000000000000000000000000";

/// `rbit preflight push [--ref BRANCH] [--new REV]`.
pub async fn push(api: &Api, repo: &Repo, branch: &str, new: &str, out: &Output) -> anyhow::Result<i32> {
    let reference = if branch.starts_with("refs/") { branch.to_owned() } else { format!("refs/heads/{branch}") };
    let short_name = reference.strip_prefix("refs/heads/").unwrap_or(&reference);
    let new = git(&["rev-parse", "--verify", "--quiet", &format!("{new}^{{commit}}")])
        .ok_or_else(|| anyhow::anyhow!("`{new}` is not a commit in this checkout"))?;

    // The server's head is the old commit; a branch that does not exist yet is all zeros.
    let status = api.get(&format!("repos/{repo}/agent/status?branch={}", encode(short_name))).await?;
    let server_head = text(&status["head"], "sha").to_owned();
    let old = if server_head.is_empty() { ZERO.to_owned() } else { server_head };

    // A new commit that does not contain the old one rewrites the branch: a force push. The
    // check needs the old commit locally; when it is not, Git's own fast-forward check decides.
    let force = old != ZERO && git(&["merge-base", "--is-ancestor", &old, &new]).is_none() && has_object(&old);
    let query = format!("ref={}&old={old}&new={new}&force={force}", encode(&reference));
    let answer = api.get(&format!("repos/{repo}/agent/preflight/push?{query}")).await?;
    let allowed = answer["allowed"].as_bool().unwrap_or(false);

    if out.json {
        let mut body = answer;
        body["ref"] = json!(reference);
        body["old"] = json!(old);
        body["new"] = json!(new);
        body["force"] = json!(force);
        agent::print("rbit.preflight/1", body);
    } else if allowed {
        println!("allowed: a push of {new} to {reference} would be accepted");
    } else {
        println!("refused: a push of {new} to {reference} would be refused");
        for refusal in answer["refusals"].as_array().into_iter().flatten() {
            println!("  [{}] {}", text(refusal, "code"), text(refusal, "message"));
            if let Some(rule) = refusal["rule"].as_str() {
                println!("    rule: {rule}");
            }
            println!("    fix: {}", text(refusal, "remediation"));
        }
    }
    Ok(if allowed { 0 } else { 3 })
}

/// Whether this checkout has `object` (a missing old commit cannot be compared).
fn has_object(object: &str) -> bool {
    git(&["cat-file", "-e", &format!("{object}^{{commit}}")]).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zero_id_is_forty_zeros() {
        assert_eq!(ZERO.len(), 40);
        assert!(ZERO.bytes().all(|byte| byte == b'0'));
    }
}
