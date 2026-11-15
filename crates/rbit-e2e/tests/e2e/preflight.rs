//! Push preflight over the REST API: the gate a real push runs, answered without pushing.

use std::time::{Duration, Instant};

use rbit_e2e::{Git, PASSWORD, TestServer};
use serde_json::Value;

const ZERO: &str = "0000000000000000000000000000000000000000";

/// `GET` the preflight with `query` as `token`; the status and the JSON answer.
async fn preflight(server: &TestServer, token: &str, query: &str) -> (reqwest::StatusCode, Value) {
    let http = reqwest::Client::builder().no_proxy().build().expect("API client");
    let response = http
        .get(server.url(&format!("/api/v1/repos/alice/demo/agent/preflight/push?{query}")))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("the API answers");
    let status = response.status();
    (status, response.json().await.expect("a JSON answer"))
}

#[tokio::test]
async fn preflight_answers_the_push_gate_without_pushing() {
    let server = TestServer::start();
    let git = Git::new();
    let alice = server.sign_up("alice").await;
    alice.create_repo("alice", "demo", "private").await;
    let sample = git.sample();
    let url = server.git_url_as("alice", "demo", "alice", PASSWORD);
    git.push_sample(&sample, &url);
    let head = sample.head.clone();
    let write = alice.create_token("agent-write", "write").await;
    let read = alice.create_token("agent-read", "read").await;

    // Commits the cases need: a release branch to protect, a fast-forward of main, and a commit
    // with no ancestor in common with main (a real force push of main).
    let clone = git.clone(&url);
    git.ok(&clone, &["push", "--quiet", &url, "HEAD:refs/heads/release"]);
    git.commit_file(&clone, "next.txt", "next\n");
    let next = git.ok(&clone, &["rev-parse", "HEAD"]).trim().to_owned();
    git.ok(&clone, &["push", "--quiet", &url, "HEAD:refs/heads/next"]);
    let tree = git.ok(&clone, &["rev-parse", "HEAD^{tree}"]).trim().to_owned();
    let unrelated = git.ok(&clone, &["commit-tree", &tree, "-m", "Unrelated history"]).trim().to_owned();
    git.ok(&clone, &["push", "--quiet", &url, &format!("{unrelated}:refs/heads/rewritten")]);

    super::protection::add_rule(&alice, "alice/demo", &[("pattern", "main"), ("deny_force_push", "on")]).await;
    super::protection::add_rule(&alice, "alice/demo", &[("pattern", "release"), ("require_pull_request", "on")]).await;

    // A new branch passes, and asking creates nothing.
    let (status, answer) = preflight(&server, &write, &format!("ref=refs/heads/preflight-new&old={ZERO}&new={head}")).await;
    assert_eq!((status, answer["allowed"].as_bool()), (reqwest::StatusCode::OK, Some(true)), "{answer}");
    assert!(answer["refusals"].as_array().is_some_and(Vec::is_empty), "{answer}");
    assert!(git.ok(&clone, &["ls-remote", &url, "refs/heads/preflight-new"]).trim().is_empty(), "a preflight pushes nothing");

    // A fast-forward of main is allowed: the server finds that old is an ancestor of new.
    let fast = format!("ref=refs/heads/main&old={head}&new={next}");
    let (_, answer) = preflight(&server, &write, &fast).await;
    assert_eq!(answer["allowed"], true, "{answer}");

    // A real force push of main is refused by its rule, with the code, rule and fix. The client
    // does not have to say so: the server sees that the new commit does not contain the old one.
    let forced = format!("ref=refs/heads/main&old={head}&new={unrelated}");
    let (_, answer) = preflight(&server, &write, &forced).await;
    assert_eq!(answer["allowed"], false, "{answer}");
    let refusal = &answer["refusals"][0];
    let code = (refusal["ref"].as_str(), refusal["code"].as_str());
    assert_eq!(code, (Some("refs/heads/main"), Some("protected_branch_force_push")), "{answer}");
    assert_eq!(refusal["rule"], "branch protection main (deny_force_push)", "{answer}");
    assert!(refusal["remediation"].as_str().is_some_and(|fix| !fix.is_empty()), "{answer}");

    // Declaring the update not forced does not change the server's answer for a commit it can see.
    let declared = format!("ref=refs/heads/main&old={head}&new={unrelated}&force=false");
    let (_, answer) = preflight(&server, &write, &declared).await;
    assert_eq!(answer["refusals"][0]["code"], "protected_branch_force_push", "{answer}");

    // A rule that requires a pull request refuses even a fast-forward.
    let release = format!("ref=refs/heads/release&old={head}&new={next}");
    let (_, answer) = preflight(&server, &write, &release).await;
    assert_eq!(answer["refusals"][0]["code"], "protected_branch_requires_pull_request", "{answer}");

    // The caller must name the head the branch really has: a zeroed old is a 409.
    let zeroed = format!("ref=refs/heads/main&old={ZERO}&new={next}");
    let (status, answer) = preflight(&server, &write, &zeroed).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "conflict", "{answer}");
    assert!(answer["message"].as_str().is_some_and(|message| message.contains(&head)), "{answer}");

    // A token too narrow to push is refused by its scope, and the answer names the scope.
    let (status, answer) = preflight(&server, &read, &format!("ref=refs/heads/preflight-new&old={ZERO}&new={head}")).await;
    assert_eq!((status, answer["allowed"].as_bool()), (reqwest::StatusCode::OK, Some(false)), "{answer}");
    assert_eq!(answer["refusals"][0]["code"], "token_scope_insufficient", "{answer}");
    assert_eq!(answer["refusals"][0]["rule"], "token scope read", "{answer}");

    // A value that is not a commit id is a 422 naming the field.
    let (status, answer) = preflight(&server, &write, "ref=refs/heads/main&old=zz&new=zz").await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
}

#[tokio::test]
async fn preflight_refuses_a_pull_mirror_as_git_does() {
    let server = TestServer::start_with(|config| config.mirrors.allow_private_addresses = true);
    let git = Git::new();
    let alice = server.sign_up("alice").await;
    alice.create_repo("alice", "upstream", "public").await;
    let sample = git.sample();
    git.push_sample(&sample, &server.git_url_as("alice", "upstream", "alice", PASSWORD));
    let upstream = server.git_url("alice", "upstream");
    alice
        .post("/new/mirror", &[("owner", "alice"), ("url", &upstream), ("name", "demo"), ("visibility", "public"), ("interval", "60")])
        .await
        .expect_redirect("/alice/demo/mirror/progress");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !alice.get("/alice/demo/branches").await.contains("feature") {
        assert!(Instant::now() < deadline, "the mirror never fetched");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let write = alice.create_token("agent-write", "write").await;
    let head = sample.head.clone();

    // Git refuses the push with the mirror's text, now carrying its code.
    let checkout = git.clone(&server.git_url_as("alice", "demo", "alice", PASSWORD));
    git.commit_file(&checkout, "local.txt", "local\n");
    let refused = git.fails(&checkout, &["push", "origin", "main"]);
    assert!(refused.contains("[repository_mirror]"), "{refused}");

    // Preflight answers the same decision: a refusal with the same code, and nothing pushed.
    let (status, answer) = preflight(&server, &write, &format!("ref=refs/heads/main&old={head}&new={head}")).await;
    assert_eq!((status, answer["allowed"].as_bool()), (reqwest::StatusCode::OK, Some(false)), "{answer}");
    assert_eq!(answer["refusals"][0]["code"], "repository_mirror", "{answer}");
    assert!(answer["refusals"][0]["remediation"].as_str().is_some_and(|fix| fix.contains("upstream")), "{answer}");
}
