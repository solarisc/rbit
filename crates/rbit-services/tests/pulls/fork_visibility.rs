//! A public fork that turns private must stop feeding its pull request into the public base.

use super::*;

#[tokio::test]
async fn a_public_fork_that_turns_private_stops_feeding_its_pull_request() {
    use rbit_services::repo_settings::UpdateRepository;
    let fixture = Fixture::new().await;
    // bob opens a pull request from his public fork into alice's public repository.
    let number = fixture.create(&fixture.bob, "bob", "feature").await.unwrap();
    let before = fixture.open_pull(&fixture.alice, number).await.pull.head_sha;

    // He makes the fork private and pushes a commit to the head branch.
    let fork = fixture.repo(&fixture.bob, "bob").await;
    let private = UpdateRepository { visibility: Visibility::Private, ..Default::default() };
    fixture.services.repo_settings.update(&fork, private).await.unwrap();
    git(&fixture.work, &["checkout", "-q", "feature"]);
    let secret = commit(
        &fixture.work,
        "secret.txt",
        "private
",
        "Secret work",
    );
    git(&fixture.work, &["checkout", "-q", "main"]);
    fixture.push(&fixture.bob, "bob", &["feature"]).await;

    // The public pull request keeps its old head and the base gets no ref to the private commit.
    let after = fixture.open_pull(&fixture.alice, number).await;
    assert_eq!(after.pull.head_sha, before, "a private head must not sync into the public pull request");
    let base = fixture.repo(&fixture.alice, "alice").await;
    assert_eq!(base.reader.commit_id(format!("refs/pull/{number}/head")).await.unwrap(), before);
    assert_ne!(secret, before);

    // Closed, it cannot be reopened while its head is private.
    let ctx = fixture.open_pull(&fixture.alice, number).await;
    fixture.services.timeline.set_state(&fixture.alice, &ctx.thread, StateChange::Close(StateReason::Completed)).await.unwrap();
    let closed = fixture.open_pull(&fixture.alice, number).await;
    let error = fixture.services.timeline.set_state(&fixture.alice, &closed.thread, StateChange::Reopen).await.unwrap_err();
    assert!(error.to_string().contains("private fork"), "{error}");

    // A new pull request from the private fork is refused as well.
    let error = fixture.create(&fixture.bob, "bob", "feature").await.unwrap_err();
    assert!(error.to_string().contains("private fork"), "{error}");
}
