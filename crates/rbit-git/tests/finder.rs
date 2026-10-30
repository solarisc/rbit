//! File paths for "Go to file", history length and branch divergence.

use std::{path::Path, process::Command};

use rbit_git::{Divergence, RepositoryReader};

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "init.defaultBranch=main"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git is installed");
    assert!(output.status.success(), "git {args:?} failed");
}

fn commit(dir: &Path, file: &str, message: &str) {
    let path = dir.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, message).unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-q", "-m", message]);
}

/// main: a → b → c; feature (from b): f1 → f2.
fn fixture() -> (tempfile::TempDir, RepositoryReader) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    commit(root, "README.md", "a");
    commit(root, "src/lib.rs", "b");
    git(root, &["checkout", "-q", "-b", "feature"]);
    commit(root, "src/net/client.rs", "f1");
    commit(root, "docs/guide.md", "f2");
    git(root, &["checkout", "-q", "main"]);
    commit(root, "src/main.rs", "c");
    let reader = RepositoryReader::new(root.join(".git"));
    (dir, reader)
}

#[tokio::test]
async fn lists_every_file_sorted_and_bounded() {
    let (_dir, reader) = fixture();
    let (paths, truncated) = reader.file_paths("feature".into(), 100).await.unwrap();
    assert_eq!(paths, ["README.md", "docs/guide.md", "src/lib.rs", "src/net/client.rs"]);
    assert!(!truncated);
    let (paths, truncated) = reader.file_paths("feature".into(), 2).await.unwrap();
    assert_eq!(paths.len(), 2);
    assert!(truncated);
}

#[tokio::test]
async fn counts_history_up_to_a_cap() {
    let (_dir, reader) = fixture();
    assert_eq!(reader.commit_count("main".into(), 100).await.unwrap(), (3, false));
    assert_eq!(reader.commit_count("feature".into(), 100).await.unwrap(), (4, false));
    assert_eq!(reader.commit_count("feature".into(), 2).await.unwrap(), (2, true));
}

#[tokio::test]
async fn measures_divergence_from_a_base() {
    let (_dir, reader) = fixture();
    let found = reader.divergence("main".into(), vec!["feature".into(), "main".into(), "missing".into()], 100).await.unwrap();
    assert_eq!(found[0], Some(Divergence { ahead: 2, behind: 1, capped: false }));
    assert_eq!(found[1], Some(Divergence::default()));
    assert_eq!(found[2], None);
    let capped = reader.divergence("main".into(), vec!["feature".into()], 1).await.unwrap();
    assert_eq!(capped[0], Some(Divergence { ahead: 1, behind: 1, capped: true }));
}
