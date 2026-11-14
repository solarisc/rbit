use super::*;

#[tokio::test]
async fn replay_yields_saved_bytes_then_the_rest() {
    let rest: &[u8] = b" world";
    let mut replay = Replay::new(b"hello".to_vec(), rest, Remaining::ToEnd);
    let mut all = Vec::new();
    replay.read_to_end(&mut all).await.unwrap();
    assert_eq!(all, b"hello world");
}

#[tokio::test]
async fn replay_respects_small_reads() {
    let rest: &[u8] = b"cd";
    let mut replay = Replay::new(b"ab".to_vec(), rest, Remaining::ToEnd);
    let mut one = [0; 1];
    let mut seen = Vec::new();
    while replay.read(&mut one).await.unwrap() == 1 {
        seen.push(one[0]);
    }
    assert_eq!(seen, b"abcd");
}

#[tokio::test]
async fn drain_reads_to_the_end_only_when_more_is_expected() {
    let (mut client, server) = tokio::io::duplex(16);
    // The client keeps the stream open: draining must not wait for it.
    drain(Replay::new(b"0000".to_vec(), server, Remaining::Nothing)).await;

    let (client2, server2) = tokio::io::duplex(16);
    drop(client2);
    drain(Replay::new(Vec::new(), server2, Remaining::ToEnd)).await;
    tokio::io::AsyncWriteExt::shutdown(&mut client).await.unwrap();
}

#[test]
fn report_lines_stay_on_one_line() {
    assert_eq!(one_line("a\nb\rc"), "a b c");
    let mut out = Vec::new();
    pkt_line(&mut out, b"unpack ok\n");
    assert_eq!(out, b"000eunpack ok\n");
}

#[test]
fn commands_convert_to_ref_updates() {
    let id = "1".repeat(40);
    let list = CommandList::new(
        vec![
            PushCommand { old: ZERO_ID.to_owned(), new: id.clone(), name: "refs/heads/new".to_owned() },
            PushCommand { old: id.clone(), new: ZERO_ID.to_owned(), name: "refs/heads/gone".to_owned() },
        ],
        vec!["report-status".to_owned(), "agent=git/2.50".to_owned()],
        Vec::new(),
    );
    let updates = list.updates();
    assert!(updates[0].is_created() && updates[0].after.as_deref() == Some(id.as_str()));
    assert!(updates[1].is_deleted() && updates[1].before.as_deref() == Some(id.as_str()));
    assert!(list.wants_report() && list.has_capability("agent") && !list.has_capability("side-band-64k"));
    assert!(!list.is_empty() && CommandList::default().is_empty());
}

#[tokio::test]
async fn sha256_deletions_do_not_wait_for_a_pack() {
    let zero = "0".repeat(64);
    let line = format!("{} {zero} refs/heads/main\0report-status", "1".repeat(64));
    let mut request = Vec::new();
    pkt_line(&mut request, line.as_bytes());
    request.extend_from_slice(b"0000");
    let Intercept::Read { commands, input } = intercept(request.as_slice(), CommandLimits::default()).await.unwrap() else {
        panic!("commands were not read");
    };
    assert!(commands.updates()[0].is_deleted());
    assert_eq!(input.remaining(), Remaining::Nothing);
    let creation = PushCommand { old: zero, new: "2".repeat(64), name: "refs/heads/new".to_owned() };
    assert!(creation.update().is_created());
}

#[test]
fn refusal_messages_list_each_ref() {
    let refusals = [Refusal::new("refs/heads/main", "protected_branch_deletion", "protected branch", "Ask an administrator.")];
    assert_eq!(refusal_message(&refusals), "refs/heads/main: [protected_branch_deletion] protected branch (fix: Ask an administrator.)\n");
}
