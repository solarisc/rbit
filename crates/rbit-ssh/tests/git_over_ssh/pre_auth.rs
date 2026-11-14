//! Unauthenticated SSH connections are capped per address and freed when they authenticate.

use super::*;

/// Whether the server has closed `stream` (end of file or reset) within a second. An
/// admitted connection instead receives its SSH banner or stays silent, so it is not closed.
async fn closed_by_server(stream: &mut tokio::net::TcpStream) -> bool {
    use tokio::io::AsyncReadExt;
    let mut byte = [0_u8; 1];
    matches!(tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut byte)).await, Ok(Ok(0) | Err(_)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthenticated_connections_are_capped_and_freed_by_authentication() {
    let mut harness = Harness::start_with(|config| config.ssh.max_connections_per_ip = 32).await;
    let owner = harness.user("alice").await;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[45; 32]));
    let public = key.public_key().to_openssh().unwrap();
    harness.services.ssh_keys.add_user_key(&owner, AddSshKey { title: "test".to_owned(), key: public }).await.unwrap();

    // Eight connections that never authenticate use every unauthenticated slot for this address.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(tokio::net::TcpStream::connect(("127.0.0.1", harness.port)).await.unwrap());
    }
    // The ninth is refused at once, long before the auth timeout.
    let mut ninth = tokio::net::TcpStream::connect(("127.0.0.1", harness.port)).await.unwrap();
    assert!(closed_by_server(&mut ninth).await, "the ninth unauthenticated connection must be closed");

    // Dropping one unauthenticated connection frees its slot; an authenticating client takes
    // it, and gives it back as soon as it authenticates.
    drop(held.pop());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let client = persistent_client(&harness, key).await;
    assert_eq!(persistent_exec(&client, "true").await.0, 0);

    // Back to the full eight unauthenticated slots: one more is accepted, the next is refused.
    let mut accepted = tokio::net::TcpStream::connect(("127.0.0.1", harness.port)).await.unwrap();
    assert!(!closed_by_server(&mut accepted).await, "a connection within the cap must stay open");
    let mut refused = tokio::net::TcpStream::connect(("127.0.0.1", harness.port)).await.unwrap();
    assert!(closed_by_server(&mut refused).await, "the connection past the cap must be closed");

    drop(client);
    drop(held);
    harness.server.take().unwrap().shutdown().await;
}
