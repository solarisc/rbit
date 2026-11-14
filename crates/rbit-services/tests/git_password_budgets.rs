//! Git HTTP password guesses are throttled per client network, per typed login and per
//! account, exactly like web sign-in: a stranger cannot lock the owner out from another network.

use std::{num::NonZeroUsize, sync::Arc};

use rbit_core::{Config, User};
use rbit_identity::PasswordWork;
use rbit_identity_models::sessions::ClientInfo;
use rbit_kernel::BlockingBudget;
use rbit_services::{ServiceError, Services, SignUp};
use rbit_storage::{Database, KvStore};

const PASSWORD: &str = "correct horse battery";

struct Fixture {
    _directory: tempfile::TempDir,
    services: Services,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.storage.data_dir = directory.path().to_path_buf();
        let database = Database::open(&config.storage.sqlite_path()).await.unwrap();
        let kv = KvStore::open(&config.storage.kv_path()).unwrap();
        let passwords = PasswordWork::new(BlockingBudget::new(NonZeroUsize::new(1).unwrap()));
        let services = Services::with_password_work(Arc::new(config), &database, &kv, passwords).await.unwrap();
        let input = SignUp { username: "alice".into(), email: "alice@example.com".into(), password: PASSWORD.into() };
        let _: User = services.accounts.create_user(input, Some(false)).await.unwrap();
        Self { _directory: directory, services }
    }
}

fn network(address: &str) -> ClientInfo {
    ClientInfo { ip: Some(address.parse().unwrap()), user_agent: "git/2".into() }
}

/// One Git Basic-auth attempt; `Ok(true)` when the password was accepted, `Err` on refusal.
async fn attempt(services: &Services, login: &str, password: &str, client: &ClientInfo) -> Result<bool, ServiceError> {
    services.authenticate_git_password(login, password.into(), client).await.map(|outcome| {
        assert!(matches!(outcome, rbit_services::two_factor::GitPasswordOutcome::Authenticated(_)));
        true
    })
}

#[tokio::test]
async fn a_stranger_guessing_from_one_network_does_not_lock_the_owner_out_from_another() {
    let fixture = Fixture::new().await;
    let stranger = network("198.51.100.1");
    let mut limited = false;
    for _ in 0..10 {
        match attempt(&fixture.services, "alice", "wrong", &stranger).await {
            Err(ServiceError::InvalidCredentials) => {}
            Err(ServiceError::RateLimited { .. }) => {
                limited = true;
                break;
            }
            Err(error) => panic!("unexpected {error:?}"),
            Ok(_) => panic!("a wrong password was accepted"),
        }
    }
    assert!(limited, "the stranger's own network must be throttled");
    let owner = network("203.0.113.9");
    assert!(attempt(&fixture.services, "alice", PASSWORD, &owner).await.unwrap(), "the owner from another network must still sign in");
}

#[tokio::test]
async fn guesses_from_one_network_share_one_budget_for_the_username_and_the_email() {
    let fixture = Fixture::new().await;
    let client = network("198.51.100.2");
    let mut limited = false;
    for _ in 0..10 {
        match attempt(&fixture.services, "alice", "wrong", &client).await {
            Err(ServiceError::InvalidCredentials) => {}
            Err(ServiceError::RateLimited { .. }) => {
                limited = true;
                break;
            }
            Err(error) => panic!("unexpected {error:?}"),
            Ok(_) => panic!("a wrong password was accepted"),
        }
    }
    assert!(limited);
    // The same account under its email address shares the network's per-account budget.
    match attempt(&fixture.services, "alice@example.com", "wrong", &client).await {
        Err(ServiceError::RateLimited { .. }) => {}
        other => panic!("the email alias must be throttled with the username, got {}", other.is_ok()),
    }
}

#[tokio::test]
async fn the_account_wide_budget_still_stops_guesses_spread_over_many_networks() {
    let fixture = Fixture::new().await;
    let mut limited = false;
    for host in 1..=40 {
        let client = network(&format!("198.51.100.{host}"));
        match attempt(&fixture.services, "alice", "wrong", &client).await {
            Err(ServiceError::InvalidCredentials) => {}
            Err(ServiceError::RateLimited { .. }) => {
                limited = true;
                break;
            }
            Err(error) => panic!("unexpected {error:?}"),
            Ok(_) => panic!("a wrong password was accepted"),
        }
    }
    assert!(limited, "guesses from many networks must reach the account-wide budget");
    let owner = network("203.0.113.9");
    assert!(
        matches!(attempt(&fixture.services, "alice", PASSWORD, &owner).await, Err(ServiceError::RateLimited { .. })),
        "the account-wide budget refuses the owner too"
    );
}
