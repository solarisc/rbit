//! Credential changes from the web need a recent proof of identity: a sign-in within the window,
//! or the account's current password. The proof lives server-side; a stolen session cookie alone
//! cannot make one, and a password guess spends the account's password-check budget.

use axum::http::{HeaderMap, Method, StatusCode, header};
use rbit_auth::SessionToken;
use sha2::{Digest, Sha256};

use super::fixture::{Fixture, PASSWORD};

const SESSION: &str = "rbit_session";
const STAMP: &str = "rbit_sudo";
const TOKEN_FORM: &str = "name=ci&scope=read&expires=30";

fn now() -> i64 {
    i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

/// POSTs the token form as `session`, with `stamp` when given.
async fn create_token(fixture: &Fixture, session: &SessionToken, stamp: Option<&str>, form: &str) -> (StatusCode, HeaderMap, String) {
    let cookie = match stamp {
        Some(stamp) => format!("{SESSION}={}; {STAMP}={stamp}", session.encode()),
        None => format!("{SESSION}={}", session.encode()),
    };
    fixture
        .request(
            Method::POST,
            "/settings/tokens",
            &[(header::CONTENT_TYPE.as_str(), "application/x-www-form-urlencoded"), (header::COOKIE.as_str(), &cookie), ("HX-Request", "true")],
            form,
        )
        .await
}

#[tokio::test]
async fn a_fresh_proof_lets_a_token_be_created_without_the_password() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let stamp = fixture.services.sudo.stamp(&session.encode(), now()).await.unwrap();
    let (status, _, body) = create_token(&fixture, &session, Some(&stamp), TOKEN_FORM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("rbit_"), "the new secret is shown once");
    assert_eq!(fixture.services.tokens.list(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_stale_proof_without_a_password_creates_nothing() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let (status, _, body) = create_token(&fixture, &session, None, TOKEN_FORM).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("confirm your current password"), "the form asks for the password");
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_correct_password_creates_the_token_and_renews_the_window() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let form = format!("{TOKEN_FORM}&current_password={PASSWORD}");
    let (status, headers, body) = create_token(&fixture, &session, None, &form).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.get_all(header::SET_COOKIE).iter().any(|value| value.to_str().unwrap().starts_with("rbit_sudo=")));
    assert_eq!(fixture.services.tokens.list(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_then_throttled_even_when_correct() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let wrong = format!("{TOKEN_FORM}&current_password=wrong-guess");
    let mut throttled = false;
    for _ in 0..40 {
        let (status, _, _) = create_token(&fixture, &session, None, &wrong).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a wrong password is refused, not accepted");
    }
    assert!(throttled, "guesses must reach the account's password-check budget");
    let correct = format!("{TOKEN_FORM}&current_password={PASSWORD}");
    let (status, _, _) = create_token(&fixture, &session, None, &correct).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the budget refuses the owner too, until it recovers");
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_proof_from_another_session_does_not_count() {
    let fixture = Fixture::new().await;
    let first = fixture.session().await;
    let second = fixture.session().await;
    let stamp = fixture.services.sudo.stamp(&first.encode(), now()).await.unwrap();
    let (status, _, _) = create_token(&fixture, &second, Some(&stamp), TOKEN_FORM).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn knowing_the_session_token_is_not_enough_to_make_a_proof() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let now = now();
    // What a first draft stamped: an unkeyed digest over the token and the time. It is refused.
    let unkeyed = Sha256::digest(format!("rbit-sudo-v1\0{}\0{now}", session.encode()).as_bytes());
    let unkeyed = unkeyed.iter().fold(String::new(), |mut hex, byte| {
        hex.push_str(&format!("{byte:02x}"));
        hex
    });
    for forged in [format!("{now}.{unkeyed}"), format!("{now}.{}", "0".repeat(64)), format!("{now}.not-hex")] {
        let (status, _, _) = create_token(&fixture, &session, Some(&forged), TOKEN_FORM).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "forged proof {forged} must not count");
    }
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}
