//! Credential changes from the web need a recent proof of identity: a sign-in within the window,
//! or the account's current password. The proof lives server-side; a stolen session cookie alone
//! cannot make one, and a password guess spends the account's password-check budget.

use axum::http::{HeaderMap, Method, StatusCode, header};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rbit_core::Visibility;
use rbit_services::CreateRepository;
use sha2::{Digest, Sha256};

use super::fixture::{Fixture, LOGIN_FORM, PASSWORD};

const SESSION: &str = "rbit_session";
const STAMP: &str = "rbit_sudo";
const TOKEN_FORM: &str = "name=ci&scope=read&expires=30";
const SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAU5O8WQTG+ptksHlmxF+ieJyp0kwsQ2tQsz0JAuTWme";

fn now() -> i64 {
    i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

/// The `Cookie` header for a session and an optional stamp.
fn cookies(session: &str, stamp: Option<&str>) -> String {
    match stamp {
        Some(stamp) => format!("{SESSION}={session}; {STAMP}={stamp}"),
        None => format!("{SESSION}={session}"),
    }
}

/// POSTs `form` to `path`, with `cookie` as the `Cookie` header when it is not empty.
async fn post(fixture: &Fixture, cookie: &str, path: &str, form: &str) -> (StatusCode, HeaderMap, String) {
    let mut headers = vec![(header::CONTENT_TYPE.as_str(), "application/x-www-form-urlencoded"), ("HX-Request", "true")];
    if !cookie.is_empty() {
        headers.push((header::COOKIE.as_str(), cookie));
    }
    fixture.request(Method::POST, path, &headers, form).await
}

/// POSTs the token form as `session`, with `stamp` when given.
async fn create_token(fixture: &Fixture, session: &str, stamp: Option<&str>, form: &str) -> (StatusCode, HeaderMap, String) {
    post(fixture, &cookies(session, stamp), "/settings/tokens", form).await
}

/// The value of the cookie `name` among the `Set-Cookie` headers, if one was set.
fn set_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::SET_COOKIE).iter().find_map(|value| {
        let value = value.to_str().ok()?;
        let pair = value.split(';').next()?;
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

/// A key form body; the key is percent-encoded because it contains `+`, `/` and `=`.
fn key_form(extra: &str) -> String {
    format!("title=laptop&key={}{extra}", utf8_percent_encode(SSH_KEY, NON_ALPHANUMERIC))
}

#[tokio::test]
async fn a_fresh_proof_lets_a_token_be_created_without_the_password() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let stamp = fixture.services.sudo.stamp(&session.encode(), now()).await.unwrap();
    let (status, _, body) = create_token(&fixture, &session.encode(), Some(&stamp), TOKEN_FORM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("rbit_"), "the new secret is shown once");
    assert_eq!(fixture.services.tokens.list(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_stale_proof_without_a_password_creates_nothing() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let (status, _, body) = create_token(&fixture, &session.encode(), None, TOKEN_FORM).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("confirm your current password"), "the form asks for the password");
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_correct_password_creates_the_token_and_renews_the_window() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let form = format!("{TOKEN_FORM}&current_password={PASSWORD}");
    let (status, headers, body) = create_token(&fixture, &session.encode(), None, &form).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(set_cookie(&headers, STAMP).is_some(), "the window is renewed");
    assert_eq!(fixture.services.tokens.list(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_then_throttled_even_when_correct() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let wrong = format!("{TOKEN_FORM}&current_password=wrong-guess");
    let mut throttled = false;
    for _ in 0..40 {
        let (status, _, _) = create_token(&fixture, &session.encode(), None, &wrong).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a wrong password is refused, not accepted");
    }
    assert!(throttled, "guesses must reach the account's password-check budget");
    let correct = format!("{TOKEN_FORM}&current_password={PASSWORD}");
    let (status, _, _) = create_token(&fixture, &session.encode(), None, &correct).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the budget refuses the owner too, until it recovers");
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_proof_from_another_session_does_not_count() {
    let fixture = Fixture::new().await;
    let first = fixture.session().await;
    let second = fixture.session().await;
    let stamp = fixture.services.sudo.stamp(&first.encode(), now()).await.unwrap();
    let (status, _, _) = create_token(&fixture, &second.encode(), Some(&stamp), TOKEN_FORM).await;
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
        let (status, _, _) = create_token(&fixture, &session.encode(), Some(&forged), TOKEN_FORM).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "forged proof {forged} must not count");
    }
    assert!(fixture.services.tokens.list(&fixture.user).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_real_sign_in_stamps_the_window_that_lets_a_token_be_created() {
    let fixture = Fixture::new().await;
    let (status, headers, body) = post(&fixture, "", "/login", LOGIN_FORM).await;
    assert!(status.is_redirection(), "sign-in redirects: {status} {body}");
    let session = set_cookie(&headers, SESSION).expect("sign-in sets the session");
    let stamp = set_cookie(&headers, STAMP).expect("sign-in stamps the window");
    let (status, _, body) = create_token(&fixture, &session, Some(&stamp), TOKEN_FORM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fixture.services.tokens.list(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_stale_proof_refuses_an_ssh_key_without_the_password_and_accepts_it_with() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let (status, _, _) = post(&fixture, &cookies(&session.encode(), None), "/settings/keys", &key_form("")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(fixture.services.ssh_keys.list_user_keys(&fixture.user).await.unwrap().is_empty());

    let form = key_form(&format!("&current_password={PASSWORD}"));
    let (status, _, body) = post(&fixture, &cookies(&session.encode(), None), "/settings/keys", &form).await;
    assert!(status.is_redirection(), "{status} {body}");
    assert_eq!(fixture.services.ssh_keys.list_user_keys(&fixture.user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_stale_proof_refuses_a_deploy_key_without_the_password_and_accepts_it_with() {
    let fixture = Fixture::new().await;
    let create = CreateRepository { name: "vault".into(), description: String::new(), visibility: Visibility::Private };
    fixture.services.repositories.create(&fixture.user, create).await.unwrap();
    let repo = fixture.services.repositories.open(Some(&fixture.user), "keeper", "vault").await.unwrap();
    let session = fixture.session().await;
    let path = "/keeper/vault/settings/keys";
    let (status, _, _) = post(&fixture, &cookies(&session.encode(), None), path, &key_form("")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(fixture.services.ssh_keys.list_deploy_keys(&repo).await.unwrap().is_empty());

    let form = key_form(&format!("&current_password={PASSWORD}"));
    let (status, _, body) = post(&fixture, &cookies(&session.encode(), None), path, &form).await;
    assert!(status.is_redirection(), "{status} {body}");
    assert_eq!(fixture.services.ssh_keys.list_deploy_keys(&repo).await.unwrap().len(), 1);
}
