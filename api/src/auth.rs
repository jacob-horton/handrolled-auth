use http_from_scratch::common::Header;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::USERS;

static SIGNING_KEY: &'static str = "secret";

static ISSUER: &'static str = "handrolled-auth-api";
lazy_static! {
    static ref VALIDATION: Validation = {
        let mut val = Validation::default();
        val.set_issuer(&[ISSUER]);
        val
    };
}

// static ACCESS_EXPIRATION: Duration = Duration::from_secs(5 * 60);
pub static ACCESS_EXPIRATION: Duration = Duration::from_secs(5);
pub static REFRESH_EXPIRATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    exp: usize,
    iss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshClaims {
    sub: String,
    exp: usize,
    iss: String,
    version: usize,
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub new_tokens: Option<Tokens>,
}

#[derive(Debug, Clone)]
pub enum SessionError {
    AccessExpired,
    MissingCookies,
    MissingOrInvalidAccessCookie,
    InvalidToken,
}

pub fn generate_tokens(id: &str, session_version: usize) -> Result<Tokens, ()> {
    let access_claims = AccessClaims {
        sub: id.to_string(),
        exp: (SystemTime::now() + ACCESS_EXPIRATION)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
        iss: ISSUER.to_string(),
    };

    let access_token = encode(
        &jsonwebtoken::Header::default(),
        &access_claims,
        &EncodingKey::from_secret(SIGNING_KEY.as_ref()),
    )
    .or(Err(()))?;

    let refresh_claims = RefreshClaims {
        sub: id.to_string(),
        exp: (SystemTime::now() + REFRESH_EXPIRATION)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
        iss: ISSUER.to_string(),
        version: session_version,
    };

    let refresh_token = encode(
        &jsonwebtoken::Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(SIGNING_KEY.as_ref()),
    )
    .or(Err(()))?;

    Ok(Tokens {
        access_token,
        refresh_token,
    })
}

// TODO: return errors - not found vs incorrectly formatted
fn get_cookie<'a>(cookies: &Vec<&'a str>, name: &str) -> Option<&'a str> {
    cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .map(|x| x.split_once("=").map(|c| c.1))
        .flatten()
}

fn validate_access_token(headers: &Vec<Header>) -> Result<Session, SessionError> {
    let cookies = headers
        .iter()
        .find(|h| h.name.to_lowercase() == "cookie")
        .ok_or(SessionError::MissingCookies)?;

    let cookies: Vec<_> = cookies.value.split("; ").collect();
    let access_token =
        get_cookie(&cookies, "access_token").ok_or(SessionError::MissingOrInvalidAccessCookie)?;

    let token = decode::<AccessClaims>(
        access_token,
        &DecodingKey::from_secret(SIGNING_KEY.as_ref()),
        &VALIDATION,
    );

    match token {
        Ok(t) => {
            let user = unsafe {
                USERS
                    .read()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .find(|u| u.id == t.claims.sub)
                    .unwrap()
            };

            return Ok(Session {
                user_id: user.id.to_string(),
                new_tokens: None,
            });
        }
        Err(e) => match e.kind() {
            ErrorKind::ExpiredSignature => Err(SessionError::AccessExpired),
            _ => Err(SessionError::InvalidToken),
        },
    }
}

// TODO: different errors
pub fn validate_session(headers: &Vec<Header>) -> Result<Session, ()> {
    // TODO: reduce lookup of cookies
    match validate_access_token(headers) {
        Ok(session) => return Ok(session),
        Err(SessionError::MissingOrInvalidAccessCookie) | Err(SessionError::AccessExpired) => {
            let cookies = headers
                .iter()
                .find(|h| h.name.to_lowercase() == "cookie")
                .ok_or(())?;

            let cookies: Vec<_> = cookies.value.split("; ").collect();
            let refresh_token = get_cookie(&cookies, "refresh_token").ok_or(())?;

            let claims = decode::<RefreshClaims>(
                refresh_token,
                &DecodingKey::from_secret(SIGNING_KEY.as_ref()),
                &VALIDATION,
            )
            .or(Err(()))?
            .claims;

            // TODO: check session is valid, password is correct etc.
            let user = unsafe {
                USERS
                    .read()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .find(|u| u.id == claims.sub)
                    .unwrap()
            };

            if claims.version != user.session_version {
                return Err(());
            }

            let tokens = generate_tokens(&user.id, claims.version).unwrap();

            return Ok(Session {
                user_id: user.id.to_string(),
                new_tokens: Some(tokens),
            });
        }
        _ => return Err(()),
    };
}
