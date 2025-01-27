use argon2::{Argon2, PasswordHash, PasswordVerifier};
use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};
use serde::Deserialize;

use crate::{
    auth::{generate_tokens, ACCESS_EXPIRATION, REFRESH_EXPIRATION},
    db::USERS,
};

#[derive(Debug, Clone, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

pub fn login(req: Request) -> Response {
    let decoded: LoginRequest = serde_json::from_str(&req.body.unwrap()).unwrap();

    // TODO: better handle no user
    let user = unsafe {
        USERS
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .find(|u| u.username == decoded.username)
            .expect("User not found")
    };

    let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
    if !Argon2::default()
        .verify_password(decoded.password.as_ref(), &parsed_hash)
        .is_ok()
    {
        return Response::new(Status::Unauthorized)
            .with_cors("http://localhost:3000")
            .with_body("Invalid password");
    }

    let tokens = generate_tokens(&user.id, user.session_version).unwrap();

    Response::new(Status::NoContent)
        .with_cors("http://localhost:3000")
        .with_cookie(
            "access_token",
            &tokens.access_token,
            ACCESS_EXPIRATION.as_secs(),
            true,
        )
        .with_cookie(
            "refresh_token",
            &tokens.refresh_token,
            REFRESH_EXPIRATION.as_secs(),
            true,
        )
}
