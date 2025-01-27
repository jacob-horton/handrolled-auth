use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};
use serde::Deserialize;

use crate::{
    db::USERS,
    tokens::{generate_tokens, ACCESS_EXPIRATION, REFRESH_EXPIRATION},
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

    // TODO: password hashing
    if user.password != decoded.password {
        panic!("Invalid password");
    }

    let tokens = generate_tokens(user.id, user.session_version).unwrap();

    Response::new(Status::NoContent)
        .with_cors("http://localhost:3000".to_string())
        .with_cookie(
            "access_token".to_string(),
            tokens.access_token,
            ACCESS_EXPIRATION.as_secs(),
            true,
        )
        .with_cookie(
            "refresh_token".to_string(),
            tokens.refresh_token,
            REFRESH_EXPIRATION.as_secs(),
            true,
        )
}
