use http_from_scratch::{
    request::Request,
    response::{Response, Status},
    router::Params,
};
use serde::Deserialize;

use crate::{
    auth::{generate_tokens, ACCESS_EXPIRATION, REFRESH_EXPIRATION},
    db::UserDatabase,
};

#[derive(Debug, Clone, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

pub fn login(req: Request, _: &Params, db: &dyn UserDatabase) -> Response {
    let decoded: LoginRequest = serde_json::from_str(&req.body.unwrap()).unwrap();

    let user = match db.get_user_by_username(&decoded.username) {
        Some(user) => {
            if !user.check_password(&decoded.password) {
                return Response::new(Status::Unauthorized)
                    .with_cors("http://localhost:3000")
                    .with_body("Invalid password");
            }

            user
        }
        None => {
            return Response::new(Status::NotFound)
                .with_cors("http://localhost:3000")
                .with_body("User not found");
        }
    };

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
