use http_from_scratch::{
    request::Request,
    response::{Response, Status},
    router::Params,
};

use crate::{
    auth::{validate_session, ACCESS_EXPIRATION, REFRESH_EXPIRATION},
    db::UserDatabase,
};

pub fn session_info(req: Request, _: &Params, db: &&dyn UserDatabase) -> Response {
    match validate_session(&req, *db) {
        Ok(session) => {
            let user = db.get_user_by_id(&session.user_id).expect("User not found");

            let mut resp = Response::new(Status::Ok)
                .with_cors("http://localhost:3000")
                .with_body(&user.username);

            // Update tokens if there are new ones
            if let Some(tokens) = session.new_tokens {
                resp = resp
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
                    );
            }

            resp
        }
        Err(_) => Response::new(Status::Unauthorized).with_cors("http://localhost:3000"),
    }
}
