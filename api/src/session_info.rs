use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};

use crate::{
    db::USERS,
    tokens::{validate_session, ACCESS_EXPIRATION, REFRESH_EXPIRATION},
};

pub fn session_info(req: Request) -> Response {
    let result = validate_session(&req.headers);
    match result {
        Ok(session) => {
            let user = unsafe {
                USERS
                    .read()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .find(|u| u.id == session.user_id)
                    .unwrap()
            };

            let mut resp = Response::new(Status::Ok)
                .with_cors("http://localhost:3000".to_string())
                .with_body(user.username.to_string());

            // Update tokens if there are new ones
            if let Some(tokens) = session.new_tokens {
                resp = resp
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
                    );
            }

            resp
        }
        Err(_) => {
            Response::new(Status::Unauthorized).with_cors("http://localhost:3000".to_string())
        }
    }
}
