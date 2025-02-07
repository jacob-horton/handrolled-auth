use http_from_scratch::{
    request::Request,
    response::{Response, Status},
    router::Params,
};

use crate::db::UserDatabase;

pub fn invalidate_session(_: Request, params: &Params, db: &&dyn UserDatabase) -> Response {
    db.invalidate_user_sessions(params.get("id").unwrap());
    Response::new(Status::NoContent).with_cors("http://localhost:3000")
}
