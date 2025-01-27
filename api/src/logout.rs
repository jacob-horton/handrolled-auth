use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};

pub fn logout(_: Request) -> Response {
    Response::new(Status::NoContent)
        .with_cors("http://localhost:3000")
        .with_cookie("access_token", "", 0, true)
        .with_cookie("refresh_token", "", 0, true)
}
