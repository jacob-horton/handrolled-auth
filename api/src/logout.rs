use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};

pub fn logout(_: Request) -> Response {
    Response::new(Status::NoContent)
        .with_cors("http://localhost:3000".to_string())
        .with_cookie("access_token".to_string(), "".to_string(), 0, true)
        .with_cookie("refresh_token".to_string(), "".to_string(), 0, true)
}
