extern crate http_from_scratch;

mod auth;
mod db;
mod login;
mod logout;
mod session_info;

use argon2::Argon2;
use db::{Database, User, UserDatabase};
use http_from_scratch::{
    common::Method,
    request::Request,
    response::{Response, Status},
    router::{Params, Router},
};
use login::login;
use logout::logout;
use password_hash::{PasswordHasher, SaltString};
use rand::rngs::OsRng;
use session_info::session_info;

use std::{io::Write, net::TcpListener};

fn invalidate_session(_: Request, params: &Params, db: &&dyn UserDatabase) -> Response {
    db.invalidate_user_sessions(params.get("id").unwrap());
    Response::new(Status::NoContent).with_cors("http://localhost:3000")
}

fn options(_: Request, _: &Params, _: &&dyn UserDatabase) -> Response {
    Response::new(Status::Ok)
        .with_cors("http://localhost:3000")
        .with_header(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
}

fn setup_user(db: &dyn UserDatabase) {
    let salt = SaltString::generate(OsRng);
    let hash = Argon2::default()
        .hash_password("passw0rd".as_bytes(), &salt)
        .unwrap();

    db.add_user(User {
        id: "12345".to_string(),
        username: "JJ".to_string(),
        password_hash: hash.to_string(),
        session_version: 1,
    });
}

fn main() {
    let db = Database::new();
    setup_user(&db);

    let mut router = Router::<&dyn UserDatabase>::new(&db);
    router.add(Method::Post, "/session", login);
    router.add(Method::Delete, "/session", logout);
    router.add(Method::Get, "/session", session_info);
    router.add(Method::Delete, "/user/:id/session", invalidate_session);
    router.add(Method::Options, "*", options);

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let req = Request::from_reader(&mut stream);

        let resp = router
            .handle(req)
            .unwrap_or(Response::new(Status::NotFound).with_cors("http://localhost:3000"));

        stream.write_all(resp.to_string().as_bytes()).unwrap();
    }
}
