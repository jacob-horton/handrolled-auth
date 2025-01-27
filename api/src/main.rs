extern crate http_from_scratch;

mod auth;
mod db;
mod login;
mod logout;
mod session_info;

use argon2::Argon2;
use db::{User, USERS};
use http_from_scratch::{
    common::Method,
    request::Request,
    response::{Response, Status},
};
use login::login;
use logout::logout;
use password_hash::{PasswordHasher, SaltString};
use rand::rngs::OsRng;
use session_info::session_info;

use std::{
    io::Write,
    net::{TcpListener, TcpStream},
};

fn handle_connection(mut stream: TcpStream) {
    let req = Request::from_reader(&mut stream);

    let resp = match (&req.method, req.path.as_str()) {
        (Method::Post, "/session") => login(req),
        (Method::Delete, "/session") => logout(req),
        (Method::Get, "/session") => session_info(req),
        (Method::Post, "/increment-version") => {
            unsafe {
                USERS
                    .write()
                    .unwrap()
                    .iter_mut()
                    .for_each(|u| u.session_version += 1);
            }

            Response::new(Status::NoContent).with_cors("http://localhost:3000")
        }
        (Method::Options, _) => Response::new(Status::Ok)
            .with_cors("http://localhost:3000")
            .with_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS",
            ),
        _ => Response::new(Status::NotFound).with_cors("http://localhost:3000"),
    };

    stream.write_all(resp.to_string().as_bytes()).unwrap();
}

fn setup_user() {
    let salt = SaltString::generate(OsRng::default());
    let hash = Argon2::default()
        .hash_password("passw0rd".as_bytes(), &salt)
        .unwrap();

    unsafe {
        USERS.write().unwrap().push(User {
            id: "12345".to_string(),
            username: "JJ".to_string(),
            password_hash: hash.to_string(),
            session_version: 1,
        });
    }
}

fn main() {
    setup_user();

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}
