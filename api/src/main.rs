extern crate http_from_scratch;

mod db;
mod login;
mod logout;
mod session_info;
mod tokens;

use db::{User, USERS};
use http_from_scratch::{
    common::Method,
    request::Request,
    response::{Response, Status},
};
use login::login;
use logout::logout;
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

            Response::new(Status::NoContent).with_cors("http://localhost:3000".to_string())
        }
        (Method::Options, _) => Response::new(Status::Ok)
            .with_cors("http://localhost:3000".to_string())
            .with_header(
                "Access-Control-Allow-Methods".to_string(),
                "GET, POST, PUT, DELETE, OPTIONS".to_string(),
            ),
        _ => Response::new(Status::NotFound).with_cors("http://localhost:3000".to_string()),
    };

    stream.write_all(resp.to_string().as_bytes()).unwrap();
}

fn main() {
    unsafe {
        USERS.write().unwrap().push(User {
            id: "12345",
            username: "JJ",
            password: "passw0rd",
            session_version: 1,
        });
    }

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}
