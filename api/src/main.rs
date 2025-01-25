extern crate http_from_scratch;

use http_from_scratch::{
    request::Request,
    response::{Response, Status},
};

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};

fn handle_connection(mut stream: TcpStream) {
    let req = Request::from_reader(&mut stream);

    println!("{req:#?}");

    let resp = Response {
        version: "HTTP/1.1".to_string(),
        status_code: Status::Ok,
        headers: HashMap::new(),
        body: req.body,
    };

    println!("{}", resp.to_string());

    stream.write_all(resp.to_string().as_bytes()).unwrap();
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}
