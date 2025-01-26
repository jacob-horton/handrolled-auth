extern crate http_from_scratch;

use http_from_scratch::{
    common::{Header, Method},
    request::Request,
    response::{Response, Status},
};
use jsonwebtoken::{decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

static USERS: &[User] = &[User {
    id: "12345",
    username: "JJ",
    password: "passw0rd",
}];

static SIGNING_KEY: &'static str = "secret";

#[derive(Debug, Serialize, Deserialize)]
struct User<'a> {
    id: &'a str,
    username: &'a str,
    password: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    exp: usize,
    iss: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshClaims {
    sub: String,
    exp: usize,
    iss: String,
    version: usize,
}

#[derive(Debug)]
struct Tokens {
    access_token: String,
    refresh_token: String,
}

fn generate_tokens(id: &str) -> Result<Tokens, ()> {
    let access_claims = AccessClaims {
        sub: id.to_string(),
        // Expire access in 5 minutes
        exp: (SystemTime::now() + Duration::from_secs(5 * 60))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
        iss: "handrolled-auth-api".to_string(),
    };

    let access_token = encode(
        &jsonwebtoken::Header::default(),
        &access_claims,
        &EncodingKey::from_secret(SIGNING_KEY.as_ref()),
    )
    .map_err(|_| ())?;

    let refresh_claims = RefreshClaims {
        sub: id.to_string(),
        // Expire refresh in 30 days
        exp: (SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 30))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
        iss: "handrolled-auth-api".to_string(),
        version: 1,
    };

    let refresh_token = encode(
        &jsonwebtoken::Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(SIGNING_KEY.as_ref()),
    )
    .map_err(|_| ())?;

    Ok(Tokens {
        access_token,
        refresh_token,
    })
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

fn handle_connection(mut stream: TcpStream) {
    let req = Request::from_reader(&mut stream);

    let resp = match (&req.method, req.path.as_str()) {
        // Login
        (Method::Post, "/session") => {
            let decoded: LoginRequest = serde_json::from_str(&req.body.unwrap()).unwrap();

            // TODO: better handle no user
            let user = USERS
                .iter()
                .find(|u| u.username == decoded.username)
                .expect("User not found");

            // TODO: password hashing
            if user.password != decoded.password {
                panic!("Invalid password");
            }

            let tokens = generate_tokens(user.id).unwrap();

            Response {
                version: "HTTP/1.1".to_string(),
                status_code: Status::NoContent,
                headers: vec![
                    // TODO: cookie settings from ben awad video
                    // TODO: don't duplicate time period here and in jwt
                    Header {
                        name: "Set-Cookie".to_string(),
                        value: format!(
                            "access_token={}; Max-Age={}; HttpOnly",
                            tokens.access_token,
                            // 5 minutes
                            5 * 60,
                        ),
                    },
                    Header {
                        name: "Set-Cookie".to_string(),
                        value: format!(
                            "refresh_token={}; Max-Age={}; HttpOnly",
                            tokens.refresh_token,
                            // 1 month
                            30u64 * 24 * 60 * 60,
                        ),
                    },
                    Header {
                        name: "Access-Control-Allow-Origin".to_string(),
                        value: "http://localhost:3000".to_string(),
                    },
                    Header {
                        name: "Access-Control-Allow-Credentials".to_string(),
                        value: "true".to_string(),
                    },
                ],
                body: None,
            }
        }
        (Method::Delete, "/session") => Response {
            version: "HTTP/1.1".to_string(),
            status_code: Status::NoContent,
            headers: vec![
                Header {
                    name: "Set-Cookie".to_string(),
                    value: "access_token=; Max-Age=0; HttpOnly".to_string(),
                },
                Header {
                    name: "Set-Cookie".to_string(),
                    value: "access_token=; Max-Age=0; HttpOnly".to_string(),
                },
                Header {
                    name: "Set-Cookie".to_string(),
                    value: "refresh_token=; Max-Age=0; HttpOnly".to_string(),
                },
                Header {
                    name: "Access-Control-Allow-Origin".to_string(),
                    value: "http://localhost:3000".to_string(),
                },
                Header {
                    name: "Access-Control-Allow-Credentials".to_string(),
                    value: "true".to_string(),
                },
            ],
            body: None,
        },
        (Method::Get, "/session") => {
            let cookies = req
                .headers
                .iter()
                .find(|h| h.name.to_lowercase() == "cookie");

            match cookies {
                Some(cookies) => {
                    let mut cookies = cookies.value.split("; ");

                    let access_token = cookies
                        .find(|cookie| cookie.starts_with("access_token="))
                        .unwrap()
                        .split_once("=")
                        .unwrap()
                        .1;

                    let token = decode::<AccessClaims>(
                        access_token,
                        &DecodingKey::from_secret(SIGNING_KEY.as_ref()),
                        &Validation::default(),
                    );

                    match token {
                        Ok(t) => {
                            let user = USERS.iter().find(|u| u.id == t.claims.sub).unwrap();

                            Response {
                                version: "HTTP/1.1".to_string(),
                                status_code: Status::Ok,
                                headers: vec![
                                    Header {
                                        name: "Access-Control-Allow-Origin".to_string(),
                                        value: "http://localhost:3000".to_string(),
                                    },
                                    Header {
                                        name: "Access-Control-Allow-Credentials".to_string(),
                                        value: "true".to_string(),
                                    },
                                ],
                                body: Some(user.username.to_string()),
                            }
                        }
                        Err(e) => match e.kind() {
                            ErrorKind::ExpiredSignature => {
                                let refresh_token = cookies
                                    .find(|cookie| cookie.starts_with("refresh_token="))
                                    .unwrap()
                                    .split_once("=")
                                    .unwrap()
                                    .1;

                                // TODO: if expired, log out
                                let claims = decode::<AccessClaims>(
                                    refresh_token,
                                    &DecodingKey::from_secret(SIGNING_KEY.as_ref()),
                                    &Validation::default(),
                                )
                                .unwrap()
                                .claims;

                                // TODO: reauthenticate
                                let user = USERS.iter().find(|u| u.id == claims.sub).unwrap();
                                let tokens = generate_tokens(user.id).unwrap();

                                Response {
                                    version: "HTTP/1.1".to_string(),
                                    status_code: Status::Ok,
                                    headers: vec![
                                        Header {
                                            name: "Access-Control-Allow-Origin".to_string(),
                                            value: "http://localhost:3000".to_string(),
                                        },
                                        Header {
                                            name: "Access-Control-Allow-Credentials".to_string(),
                                            value: "true".to_string(),
                                        },
                                        Header {
                                            name: "Set-Cookie".to_string(),
                                            value: format!(
                                                "access_token={}; Max-Age={}; HttpOnly",
                                                tokens.access_token,
                                                // 5 minutes
                                                5 * 60,
                                            ),
                                        },
                                        Header {
                                            name: "Set-Cookie".to_string(),
                                            value: format!(
                                                "refresh_token={}; Max-Age={}; HttpOnly",
                                                tokens.refresh_token,
                                                // 1 month
                                                30u64 * 24 * 60 * 60,
                                            ),
                                        },
                                    ],
                                    body: Some(user.username.to_string()),
                                }
                            }
                            _ => panic!("{e:#?}"),
                        },
                    }
                }
                None => Response {
                    version: "HTTP/1.1".to_string(),
                    status_code: Status::Unauthorized,
                    headers: vec![
                        Header {
                            name: "Access-Control-Allow-Origin".to_string(),
                            value: "http://localhost:3000".to_string(),
                        },
                        Header {
                            name: "Access-Control-Allow-Credentials".to_string(),
                            value: "true".to_string(),
                        },
                    ],
                    body: None,
                },
            }
        }
        (Method::Options, _) => Response {
            version: "HTTP/1.1".to_string(),
            status_code: Status::Ok,
            headers: vec![
                Header {
                    name: "Access-Control-Allow-Origin".to_string(),
                    value: "http://localhost:3000".to_string(),
                },
                Header {
                    name: "Access-Control-Allow-Credentials".to_string(),
                    value: "true".to_string(),
                },
                Header {
                    name: "Access-Control-Allow-Methods".to_string(),
                    value: "GET, POST, PUT, DELETE, OPTIONS".to_string(),
                },
            ],
            body: None,
        },
        _ => Response {
            version: "HTTP/1.1".to_string(),
            status_code: Status::NotFound,
            headers: Vec::new(),
            body: None,
        },
    };

    stream.write_all(resp.to_string().as_bytes()).unwrap();
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}
