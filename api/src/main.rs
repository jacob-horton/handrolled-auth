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
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

static mut USERS: RwLock<Vec<User>> = RwLock::new(Vec::new());

static SIGNING_KEY: &'static str = "secret";

static ACCESS_EXPIRATION: Duration = Duration::from_secs(5 * 60);
static REFRESH_EXPIRATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User<'a> {
    id: &'a str,
    username: &'a str,
    password: &'a str,
    session_version: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    exp: usize,
    iss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshClaims {
    sub: String,
    exp: usize,
    iss: String,
    version: usize,
}

#[derive(Debug, Clone)]
struct Tokens {
    access_token: String,
    refresh_token: String,
}

fn generate_tokens(id: &str, session_version: usize) -> Result<Tokens, ()> {
    let access_claims = AccessClaims {
        sub: id.to_string(),
        exp: (SystemTime::now() + ACCESS_EXPIRATION)
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
        exp: (SystemTime::now() + REFRESH_EXPIRATION)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
        iss: "handrolled-auth-api".to_string(),
        version: session_version,
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

#[derive(Debug, Clone, Deserialize)]
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
            let user = unsafe {
                USERS
                    .read()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .find(|u| u.username == decoded.username)
                    .expect("User not found")
            };

            // TODO: password hashing
            if user.password != decoded.password {
                panic!("Invalid password");
            }

            let tokens = generate_tokens(user.id, user.session_version).unwrap();

            Response {
                version: "HTTP/1.1".to_string(),
                status_code: Status::NoContent,
                headers: vec![
                    // TODO: cookie settings from ben awad video
                    Header {
                        name: "Set-Cookie".to_string(),
                        value: format!(
                            "access_token={}; Max-Age={}; HttpOnly",
                            tokens.access_token,
                            ACCESS_EXPIRATION.as_secs() * 100,
                        ),
                    },
                    Header {
                        name: "Set-Cookie".to_string(),
                        value: format!(
                            "refresh_token={}; Max-Age={}; HttpOnly",
                            tokens.refresh_token,
                            REFRESH_EXPIRATION.as_secs(),
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
        (Method::Post, "/increment-version") => {
            unsafe {
                USERS
                    .write()
                    .unwrap()
                    .iter_mut()
                    .for_each(|u| u.session_version += 1);
            }

            Response {
                version: "HTTP/1.1".to_string(),
                body: None,
                headers: Vec::new(),
                status_code: Status::NoContent,
            }
        }
        (Method::Get, "/session") => {
            let cookies = req
                .headers
                .iter()
                .find(|h| h.name.to_lowercase() == "cookie");

            match cookies {
                Some(cookies) => {
                    let cookies = cookies.value.split("; ");

                    let access_token = cookies
                        .clone()
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
                            let user = unsafe {
                                USERS
                                    .read()
                                    .unwrap()
                                    .clone()
                                    .into_iter()
                                    .find(|u| u.id == t.claims.sub)
                                    .unwrap()
                            };

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
                                    .clone()
                                    .find(|cookie| cookie.starts_with("refresh_token="))
                                    .unwrap()
                                    .split_once("=")
                                    .unwrap()
                                    .1;

                                println!("yipyip");
                                let mut validation = Validation::default();
                                validation.set_issuer(&["handrolled-auth-api"]);

                                // TODO: if expired, log out
                                let claims = decode::<RefreshClaims>(
                                    refresh_token,
                                    &DecodingKey::from_secret(SIGNING_KEY.as_ref()),
                                    &validation,
                                )
                                .unwrap()
                                .claims;

                                // TODO: reauthenticate
                                let user = unsafe {
                                    USERS
                                        .read()
                                        .unwrap()
                                        .clone()
                                        .into_iter()
                                        .find(|u| u.id == claims.sub)
                                        .unwrap()
                                };

                                if claims.version != user.session_version {
                                    panic!("Invalid session version.");
                                }

                                let tokens = generate_tokens(user.id, claims.version).unwrap();

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
                                                ACCESS_EXPIRATION.as_secs() * 100,
                                            ),
                                        },
                                        Header {
                                            name: "Set-Cookie".to_string(),
                                            value: format!(
                                                "refresh_token={}; Max-Age={}; HttpOnly",
                                                tokens.refresh_token,
                                                REFRESH_EXPIRATION.as_secs(),
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
