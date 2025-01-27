use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User<'a> {
    pub id: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub session_version: usize,
}

pub static mut USERS: RwLock<Vec<User>> = RwLock::new(Vec::new());
