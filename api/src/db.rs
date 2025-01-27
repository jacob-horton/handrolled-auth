use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub session_version: usize,
}

// TODO: setup user here
pub static mut USERS: RwLock<Vec<User>> = RwLock::new(Vec::new());
