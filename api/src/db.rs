use std::sync::RwLock;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub session_version: usize,
}

impl User {
    pub fn check_password(&self, password: &str) -> bool {
        let parsed_hash = PasswordHash::new(&self.password_hash).unwrap();
        return Argon2::default()
            .verify_password(password.as_ref(), &parsed_hash)
            .is_ok();
    }
}

pub trait UserDatabase {
    fn get_user_by_id(&self, id: &str) -> Option<User>;
    fn get_user_by_username(&self, username: &str) -> Option<User>;

    fn add_user(&self, user: User);
    fn invalidate_user_sessions(&self, id: &str);
}

pub struct Database {
    users: RwLock<Vec<User>>,
}

impl Database {
    pub fn new() -> Self {
        return Database {
            users: RwLock::new(Vec::new()),
        };
    }
}

impl UserDatabase for Database {
    fn get_user_by_id(&self, id: &str) -> Option<User> {
        let lock = self.users.read().unwrap();
        let user = lock.iter().find(|u| u.id == id);

        // Clone user if they exist
        return user.map(|u| u.clone());
    }

    fn add_user(&self, user: User) {
        let mut lock = self.users.write().unwrap();
        lock.push(user);
    }

    fn invalidate_user_sessions(&self, id: &str) {
        let mut lock = self.users.write().unwrap();
        let user = lock.iter_mut().find(|u| u.id == id);

        if let Some(user) = user {
            user.session_version += 1;
        }
    }

    fn get_user_by_username(&self, username: &str) -> Option<User> {
        let lock = self.users.read().unwrap();
        let user = lock.iter().find(|u| u.username == username);

        // Clone user if they exist
        return user.map(|u| u.clone());
    }
}
