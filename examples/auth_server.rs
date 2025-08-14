use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use nix::unistd::{ForkResult, Uid, fork, setuid};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

// user account data structure
#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserAccount {
  username: String,
  password_hash: String,
  failed_attempts: u32,
  is_locked: bool,
}

// authentication result
#[derive(Debug)]
enum AuthResult {
  Success,
  InvalidCredentials,
  AccountLocked,
  UserNotFound,
}

// user database manager
struct UserDatabase {
  users: HashMap<String, UserAccount>,
  file_path: String,
}

impl UserDatabase {
  fn new(file_path: &str) -> Self {
    let mut db = UserDatabase {
      users: HashMap::new(),
      file_path: file_path.to_string(),
    };
    db.load_from_file();
    db
  }

  fn load_from_file(&mut self) {
    if Path::new(&self.file_path).exists() {
      match File::open(&self.file_path) {
        Ok(file) => {
          let reader = BufReader::new(file);
          for line in reader.lines() {
            if let Ok(line_content) = line {
              if let Ok(user) = serde_json::from_str::<UserAccount>(&line_content) {
                self.users.insert(user.username.clone(), user);
              }
            }
          }
        }
        Err(e) => eprintln!("Warning: could not load user database: {e}"),
      }
    } else {
      // create initial admin user if file doesn't exist
      self.create_initial_admin();
    }
  }

  fn save_to_file(&self) {
    match OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(&self.file_path)
    {
      Ok(file) => {
        let mut writer = BufWriter::new(file);
        for user in self.users.values() {
          if let Ok(json) = serde_json::to_string(user) {
            let _ = writeln!(writer, "{json}");
          }
        }
        let _ = writer.flush();
      }
      Err(e) => eprintln!("Error: could not save user database: {e}"),
    }
  }

  fn create_initial_admin(&mut self) {
    let password = "admin123";
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .unwrap()
      .to_string();

    let admin_user = UserAccount {
      username: "admin".to_string(),
      password_hash,
      failed_attempts: 0,
      is_locked: false,
    };

    self.users.insert("admin".to_string(), admin_user);
    self.save_to_file();
    println!("Created initial admin user (username: admin, password: admin123)");
  }

  fn authenticate(&mut self, username: &str, password: &str) -> AuthResult {
    todo!()
  }

  fn add_user(&mut self, username: &str, password: &str) -> Result<(), String> {
    todo!()
  }

  fn handle_client(mut stream: TcpStream, db: Arc<Mutex<UserDatabase>>) {
    todo!()
  }

  fn run_child_process(listener: TcpListener) {
    todo!()
  }
}

fn main() {}
