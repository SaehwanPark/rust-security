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
    match self.add_user("admin", "admin123") {
      Ok(_) => println!("Created initial admin user (username: admin, password: admin123)"),
      Err(e) => eprintln!("Failed to create initial admin user: {e}"),
    }
  }

  fn authenticate(&mut self, username: &str, password: &str) -> AuthResult {
    let user = match self.users.get_mut(username) {
      Some(user) => user,
      None => return AuthResult::UserNotFound,
    };

    if user.is_locked {
      return AuthResult::AccountLocked;
    }

    let argon2 = Argon2::default();
    match PasswordHash::new(&user.password_hash) {
      Ok(parsed_hash) => {
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
          Ok(_) => {
            // reset failed attempts on successful login
            user.failed_attempts = 0;
            self.save_to_file();
            AuthResult::Success
          }
          Err(_) => {
            user.failed_attempts += 1;
            if user.failed_attempts >= 3 {
              user.is_locked = true;
              println!("Account `{username}` locked after 3 failed attempts");
            }
            self.save_to_file();
            AuthResult::InvalidCredentials
          }
        }
      }
      Err(_) => AuthResult::InvalidCredentials,
    }
  }

  fn add_user(&mut self, username: &str, password: &str) -> Result<(), String> {
    if self.users.contains_key(username) {
      return Err("User already exists".to_string());
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .map_err(|e| format!("Failed to hash password: {e}"))?
      .to_string();

    let new_user = UserAccount {
      username: username.to_string(),
      password_hash,
      failed_attempts: 0,
      is_locked: false,
    };

    self.users.insert(username.to_string(), new_user);
    self.save_to_file();
    Ok(())
  }
}

fn handle_client(mut stream: TcpStream, db: Arc<Mutex<UserDatabase>>) {
  let peer_addr = stream
    .peer_addr()
    .unwrap_or_else(|_| "unknown".parse().unwrap());
  println!("New connection from: {peer_addr}");

  // send welcome message
  let _ = stream.write_all(b"=== Authentication Server ===\n");
  let _ = stream.write_all(b"username: ");

  // read username
  let mut buffer = [0; 256];
  let username = match stream.read(&mut buffer) {
    Ok(n) if n > 0 => String::from_utf8_lossy(&buffer[0..n]).trim().to_string(),
    _ => {
      let _ = stream.write_all(b"Error: Failed to read username\n");
      return;
    }
  };

  if username.is_empty() {
    let _ = stream.write_all(b"Error: username cannot be empty\n");
    return;
  }

  // prompt for password
  let _ = stream.write_all(b"password: ");

  // read password
  buffer.fill(0);
  let password = match stream.read(&mut buffer) {
    Ok(n) if n > 0 => String::from_utf8_lossy(&buffer[0..n]).trim().to_string(),
    _ => {
      let _ = stream.write_all(b"Error: Failed to read password\n");
      return;
    }
  };

  // authenticate user
  let auth_result = {
    let mut db = db.lock().unwrap();
    db.authenticate(&username, &password)
  };

  match auth_result {
    AuthResult::Success => {
      let _ = stream.write_all(b"Access granted\n");
      println!("Successful login for user: {username}");
    }
    AuthResult::InvalidCredentials => {
      let _ = stream.write_all(b"Access denied: invalid credentials\n");
      println!("Failed login attemp for user: {username}");
    }
    AuthResult::AccountLocked => {
      let _ = stream.write_all(b"Access denied: account locked\n");
      println!("Login attempt for non-existent user: {username}");
    }
    AuthResult::UserNotFound => {
      let _ = stream.write_all(b"Access denied: user not found\n");
      println!("Login attempt for non-existent user: {username}");
    }
  }

  // close connection after authentication attemp
  let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn run_child_process(listener: TcpListener) {
  // drop privileges -- switch to unprivileged user (uid 1000)
  if let Err(e) = setuid(Uid::from_raw(1000)) {
    eprintln!("Failed to drop privileges: {e}");
    std::process::exit(1);
  }

  println!("Child process running as unprivileged user (uid 1000)");

  // initialize user database
  let db = Arc::new(Mutex::new(UserDatabase::new("users.json")));

  // handle incoming connections
  for stream in listener.incoming() {
    match stream {
      Ok(stream) => {
        let db_clone = Arc::clone(&db);
        std::thread::spawn(move || {
          handle_client(stream, db_clone);
        });
      }
      Err(e) => {
        eprintln!("Error accepting connection: {e}");
      }
    }
  }
}

fn main() {
  println!("Starting privilege-separated authentication server");

  // bind socket with elevated privileges
  let listener = TcpListener::bind("127.0.0.1:8080")
    .expect("Failed to bind socket - ensure you have permission to bind to port 8080");

  println!("Server bound to 127.0.0.1:8080");

  // fork process
  match unsafe { fork() } {
    Ok(ForkResult::Parent { child, .. }) => {
      println!("Privileged parent process created child {child}");
      println!("Parent process exiting after socket handoff");
      // parent exits immediately after creating child
    }
    Ok(ForkResult::Child) => {
      // child process handles authentication
      run_child_process(listener);
    }
    Err(e) => {
      eprintln!("Fork failed: {e}");
      std::process::exit(1);
    }
  }
}
