use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
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

fn run_unprivileged_server() {
  println!("Starting unprivileged authentication server on port 8081");

  // bind to a non-privileged port for the authentication server
  let listener = TcpListener::bind("127.0.0.1:8081").expect("Failed to bind to port 8081");

  println!("Authentication server listening on 127.0.0.1:8081");

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
      Err(e) => eprintln!("Error accepting connection: {e}"),
    }
  }
}

fn start_privileged_proxy() {
  println!("Starting privileged proxy on port 8080");

  // bind to privileged port
  let listener = TcpListener::bind("127.0.0.1:8080")
    .expect("Failed to bind socket - ensure you have permission to bind to port 8080");

  println!("Proxy bound to 127.0.0.1:8080, forwarding to 127.0.0.1:8081");

  // handle incoming connections by forwarding to unprivileged server
  for stream in listener.incoming() {
    match stream {
      Ok(client_stream) => {
        std::thread::spawn(move || {
          // connect to the unprivileged authentication server
          match TcpStream::connect("127.0.0.1:8081") {
            Ok(auth_stream) => {
              // spawn threads to forward data in both directions
              let mut client_to_auth = client_stream.try_clone().unwrap();
              let mut auth_to_client = auth_stream.try_clone().unwrap();
              let mut auth_stream_clone = auth_stream;
              let mut client_stream_clone = client_stream;

              let forward_thread = std::thread::spawn(move || {
                let _ = std::io::copy(&mut client_to_auth, &mut auth_stream_clone);
              });

              let _ = std::io::copy(&mut auth_to_client, &mut client_stream_clone);
              let _ = forward_thread.join();
            }
            Err(e) => eprintln!("Failed to connect to authentication server: {e}"),
          }
        });
      }
      Err(e) => eprintln!("Error accepting connection: {e}"),
    }
  }
}

fn drop_privileges_with_sudo() -> Result<(), Box<dyn std::error::Error>> {
  // check if we can use sudo to drop privileges
  let output = Command::new("sudo")
    .arg("-n") // non-interactive
    .arg("-u")
    .arg("nobody") // switch to nobody user (safe, low-privilege user)
    .arg("id")
    .output()?;

  if output.status.success() {
    println!("Privilege dropping available via sudo");
    return Ok(());
  }

  Err("Sudo not available or not configured for privilege dropping".into())
}

fn spawn_unprivileged_server() -> Result<std::process::Child, Box<dyn std::error::Error>> {
  let args: Vec<String> = env::args().collect();

  // try to spawn with reduced privileges using sudo if available
  if drop_privileges_with_sudo().is_ok() {
    println!("Spawning authentication server with dropping privileges (using sudo)");
    return Ok(
      Command::new("sudo")
        .arg("-n")
        .arg("-u")
        .arg("nobody")
        .arg(&args[0])
        .arg("--auth-server")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?,
    );
  }

  // fallback: spawn without privilege dropping (relies on OS security)
  println!("Spawning authentication server without explicit privilege dropping");
  println!("Note: run as root and configure sudo for better privilege separation");

  Ok(
    Command::new(&args[0])
      .arg("--auth-server")
      .stdin(Stdio::null())
      .stdout(Stdio::inherit())
      .stderr(Stdio::inherit())
      .spawn()?,
  )
}

fn main() {
  let args: Vec<String> = env::args().collect();

  // check if we're being run as the auentication server component
  if args.len() > 1 && args[1] == "--auth-server" {
    run_unprivileged_server();
    return;
  }

  println!("Starting privilege-separated authentication server");
  println!("Architecture: tcp proxy (privileged) + auth server (unprivileged)");

  // spawn the unprivileged authentication server as a separate process
  match spawn_unprivileged_server() {
    Ok(mut child) => {
      println!("Spawned authentication server (pid: {})", child.id());

      // give the auth server a moment to start up
      std::thread::sleep(std::time::Duration::from_millis(1000));

      // start the privileged proxy
      start_privileged_proxy();

      // if we reach here, the proxy has stopped, so terminate the auth server
      let _ = child.kill();
      let _ = child.wait();
    }
    Err(e) => {
      eprintln!("Failed to spawn authentication server: {e}");
      std::process::exit(1);
    }
  }
}
