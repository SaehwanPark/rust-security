use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn test_authentication(username: &str, password: &str) -> Result<String, std::io::Error> {
  let mut stream = TcpStream::connect("127.0.0.1:8080")?;

  // read welcome message
  let mut buffer = [0; 1024];
  let _ = stream.read(&mut buffer)?;
  let welcome = String::from_utf8_lossy(&buffer);
  print!("{}", welcome.trim_matches('\0'));

  // send username
  stream.write_all(username.as_bytes())?;
  stream.write_all(b"\n")?;

  // small delay to ensure server processes username
  thread::sleep(Duration::from_millis(100));

  // read password prompt
  buffer.fill(0);
  let _ = stream.read(&mut buffer)?;
  let prompt = String::from_utf8_lossy(&buffer);
  print!("{}", prompt.trim_matches('\0'));

  // send password
  stream.write_all(password.as_bytes())?;
  stream.write_all(b"\n")?;

  // read authentication result
  buffer.fill(0);
  let n = stream.read(&mut buffer)?;
  let result = String::from_utf8_lossy(&buffer[0..n]);

  Ok(result.to_string())
}

fn main() {
  println!("=== authentication server test client ===\n");

  // test cases
  let test_cases = vec![
    ("admin", "admin123", "valid admin credentials"),
    ("admin", "wrongpass", "invalid admin password"),
    ("admin", "wrongpass2", "second failed attempt"),
    (
      "admin",
      "wrongpass3",
      "third failed attempt (should lock account)",
    ),
    ("admin", "admin123", "correct password for locked account"),
    ("nonexistent", "anypass", "non-existent user"),
  ];

  for (i, (username, password, description)) in test_cases.iter().enumerate() {
    println!("test {}: {description}", i + 1);
    println!("trying username='{username}', password='{password}'");

    match test_authentication(username, password) {
      Ok(result) => {
        println!("result: {}", result.trim());
      }
      Err(e) => {
        println!("connection error: {e}");
      }
    }

    println!("{}", "-".repeat(50));

    // small delay between tests
    thread::sleep(Duration::from_millis(500));
  }

  println!("test completed. check server logs for detailed information.");
}
