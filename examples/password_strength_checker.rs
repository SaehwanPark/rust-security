use std::io::{self, Write};

fn is_common_password(pw: &str) -> bool {
  let list = include_str!("common_passwords.txt");
  list.lines().any(|line| line.trim() == pw)
}

/// Checks password strengths and returns score
/// Scores are added when the given passwrod satisfies:
/// 1. Minimum length = 12
/// 2. Containing uppercase
/// 3. Containing lowercase
/// 4. Containing digits
/// 5. Containing symbols
///
/// Also, if the password is common, returns 0 always
///
/// Total score ranges between 0 and 5
fn evaluate_password(pw: &str) -> u8 {
  let mut score = 0;
  let mut pw_chars = pw.chars();

  if is_common_password(pw) {
    println!("⚠️ This is a common password — very weak!");
    return score; // 0
  }

  if pw.len() >= 12 {
    // length check
    score += 1;
  }
  if pw_chars.any(|c| c.is_uppercase()) {
    score += 1;
  }
  if pw_chars.any(|c| c.is_lowercase()) {
    score += 1;
  }
  if pw_chars.any(|c| c.is_ascii_digit()) {
    score += 1;
  }
  if pw_chars.any(|c| !c.is_alphanumeric()) {
    score += 1;
  }
  score
}

fn main() {
  print!("Enter password: ");
  io::stdout().flush().unwrap();

  let mut password = String::new();
  io::stdin()
    .read_line(&mut password)
    .expect("Failed to read input");
  let password = password.trim(); // remove trailing newline

  let score = evaluate_password(password);
  println!("Password score: {score}/5");

  // feedback
  match score {
    5 => println!("✅ Very strong"),
    4 => println!("🟢 Strong"),
    3 => println!("🟡 Moderate"),
    _ => println!("🔴 Weak"),
  }
}
