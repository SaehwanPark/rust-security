use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;

fn main() {
  let password = "MySecurePassword123";

  // Generate random salt
  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();

  // Hash password
  let password_hash = argon2
    .hash_password(password.as_bytes(), &salt)
    .unwrap()
    .to_string();
  println!("Hashed password: {}", password_hash);

  // Verify
  let parsed_hash = PasswordHash::new(&password_hash).unwrap();
  match argon2.verify_password(password.as_bytes(), &parsed_hash) {
    Ok(_) => println!("Password is valid!"),
    Err(_) => println!("Invalid password!"),
  }
}
