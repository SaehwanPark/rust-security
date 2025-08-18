//! RSA keygen + OAEP encrypt/decrypt demo
//! Usage: `cargo run --example rsa`

use anyhow::Result;
use rand::thread_rng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

fn main() -> Result<()> {
  // 1) Generate a 2048-bit keypair
  let mut rng = thread_rng();
  let bits = 2048;
  let private_key = RsaPrivateKey::new(&mut rng, bits)?;
  let public_key = RsaPublicKey::from(&private_key);

  // 2) Encrypt the same plaintext twice with OAEP(SHA-256)
  let plaintext = b"Public-key crypto in Rust: hello, OAEP!";

  let ct1 = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), plaintext)?;
  let ct2 = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), plaintext)?;

  // 3) Decrypt
  let pt1 = private_key.decrypt(Oaep::new::<Sha256>(), &ct1)?;
  let pt2 = private_key.decrypt(Oaep::new::<Sha256>(), &ct2)?;

  // 4) Report
  println!("modulus bits: {}", bits);
  println!("ciphertext len (bytes): {}", ct1.len()); // equals modulus size in bytes (~256)
  println!("decrypted #1: {}", String::from_utf8_lossy(&pt1));
  println!("decrypted #2: {}", String::from_utf8_lossy(&pt2));
  println!(
    "OAEP randomization yields different ciphertexts: {}",
    if ct1 != ct2 { "YES" } else { "NO" }
  );

  Ok(())
}
