use rand::RngCore;
use std::collections::HashMap;

/// implements xor cipher
fn xor_cipher(input: &[u8], key: &[u8]) -> Vec<u8> {
  input
    .iter()
    .enumerate()
    .map(|(i, &b)| b ^ key[i % key.len()]) // ^ is bitwise XOR
    .collect()
}

/// analyzes byte frequency to demonstrate cyptographic weakness
fn frequency_analysis(data: &[u8]) -> HashMap<u8, usize> {
  let mut freq = HashMap::new();
  for &byte in data {
    *freq.entry(byte).or_insert(0) += 1;
  }
  freq
}

/// returns c1 xor c2 to demonstrate key reuse attack on xor cipher
fn key_reuse_attack(ciphertext1: &[u8], ciphertext2: &[u8]) -> Vec<u8> {
  // if same key used: c1 xor c2 = p1 xor p2
  // this reveals relationship between plaintexts
  ciphertext1
    .iter()
    .zip(ciphertext2.iter())
    .map(|(&a, &b)| a ^ b)
    .collect()
}

fn main() {
  println!("=== XOR cipher demonstration ===\n");

  // basic xor encryption and decryption
  let plain_text = b"attact at dawn! this is a secret message.";
  let key = b"secret";

  println!("Plain text: {}", String::from_utf8_lossy(plain_text));
  println!("Key: {}", String::from_utf8_lossy(key));

  let cipher_text = xor_cipher(plain_text, key);
  println!("Cipher text: {}", hex::encode(&cipher_text));

  let decrypted = xor_cipher(&cipher_text, key);
  println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

  assert_eq!(plain_text, &decrypted[..]);
  println!("✅ encryption/decryption successful.\n");

  // demonstrate vulnerability with short keys
  println!("=== Vulnarability demo: short key with repetitive text ===");
  let repetitive_text = b"abababababababababababababababab";
  let short_key = b"xy";

  let cipher_repetitive = xor_cipher(repetitive_text, short_key);
  println!(
    "Repetitive plain text: {}",
    String::from_utf8_lossy(repetitive_text)
  );
  println!("Cipher text: {:?}", cipher_repetitive);

  // show pattern in ciphertext
  println!("Pattern in cipher text (every 2 bytes should be same):");
  for chunk in cipher_repetitive.chunks(2) {
    print!("{:02x}{:02x} ", chunk[0], chunk.get(1).unwrap_or(&0));
  }
  println!("\n");

  // frequency analysis demonstration
  println!("=== frequency analysis attack ===");
  let long_text = b"the quick brown fox jumps over the lazy dog. \
                    the quick brown fox jumps over the lazy dog. \
                    the quick brown fox jumps over the lazy dog.";

  let cipher_long = xor_cipher(long_text, b"key");

  let plaintext_freq = frequency_analysis(long_text);
  let ciphertext_freq = frequency_analysis(&cipher_long);

  println!("most common bytes in plaintext:");
  let mut pt_sorted: Vec<_> = plaintext_freq.iter().collect();
  pt_sorted.sort_by(|a, b| b.1.cmp(a.1));
  for (byte, count) in pt_sorted.iter().take(5) {
    println!("  '{}' (0x{:02x}): {} times", **byte as char, byte, count);
  }

  println!("most common bytes in ciphertext:");
  let mut ct_sorted: Vec<_> = ciphertext_freq.iter().collect();
  ct_sorted.sort_by(|a, b| b.1.cmp(a.1));
  for (byte, count) in ct_sorted.iter().take(5) {
    println!("  0x{:02x}: {} times", byte, count);
  }

  // demonstrate key reuse attack
  println!("\n=== key reuse attack ===");
  let message1 = b"attack at dawn tomorrow";
  let message2 = b"retreat at midnight now";
  let shared_key = b"secretkey";

  let cipher1 = xor_cipher(message1, shared_key);
  let cipher2 = xor_cipher(message2, shared_key);

  println!("message 1: {}", String::from_utf8_lossy(message1));
  println!("message 2: {}", String::from_utf8_lossy(message2));

  let xor_result1 = key_reuse_attack(message1, message2);
  let xor_result2 = key_reuse_attack(&cipher1, &cipher2);
  println!("c1 ⊕ c2 = p1 ⊕ p2");
  println!(
    "XOR between plain texts: {}",
    String::from_utf8_lossy(&xor_result1)
  );
  println!(
    "XOR between cipher texts: {}",
    String::from_utf8_lossy(&xor_result2)
  );
  println!("this reveals plaintext relationship without knowing the key!\n");

  // demonstrate with secure random key
  println!("=== comparison with secure random key ===");
  let mut secure_key = vec![0u8; plain_text.len()]; // one-time pad
  rand::rng().fill_bytes(&mut secure_key);

  let secure_cipher = xor_cipher(plain_text, &secure_key);
  let secure_freq = frequency_analysis(&secure_cipher);

  println!("secure ciphertext frequency distribution:");
  let mut secure_sorted: Vec<_> = secure_freq.iter().collect();
  secure_sorted.sort_by(|a, b| b.1.cmp(a.1));
  for (byte, count) in secure_sorted.iter().take(5) {
    println!("  0x{:02x}: {} times", byte, count);
  }
}
