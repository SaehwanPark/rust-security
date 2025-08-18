// secure hmac-sha256 implementation with nonce/replay protection
// and constant-time verification using subtle crate

use rand::RngCore;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

// import our hmac implementation
#[path = "hmac_sha256_from_scratch.rs"]
mod hmac_impl;

use hmac_impl::{from_hex, hmac_sha256, to_hex};

const NONCE_SIZE: usize = 16;
const MAX_CLOCK_SKEW: u64 = 300; // 5 minutes in seconds
const REPLAY_WINDOW: u64 = 3600; // 1 hour in seconds

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecureKey {
  #[zeroize(skip)]
  key_id: String,
  key_data: Vec<u8>,
}

impl SecureKey {
  pub fn new(key_id: String, key_data: Vec<u8>) -> Self {
    Self { key_id, key_data }
  }

  pub fn from_hex(key_id: String, hex_key: &str) -> Result<Self, String> {
    let key_data = from_hex(hex_key)?;
    Ok(Self::new(key_id, key_data))
  }

  pub fn generate_random(key_id: String) -> Self {
    let mut key_data = vec![0u8; 32]; // 256-bit key
    rand::thread_rng().fill_bytes(&mut key_data);
    Self::new(key_id, key_data)
  }

  pub fn key_id(&self) -> &str {
    &self.key_id
  }

  pub fn key_data(&self) -> &[u8] {
    &self.key_data
  }
}

#[derive(Debug, Clone)]
pub struct Nonce {
  value: [u8; NONCE_SIZE],
  timestamp: u64,
}

impl Nonce {
  pub fn generate() -> Self {
    let mut value = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut value);

    let timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs();

    Self { value, timestamp }
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
    if data.len() < NONCE_SIZE + 8 {
      return Err("nonce data too short".to_string());
    }

    let mut value = [0u8; NONCE_SIZE];
    value.copy_from_slice(&data[..NONCE_SIZE]);

    let timestamp = u64::from_be_bytes([
      data[NONCE_SIZE],
      data[NONCE_SIZE + 1],
      data[NONCE_SIZE + 2],
      data[NONCE_SIZE + 3],
      data[NONCE_SIZE + 4],
      data[NONCE_SIZE + 5],
      data[NONCE_SIZE + 6],
      data[NONCE_SIZE + 7],
    ]);

    Ok(Self { value, timestamp })
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut result = Vec::with_capacity(NONCE_SIZE + 8);
    result.extend_from_slice(&self.value);
    result.extend_from_slice(&self.timestamp.to_be_bytes());
    result
  }

  pub fn is_valid(&self, max_age_seconds: u64) -> bool {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs();

    // check for future timestamps (allowing some clock skew)
    if self.timestamp > now + MAX_CLOCK_SKEW {
      return false;
    }

    // check for expired timestamps
    if now - self.timestamp > max_age_seconds {
      return false;
    }

    true
  }

  pub fn timestamp(&self) -> u64 {
    self.timestamp
  }

  pub fn as_hex(&self) -> String {
    to_hex(&self.to_bytes())
  }
}

// nonce used for constant-time comparison
impl ConstantTimeEq for Nonce {
  fn ct_eq(&self, other: &Self) -> subtle::Choice {
    self.value.ct_eq(&other.value) & self.timestamp.ct_eq(&other.timestamp)
  }
}

#[derive(Debug)]
pub struct NonceTracker {
  used_nonces: HashMap<String, u64>, // nonce_hex -> timestamp
  cleanup_interval: Duration,
  last_cleanup: SystemTime,
}

impl NonceTracker {
  pub fn new() -> Self {
    Self {
      used_nonces: HashMap::new(),
      cleanup_interval: Duration::from_secs(300), // cleanup every 5 minutes
      last_cleanup: SystemTime::now(),
    }
  }

  pub fn is_nonce_used(&mut self, nonce: &Nonce) -> bool {
    self.cleanup_expired_nonces();

    let nonce_hex = nonce.as_hex();
    if self.used_nonces.contains_key(&nonce_hex) {
      return true;
    }

    // record this nonce as used
    self.used_nonces.insert(nonce_hex, nonce.timestamp());
    false
  }

  fn cleanup_expired_nonces(&mut self) {
    let now = SystemTime::now();
    if now.duration_since(self.last_cleanup).unwrap() < self.cleanup_interval {
      return;
    }

    let current_timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

    self
      .used_nonces
      .retain(|_, &mut timestamp| current_timestamp - timestamp <= REPLAY_WINDOW);

    self.last_cleanup = now;
  }

  pub fn nonce_count(&self) -> usize {
    self.used_nonces.len()
  }
}

#[derive(Debug)]
pub struct SecureHmac {
  key: SecureKey,
  nonce_tracker: NonceTracker,
}

impl SecureHmac {
  pub fn new(key: SecureKey) -> Self {
    Self {
      key,
      nonce_tracker: NonceTracker::new(),
    }
  }

  pub fn compute_with_nonce(&self, message: &[u8], nonce: &Nonce) -> Vec<u8> {
    // construct the complete message: nonce || message
    let nonce_bytes = nonce.to_bytes();
    let mut complete_message = Vec::with_capacity(nonce_bytes.len() + message.len());
    complete_message.extend_from_slice(&nonce_bytes);
    complete_message.extend_from_slice(message);

    hmac_sha256(self.key.key_data(), &complete_message).to_vec()
  }

  pub fn compute(&self, message: &[u8]) -> (Nonce, Vec<u8>) {
    let nonce = Nonce::generate();
    let hmac = self.compute_with_nonce(message, &nonce);
    (nonce, hmac)
  }

  pub fn verify_with_nonce(
    &mut self,
    message: &[u8],
    nonce: &Nonce,
    expected_hmac: &[u8],
  ) -> Result<bool, String> {
    // check nonce validity
    if !nonce.is_valid(REPLAY_WINDOW) {
      return Err("nonce is expired or invalid".to_string());
    }

    // check for replay attack
    if self.nonce_tracker.is_nonce_used(nonce) {
      return Err("nonce has already been used (replay attack detected)".to_string());
    }

    // compute expected hmac
    let computed_hmac = self.compute_with_nonce(message, nonce);

    // constant-time comparison to prevent timing attacks
    Ok(computed_hmac.ct_eq(expected_hmac).into())
  }

  pub fn verify(
    &mut self,
    message: &[u8],
    nonce_hex: &str,
    expected_hmac_hex: &str,
  ) -> Result<bool, String> {
    let nonce_bytes = from_hex(nonce_hex)?;
    let nonce = Nonce::from_bytes(&nonce_bytes)?;
    let expected_hmac = from_hex(expected_hmac_hex)?;

    self.verify_with_nonce(message, &nonce, &expected_hmac)
  }

  pub fn key_id(&self) -> &str {
    self.key.key_id()
  }

  pub fn nonce_count(&self) -> usize {
    self.nonce_tracker.nonce_count()
  }
}

#[derive(Debug)]
pub struct SecureMessage {
  pub key_id: String,
  pub nonce: Nonce,
  pub message: Vec<u8>,
  pub hmac: Vec<u8>,
}

impl SecureMessage {
  pub fn new(secure_hmac: &SecureHmac, message: Vec<u8>) -> Self {
    let (nonce, hmac) = secure_hmac.compute(&message);

    Self {
      key_id: secure_hmac.key_id().to_string(),
      nonce,
      message,
      hmac,
    }
  }

  pub fn verify(&self, secure_hmac: &mut SecureHmac) -> Result<bool, String> {
    if self.key_id != secure_hmac.key_id() {
      return Err("key id mismatch".to_string());
    }

    secure_hmac.verify_with_nonce(&self.message, &self.nonce, &self.hmac)
  }

  pub fn to_wire_format(&self) -> String {
    format!(
      "{}:{}:{}:{}",
      self.key_id,
      self.nonce.as_hex(),
      to_hex(&self.message),
      to_hex(&self.hmac)
    )
  }

  pub fn from_wire_format(wire_data: &str) -> Result<Self, String> {
    let parts: Vec<&str> = wire_data.split(':').collect();
    if parts.len() != 4 {
      return Err("invalid wire format".to_string());
    }

    let key_id = parts[0].to_string();
    let nonce_bytes = from_hex(parts[1])?;
    let nonce = Nonce::from_bytes(&nonce_bytes)?;
    let message = from_hex(parts[2])?;
    let hmac = from_hex(parts[3])?;

    Ok(Self {
      key_id,
      nonce,
      message,
      hmac,
    })
  }
}

// constant-time hex comparison utility
pub fn constant_time_hex_eq(a: &str, b: &str) -> bool {
  if a.len() != b.len() {
    return false;
  }

  let a_bytes = a.as_bytes();
  let b_bytes = b.as_bytes();

  a_bytes.ct_eq(b_bytes).into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("Secure HMAC-SHA256 with Nonce and Replay Protection");
  println!("===================================================");

  // create a secure key
  let key = SecureKey::generate_random("app_key_001".to_string());
  println!(
    "Generated key: {} (id: {})",
    to_hex(key.key_data()),
    key.key_id()
  );

  // create secure hmac instance
  let mut secure_hmac = SecureHmac::new(key);

  // create a secure message
  let message = b"Hello, secure world!";
  let secure_msg = SecureMessage::new(&secure_hmac, message.to_vec());

  println!("\nSecure Message:");
  println!("Key ID: {}", secure_msg.key_id);
  println!("Nonce: {}", secure_msg.nonce.as_hex());
  println!(
    "Message: {:?}",
    std::str::from_utf8(&secure_msg.message).unwrap()
  );
  println!("HMAC: {}", to_hex(&secure_msg.hmac));

  // wire format
  let wire_format = secure_msg.to_wire_format();
  println!("\nWire format: {}", wire_format);

  // verify the message
  match secure_msg.verify(&mut secure_hmac) {
    Ok(true) => println!("✅ Message verification: PASS"),
    Ok(false) => println!("❌ Message verification: FAIL"),
    Err(e) => println!("❌ Verification error: {}", e),
  }

  // test replay attack detection
  println!("\nReplay Attack Test:");
  println!("==================");

  // try to verify the same message again (should fail due to nonce reuse)
  let parsed_msg = SecureMessage::from_wire_format(&wire_format)?;
  match parsed_msg.verify(&mut secure_hmac) {
    Ok(true) => println!("❌ Replay attack NOT detected (security vulnerability!)"),
    Ok(false) => println!("❌ Message verification failed"),
    Err(e) => println!("✅ Replay attack detected: {}", e),
  }

  // test with tampered message
  println!("\nTampering Test:");
  println!("===============");

  let mut tampered_wire = wire_format.clone();
  // change one character in the message part
  let parts: Vec<&str> = tampered_wire.split(':').collect();
  let mut tampered_msg_hex = parts[2].to_string();
  tampered_msg_hex.push_str("41"); // append 'A'
  tampered_wire = format!(
    "{}:{}:{}:{}",
    parts[0], parts[1], tampered_msg_hex, parts[3]
  );

  let tampered_msg = SecureMessage::from_wire_format(&tampered_wire)?;
  match tampered_msg.verify(&mut secure_hmac) {
    Ok(true) => println!("❌ Tampered message verified (security vulnerability!)"),
    Ok(false) => println!("✅ Tampered message rejected"),
    Err(e) => println!("✅ Tampered message error: {}", e),
  }

  // benchmark constant-time comparison
  println!("\nConstant-Time Comparison Benchmark:");
  println!("===================================");

  let hmac1 = to_hex(&hmac_sha256(b"key1", b"message1"));
  let hmac2 = to_hex(&hmac_sha256(b"key2", b"message2"));

  use std::time::Instant;

  let iterations = 1_000_000;

  // timing attack vulnerable comparison
  let start = Instant::now();
  for _ in 0..iterations {
    let _ = hmac1 == hmac2; // early termination possible
  }
  let vulnerable_time = start.elapsed();

  // constant-time comparison
  let start = Instant::now();
  for _ in 0..iterations {
    let _ = constant_time_hex_eq(&hmac1, &hmac2);
  }
  let secure_time = start.elapsed();

  println!(
    "vulnerable comparison: {:.2}μs per operation",
    vulnerable_time.as_nanos() as f64 / iterations as f64 / 1000.0
  );
  println!(
    "constant-time comparison: {:.2}μs per operation",
    secure_time.as_nanos() as f64 / iterations as f64 / 1000.0
  );

  // nonce tracker stats
  println!("\nNonce Tracker Stats:");
  println!("====================");
  println!("Tracked nonces: {}", secure_hmac.nonce_count());

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::thread;
  use std::time::Duration;

  #[test]
  fn test_nonce_generation() {
    let nonce1 = Nonce::generate();
    let nonce2 = Nonce::generate();

    // nonces should be different
    assert_ne!(nonce1.value, nonce2.value);
    assert!(nonce1.is_valid(3600));
    assert!(nonce2.is_valid(3600));
  }

  #[test]
  fn test_nonce_serialization() {
    let nonce = Nonce::generate();
    let bytes = nonce.to_bytes();
    let restored = Nonce::from_bytes(&bytes).unwrap();

    assert_eq!(nonce.value, restored.value);
    assert_eq!(nonce.timestamp, restored.timestamp);
  }

  #[test]
  fn test_nonce_validation() {
    let mut nonce = Nonce::generate();
    assert!(nonce.is_valid(3600));

    // test future timestamp
    nonce.timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs()
      + 1000;
    assert!(!nonce.is_valid(3600));

    // test expired timestamp
    nonce.timestamp = 100; // very old timestamp
    assert!(!nonce.is_valid(3600));
  }

  #[test]
  fn test_replay_protection() {
    let key = SecureKey::generate_random("test_key".to_string());
    let mut secure_hmac = SecureHmac::new(key);

    let message = b"test message";
    let nonce = Nonce::generate();
    let hmac = secure_hmac.compute_with_nonce(message, &nonce);

    // first verification should succeed
    assert!(
      secure_hmac
        .verify_with_nonce(message, &nonce, &hmac)
        .unwrap()
    );

    // second verification with same nonce should fail
    assert!(
      secure_hmac
        .verify_with_nonce(message, &nonce, &hmac)
        .is_err()
    );
  }

  #[test]
  fn test_secure_message() {
    let key = SecureKey::generate_random("test_key".to_string());
    let mut secure_hmac = SecureHmac::new(key);

    let message = b"test message".to_vec();
    let secure_msg = SecureMessage::new(&secure_hmac, message);

    // verification should succeed
    assert!(secure_msg.verify(&mut secure_hmac).unwrap());

    // wire format round trip
    let wire = secure_msg.to_wire_format();
    let restored = SecureMessage::from_wire_format(&wire).unwrap();

    assert_eq!(secure_msg.key_id, restored.key_id);
    assert_eq!(secure_msg.message, restored.message);
    assert_eq!(secure_msg.hmac, restored.hmac);
  }

  #[test]
  fn test_constant_time_comparison() {
    let a = "deadbeef";
    let b = "deadbeef";
    let c = "deadbeee";

    assert!(constant_time_hex_eq(a, b));
    assert!(!constant_time_hex_eq(a, c));
    assert!(!constant_time_hex_eq(a, "dead")); // different lengths
  }
}
