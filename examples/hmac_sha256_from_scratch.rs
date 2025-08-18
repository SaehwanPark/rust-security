/// hmac-sha256 implementation from first principles
/// follows RFC 2104 (HMAC) and FIPS 180-4 (SHA-256)
use std::fmt;

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_DIGEST_SIZE: usize = 32;

// sha-256 constants from FIPS 180-4
const K: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone)]
pub struct Sha256 {
  state: [u32; 8],
  buffer: [u8; SHA256_BLOCK_SIZE],
  buffer_len: usize,
  total_len: u64,
}

impl Sha256 {
  pub fn new() -> Self {
    Self {
      // initial hash values from FIPS 180-4
      state: [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
      ],
      buffer: [0; SHA256_BLOCK_SIZE],
      buffer_len: 0,
      total_len: 0,
    }
  }

  pub fn update(&mut self, data: &[u8]) {
    let mut data_pos = 0;
    let data_len = data.len();

    self.total_len += data_len as u64;

    // process any remaining data in buffer first
    if self.buffer_len > 0 {
      let buffer_space = SHA256_BLOCK_SIZE - self.buffer_len;
      let copy_len = std::cmp::min(buffer_space, data_len);

      self.buffer[self.buffer_len..self.buffer_len + copy_len].copy_from_slice(&data[..copy_len]);
      self.buffer_len += copy_len;
      data_pos += copy_len;

      if self.buffer_len == SHA256_BLOCK_SIZE {
        let block = self.buffer;
        self.process_block(&block);
        self.buffer_len = 0;
      }
    }

    // process complete blocks
    while data_pos + SHA256_BLOCK_SIZE <= data_len {
      let block = &data[data_pos..data_pos + SHA256_BLOCK_SIZE];
      self.process_block(block);
      data_pos += SHA256_BLOCK_SIZE;
    }

    // store remaining data in buffer
    if data_pos < data_len {
      let remaining = data_len - data_pos;
      self.buffer[..remaining].copy_from_slice(&data[data_pos..]);
      self.buffer_len = remaining;
    }
  }

  pub fn finalize(&mut self) -> [u8; SHA256_DIGEST_SIZE] {
    // add padding
    let total_bits = self.total_len * 8;
    let mut buffer = [0u8; SHA256_BLOCK_SIZE * 2];

    // copy current buffer
    buffer[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
    let mut buffer_len = self.buffer_len;

    // append '1' bit (0x80)
    buffer[buffer_len] = 0x80;
    buffer_len += 1;

    // pad with zeros until we have 8 bytes left for length
    if buffer_len > SHA256_BLOCK_SIZE - 8 {
      // need two blocks
      while buffer_len % SHA256_BLOCK_SIZE != 0 {
        buffer[buffer_len] = 0;
        buffer_len += 1;
      }

      self.process_block(&buffer[..SHA256_BLOCK_SIZE]);
      buffer = [0u8; SHA256_BLOCK_SIZE * 2];
      buffer_len = 0;
    }

    // pad to 56 bytes (leaving 8 for length)
    while buffer_len % SHA256_BLOCK_SIZE != SHA256_BLOCK_SIZE - 8 {
      buffer[buffer_len] = 0;
      buffer_len += 1;
    }

    // append length in big-endian format
    let length_bytes = total_bits.to_be_bytes();
    buffer[buffer_len..buffer_len + 8].copy_from_slice(&length_bytes);

    self.process_block(&buffer[..SHA256_BLOCK_SIZE]);

    // convert state to bytes
    let mut result = [0u8; SHA256_DIGEST_SIZE];
    for (i, &state_word) in self.state.iter().enumerate() {
      result[i * 4..(i + 1) * 4].copy_from_slice(&state_word.to_be_bytes());
    }

    result
  }

  fn process_block(&mut self, block: &[u8]) {
    let mut w = [0u32; 64];

    // prepare message schedule
    for i in 0..16 {
      w[i] = u32::from_be_bytes([
        block[i * 4],
        block[i * 4 + 1],
        block[i * 4 + 2],
        block[i * 4 + 3],
      ]);
    }

    for i in 16..64 {
      let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
      let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16]
        .wrapping_add(s0)
        .wrapping_add(w[i - 7])
        .wrapping_add(s1);
    }

    // initialize working variables
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

    // main loop
    for i in 0..64 {
      let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
      let ch = (e & f) ^ ((!e) & g);
      let temp1 = h
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(K[i])
        .wrapping_add(w[i]);
      let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = s0.wrapping_add(maj);

      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(temp1);
      d = c;
      c = b;
      b = a;
      a = temp1.wrapping_add(temp2);
    }

    // add to state
    self.state[0] = self.state[0].wrapping_add(a);
    self.state[1] = self.state[1].wrapping_add(b);
    self.state[2] = self.state[2].wrapping_add(c);
    self.state[3] = self.state[3].wrapping_add(d);
    self.state[4] = self.state[4].wrapping_add(e);
    self.state[5] = self.state[5].wrapping_add(f);
    self.state[6] = self.state[6].wrapping_add(g);
    self.state[7] = self.state[7].wrapping_add(h);
  }
}

// compute sha256 hash
pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
  let mut hasher = Sha256::new();
  hasher.update(data);
  hasher.finalize()
}

// hmac-sha256 implementation following RFC 2104
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
  let mut actual_key = [0u8; SHA256_BLOCK_SIZE];

  // if key is longer than block size, hash it first
  if key.len() > SHA256_BLOCK_SIZE {
    let hashed_key = sha256(key);
    actual_key[..SHA256_DIGEST_SIZE].copy_from_slice(&hashed_key);
  } else {
    // if key is shorter than block size, pad with zeros
    let copy_len = std::cmp::min(key.len(), SHA256_BLOCK_SIZE);
    actual_key[..copy_len].copy_from_slice(&key[..copy_len]);
  }

  // create inner and outer padding
  let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
  let mut opad = [0x5cu8; SHA256_BLOCK_SIZE];

  // xor key with padding
  for i in 0..SHA256_BLOCK_SIZE {
    ipad[i] ^= actual_key[i];
    opad[i] ^= actual_key[i];
  }

  // compute inner hash: H(K XOR ipad, message)
  let mut inner_hasher = Sha256::new();
  inner_hasher.update(&ipad);
  inner_hasher.update(message);
  let inner_hash = inner_hasher.finalize();

  // compute outer hash: H(K XOR opad, inner_hash)
  let mut outer_hasher = Sha256::new();
  outer_hasher.update(&opad);
  outer_hasher.update(&inner_hash);
  outer_hasher.finalize()
}

#[derive(Debug)]
pub struct HmacSha256 {
  key: Vec<u8>,
}

impl HmacSha256 {
  pub fn new(key: &[u8]) -> Self {
    Self { key: key.to_vec() }
  }

  pub fn compute(&self, message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    hmac_sha256(&self.key, message)
  }

  pub fn verify(&self, message: &[u8], expected_mac: &[u8]) -> bool {
    let computed_mac = self.compute(message);
    computed_mac.as_slice() == expected_mac
  }
}

impl fmt::Display for HmacSha256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "HmacSha256(key_len={})", self.key.len())
  }
}

// utility functions
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
  let clean_str = hex_str.replace(" ", "").replace("\n", "");
  if clean_str.len() % 2 != 0 {
    return Err("hex string must have even length".to_string());
  }

  let mut result = Vec::new();
  for chunk in clean_str.as_bytes().chunks(2) {
    if let Ok(hex_str) = std::str::from_utf8(chunk) {
      if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
        result.push(byte);
      } else {
        return Err(format!("invalid hex character in '{}'", hex_str));
      }
    } else {
      return Err("invalid utf-8 in hex string".to_string());
    }
  }

  Ok(result)
}

pub fn to_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
  println!("HMAC-SHA256 Implementation from First Principles");
  println!("=================================================");

  // basic test
  let key = b"my secret key";
  let message = b"hello world";
  let mac = hmac_sha256(key, message);

  println!("Key: {:?}", std::str::from_utf8(key).unwrap());
  println!("Message: {:?}", std::str::from_utf8(message).unwrap());
  println!("HMAC-SHA256: {}", to_hex(&mac));

  // test with hmac struct
  let hmac = HmacSha256::new(key);
  let mac2 = hmac.compute(message);

  println!("Via struct: {}", to_hex(&mac2));
  println!("Match: {}", mac == mac2);

  // verify functionality
  println!("Verification test: {}", hmac.verify(message, &mac));
  println!(
    "Verification with wrong MAC: {}",
    hmac.verify(message, &[0u8; 32])
  );
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sha256_empty() {
    let hash = sha256(b"");
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(to_hex(&hash), expected);
  }

  #[test]
  fn test_sha256_abc() {
    let hash = sha256(b"abc");
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(to_hex(&hash), expected);
  }

  #[test]
  fn test_hmac_basic() {
    let key = b"key";
    let message = b"The quick brown fox jumps over the lazy dog";
    let mac = hmac_sha256(key, message);

    // known good value from standard implementation
    let expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    assert_eq!(to_hex(&mac), expected);
  }

  #[test]
  fn test_hmac_struct() {
    let hmac = HmacSha256::new(b"secret");
    let mac = hmac.compute(b"message");

    assert!(hmac.verify(b"message", &mac));
    assert!(!hmac.verify(b"different", &mac));
  }
}
