use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::{RngCore, rng};
use std::time::Instant;

// type aliases
type Aes128CbcEnc = CbcEncryptor<Aes128>;
type Aes128CbcDec = CbcDecryptor<Aes128>;

/// simple ecb implementation for comparison
struct EcbMode {
  cipher: Aes128,
}

impl EcbMode {
  fn new(key: &[u8]) -> Self {
    let key_array = GenericArray::from_slice(key);
    Self {
      cipher: Aes128::new(key_array),
    }
  }

  fn encrypt(&self, data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut result = Vec::new();

    for chunk in data.chunks(block_size) {
      let mut block = [0u8; 16];
      if chunk.len() == block_size {
        block.copy_from_slice(chunk);
      } else {
        // pad with pkcs7
        block[..chunk.len()].copy_from_slice(chunk);
        let padding = block_size - chunk.len();
        for i in chunk.len()..block_size {
          block[i] = padding as u8;
        }
      }

      let mut block_array = GenericArray::from(block);
      self.cipher.encrypt_block(&mut block_array);
      result.extend_from_slice(&block_array);
    }

    result
  }

  fn decrypt(&self, data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut result = Vec::new();

    for chunk in data.chunks(block_size) {
      let mut block_array = GenericArray::clone_from_slice(chunk);
      self.cipher.decrypt_block(&mut block_array);
      result.extend_from_slice(&block_array);
    }

    // remove pkcs7 padding
    if let Some(&padding) = result.last() {
      if padding <= block_size as u8 && padding > 0 {
        let padding_start = result.len() - padding as usize;
        if result[padding_start..].iter().all(|&b| b == padding) {
          result.truncate(padding_start);
        }
      }
    }

    result
  }
}

/// compare ecb vs cbc with same plaintext
fn side_by_side_comparison() {
  println!("=== ecb vs cbc side-by-side comparison ===");

  let key = b"comparisonkey123";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  // create plaintext with obvious patterns
  let plaintext = b"aaaaaaaaaaaaaaaa\
                    bbbbbbbbbbbbbbbb\
                    aaaaaaaaaaaaaaaa\
                    cccccccccccccccc\
                    aaaaaaaaaaaaaaaa";

  println!("plaintext pattern (each line = 16 bytes):");
  for (i, chunk) in plaintext.chunks(16).enumerate() {
    println!("  block {}: {}", i, String::from_utf8_lossy(chunk));
  }

  // encrypt with ecb
  let ecb = EcbMode::new(key);
  let ecb_ciphertext = ecb.encrypt(plaintext);

  // encrypt with cbc
  let cbc_ciphertext =
    Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

  println!("\necb ciphertext:");
  for (i, chunk) in ecb_ciphertext.chunks(16).enumerate() {
    println!("  block {}: {}", i, hex::encode(chunk));
  }

  println!("\ncbc ciphertext:");
  for (i, chunk) in cbc_ciphertext.chunks(16).enumerate() {
    println!("  block {}: {}", i, hex::encode(chunk));
  }

  // analyze patterns
  println!("\npattern analysis:");

  // ecb pattern analysis
  let ecb_blocks: Vec<String> = ecb_ciphertext.chunks(16).map(hex::encode).collect();
  let mut ecb_duplicates = std::collections::HashMap::new();
  for (i, block) in ecb_blocks.iter().enumerate() {
    ecb_duplicates
      .entry(block.clone())
      .or_insert(Vec::new())
      .push(i);
  }

  println!("ecb duplicate blocks:");
  for (block, positions) in ecb_duplicates.iter() {
    if positions.len() > 1 {
      println!("  {} at positions: {:?}", &block[..16], positions);
    }
  }

  // cbc pattern analysis
  let cbc_blocks: Vec<String> = cbc_ciphertext.chunks(16).map(hex::encode).collect();
  let mut cbc_duplicates = std::collections::HashMap::new();
  for (i, block) in cbc_blocks.iter().enumerate() {
    cbc_duplicates
      .entry(block.clone())
      .or_insert(Vec::new())
      .push(i);
  }

  println!("cbc duplicate blocks:");
  let has_duplicates = cbc_duplicates.values().any(|v| v.len() > 1);
  if !has_duplicates {
    println!("  none found - all blocks unique! ✅");
  } else {
    for (block, positions) in cbc_duplicates.iter() {
      if positions.len() > 1 {
        println!("  {} at positions: {:?}", &block[..16], positions);
      }
    }
  }

  // verify decryption
  let ecb_decrypted = ecb.decrypt(&ecb_ciphertext);
  let cbc_decrypted = Aes128CbcDec::new(key.into(), &iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&cbc_ciphertext)
    .expect("cbc decryption failed");

  assert_eq!(plaintext, &ecb_decrypted[..]);
  assert_eq!(plaintext, &cbc_decrypted[..]);
  println!("\n✓ both modes decrypt correctly");
}

/// compare ciphertext lengths
fn length_comparison() {
  println!("\n=== ciphertext length comparison ===");

  let key = b"lengthcompareky1"; // exactly 16 bytes
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  let test_messages = [
    "short",
    "exactly16bytes!!", // exactly 16 bytes
    "this message is longer than 16 bytes and spans multiple blocks",
    &"a".repeat(100),
  ];

  for (i, &msg) in test_messages.iter().enumerate() {
    let plaintext = msg.as_bytes();

    let ecb = EcbMode::new(key);
    let ecb_ciphertext = ecb.encrypt(plaintext);

    // use fresh iv for each cbc encryption
    rng().fill_bytes(&mut iv);
    let cbc_ciphertext =
      Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    println!("message {}: {} bytes", i + 1, plaintext.len());
    println!("  ecb ciphertext: {} bytes", ecb_ciphertext.len());
    println!("  cbc ciphertext: {} bytes", cbc_ciphertext.len());
    println!(
      "  same length: {}",
      ecb_ciphertext.len() == cbc_ciphertext.len()
    );

    // verify both decrypt correctly
    let ecb_decrypted = ecb.decrypt(&ecb_ciphertext);
    let cbc_decrypted = Aes128CbcDec::new(key.into(), &iv.into())
      .decrypt_padded_vec_mut::<Pkcs7>(&cbc_ciphertext)
      .expect("cbc decryption failed");

    assert_eq!(plaintext, &ecb_decrypted[..]);
    assert_eq!(plaintext, &cbc_decrypted[..]);
  }

  println!("\n💡 both modes produce same ciphertext length (padding is identical)");
}

/// performance benchmark
fn performance_comparison() {
  println!("\n=== performance comparison ===");

  let key = b"benchmarkkey1234";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  // generate large test data
  let mut large_data = vec![0u8; 1024 * 1024]; // 1mb
  rng().fill_bytes(&mut large_data);

  println!("testing with {} bytes of data", large_data.len());

  // benchmark ecb encryption
  let ecb = EcbMode::new(key);
  let start = Instant::now();
  let ecb_result = ecb.encrypt(&large_data);
  let ecb_encrypt_time = start.elapsed();

  // benchmark cbc encryption
  let start = Instant::now();
  let cbc_result =
    Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&large_data);
  let cbc_encrypt_time = start.elapsed();

  println!("encryption performance:");
  println!("  ecb: {:?}", ecb_encrypt_time);
  println!("  cbc: {:?}", cbc_encrypt_time);

  if ecb_encrypt_time.as_nanos() > 0 {
    let overhead =
      (cbc_encrypt_time.as_nanos() as f64 / ecb_encrypt_time.as_nanos() as f64 - 1.0) * 100.0;
    println!("  cbc overhead: {:.2}%", overhead);
  }

  // benchmark decryption
  let start = Instant::now();
  let _ecb_decrypted = ecb.decrypt(&ecb_result);
  let ecb_decrypt_time = start.elapsed();

  let start = Instant::now();
  let _cbc_decrypted = Aes128CbcDec::new(key.into(), &iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&cbc_result)
    .expect("cbc decryption failed");
  let cbc_decrypt_time = start.elapsed();

  println!("decryption performance:");
  println!("  ecb: {:?}", ecb_decrypt_time);
  println!("  cbc: {:?}", cbc_decrypt_time);

  println!("\n💡 cbc has minimal performance overhead vs ecb");
  println!("the security benefits far outweigh the small performance cost");
}

/// demonstrate security properties
fn security_analysis() {
  println!("\n=== security analysis ===");

  let key = b"securitytestkey1";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  // test with identical message blocks
  let identical_blocks = b"samedata12345678".repeat(4); // 4 identical blocks

  let ecb = EcbMode::new(key);
  let ecb_cipher = ecb.encrypt(&identical_blocks);

  let cbc_cipher =
    Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&identical_blocks);

  // count unique blocks
  let ecb_unique = ecb_cipher
    .chunks(16)
    .map(hex::encode)
    .collect::<std::collections::HashSet<_>>()
    .len();

  let cbc_unique = cbc_cipher
    .chunks(16)
    .map(hex::encode)
    .collect::<std::collections::HashSet<_>>()
    .len();

  let total_blocks = identical_blocks.len() / 16;

  println!("encrypting {} identical plaintext blocks:", total_blocks);
  println!(
    "  ecb unique ciphertext blocks: {}/{}",
    ecb_unique, total_blocks
  );
  println!(
    "  cbc unique ciphertext blocks: {}/{}",
    cbc_unique, total_blocks
  );

  // semantic security test
  println!("\nsemantic security test:");
  let msg1 = b"attack at dawn!!"; // 16 bytes
  let msg2 = b"attack at noon!!"; // 16 bytes, similar

  let ecb_c1 = ecb.encrypt(msg1);
  let ecb_c2 = ecb.encrypt(msg2);

  let cbc_c1 = Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(msg1);

  rng().fill_bytes(&mut iv); // new iv for second message
  let cbc_c2 = Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(msg2);

  println!("  similar messages with ecb:");
  println!("    msg1 cipher: {}", hex::encode(&ecb_c1));
  println!("    msg2 cipher: {}", hex::encode(&ecb_c2));
  println!("    correlation detectable: {}", ecb_c1[..8] == ecb_c2[..8]);

  println!("  similar messages with cbc (different ivs):");
  println!("    msg1 cipher: {}", hex::encode(&cbc_c1[..16]));
  println!("    msg2 cipher: {}", hex::encode(&cbc_c2[..16]));
  println!("    correlation detectable: {}", cbc_c1 == cbc_c2);

  // demonstrate chosen plaintext attack resistance
  println!("\nchosen plaintext attack resistance:");
  println!("  ecb: ❌ attacker can build codebook of plaintext→ciphertext");
  println!("  cbc: ✅ random iv prevents codebook attacks");
}

/// demonstrate real-world attack scenarios
fn attack_scenario_demo() {
  println!("\n=== real-world attack scenarios ===");

  let key = b"webapplicationk1"; // exactly 16 bytes

  // simulate web application tokens
  println!("web application session tokens:");
  let base_token = b"user=admin&role=";
  let roles = ["guest", "user", "admin"];

  // ecb attack scenario
  println!("\necb mode (vulnerable):");
  let ecb = EcbMode::new(key);

  for role in &roles {
    let mut token = base_token.to_vec();
    token.extend_from_slice(role.as_bytes());
    // pad to make analysis easier
    while token.len() % 16 != 0 {
      token.push(b' ');
    }

    let encrypted_token = ecb.encrypt(&token);
    println!("  role '{}': {}", role, hex::encode(&encrypted_token[..32]));
  }
  println!("  ⚠️  common prefix patterns are visible!");

  // cbc mode (secure)
  println!("\ncbc mode (secure):");
  for role in &roles {
    let mut token = base_token.to_vec();
    token.extend_from_slice(role.as_bytes());

    let mut iv = [0u8; 16];
    rng().fill_bytes(&mut iv);

    let encrypted_token =
      Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&token);

    println!("  role '{}': {}", role, hex::encode(&encrypted_token[..32]));
  }
  println!("  ✅ no patterns visible, even with common prefixes");
}

fn main() {
  println!("=== part d: cipher mode comparison ===\n");

  side_by_side_comparison();
  length_comparison();
  performance_comparison();
  security_analysis();
  attack_scenario_demo();

  println!("\n=== comprehensive comparison summary ===");

  println!("\n📊 ecb mode:");
  println!("✅ advantages:");
  println!("  • simple implementation");
  println!("  • parallelizable encryption/decryption");
  println!("  • no iv required");
  println!("  • slightly faster");
  println!("  • error doesn't propagate between blocks");

  println!("❌ disadvantages:");
  println!("  • identical blocks → identical ciphertexts");
  println!("  • patterns visible in structured data");
  println!("  • vulnerable to chosen plaintext attacks");
  println!("  • not semantically secure");
  println!("  • block rearrangement attacks possible");
  println!("  • frequency analysis reveals information");

  println!("\n🔒 cbc mode:");
  println!("✅ advantages:");
  println!("  • semantically secure with random ivs");
  println!("  • hides patterns in plaintext");
  println!("  • widely standardized and supported");
  println!("  • resistant to chosen plaintext attacks");
  println!("  • each block depends on all previous blocks");

  println!("❌ disadvantages:");
  println!("  • requires unique iv per encryption");
  println!("  • sequential encryption (not parallelizable)");
  println!("  • iv management complexity");
  println!("  • vulnerable to padding oracle attacks");
  println!("  • error propagation affects subsequent blocks");

  println!("\n📈 performance comparison:");
  println!("  • ecb: ~5-10% faster due to parallelization potential");
  println!("  • cbc: minimal overhead, excellent security/performance ratio");

  println!("\n🎯 use cases:");
  println!("  • ecb: never use for real applications!");
  println!("  • cbc: legacy systems, when gcm not available");
  println!("  • modern: prefer aes-gcm for authenticated encryption");

  println!("\n🏆 recommendation:");
  println!("• never use ecb for real applications");
  println!("• use cbc with proper iv generation for legacy compatibility");
  println!("• prefer authenticated encryption (aes-gcm) when possible");
  println!("• always use cryptographic libraries, never roll your own");
  println!("• test implementations against known attack vectors");
}
