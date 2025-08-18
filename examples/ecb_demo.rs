use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::RngCore;

/// ecb mode implementation -- demonstrate why ecb is insecure
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

  /// encrypt in ecb mode - each block encrypted independently
  fn encrypt(&self, data: &[u8]) -> Vec<u8> {
    let block_size = 16; // aes block size
    let mut result = Vec::new();

    // process full blocks
    for chunk in data.chunks(block_size) {
      let mut block = [0u8; 16];
      if chunk.len() == block_size {
        block.copy_from_slice(chunk);
      } else {
        // pad last block with pkcs7
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

  /// decrypt in ecb mode
  fn decrypt(&self, data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut result = Vec::new();

    for chunk in data.chunks(block_size) {
      let mut block_array = GenericArray::clone_from_slice(chunk);
      self.cipher.decrypt_block(&mut block_array);
      result.extend_from_slice(&block_array);
    }

    // remove pkcs7 padding from last block
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

/// create test pattern to demonstrate ecb weakness
fn create_pattern_data() -> Vec<u8> {
  let mut data = Vec::new();

  // create repetitive 16-byte blocks
  let block_a = b"aaaaaaaaaaaaaaaa"; // 16 a's
  let block_b = b"bbbbbbbbbbbbbbbb"; // 16 b's
  let block_c = b"cccccccccccccccc"; // 16 c's

  // repeat pattern multiple times
  for _ in 0..3 {
    data.extend_from_slice(block_a);
    data.extend_from_slice(block_b);
    data.extend_from_slice(block_c);
  }

  data
}

/// demonstrate ecb pattern leakage with text
fn text_pattern_demo() {
  println!("=== text pattern demonstration ===");

  let key = b"verysecretkey123"; // 16 bytes for aes-128
  let ecb = EcbMode::new(key);

  let pattern_data = create_pattern_data();
  println!("original data ({} bytes):", pattern_data.len());
  println!("{}", String::from_utf8_lossy(&pattern_data));

  let encrypted = ecb.encrypt(&pattern_data);
  println!("\necb encrypted data (hex):");
  for (i, chunk) in encrypted.chunks(16).enumerate() {
    println!("block {}: {}", i, hex::encode(chunk));
  }

  // identify identical blocks
  println!("\nidentical encrypted blocks:");
  let mut block_map = std::collections::HashMap::new();
  for (i, chunk) in encrypted.chunks(16).enumerate() {
    let hex_block = hex::encode(chunk);
    block_map
      .entry(hex_block.clone())
      .or_insert(Vec::new())
      .push(i);
  }

  for (block_hex, positions) in block_map.iter() {
    if positions.len() > 1 {
      println!("block {} appears at positions: {:?}", block_hex, positions);
    }
  }

  // decrypt to verify
  let decrypted = ecb.decrypt(&encrypted);
  assert_eq!(pattern_data, decrypted);
  println!("✓ decryption successful\n");
}

/// simulate image encryption to show visual patterns
fn simulate_image_ecb() {
  println!("=== simulated image ecb encryption ===");

  // create a simple "image" with repeating patterns
  let mut image_data = Vec::new();

  // simulate 8x8 pixel blocks with same color
  let white_block = vec![255u8; 16]; // 16 bytes = simulated pixel block
  let black_block = vec![0u8; 16];
  let gray_block = vec![128u8; 16];

  // create a pattern: white-black-white across multiple "rows"
  for _row in 0..4 {
    image_data.extend_from_slice(&white_block);
    image_data.extend_from_slice(&black_block);
    image_data.extend_from_slice(&white_block);
    image_data.extend_from_slice(&gray_block);
  }

  println!("simulated image data pattern:");
  for (i, chunk) in image_data.chunks(16).enumerate() {
    let avg = chunk.iter().map(|&x| x as u32).sum::<u32>() / chunk.len() as u32;
    let color = match avg {
      0..=80 => "black",
      81..=180 => "gray",
      _ => "white",
    };
    println!("block {}: {} (avg: {})", i, color, avg);
  }

  let key = b"imageencryptkey1";
  let ecb = EcbMode::new(key);

  let encrypted_image = ecb.encrypt(&image_data);

  println!("\necb encrypted 'image' blocks:");
  let mut unique_blocks = std::collections::HashSet::new();
  for (i, chunk) in encrypted_image.chunks(16).enumerate() {
    let block_hex = hex::encode(chunk);
    let is_duplicate = !unique_blocks.insert(block_hex.clone());
    println!(
      "block {}: {} {}",
      i,
      &block_hex[..16],
      if is_duplicate {
        "(duplicate!)"
      } else {
        "(unique)"
      }
    );
  }

  println!("\n⚠️  identical plaintext blocks → identical ciphertext blocks");
  println!("this preserves visual patterns in images!");
}

/// compare ecb vs random data
fn randomness_comparison() {
  println!("=== randomness comparison ===");

  let key = b"testkey123456789";
  let ecb = EcbMode::new(key);

  // encrypt structured data
  let structured = b"aaaaaaaaaaaaaaaa".repeat(4); // very predictable
  let ecb_encrypted = ecb.encrypt(&structured);

  // generate truly random data of same length
  let mut random_data = vec![0u8; ecb_encrypted.len()];
  rand::thread_rng().fill_bytes(&mut random_data);

  // analyze block uniqueness
  let ecb_unique_blocks = ecb_encrypted
    .chunks(16)
    .map(hex::encode)
    .collect::<std::collections::HashSet<_>>()
    .len();

  let random_unique_blocks = random_data
    .chunks(16)
    .map(hex::encode)
    .collect::<std::collections::HashSet<_>>()
    .len();

  let total_blocks = ecb_encrypted.len() / 16;

  println!("structured data encrypted with ecb:");
  println!("  total blocks: {}", total_blocks);
  println!("  unique blocks: {}", ecb_unique_blocks);
  println!(
    "  uniqueness ratio: {:.2}",
    ecb_unique_blocks as f64 / total_blocks as f64
  );

  println!("truly random data:");
  println!("  total blocks: {}", total_blocks);
  println!("  unique blocks: {}", random_unique_blocks);
  println!(
    "  uniqueness ratio: {:.2}",
    random_unique_blocks as f64 / total_blocks as f64
  );

  println!("\n⚠️  ecb mode fails the 'looks random' test!");
}

fn main() {
  println!("=== part b: ecb mode pitfall demonstration ===\n");

  text_pattern_demo();
  simulate_image_ecb();
  randomness_comparison();

  println!("=== security analysis ===");
  println!("ecb mode weaknesses:");
  println!("• identical plaintext blocks → identical ciphertext blocks");
  println!("• patterns in plaintext remain visible in ciphertext");
  println!("• vulnerable to block rearrangement attacks");
  println!("• does not provide semantic security");
  println!("• statistical analysis can reveal information");

  println!("\nwhy this matters:");
  println!("• images encrypted with ecb still show visual outlines");
  println!("• database records with same fields leak information");
  println!("• structured data formats become partially readable");

  println!("\n✅ solution: use cbc, ctr, or gcm modes instead!");
  println!("these modes ensure identical blocks encrypt differently");
}
