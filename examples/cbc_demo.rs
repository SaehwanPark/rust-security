use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::{RngCore, rng};

// type aliases for convenience
type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// demonstrate aes-cbc encryption and decryption
fn basic_cbc_demo() {
  println!("=== basic aes-cbc demonstration ===");

  let key = b"verysecretkey!!!"; // 16 bytes for aes-128
  let iv = b"uniqueinitvectr!"; // 16 bytes iv
  let plaintext = b"confidential data that needs protection!";

  println!("plaintext: {}", String::from_utf8_lossy(plaintext));
  println!("key: {}", String::from_utf8_lossy(key));
  println!("iv: {}", hex::encode(iv));

  // encrypt
  let ciphertext =
    Aes128CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

  println!("ciphertext: {}", hex::encode(&ciphertext));

  // decrypt
  let decrypted = Aes128CbcDec::new(key.into(), iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
    .expect("decryption failed");

  println!("decrypted: {}", String::from_utf8_lossy(&decrypted));

  assert_eq!(plaintext, &decrypted[..]);
  println!("✓ encryption/decryption successful\n");
}

/// demonstrate why iv must be unique and unpredictable
fn iv_importance_demo() {
  println!("=== iv importance demonstration ===");

  let key = b"samekeyforall!!!";
  let plaintext = b"attack at dawn!!"; // exactly 16 bytes (one block)

  // encrypt same plaintext with same iv (bad!)
  let fixed_iv = b"fixediv123456789";
  let cipher1 =
    Aes128CbcEnc::new(key.into(), fixed_iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
  let cipher2 =
    Aes128CbcEnc::new(key.into(), fixed_iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

  println!("same plaintext, same iv:");
  println!("  plaintext: {}", String::from_utf8_lossy(plaintext));
  println!("  cipher 1:  {}", hex::encode(&cipher1));
  println!("  cipher 2:  {}", hex::encode(&cipher2));
  println!("  identical: {}", cipher1 == cipher2);

  // encrypt same plaintext with different ivs (good!)
  let mut iv1 = [0u8; 16];
  let mut iv2 = [0u8; 16];
  rng().fill_bytes(&mut iv1);
  rng().fill_bytes(&mut iv2);

  let cipher3 =
    Aes128CbcEnc::new(key.into(), &iv1.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
  let cipher4 =
    Aes128CbcEnc::new(key.into(), &iv2.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

  println!("\nsame plaintext, different random ivs:");
  println!("  plaintext: {}", String::from_utf8_lossy(plaintext));
  println!("  iv 1:      {}", hex::encode(&iv1));
  println!("  cipher 1:  {}", hex::encode(&cipher3));
  println!("  iv 2:      {}", hex::encode(&iv2));
  println!("  cipher 2:  {}", hex::encode(&cipher4));
  println!("  identical: {}", cipher3 == cipher4);

  println!("\n⚠️  reusing ivs reveals when same plaintext is encrypted!");
}

/// demonstrate iv corruption effects
fn iv_corruption_demo() {
  println!("=== iv corruption demonstration ===");

  let key = b"testkey123456789";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  let plaintext = b"this is a multi-block message that spans several aes blocks!";

  println!("original plaintext: {}", String::from_utf8_lossy(plaintext));

  // encrypt
  let ciphertext =
    Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

  // decrypt with correct iv
  let correct_decrypt = Aes128CbcDec::new(key.into(), &iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
    .expect("decryption failed");

  println!(
    "correct decryption: {}",
    String::from_utf8_lossy(&correct_decrypt)
  );

  // corrupt one bit in iv
  let mut corrupted_iv = iv;
  corrupted_iv[0] ^= 0x01; // flip one bit

  let corrupted_decrypt = Aes128CbcDec::new(key.into(), &corrupted_iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
    .expect("decryption failed");

  println!(
    "corrupted iv decrypt: {}",
    String::from_utf8_lossy(&corrupted_decrypt)
  );

  // analyze the damage
  let original_blocks: Vec<&[u8]> = correct_decrypt.chunks(16).collect();
  let corrupted_blocks: Vec<&[u8]> = corrupted_decrypt.chunks(16).collect();

  println!("\nblock-by-block comparison:");
  for (i, (orig, corr)) in original_blocks
    .iter()
    .zip(corrupted_blocks.iter())
    .enumerate()
  {
    let differs = orig != corr;
    println!(
      "  block {}: {}",
      i,
      if differs { "differs" } else { "same" }
    );
    if differs && i == 0 {
      println!("    original: {}", String::from_utf8_lossy(orig));
      println!("    corrupted: {}", String::from_utf8_lossy(corr));
    }
  }

  println!("\n💡 iv corruption only affects the first plaintext block!");
}

/// demonstrate cbc chaining effect
fn chaining_demo() {
  println!("=== cbc chaining demonstration ===");

  let key = b"chaindemokeytest";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  // create plaintext with repetitive blocks
  let block1 = b"aaaaaaaaaaaaaaaa"; // 16 bytes
  let block2 = b"aaaaaaaaaaaaaaaa"; // identical to block1
  let block3 = b"bbbbbbbbbbbbbbbb"; // different from block1

  let mut plaintext = Vec::new();
  plaintext.extend_from_slice(block1);
  plaintext.extend_from_slice(block2);
  plaintext.extend_from_slice(block3);

  println!("plaintext blocks:");
  println!("  block 1: {}", String::from_utf8_lossy(block1));
  println!("  block 2: {}", String::from_utf8_lossy(block2));
  println!("  block 3: {}", String::from_utf8_lossy(block3));

  // encrypt
  let ciphertext =
    Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

  println!("\nciphertext blocks:");
  for (i, chunk) in ciphertext.chunks(16).enumerate() {
    println!("  block {}: {}", i, hex::encode(chunk));
  }

  // compare ciphertext blocks
  let cipher_blocks: Vec<&[u8]> = ciphertext.chunks(16).collect();
  println!("\nciphertext block comparison:");
  println!(
    "  block 0 == block 1: {}",
    cipher_blocks[0] == cipher_blocks[1]
  );
  println!(
    "  block 1 == block 2: {}",
    cipher_blocks[1] == cipher_blocks[2]
  );

  println!("\n💡 cbc mode: identical plaintext blocks → different ciphertext blocks!");
  println!("this is because each block is xored with previous ciphertext block");
}

/// demonstrate secure random iv generation
fn secure_iv_generation() {
  println!("=== secure iv generation ===");

  let key = b"secureivtestkey1";
  let plaintext = b"sensitive data requiring secure iv";

  println!("plaintext: {}", String::from_utf8_lossy(plaintext));

  // generate multiple encryptions with secure random ivs
  println!("\nmultiple encryptions with random ivs:");
  for i in 0..3 {
    let mut iv = [0u8; 16];
    rng().fill_bytes(&mut iv);

    let ciphertext =
      Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    println!("  encryption {}:", i + 1);
    println!("    iv: {}", hex::encode(&iv));
    println!("    ciphertext: {}", hex::encode(&ciphertext));
  }

  println!("\n✅ each encryption produces completely different ciphertext!");
  println!("this provides semantic security against chosen-plaintext attacks");
}

/// demonstrate padding oracle vulnerability setup
fn padding_awareness_demo() {
  println!("=== padding awareness demonstration ===");

  let key = b"paddingdemokey12";
  let mut iv = [0u8; 16];
  rng().fill_bytes(&mut iv);

  // test different message lengths to show padding
  let messages = [
    "a",                                 // 1 byte -> 15 bytes padding
    "hello world!",                      // 12 bytes -> 4 bytes padding
    "exactly16bytes!",                   // 16 bytes -> 16 bytes padding (full block)
    "this is longer than sixteen bytes", // > 16 bytes
  ];

  for (i, &msg) in messages.iter().enumerate() {
    let plaintext = msg.as_bytes();
    println!(
      "\nmessage {}: \"{}\" ({} bytes)",
      i + 1,
      msg,
      plaintext.len()
    );

    let ciphertext =
      Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let padded_blocks = ciphertext.len() / 16;
    println!("  ciphertext blocks: {}", padded_blocks);
    println!("  total ciphertext length: {} bytes", ciphertext.len());

    // decrypt to see padding
    let decrypted = Aes128CbcDec::new(key.into(), &iv.into())
      .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
      .expect("decryption failed");

    assert_eq!(plaintext, &decrypted[..]);
    println!("  ✓ decryption successful");
  }

  println!("\n⚠️  padding can leak information about message length");
  println!("in production, use authenticated encryption (aes-gcm) to prevent");
  println!("padding oracle attacks and ensure ciphertext integrity!");
}

fn main() {
  println!("=== part c: aes cbc mode implementation ===\n");

  basic_cbc_demo();
  iv_importance_demo();
  iv_corruption_demo();
  chaining_demo();
  secure_iv_generation();
  padding_awareness_demo();

  println!("\n=== cbc mode security properties ===");
  println!("✅ advantages:");
  println!("• identical plaintext blocks encrypt to different ciphertext");
  println!("• provides semantic security with random ivs");
  println!("• widely supported and standardized");
  println!("• efficient for bulk encryption");

  println!("\n⚠️  requirements for security:");
  println!("• iv must be unique for each encryption with same key");
  println!("• iv should be unpredictable (cryptographically random)");
  println!("• iv can be public but must not be reused");
  println!("• requires additional authentication for integrity");

  println!("\n🔒 best practices:");
  println!("• generate fresh random iv for each message");
  println!("• prepend iv to ciphertext for transmission/storage");
  println!("• use authenticated encryption (aes-gcm) when possible");
  println!("• implement proper error handling for padding");
  println!("• never reuse key/iv pairs");
}
