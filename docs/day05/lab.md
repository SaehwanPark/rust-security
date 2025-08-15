# **Day 5 – Cryptography Fundamentals: Lab & Coding Exercises**

## **Overview**

In today’s lab, you’ll move from **understanding** cryptography to **building** it in Rust.
You’ll implement simple ciphers, experiment with encryption modes, and see firsthand how design choices affect security.

---

## **1. Learning Goals**

By the end of the lab, you should be able to:

* Implement basic symmetric encryption in Rust.
* Compare weak and strong cipher designs.
* Observe vulnerabilities like ECB mode’s pattern leakage.
* Use the Rust `aes` crate to perform AES encryption and decryption.
* Critically analyze output for security flaws.

---

## **2. Lab Steps**

### **Part A – XOR Cipher (Your Crypto “Hello World”)**

**Goal:** Build intuition for encryption by implementing the simplest possible scheme.

**Tasks:**

1. Write a Rust function `xor_cipher(input: &[u8], key: &[u8]) -> Vec<u8>` that:

   * Iterates over the plaintext bytes.
   * XORs each byte with the corresponding byte from the key (repeating if necessary).
2. Use it to encrypt and decrypt a message.
3. Experiment with:

   * Different key lengths.
   * Highly repetitive plaintext (to see frequency leaks).

**Example Starter Code:**

```rust
fn xor_cipher(input: &[u8], key: &[u8]) -> Vec<u8> {
    input.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn main() {
    let plaintext = b"Attack at dawn!";
    let key = b"secret";

    let ciphertext = xor_cipher(plaintext, key);
    println!("Ciphertext: {:?}", ciphertext);

    let decrypted = xor_cipher(&ciphertext, key);
    println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap());
}
```

---

### **Part B – ECB Mode Pitfall**

**Goal:** Witness why ECB mode is dangerous.

**Tasks:**

1. Find or create a **bitmap image** with a large block of solid color (e.g., the classic penguin image).
2. Encrypt it using AES in **ECB mode** with the `aes` + `block-modes` crates.
3. Save the output and view the image — you should still see the original patterns.

**Hints:**

* You’ll need to read the file as bytes, encrypt block-by-block, and write back to disk.
* Compare the encrypted ECB image with a CBC-encrypted version.

---

### **Part C – AES in CBC Mode**

**Goal:** Implement strong symmetric encryption.

**Tasks:**

1. Use the `aes` crate with CBC mode (via `block-modes`).
2. Encrypt a sample message.
3. Change the IV slightly and try decrypting — observe how the plaintext changes completely.
4. Document why the IV must be unique and unpredictable.

**Example Starter Code:**

```rust
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    let key = b"verysecretkey!!";
    let iv = b"uniqueinitvectr";
    let plaintext = b"Confidential data!";

    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext);
    println!("Ciphertext: {:?}", ciphertext);

    let decrypted = cipher.decrypt_vec(&ciphertext).unwrap();
    println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap());
}
```

---

### **Part D – Cipher Mode Analysis**

**Goal:** Develop a critical eye for cipher design.

**Tasks:**

1. Encrypt the **same** plaintext in ECB and CBC mode.
2. Compare:

   * Ciphertext length
   * Visual patterns (if using images)
   * Resistance to partial plaintext disclosure
3. Write a short summary of your observations.

---

## **3. Stretch Goals (Optional)**

* Implement your own CBC mode manually using your XOR cipher from Part A.
* Benchmark AES-128 vs AES-256 in Rust to compare performance.
* Use Rust’s `rand` crate to generate secure random keys and IVs.
* Try GCM mode for authenticated encryption and verify integrity checks.

---

## **4. Deliverables**

* Rust source files for each part.
* ECB vs CBC mode comparison notes (1–2 paragraphs).
* Screenshots or images showing the ECB pattern leak.
* Reflection: *“What makes strong crypto strong?”* (200–300 words).
