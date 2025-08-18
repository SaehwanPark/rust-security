# Day 7 Lab — Public-Key Cryptography & PKI

## Overview

Today’s lab is your hands-on journey into **asymmetric cryptography**. You will:

1. Generate RSA keypairs and perform encryption/decryption in Rust.
2. Experiment with key sizes and padding schemes.
3. Parse and inspect X.509 certificates.
4. Attempt a minimal verification workflow.

Keep your code in `examples/day07/` for consistency.

---

## Part 1: RSA Key Generation, Encryption & Decryption

### Task

* Write a Rust program that:

  * Generates a **2048-bit RSA keypair** using the `rsa` crate.
  * Encrypts a short plaintext string using the **public key**.
  * Decrypts it back using the **private key**.
  * Prints ciphertext length and recovered plaintext.

### Hints

* Add dependencies:

  ```toml
  rsa = { version = "0.9", features = ["sha2"] }
  sha2 = "0.10"
  rand = "0.8"
  ```
* Use `Oaep::<Sha256>::new()` instead of PKCS#1 v1.5 — it’s safer.
* Ciphertext size will equal the modulus size (256 bytes for 2048-bit keys).
* For repeatability, try encrypting the same plaintext twice — notice how OAEP randomization changes ciphertext.

---

## Part 2: Exploring Key Sizes & Padding

### Task

* Extend your program to support:

  * 1024-bit, 2048-bit, and 4096-bit keys.
  * Both **OAEP** and **PKCS#1 v1.5** padding modes.
* Benchmark encryption + decryption timings for each.

### Hints

* Use Rust’s `std::time::Instant` for timing.
* PKCS#1 v1.5 encryption is unsafe — expect identical ciphertexts for identical plaintexts. Why is this dangerous? (Think chosen-plaintext attacks.)

---

## Part 3: Parsing X.509 Certificates

### Task

* Write `certinfo.rs` that:

  * Loads a `.pem` certificate file.
  * Extracts and prints:

    * Subject
    * Issuer
    * Validity period
    * Public key algorithm and key size

### Hints

* Dependency:

  ```toml
  x509-parser = "0.16"
  ```
* Look at `X509Certificate::from_pem` for parsing.
* You can download test certs (e.g., from any HTTPS site with `openssl s_client -connect example.com:443 -showcerts`).
* Store test certs in a `fixtures/` folder inside your repo.

---

## Part 4: Minimal Certificate Verification

### Task

* Implement a simplified trust check:

  * Verify that the certificate is **currently valid** (date checks).
  * Confirm that its **issuer matches** a provided CA cert.
  * Verify the signature chain (bonus, advanced).

### Hints

* You don’t need a full PKI engine — just implement sanity checks.
* To check time validity, compare `cert.validity().not_before` and `not_after` with `chrono::Utc::now()`.
* Signature verification is more complex — `x509-parser` can expose the signature bytes, but verifying requires pulling in `ring` or `openssl` crates. Treat it as a **stretch challenge**.

---

## Part 5: Integration with Project 2 (Secure Chat)

### Task

* Replace your fixed test key from Day 6’s Secure Chat with:

  * **RSA key exchange**: server holds RSA private key; client encrypts a session key with server’s public key.
  * OR **X25519 ephemeral key exchange** (preferred).

### Hints

* RSA approach is simpler but less modern. Try it first for practice.
* Ensure that after the key exchange, you still encrypt actual messages symmetrically (AES-GCM or ChaCha20-Poly1305).
* This will prepare you for **Day 8 TLS**.

---

## Deliverables

* `examples/day07_rsa.rs` — basic RSA demo.
* `examples/day07_rsa_bench.rs` — benchmarks for key sizes and padding.
* `examples/day07_certinfo.rs` — certificate inspector tool.
* Updated Secure Chat with RSA/X25519 exchange.

---

## Reflection Questions

1. Why should we avoid using RSA directly to encrypt bulk data?
2. What security failure would happen if browsers ignored certificate validity dates?
3. What’s the main weakness of the CA-based PKI model?
4. How does OAEP padding improve security compared to PKCS#1 v1.5?
