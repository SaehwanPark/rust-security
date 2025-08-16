# **Day 6 – Symmetric Encryption, Hashes, and MACs**

---

## **Opening Narrative: The Locked Journal**

Imagine you’ve inherited a locked journal from your great-grandparent. The key is a sequence of numbers and letters, but the lock has two unusual properties:

1. Every entry you add is scrambled into something unreadable unless the correct key is applied.
2. Every page has a special signature at the bottom proving it hasn’t been tampered with.

This journal is the perfect metaphor for today’s lesson: **symmetric encryption, hashes, and message authentication codes (MACs).**

Symmetric encryption = the lock.
Hashing = a fingerprint of the content.
MAC = the proof nobody altered the page.

We will travel from the basics of **block and stream ciphers**, through **SHA-256**, and finally arrive at **HMAC** — the cornerstone of secure messaging.

---

## **Part I: Symmetric Encryption Deep Dive**

### 1. **Block Ciphers**

* **Definition**: Algorithms that operate on fixed-size blocks (e.g., AES works on 128-bit blocks).
* **Key idea**: Same key for encryption and decryption.
* **Modes of operation**: ECB (dangerous), CBC, CTR, GCM.

  * ECB = encrypts each block independently → identical plaintext blocks produce identical ciphertext blocks. Think “penguin image with a blanket of leaks.”
  * CBC = chains each block with the previous → fixes ECB’s pattern problem, but needs IV.
  * CTR = turns block cipher into a stream cipher using counters.
  * GCM = encryption + authentication.

**Epic storytelling hook**:
ECB is like encoding a book by substituting every letter with another letter consistently. Patterns leak (like “THE” appearing repeatedly). CBC is like writing each letter while also scrambling it based on the letter before it—context matters.

---

### 2. **Stream Ciphers**

* Work on one symbol/bit at a time.
* Generate a keystream that is XORed with plaintext.
* Faster, often used for real-time applications (e.g., video streaming).
* Example: ChaCha20 (modern, secure, widely used in TLS/HTTPS).

---

## **Part II: Hash Functions**

### 1. **What is a Hash?**

* A one-way function that maps arbitrary-length input → fixed-size digest.
* Properties:

  * **Deterministic**: same input = same output.
  * **Collision-resistant**: hard to find two inputs with the same output.
  * **Preimage-resistant**: hard to reverse a hash.
  * **Avalanche effect**: tiny input change drastically changes output.

**Example**:
Hash("Hello") → `185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969`
Hash("hello") → completely different digest.

### 2. **SHA-256**

* Produces a 256-bit digest.
* Backbone of Bitcoin, TLS, Git commit hashes.
* Visualization: a **digital fingerprint**. Even a single pixel changed in an image completely alters the hash.

---

## **Part III: Message Authentication Codes (MACs)**

### 1. **Why MACs?**

Hashes alone don’t prove authenticity. Anyone can compute a hash of a forged message.
Solution: add a **secret key** to the hashing process.

### 2. **HMAC (Hash-based MAC)**

* Construction: `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`
* Used everywhere: TLS, JWT tokens, API authentication.

**Epic analogy**:
Think of writing a secret code on a letter using invisible ink only you and your friend know how to mix. A forger might copy the text but cannot reproduce the ink signature.

---

## **Part IV: Pitfalls & Real-World Lessons**

* **Never roll your own crypto** → Always use proven libraries (`aes`, `sha2`, `ring`, `rust-crypto`).
* **Key management matters more than algorithms**. AES is useless if you hardcode the key in GitHub repo.
* **Replay attacks** → MACs don’t prevent replay; you need nonces/timestamps.

---

## **Lecture Recap**

1. Symmetric encryption is fast and efficient but requires key distribution.
2. Hashes give integrity but not authenticity.
3. MACs solve authenticity by combining hashes with secrets.

---

## **Transition to Lab**

Today’s lab:

* Implement **HMAC** in Rust using the `sha2` crate.
* Validate your implementation against Rust’s standard crypto libraries.
* Begin **Project 2: Secure Chat** → where these primitives come together to encrypt and authenticate every message.

---

## **Evening Challenge (Optional)**

* Read about **birthday attacks** and why SHA-1 is broken.
* Try implementing a **nonce-based replay protection mechanism** for your HMAC messages.

---

👉 By the end of Day 6, you’re no longer just encrypting messages — you’re proving their integrity and authenticity. You’ve built the foundation for **trustworthy digital conversations**.
