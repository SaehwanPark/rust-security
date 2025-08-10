## **Bootcamp Structure**

* **Audience:** Students with systems programming background (comfortable in Rust, or strong in C/C++ and willing to learn Rust quickly).
* **Daily Format:**

  * *Morning (3h)* — Lecture & discussion
  * *Afternoon (3h)* — Lab & coding exercises in Rust
  * *Evening (optional)* — Reading, challenges, and write-ups
* **Assessment:** 3 mini-projects + daily code challenges

---

## **Day-by-Day Plan**

### **Week 1 — Foundations and Core Defenses**

**Day 1 – Security Mindset & Rust Essentials for Security**

* **Lecture**

  * Security mindset: thinking like an attacker/defender
  * Attack surface mapping
  * Rust’s memory safety model vs. C
* **Lab**

  * Rust refresher: ownership, borrowing, lifetimes
  * Implement a simple CLI password strength checker in Rust
* **Evening**

  * Reading: *Security Engineering*, Ch. 1

---

**Day 2 – Memory Safety & Control Hijacking**

* **Lecture**

  * Buffer overflows, stack smashing
  * How unsafe Rust can mimic C vulnerabilities
* **Lab**

  * Write a vulnerable Rust program with `unsafe` and exploit it
  * Use `cargo fuzz` for discovering memory issues
* **Project 1 Start:** “Exploit and Patch” — Find and patch security bugs in a provided Rust codebase

---

**Day 3 – Defenses & Return-Oriented Programming**

* **Lecture**

  * ASLR, stack canaries, DEP
  * ROP and control flow integrity
* **Lab**

  * Simulate ROP chain in C, then port to `unsafe` Rust
  * Use `gdb` + Rust debugging to trace payload execution
* **Evening**

  * Reading: ROP primer

---

**Day 4 – Privilege Separation & Authentication**

* **Lecture**

  * Least privilege, capability systems
  * Password authentication, MFA, biometric basics
* **Lab**

  * Build a privilege-separated mini-server in Rust using multiple processes
  * Implement salted password hashing with `argon2`
* **Checkpoint:** Project 1 due

---

**Day 5 – Cryptography Fundamentals**

* **Lecture**

  * Cryptographic primitives: symmetric vs. asymmetric
  * Kerckhoffs's principle, threat models
* **Lab**

  * Implement XOR cipher, then AES with Rust `aes` crate
  * Analyze cipher modes: ECB vs. CBC
* **Evening**

  * Reading: *Handbook of Applied Cryptography*, Ch. 1–3

---

### **Week 2 — Protocols, Web, and Networks**

**Day 6 – Symmetric Encryption, Hashes, and MACs**

* **Lecture**

  * Block ciphers, stream ciphers, MACs
  * SHA-256, HMAC construction
* **Lab**

  * Implement HMAC in Rust using `sha2` crate
  * Compare manual vs. library implementations for correctness
* **Project 2 Start:** “Secure Chat” — Build an encrypted messaging tool in Rust

---

**Day 7 – Public-Key Cryptography & PKI**

* **Lecture**

  * RSA, Diffie-Hellman, ECDSA
  * Certificates, PKI trust model
* **Lab**

  * Implement RSA keygen, encryption/decryption in Rust (`rsa` crate)
  * Parse and verify X.509 certs in Rust
* **Evening**

  * Reading: Boneh & Shoup, Ch. 12–14

---

**Day 8 – Secure Communication: TLS, HTTPS**

* **Lecture**

  * TLS handshake, session keys
  * MITM attacks
* **Lab**

  * Build a TLS server/client with `rustls`
  * Implement a MITM proxy to demonstrate certificate warnings
* **Checkpoint:** Project 2 due

---

**Day 9 – Web Security & Attacks**

* **Lecture**

  * XSS, CSRF, SQL injection
  * WebAssembly security implications
* **Lab**

  * Write a vulnerable Rust web service with `actix-web`
  * Exploit it with XSS and SQLi, then patch vulnerabilities
* **Project 3 Start:** “Hardened Web API” — Securely implement a REST API

---

**Day 10 – Network Attacks, Privacy, and Wrap-Up**

* **Lecture**

  * DoS/DDoS, SYN floods
  * Tor, VPNs, anonymity networks
* **Lab**

  * Simulate SYN flood in Rust using `tokio`
  * Build a simple proxy that anonymizes outbound HTTP requests
* **Final Checkpoint:** Project 3 due
* **Wrap-Up**

  * Review key takeaways
  * Further learning roadmap (penetration testing, formal verification)

---

## **Project Summary**

1. **Exploit and Patch (Week 1)** — Find vulnerabilities in Rust code using `unsafe`, fuzzing, and patch them.
2. **Secure Chat (Week 2)** — End-to-end encrypted CLI messenger using symmetric and asymmetric crypto.
3. **Hardened Web API (Week 2)** — Secure API with TLS, authentication, and input validation.

