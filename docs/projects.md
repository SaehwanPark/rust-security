# **Project 1 — Exploit and Patch**

### Overview

In this project, you will receive a Rust codebase containing deliberate security flaws introduced through `unsafe` blocks and poor programming practices. Your task is twofold:

1. **Exploit** the vulnerabilities to demonstrate their impact.
2. **Patch** the codebase to secure it, while maintaining functional correctness.

---

### Objectives

* Practice identifying vulnerabilities in real Rust code.
* Use fuzzing and debugging tools (`cargo fuzz`, `gdb`) to uncover issues.
* Demonstrate exploitation (e.g., buffer overflow, control hijacking).
* Apply defensive programming and Rust safety features to fix them.
* Document before/after states of the vulnerabilities.

---

### Requirements

1. **Exploit Phase**

   * Identify at least **three distinct vulnerabilities** (e.g., buffer overflow, use-after-free, integer overflow).
   * Write minimal proof-of-concept exploits (input strings, crafted payloads, or small scripts).
   * Document how each exploit compromises program integrity.

2. **Patch Phase**

   * Refactor the code to eliminate unsafe patterns.
   * Apply memory safety practices (ownership/borrowing, bounds checks).
   * Re-run `cargo fuzz` to show vulnerabilities are mitigated.

3. **Deliverables**

   * Vulnerability Report (markdown/PDF) with:

     * Vulnerability description
     * Exploitation method
     * Patched code snippet
   * Updated, secure codebase.

---

### Tools & References

* Rust nightly toolchain
* [`cargo fuzz`](https://rust-fuzz.github.io/book/)
* `gdb` or `lldb`
* Reading: *The Rustonomicon* (unsafe Rust)

---

---

# **Project 2 — Secure Chat**

### Overview

You will build a **command-line encrypted chat application** in Rust. The application should support secure peer-to-peer communication using both symmetric and asymmetric cryptography.

---

### Objectives

* Implement key exchange (RSA or Diffie-Hellman).
* Derive a symmetric session key for encryption (AES or ChaCha20).
* Ensure integrity with HMAC or authenticated encryption (AES-GCM).
* Provide a usable CLI interface for chat.

---

### Requirements

1. **Functional Requirements**

   * CLI interface: `./secure_chat --server` and `./secure_chat --client <ip:port>`.
   * Server listens for connections; client connects to server.
   * Secure key exchange on connection (RSA, DH, or ECDH).
   * Derive session key and use symmetric encryption for messages.
   * Ensure message integrity (MAC or AEAD).
   * Support at least **two peers** exchanging messages in real time.

2. **Security Requirements**

   * Do not transmit plaintext keys.
   * Use fresh random session keys per connection.
   * Handle replay attacks (nonce/counter).
   * Prevent downgrade attacks in protocol negotiation.

3. **Deliverables**

   * Source code with clear module separation (`crypto.rs`, `network.rs`, `main.rs`).
   * README with:

     * Cryptographic design (algorithms, key sizes)
     * Usage instructions
     * Security considerations

---

### Tools & References

* [`rsa`](https://crates.io/crates/rsa), [`aes`](https://crates.io/crates/aes), [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305), [`sha2`](https://crates.io/crates/sha2)
* [`tokio`](https://crates.io/crates/tokio) for async networking
* Reading: Boneh & Shoup, *A Graduate Course in Applied Cryptography* (Ch. 12–14)

---

---

# **Project 3 — Hardened Web API**

### Overview

In this project, you will design and implement a secure REST API in Rust. The goal is to apply web security best practices: authentication, TLS, input validation, and safe error handling.

---

### Objectives

* Build a web service with Rust (`actix-web` or `axum`).
* Secure endpoints with authentication and HTTPS.
* Defend against common attacks (SQL injection, XSS, CSRF).
* Document security posture and trade-offs.

---

### Requirements

1. **Functional Requirements**

   * API exposes at least **three endpoints**, e.g.:

     * `POST /login`
     * `GET /data`
     * `POST /update`
   * Backend persistence with SQLite/Postgres.
   * Authentication via JWT tokens or session cookies.
   * HTTPS enabled (self-signed certs acceptable for demo).

2. **Security Requirements**

   * Input validation (reject malformed/unsafe input).
   * Parameterized SQL queries (no injection).
   * CSRF protection for state-changing requests.
   * XSS prevention (output encoding).
   * Rate limiting on login endpoint.

3. **Deliverables**

   * Source code (well-structured, idiomatic Rust).
   * README with:

     * Security design choices
     * Threat model
     * Deployment instructions
   * Security test report (e.g., SQLi/XSS attempts + results).

---

### Tools & References

* [`actix-web`](https://actix.rs/) or [`axum`](https://crates.io/crates/axum)
* [`sqlx`](https://crates.io/crates/sqlx) for safe database queries
* [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) for JWT
* [`rustls`](https://crates.io/crates/rustls) for TLS
* OWASP Top 10 (2021)
