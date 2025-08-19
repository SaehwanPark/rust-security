# 📘 Week 2 — Question Bank (Days 6–10)

---

## **Day 6: Symmetric Encryption, Hashes, and MACs**

1. **Open-ended**:
   What is the difference between a hash function and a MAC in terms of security guarantees?
   **Answer**: Hash ensures integrity against accidental corruption, but not authenticity. MAC binds message to a secret key, ensuring authenticity and integrity.

2. **Multiple Choice**:
   Which property is **not required** of a cryptographic hash?
   A) Preimage resistance
   B) Collision resistance
   C) Second-preimage resistance
   D) Fast reversibility
   **Answer**: **D** — hash functions should not be reversible.

3. **Code Interpretation**:

   ```rust
   use sha2::{Sha256, Digest};
   fn main() {
       let mut hasher = Sha256::new();
       hasher.update("hello");
       println!("{:x}", hasher.finalize());
   }
   ```

   What is the output property?
   **Answer**: A 256-bit digest in hex, deterministic for input `"hello"`.

4. **Open-ended**:
   Why is HMAC built on top of a hash instead of just hashing the key concatenated with the message?
   **Answer**: Prevents length-extension attacks and ensures security proofs hold.

5. **Multiple Choice**:
   Which best describes a block cipher used in stream mode (CTR)?
   A) Encrypts block-by-block independently
   B) Generates keystream from block cipher to XOR with plaintext
   C) Only works for short messages
   D) Provides authentication automatically
   **Answer**: **B**.

6. **Open-ended**:
   Why is SHA-1 considered insecure today, even though it still produces 160-bit outputs?
   **Answer**: Collision attacks have become computationally feasible, undermining trust.

---

## **Day 7: Public-Key Cryptography & PKI**

7. **Open-ended**:
   Explain why RSA key generation must use large primes. What risk arises if primes are too small?
   **Answer**: Small primes → factorization feasible → private key derivable.

8. **Multiple Choice**:
   Diffie-Hellman provides:
   A) Encryption only
   B) Key exchange over insecure channel
   C) Digital signatures
   D) Hashing of data
   **Answer**: **B**.

9. **Code Interpretation**:

   ```rust
   use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey};
   use rand::thread_rng;
   fn main() {
       let mut rng = thread_rng();
       let bits = 2048;
       let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
       let pub_key = RsaPublicKey::from(&priv_key);
       println!("{}", pub_key.to_pkcs1_pem().unwrap());
   }
   ```

   What does this output represent?
   **Answer**: PEM-encoded RSA public key, usable for encryption or signature verification.

10. **Open-ended**:
    Why is elliptic curve cryptography (ECC) often preferred over RSA in modern systems?
    **Answer**: Smaller keys, faster operations, same security level.

11. **Multiple Choice**:
    Which role does a certificate authority (CA) play in PKI?
    A) Generates symmetric session keys
    B) Issues and signs digital certificates vouching for identities
    C) Stores encrypted backups
    D) Randomizes memory layout
    **Answer**: **B**.

12. **Open-ended**:
    Why does the PKI model rely on trust anchors (root CAs)? What happens if one is compromised?
    **Answer**: Root CAs bootstrap trust; compromise undermines trust in all certificates they signed.

---

## **Day 8: Secure Communication — TLS, HTTPS**

13. **Open-ended**:
    Walk through the steps of a TLS handshake. Where does asymmetric vs symmetric cryptography appear?
    **Answer**: Asymmetric → key exchange & authentication; Symmetric → bulk encryption after session keys derived.

14. **Multiple Choice**:
    Which of these prevents MITM in TLS?
    A) Random IVs
    B) Server certificate validation
    C) Block cipher padding
    D) Port randomization
    **Answer**: **B**.

15. **Code Interpretation**:

```rust
use tokio_rustls::rustls;
// simplified example
// client config loads CA root certs
```

Why must the client load root CA certs?
**Answer**: To verify server’s certificate chain and prevent MITM.

16. **Open-ended**:
    Why can disabling certificate validation in a TLS client be catastrophic, even if traffic is encrypted?
    **Answer**: Any MITM can impersonate the server by presenting a bogus certificate.

17. **Multiple Choice**:
    Which element of TLS ensures forward secrecy?
    A) Use of RSA key exchange
    B) Use of ephemeral Diffie-Hellman
    C) AES block size
    D) Session resumption tickets
    **Answer**: **B**.

18. **Open-ended**:
    Why is HTTPS considered stronger than HTTP+manual encryption (e.g., AES library applied to payload)?
    **Answer**: HTTPS enforces authentication, integrity, key management, and standardized defense against downgrade/MITM.

---

## **Day 9: Web Security & Attacks**

19. **Open-ended**:
    How does reflected XSS differ from stored XSS in terms of attack surface?
    **Answer**: Reflected → payload embedded in immediate response; Stored → payload saved on server, affects all future viewers.

20. **Multiple Choice**:
    CSRF attacks rely on:
    A) Server failing to validate source of a request
    B) Client failing to sanitize input
    C) Database failing to enforce constraints
    D) User failing to use strong passwords
    **Answer**: **A**.

21. **Code Interpretation**:

```rust
// Vulnerable Actix handler
async fn login(form: web::Form<LoginForm>) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome {}", form.username))
}
```

What vulnerability exists?
**Answer**: No output encoding → XSS possible if username contains HTML/JS.

22. **Open-ended**:
    Why is SQL injection still prevalent despite being well known?
    **Answer**: Legacy code, insecure defaults, lack of parameterized queries, and developer errors.

23. **Multiple Choice**:
    Which best mitigates CSRF?
    A) Input sanitization
    B) Output encoding
    C) CSRF tokens bound to session
    D) Longer passwords
    **Answer**: **C**.

24. **Open-ended**:
    Why is WebAssembly security a concern?
    **Answer**: Provides low-level access in browser, risks side-channel attacks, memory safety issues if host bindings not sandboxed.

---

## **Day 10: Network Attacks, Privacy, and Wrap-Up**

25. **Open-ended**:
    Explain how a SYN flood exhausts server resources.
    **Answer**: Attacker sends many half-open TCP connections, filling connection table and preventing legitimate connections.

26. **Multiple Choice**:
    Which is **not** a common DDoS defense?
    A) Rate limiting
    B) SYN cookies
    C) Certificate revocation
    D) Traffic filtering
    **Answer**: **C**.

27. **Code Interpretation**:

```rust
use tokio::net::TcpStream;
// loop sending SYN-like requests
```

Why does simulating SYN flood in Rust require raw sockets or low-level control?
**Answer**: Standard TCP APIs complete handshake automatically; SYN-only packets require raw socket crafting.

28. **Open-ended**:
    How does Tor provide anonymity at the network level?
    **Answer**: Onion routing encrypts traffic in layers through multiple relays, hiding source/destination.

29. **Multiple Choice**:
    VPNs primarily provide:
    A) Perfect anonymity
    B) Encrypted tunnel between client and VPN server
    C) Application-layer XSS protection
    D) Resistance against all censorship
    **Answer**: **B**.

30. **Open-ended**:
    Looking back at the 2-week bootcamp, what is the conceptual link between “thinking like an attacker” (Day 1) and building “anonymity networks” (Day 10)?
    **Answer**: Both involve anticipating adversarial models — Day 1 focuses on breaking systems, Day 10 on designing resilient systems against adversaries.
