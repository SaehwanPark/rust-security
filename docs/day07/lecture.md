# Day 7 — Public-Key Cryptography & PKI

## 0) North Star

By tonight you should be able to:

* explain RSA, Diffie–Hellman, and ECDSA at the “math-story” level,
* implement safe RSA (OAEP) and perform key agreement (X25519) in Rust,
* parse and sanity-check X.509 certificates,
* articulate how PKI binds identity to keys — and how it can fail.

---

## 1) The Epic Hook: “Whispering in a Crowd”

Yesterday you learned to protect bytes with symmetric keys. Today we answer: **how do we create that key in the first place, over an eavesdropped network?**
Public-key crypto solves this bootstrap; PKI solves the “who are you, really?” part.

---

## 2) Visual Explanations

### 2.1 RSA — Keygen → Encrypt → Decrypt

```mermaid
flowchart TD
  A[Choose large primes p, q] --> B[n = p * q]
  B --> C["φ(n) = (p-1)(q-1)"]
  C --> D["Pick e (usually 65537) with gcd(e, φ)=1"]
  D --> E["Compute d ≡ e^{-1} mod φ(n)"]
  E --> F["Public key = (n, e)"]
  E --> G["Private key = (n, d)"]
```

```mermaid
flowchart LR
  M[Plaintext m] -->|c = m^e mod n| C[Ciphertext c]
  C -->|m = c^d mod n| M2[Recovered m]
  F["(Public (n,e))"] -. used by .-> C
  G["(Private (n,d))"] -. used by .-> M2
```

**Safety notes**: never “raw RSA”. Use OAEP for encryption and PSS for signatures. Use hybrid encryption (RSA/ECDH for keys; AES/ChaCha20 for data).

---

### 2.2 Diffie–Hellman (classic) — Key Agreement

```mermaid
sequenceDiagram
  participant A as Alice
  participant B as Bob
  participant E as Eve
  Note over A,B: Public parameters (p, g)
  A->>B: A = g^a mod p
  B->>A: B = g^b mod p
  A->>A: s = B^a mod p
  B->>B: s = A^b mod p
  E-->>E: Sees A and B but not a or b (discrete log is hard)
```

**Modern practice**: use elliptic-curve DH (X25519) — faster, shorter keys, safer defaults.

---

### 2.3 ECDSA — Signing & Verifying

```mermaid
flowchart TD
  S[Message M] --> H["Hash h = H(M)"]
  H --> K[Choose fresh random k]
  K --> R["r = (k·G).x mod n"]
  H --> D[d = private key]
  R --> S1["s = k^{-1}(h + r·d) mod n"]
  S1 --> Sig["(Signature (r, s))"]
  Sig --> V["Verify with Q = d·G"]
  V --> V1["Compute w = s^{-1} mod n; u1 = h·w; u2 = r·w"]
  V1 --> V2["X = u1·G + u2·Q; valid if X.x mod n = r"]
```

---

### 2.4 PKI — Who Do You Trust?

```mermaid
sequenceDiagram
  participant Browser
  participant Server
  participant Int as Intermediate CA
  participant Root as Root CA (Trust Store)

  Server->>Browser: Presents chain [EE cert, Intermediate cert]
  Browser->>Int: Verify EE cert signature with Intermediate pubkey
  Browser->>Root: Verify Intermediate signature with Root pubkey (pre-trusted)
  Browser->>Browser: Check hostname, validity, key usage, revocation (CRL/OCSP)
  Browser-->>Server: Proceed with TLS if all checks pass
```

**Mental model**: crypto proves *a key*; PKI asserts *whose key*.

---

## 3) Pitfalls & Red Flags (the “security engineer’s spidey-sense”)

* Using RSA to encrypt bulk data (don’t — use hybrid).
* PKCS#1 v1.5 padding for encryption (use **OAEP**).
* Deterministic or reused ECDSA nonce `k` (catastrophic key leak).
* Trusting “TLS is present” without validating the **chain, hostname, validity, EKU, and revocation**.
* Rolling your own randomness or KDF.

---

## 4) Quick Checks (self-quiz)

1. Why does public-key crypto solve the “first key” problem that symmetric crypto has?
2. In DH, Eve sees $g^a$ and $g^b$. Why can’t she compute the shared secret?
3. Name three certificate validation checks a browser performs beyond signature verification.
4. Why is ECDSA nonce reuse fatal?
5. When would you pick X25519 over P-256 (and vice versa)?

---

## 5) Reading & Reflection (evening)

* Boneh & Shoup, Chapters 12–14 (RSA, DH, signatures, PKI).
* Case study: DigiNotar 2011 — how a CA breach undermines the web of trust.
* Write a one-page reflection: *“Crypto proves keys; PKI asserts identity — where can each layer fail?”*

---

## 6) Tomorrow’s Bridge

We’ll take these primitives into the real world: **TLS**. You’ll trace the handshake, spot where DH/X25519, signatures, and certificates fit, and build a small TLS service with `rustls`.

---

### (optional) Bonus Diagram — Certificate Path Validation (decision flow)

```mermaid
flowchart TD
  S[Start: EE Certificate] --> C1{Signature ok with issuer?}
  C1 -- No --> R1[Reject: bad signature]
  C1 -- Yes --> C2{Issuer trusted or chain to a trusted root?}
  C2 -- No --> R2[Reject: untrusted issuer]
  C2 -- Yes --> C3{Hostname matches SANs?}
  C3 -- No --> R3[Reject: name mismatch]
  C3 -- Yes --> C4{Within NotBefore/NotAfter?}
  C4 -- No --> R4[Reject: expired/not yet valid]
  C4 -- Yes --> C5{Key Usage/EKU allows TLS server?}
  C5 -- No --> R5[Reject: wrong usage]
  C5 -- Yes --> C6{"Revocation check OK (CRL/OCSP)?"}
  C6 -- No --> R6[Policy decision: soft/hard fail]
  C6 -- Yes --> A[Accept]
```
