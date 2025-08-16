## XOR Cipher Deep Dive

**How it works:** Each byte of plaintext is XORed with a key byte. The beauty is that XOR is its own inverse: `A ⊕ B ⊕ B = A`.

**Mathematical foundation:**
```
Encryption: C = P ⊕ K
Decryption: P = C ⊕ K = (P ⊕ K) ⊕ K = P
```

**Critical weaknesses:**

1. **Key reuse patterns**: If your key is shorter than the message, it repeats. Characters at positions 0, 3, 6, 9... (if key length is 3) get encrypted with the same key byte, creating detectable patterns.

2. **Known plaintext attacks**: If an attacker knows any plaintext-ciphertext pair, they can recover the key: `Key = Plaintext ⊕ Ciphertext`

3. **Frequency analysis**: Repeated key bytes preserve statistical properties of the language.

**When XOR is strong**: One-Time Pad (OTP) uses XOR with a truly random key as long as the message. This is mathematically proven unbreakable -- but key distribution becomes impossible for large systems.

## ECB (Electronic Codebook) Mode

**How it works:** Split plaintext into fixed-size blocks, encrypt each block independently with the same key.

```
Block 1: C₁ = Encrypt(P₁, K)
Block 2: C₂ = Encrypt(P₂, K)
Block 3: C₃ = Encrypt(P₃, K)
```

**Major weakness -- pattern leakage**:
- Identical plaintext blocks → identical ciphertext blocks
- This creates the famous "ECB penguin" effect in images
- Attackers can see repeated data patterns, file structures, database records, etc.

**Why it's dangerous:**
- Credit card numbers, social security numbers, repeated database entries all become visible
- Block rearrangement attacks: attacker can shuffle encrypted blocks to shuffle plaintext blocks
- Statistical analysis reveals information about data distribution

## CBC (Cipher Block Chaining) Mode

**How it works:** Each plaintext block is XORed with the previous ciphertext block before encryption.

```
C₁ = Encrypt(P₁ ⊕ IV, K)
C₂ = Encrypt(P₂ ⊕ C₁, K)
C₃ = Encrypt(P₃ ⊕ C₂, K)
```

**Why it's much stronger:**
- Chaining breaks patterns: identical plaintext blocks produce different ciphertext blocks
- Avalanche effect: changing one bit affects all subsequent blocks
- IV provides randomization: same message with different IV → completely different ciphertext

**CBC requirements:**
1. **Unique IV per message**: Never reuse IV with the same key
2. **Unpredictable IV**: IV should be random, not just a counter
3. **Proper padding**: Last block needs padding (like PKCS#7) to reach block size

**CBC vulnerabilities:**
- **IV reuse**: If you encrypt two messages with the same key+IV, the XOR of first ciphertext blocks reveals the XOR of first plaintext blocks
- **Padding oracle attacks**: If decryption errors leak padding information
- **Bit-flipping attacks**: Modifying ciphertext block affects next plaintext block predictably

## Comparative Security Analysis

| Attack Vector | XOR | ECB | CBC |
|---------------|-----|-----|-----|
| Pattern leakage | High (key reuse) | High | Low |
| Known plaintext | Critical | Medium | Low |
| Block rearrangement | N/A | High | Medium |
| Parallel processing | N/A | Yes | No (encryption) |
| Error propagation | None | 1 block | 2 blocks |

**Real-world examples:**
- **WEP WiFi**: Used RC4 (stream cipher like XOR) with predictable key scheduling -- broken in minutes
- **Adobe password breach**: Used ECB mode, identical passwords had identical hashes
- **TLS**: Uses CBC (and now preferably AEAD modes like GCM) with proper IV handling

The key insight is that **cryptographic strength comes from both the algorithm AND how it's used**. Even AES becomes vulnerable with ECB mode or IV reuse in CBC mode.

This is why modern systems prefer **AEAD (Authenticated Encryption with Associated Data)** modes like AES-GCM that provide both confidentiality AND authenticity in one operation.
