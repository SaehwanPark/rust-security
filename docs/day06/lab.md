# Day 6 Lab — HMAC (SHA-256) in Rust

## Goals

1. Implement **HMAC-SHA256** from first principles.
2. Validate correctness against **RFC 4231** test vectors.
3. Build a tiny **CLI** that computes HMACs for strings/files.
4. (Stretch) Add **nonce/replay protection** and constant-time verification.
5. (Stretch) Wire this into **Project 2: Secure Chat** message framing.

---

## Hints & Common Pitfalls

* **Block size mismatch**: SHA-256 has **block size 64 bytes** (not 32). Using 32 breaks HMAC.
* **Key > block size**: You **must hash the key** then pad to 64; do not truncate without hashing.
* **iv/ipad/opad confusion**: iPad = `0x36`, oPad = `0x5c`. You XOR these with the **block-sized key**.
* **Correct concatenation**: Inner is `H(ipad || msg)`, outer is `H(opad || inner_digest)`.
* **Hex vs UTF-8 keys**: This lab lets you provide a key as `0x...` hex or raw string; know which you’re using.
* **Constant-time compare**: Always use timing-safe comparisons for tags (we used `subtle`).

---

## Concept Check (Mini-Qs)

1. Why does a plain hash **not** provide authenticity?
2. If an attacker replays a valid `(msg, tag)`, will HMAC detect it? If not, what do you add?
3. Why is **ECB** mode discouraged for encryption? How does this relate to **integrity**?

(Answers: 1) No secret in the hash function; anyone can recompute. 2) No; add nonces/timestamps or sequence numbers. 3) Patterns leak; integrity still needs MAC/AEAD.)

---

## Stretch: Nonce/Replay Protection

**Goal:** Define a message frame that includes:

```
nonce || timestamp || msg || hmac
```

* The HMAC is over `nonce || timestamp || msg`.
* Maintain a **seen-nonce** cache or require strictly **monotonic timestamps/sequence numbers**.
* Verification steps:

  1. Check `!seen(nonce)` and timestamp is within window.
  2. Recompute HMAC and timing-safe compare.
  3. Mark `nonce` as seen.

> Tip: Use `rand::rngs::OsRng` + `rand::RngCore` for nonces. Reject duplicates.

---

## Stretch: Project 2 “Secure Chat” Hook

* Define a `Frame` struct:

  ```rust
  struct Frame {
      nonce: [u8; 12],
      ts_ms: u64,
      msg: Vec<u8>,
      tag: [u8; 32],
  }
  ```
* Serialize with `bincode` or length-prefix fields.
* Sender:

  1. Generate nonce + timestamp.
  2. Compute `tag = HMAC(k, nonce || ts || msg)`.
  3. Send.
* Receiver:

  1. Check replay (nonce/timestamp).
  2. Verify tag (timing-safe).
  3. Deliver message.

> Optional: In Day 8 you’ll add **TLS**. For now, the point is mastering correctness and framing.

---

## What “Good” Looks Like (Acceptance)

* `cargo test` passes RFC vectors.
* Manual HMAC == crate HMAC.
* CLI prints identical tags for `--show_both`.
* `verify` subcommand accepts the tag you just printed.
* (Stretch) Nonce/timestamp logic rejects replays.

---

## Debrief: Why This Matters

* HMAC is the backbone of API auth, token signing, and protocol integrity.
* Subtle bugs (key handling, block size, compare) break security.
* Building it once “by hand” demystifies how the library works — and helps you use it correctly.

---

## Deliverables

* `examples/hmac_sha256_from_scratch.rs` — HMAC Sha256 Implementation
* `examples/test_rfc4231.rs` — Test with RFC 4231 vectors.
* `examples/cli_hmac.rs` — CLI that computes HMACs for strings/files
* `examples/secure_hmac.rs` — Secure HMAC with Nonce Protection
