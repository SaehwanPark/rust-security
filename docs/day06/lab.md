# Day 6 Lab — HMAC (SHA-256) in Rust

## Goals

1. Implement **HMAC-SHA256** from first principles.
2. Validate correctness against **RFC 4231** test vectors and the official **`hmac`** crate.
3. Build a tiny **CLI** that computes HMACs for strings/files.
4. (Stretch) Add **nonce/replay protection** and constant-time verification.
5. (Stretch) Wire this into **Project 2: Secure Chat** message framing.

---

## Sample Project Layout For Day 6 Lab

```
day06_hmac/
├─ Cargo.toml
└─ src/
   ├─ lib.rs         # pure library with manual HMAC + helpers
   └─ main.rs        # CLI: hmac <key> (--text <msg> | --file <path>)
```

### `Cargo.toml`

```toml
[package]
name = "day06_hmac"
version = "0.1.0"
edition = "2024"

[dependencies]
sha2 = "0.10"
hmac = "0.12"
hex = "0.4"
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"
subtle = "2.5"     # timing-safe equality
```

---

## Step 1 — Implement HMAC Manually

### `src/lib.rs`

```rust
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// HMAC with SHA-256, manual construction per RFC 2104 / 4231.
pub fn hmac_sha256_manual(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64; // block size in bytes for SHA-256
    // Step 1: process key to block-sized K0
    let mut k0 = [0u8; B];
    if key.len() > B {
        let hashed = Sha256::digest(key);
        k0[..32].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    // Step 2: ipad/opad
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    // Step 3: inner = H(ipad || msg)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(msg);
    let inner = inner_hasher.finalize();

    // Step 4: outer = H(opad || inner)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(inner);
    let out = outer_hasher.finalize();

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Timing-safe compare of two tags.
pub fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Hex helpers for nicer I/O.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Alias for HMAC-SHA256 using the crate
    type HmacSha256 = Hmac<Sha256>;

    fn manual_vs_crate(key: &[u8], msg: &[u8]) {
        let manual = hmac_sha256_manual(key, msg);
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(msg);
        let crate_tag = mac.finalize().into_bytes();
        assert_eq!(manual.as_slice(), crate_tag.as_slice());
    }

    /// RFC 4231 vectors for HMAC-SHA-256 (selected)
    /// Source: https://www.rfc-editor.org/rfc/rfc4231
    #[test]
    fn rfc4231_case_1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b\
                            881dc200c9833da726e9376c2e32cff7";
        let tag = hmac_sha256_manual(&key, data);
        assert_eq!(to_hex(&tag), expected_hex);
        manual_vs_crate(&key, data);
    }

    #[test]
    fn rfc4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected_hex = "5bdcc146bf60754e6a042426089575c7\
                            5a003f089d2739839dec58b964ec3843";
        let tag = hmac_sha256_manual(key, data);
        assert_eq!(to_hex(&tag), expected_hex);
        manual_vs_crate(key, data);
    }

    #[test]
    fn rfc4231_case_3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let expected_hex = "773ea91e36800e46854db8ebd09181a7\
                            2959098b3ef8c122d9635514ced565fe";
        let tag = hmac_sha256_manual(&key, &data);
        assert_eq!(to_hex(&tag), expected_hex);
        manual_vs_crate(&key, &data);
    }

    #[test]
    fn timing_eq_works() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(timing_safe_eq(&a, &b));
        assert!(!timing_safe_eq(&a, &c));
    }
}
```

**Run the tests:**

```bash
cargo test
```

You should see all tests pass. If not, check the block size (64 for SHA-256), ipad/opad constants, and that you used the **hashed** key when `key.len() > 64`.

---

## Step 2 — Compare with the Official `hmac` Crate in a CLI

### `src/main.rs`

```rust
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use day06_hmac::{hmac_sha256_manual, timing_safe_eq, to_hex};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{fs, path::PathBuf};

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "hmac")]
#[command(about = "HMAC-SHA256 CLI (manual vs crate)")]
struct Cli {
    /// The secret key (hex: prefix with 0x..., else treated as UTF-8).
    key: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute HMAC of a UTF-8 text message
    Text {
        /// Message string
        #[arg(long)]
        msg: String,

        /// Print both manual and crate outputs
        #[arg(long, default_value_t = false)]
        show_both: bool,
    },
    /// Compute HMAC of a file's raw bytes
    File {
        /// Path to file
        #[arg(long)]
        path: PathBuf,

        /// Print both manual and crate outputs
        #[arg(long, default_value_t = false)]
        show_both: bool,
    },
    /// Verify a provided tag (hex) against the computed HMAC
    Verify {
        #[arg(long)]
        msg: Option<String>,

        #[arg(long)]
        path: Option<PathBuf>,

        /// Expected HMAC tag (hex)
        #[arg(long)]
        tag_hex: String,
    },
}

fn parse_key(k: &str) -> Result<Vec<u8>> {
    let k = k.trim();
    if let Some(stripped) = k.strip_prefix("0x") {
        Ok(hex::decode(stripped).context("invalid hex key")?)
    } else {
        Ok(k.as_bytes().to_vec())
    }
}

fn hmac_both(key: &[u8], msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let manual = hmac_sha256_manual(key, msg).to_vec();
    let mut mac = HmacSha256::new_from_slice(key).expect("key size ok");
    mac.update(msg);
    let lib = mac.finalize().into_bytes().to_vec();
    (manual, lib)
}

fn load_msg(msg: &Option<String>, path: &Option<PathBuf>) -> Result<Vec<u8>> {
    match (msg, path) {
        (Some(m), None) => Ok(m.as_bytes().to_vec()),
        (None, Some(p)) => Ok(fs::read(p).with_context(|| format!("reading {}", p.display()))?),
        _ => bail!("Provide either --msg or --path (but not both)"),
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let key = parse_key(&args.key)?;

    match args.cmd {
        Command::Text { msg, show_both } => {
            let (manual, lib) = hmac_both(&key, msg.as_bytes());
            if show_both {
                println!("manual: {}", to_hex(&manual));
                println!(" crate: {}", to_hex(&lib));
            } else {
                println!("{}", to_hex(&manual));
            }
        }
        Command::File { path, show_both } => {
            let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let (manual, lib) = hmac_both(&key, &data);
            if show_both {
                println!("manual: {}", to_hex(&manual));
                println!(" crate: {}", to_hex(&lib));
            } else {
                println!("{}", to_hex(&manual));
            }
        }
        Command::Verify { msg, path, tag_hex } => {
            let expected = hex::decode(tag_hex.trim())?;
            let data = load_msg(&msg, &path)?;
            let (manual, lib) = hmac_both(&key, &data);
            if !timing_safe_eq(&manual, &expected) {
                println!("manual:   {}", to_hex(&manual));
                println!("expected: {}", to_hex(&expected));
                bail!("verification failed (manual)");
            }
            if !timing_safe_eq(&lib, &expected) {
                println!(" crate:   {}", to_hex(&lib));
                println!("expected: {}", to_hex(&expected));
                bail!("verification failed (crate)");
            }
            println!("OK (timing-safe match).");
        }
    }
    Ok(())
}
```

### Try it out

```bash
# Build & test
cargo test
cargo run -- --help

# Case 1 (RFC 4231)
cargo run -- "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" \
  text --msg "Hi There" --show_both

# Jefe vector (RFC 4231)
cargo run -- Jefe text --msg "what do ya want for nothing?" --show_both

# File mode
echo -n "secret file contents" > /tmp/secret.txt
cargo run -- "mykey" file --path /tmp/secret.txt --show_both

# Verification (copy the output tag)
cargo run -- mykey verify --path /tmp/secret.txt --tag_hex <paste_tag_here>
```

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

## Step 3 — Stretch: Nonce/Replay Protection

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

## Step 4 — Stretch: Project 2 “Secure Chat” Hook

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
