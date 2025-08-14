### src/lib.rs
```rust
//! Helpers shared across binaries.

use rand::rngs::OsRng;
use rand::RngCore;
use anyhow::{anyhow, Result};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn parse_hex_to_bytes(h: &str) -> Result<Vec<u8>> {
    let s = h.trim();
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex string length must be even"));
    }
    Ok(hex::decode(s)?)
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
````

---

### src/bin/xor.rs

```rust
use anyhow::{Result, anyhow};
use clap::Parser;
use std::fs;
use std::io::{self, Read};

/// Simple XOR cipher (symmetric). Educational only.
#[derive(Parser, Debug)]
#[command(name = "xor")]
#[command(about = "XOR cipher for text or files")]
struct Args {
    /// Key used for XOR (as UTF-8 text)
    #[arg(long)]
    key: String,

    /// Text input (mutually exclusive with --in)
    #[arg(long, conflicts_with = "in_path")]
    text: Option<String>,

    /// Hex-encoded input (mutually exclusive with --in, --text)
    #[arg(long, conflicts_with_all = ["in_path", "text"])]
    hex_in: Option<String>,

    /// Input file path (mutually exclusive with --text)
    #[arg(long, value_name = "FILE", conflicts_with = "text")]
    in_path: Option<String>,

    /// Output file path (optional). If omitted, prints hex to stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<String>,
}

fn xor_cipher(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.key.is_empty() {
        return Err(anyhow!("key must not be empty"));
    }
    let key = args.key.as_bytes();

    let input_bytes: Vec<u8> = if let Some(t) = args.text {
        t.into_bytes()
    } else if let Some(h) = args.hex_in {
        hex::decode(h)?
    } else if let Some(p) = args.in_path {
        fs::read(p)?
    } else {
        // read from stdin
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    let out = xor_cipher(&input_bytes, key);
    let hex_out = hex::encode(&out);

    if let Some(out_path) = args.out {
        fs::write(out_path, hex_out)?;
    } else {
        println!("{hex_out}");
    }
    Ok(())
}
```

---

### src/bin/aes\_cbc.rs

```rust
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use aes::Aes128;
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

#[derive(Parser, Debug)]
#[command(name = "aes_cbc")]
#[command(about = "AES-128 CBC encrypt/decrypt text or files (PKCS#7 padding)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt input (text or file). By default requires --key-hex and --iv-hex (32-hex each)
    Encrypt {
        /// Input file path. If omitted, use --text or STDIN.
        #[arg(long, value_name = "FILE")]
        r#in: Option<String>,

        /// Treat input as text (UTF-8). Conflicts with --in
        #[arg(long, conflicts_with = "in")]
        text: Option<String>,

        /// Output file path (binary ciphertext). If omitted, writes to STDOUT.
        #[arg(long, value_name = "FILE")]
        out: Option<String>,

        /// 16-byte key as hex (32 hex chars)
        #[arg(long, value_parser = parse_hex_16)]
        key_hex: Option<Vec<u8>>,

        /// 16-byte IV as hex (32 hex chars)
        #[arg(long, value_parser = parse_hex_16)]
        iv_hex: Option<Vec<u8>>,

        /// If set, generate random key/iv and print them (encrypt only)
        #[arg(long, default_value_t=false)]
        gen_key_iv: bool,
    },
    /// Decrypt input file or hex with AES-128-CBC (PKCS#7)
    Decrypt {
        /// Input file (binary ciphertext). If omitted, reads hex from --hex or STDIN.
        #[arg(long, value_name = "FILE")]
        r#in: Option<String>,

        /// Hex-encoded ciphertext (conflicts with --in)
        #[arg(long, conflicts_with = "in")]
        hex: Option<String>,

        /// Output path for plaintext (if omitted prints as UTF-8 where possible)
        #[arg(long, value_name = "FILE")]
        out: Option<String>,

        /// 16-byte key as hex (32 hex chars) [required]
        #[arg(long, value_parser = parse_hex_16)]
        key_hex: Vec<u8>,

        /// 16-byte IV as hex (32 hex chars) [required]
        #[arg(long, value_parser = parse_hex_16)]
        iv_hex: Vec<u8>,
    },
}

fn parse_hex_16(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    match hex::decode(s) {
        Ok(bytes) if bytes.len() == 16 => Ok(bytes),
        Ok(_) => Err("expected 16 bytes (32 hex chars)".into()),
        Err(e) => Err(format!("invalid hex: {e}")),
    }
}

fn read_all(path: Option<String>, text: Option<String>) -> Result<Vec<u8>> {
    if let Some(p) = path {
        Ok(fs::read(p)?)
    } else if let Some(t) = text {
        Ok(t.into_bytes())
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encrypt { r#in, text, out, key_hex, iv_hex, gen_key_iv } => {
            let mut key = key_hex.unwrap_or_default();
            let mut iv  = iv_hex.unwrap_or_default();

            if gen_key_iv {
                if key.is_empty() { key = rand_bytes(16); }
                if iv.is_empty()  { iv  = rand_bytes(16); }
                eprintln!("key-hex={}", hex::encode(&key));
                eprintln!("iv-hex={}",  hex::encode(&iv));
            }

            if key.len() != 16 || iv.len() != 16 {
                return Err(anyhow!("key/iv must be 16 bytes each (provide --key-hex and --iv-hex or use --gen-key-iv)"));
            }

            let plaintext = read_all(in_to_owned(r#in), text)?;
            let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
            let ciphertext = cipher.encrypt_vec(&plaintext);

            if let Some(path) = out {
                fs::write(path, &ciphertext)?;
            } else {
                println!("{}", hex::encode(&ciphertext));
            }
        }
        Cmd::Decrypt { r#in, hex: hex_in, out, key_hex, iv_hex } => {
            let ciphertext = if let Some(path) = r#in {
                fs::read(path)?
            } else if let Some(h) = hex_in {
                hex::decode(h)?
            } else {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                hex::decode(buf.trim())?
            };

            let cipher = Aes128Cbc::new_from_slices(&key_hex, &iv_hex).unwrap();
            let decrypted = cipher.decrypt_vec(&ciphertext)
                .map_err(|e| anyhow!("decrypt failed: {e}"))?;

            if let Some(path) = out {
                fs::write(path, &decrypted)?;
            } else {
                match String::from_utf8(decrypted.clone()) {
                    Ok(s) => println!("{s}"),
                    Err(_) => {
                        io::stdout().write_all(&decrypted)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn in_to_owned(p: Option<String>) -> Option<String> { p }
```

---

### src/bin/aes\_ecb\_image.rs

```rust
use anyhow::{Result, anyhow};
use clap::Parser;
use image::{io::Reader as ImageReader, DynamicImage, ImageBuffer, Rgba};
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

/// Encrypt image pixel data block-by-block with AES-128 in ECB (no padding),
/// producing a same-sized image that reveals ECB pattern leakage.
#[derive(Parser, Debug)]
#[command(name = "aes_ecb_image")]
#[command(about = "ECB pattern demo: encrypt image pixels blockwise and save as image")]
struct Args {
    /// Input image path (any format supported by `image` crate). Larger flat regions show patterns best.
    #[arg(long, value_name = "FILE")]
    r#in: String,

    /// Output image path. Format inferred by extension (e.g., png, bmp).
    #[arg(long, value_name = "FILE")]
    out: String,

    /// AES-128 key (32 hex chars).
    #[arg(long, value_name = "HEX", value_parser = parse_hex_16)]
    key_hex: Vec<u8>,
}

fn parse_hex_16(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    match hex::decode(s) {
        Ok(bytes) if bytes.len() == 16 => Ok(bytes),
        Ok(_) => Err("expected 16 bytes (32 hex chars)".into()),
        Err(e) => Err(format!("invalid hex: {e}")),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let img = ImageReader::open(&args.r#in)?.decode()?;
    let (w, h) = img.dimensions();
    let mut rgba = img.to_rgba8(); // 4 bytes per pixel
    let buf = rgba.as_mut();

    // AES-128 block cipher
    let cipher = Aes128::new(GenericArray::from_slice(&args.key_hex));

    // Encrypt in-place, block-by-block (no padding). Any leftover < 16 bytes left as-is.
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }

    let out_img: ImageBuffer<Rgba<u8>, _> = ImageBuffer::from_raw(w, h, buf.to_vec())
        .ok_or_else(|| anyhow!("failed to build output image buffer"))?;
    DynamicImage::ImageRgba8(out_img).save(&args.out)?;
    eprintln!("wrote {}", &args.out);
    Ok(())
}
```

---

### src/bin/compare\_modes.rs

```rust
use anyhow::Result;
use clap::Parser;
use aes::Aes128;
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

#[derive(Parser, Debug)]
#[command(name = "compare_modes")]
#[command(about = "Compare AES-128 ECB vs CBC on the same input")]
struct Args {
    /// Input as text (UTF-8)
    #[arg(long)]
    text: String,

    /// 16-byte key as hex (32 hex chars)
    #[arg(long)]
    key_hex: String,

    /// 16-byte IV as hex (32 hex chars) for CBC
    #[arg(long)]
    iv_hex: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let key = hex::decode(args.key_hex.trim()).expect("invalid key hex");
    let iv  = hex::decode(args.iv_hex.trim()).expect("invalid iv hex");
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);

    let ecb = Aes128Ecb::new_from_slices(&key, Default::default()).unwrap();
    let cbc = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

    let ecb_ct = ecb.encrypt_vec(args.text.as_bytes());
    let cbc_ct = cbc.encrypt_vec(args.text.as_bytes());

    println!("ECB ciphertext (hex): {}", hex::encode(&ecb_ct));
    println!("CBC ciphertext (hex): {}", hex::encode(&cbc_ct));
    println!("ECB len: {} | CBC len: {}", ecb_ct.len(), cbc_ct.len());
    Ok(())
}
```
