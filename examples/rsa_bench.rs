//! Benchmark RSA encrypt/decrypt across sizes and paddings.
//! Examples:
//!   cargo run --example rsa_bench
//!   cargo run --example rsa_bench -- --sizes 1024 2048 4096 --padding oaep pkcs1v15
use anyhow::{Result, anyhow};
use clap::Parser;
use rand::thread_rng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use sha2::Sha256;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(version, about = "RSA benchmark for sizes & paddings")]
struct Args {
  /// Key sizes in bits
  #[arg(long, default_values_t = vec![1024, 2048, 4096])]
  sizes: Vec<usize>,
  /// Padding modes: "oaep" and/or "pkcs1v15"
  #[arg(long, default_values_t = vec!["oaep".to_string(), "pkcs1v15".to_string()])]
  padding: Vec<String>,
  /// Repetitions per measurement
  #[arg(long, default_value_t = 10)]
  reps: usize,
}

fn bench_with_padding(bits: usize, padding: &str, reps: usize) -> Result<()> {
  let mut rng = thread_rng();
  let msg = b"The quick brown fox jumps over the lazy dog";

  let privkey = RsaPrivateKey::new(&mut rng, bits)?;
  let pubkey = RsaPublicKey::from(&privkey);

  match padding {
    "oaep" => {
      let t0 = Instant::now();
      let mut last_ct = Vec::new();
      for _ in 0..reps {
        last_ct = pubkey.encrypt(&mut rng, Oaep::new::<Sha256>(), msg)?;
      }
      let enc_elapsed = t0.elapsed();

      let t1 = Instant::now();
      let mut last_pt = Vec::new();
      for _ in 0..reps {
        last_pt = privkey.decrypt(Oaep::new::<Sha256>(), &last_ct)?;
      }
      let dec_elapsed = t1.elapsed();

      println!(
        "size={} padding=OAEP  enc_ms={:.3}  dec_ms={:.3}",
        bits,
        enc_elapsed.as_secs_f64() * 1e3,
        dec_elapsed.as_secs_f64() * 1e3
      );
      // basic correctness check
      assert_eq!(last_pt, msg);
    }
    "pkcs1v15" => {
      let t0 = Instant::now();
      let mut last_ct = Vec::new();
      for _ in 0..reps {
        last_ct = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, msg)?;
      }
      let enc_elapsed = t0.elapsed();

      let t1 = Instant::now();
      let mut last_pt = Vec::new();
      for _ in 0..reps {
        last_pt = privkey.decrypt(Pkcs1v15Encrypt, &last_ct)?;
      }
      let dec_elapsed = t1.elapsed();

      println!(
        "size={} padding=PKCS1v1.5  enc_ms={:.3}  dec_ms={:.3}",
        bits,
        enc_elapsed.as_secs_f64() * 1e3,
        dec_elapsed.as_secs_f64() * 1e3
      );
      assert_eq!(last_pt, msg);
    }
    other => return Err(anyhow!("unknown padding: {}", other)),
  }

  Ok(())
}

fn main() -> Result<()> {
  let args = Args::parse();
  for &bits in &args.sizes {
    for p in &args.padding {
      bench_with_padding(bits, p, args.reps)?;
    }
  }
  eprintln!(
    "\nReminder: PKCS#1 v1.5 encryption is deterministic — identical inputs → identical ciphertexts; avoid it in new designs."
  );
  Ok(())
}
