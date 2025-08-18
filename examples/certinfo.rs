//! Inspect an X.509 certificate and perform minimal validity / issuer checks.
//! Usage:
//!   cargo run --example certinfo -- fixtures/leaf.pem
//!   cargo run --example certinfo -- fixtures/leaf.pem --issuer fixtures/ca.pem
//! Bonus (signature check) is sketched at bottom behind `--check-signature`.

use anyhow::{Context, Result};
use clap::Parser;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use x509_parser::oid_registry; // keep if you use named OIDs elsewhere
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about = "X.509 certificate inspector")]
struct Args {
  /// Path to a PEM-encoded certificate to inspect
  cert: String,

  /// Optional: path to issuer (CA) certificate for a simple issuer/subject match
  #[arg(long)]
  issuer: Option<String>,

  /// Attempt a signature verification with `ring` (issuer's key required)
  #[arg(long)]
  check_signature: bool,
}

fn load_x509_pem(path: &str) -> Result<X509Certificate<'_>> {
  let data = std::fs::read(path).with_context(|| format!("reading {}", path))?;
  let (_, pem) =
    x509_parser::pem::parse_x509_pem(&data).with_context(|| format!("parsing PEM in {}", path))?;
  let (_, cert) =
    X509Certificate::from_der(pem.contents.as_ref()).with_context(|| "decoding certificate DER")?;
  Ok(cert)
}

fn main() -> Result<()> {
  let args = Args::parse();

  // Load leaf
  let cert = load_x509_pem(&args.cert)?;
  println!("== Certificate ==");
  println!("Subject  : {}", cert.subject());
  println!("Issuer   : {}", cert.issuer());
  println!(
    "Validity : {}  to  {}",
    cert.validity().not_before,
    cert.validity().not_after
  );
  let alg = &cert.public_key().algorithm.algorithm;
  println!("Public Key Algorithm: {}", alg);

  // Try to extract RSA modulus size if RSA
  let spk = cert.public_key();
  // SPKI BIT STRING contains the DER-encoded PKCS#1 RSAPublicKey
  let der = spk.subject_public_key.data;
  if let Ok(rsa_pk) = RsaPublicKey::from_pkcs1_der(&der) {
    println!("RSA key size (bits): {}", rsa_pk.size() * 8);
    println!("RSA exponent       : {}", rsa_pk.e());
  } else {
    println!("(RSA details unavilable: SPKI didn't decode as PKCS#1 RSAPublicKey)")
  }

  // Part 4: minimal checks
  println!("\n== Minimal Checks ==");
  // 1) Validity window
  let now = time::OffsetDateTime::now_utc();
  let not_before = cert.validity().not_before.to_datetime();
  let not_after = cert.validity().not_after.to_datetime();
  let time_ok = now >= not_before && now <= not_after;
  println!("Current time within validity window? {}", time_ok);

  // 2) Issuer-subject equality (when CA provided)
  if let Some(issuer_path) = args.issuer.as_deref() {
    let ca = load_x509_pem(issuer_path)?;
    let issuer_matches = cert.issuer() == ca.subject();
    println!("Issuer matches provided CA subject? {}", issuer_matches);

    // 3) (Bonus/advanced) Signature verification sketch with `ring`
    if args.check_signature {
      use ring::signature;
      let spki = ca.public_key();
      // Prepare ring verifier from issuer SPKI
      let alg_id = &cert.signature_algorithm.algorithm;
      // Basic mapping for RSA-with-SHA256 (extend as needed)
      let ring_alg = if alg_id == &oid_registry::OID_PKCS1_SHA256WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA256
      } else {
        println!("Unsupported signature algorithm OID: {}", alg_id);
        return Ok(());
      };

      let verifier = signature::UnparsedPublicKey::new(ring_alg, &spki.subject_public_key.data);
      let tbs = cert.tbs_certificate.as_ref();
      let sig = cert.signature_value.as_ref();
      match verifier.verify(tbs, sig) {
        Ok(()) => println!("Signature verified: OK"),
        Err(e) => println!("Signature verified: FAIL ({e})"),
      }
    }
  } else {
    println!("(No CA provided; skipped issuer and signature checks.)");
  }

  Ok(())
}
