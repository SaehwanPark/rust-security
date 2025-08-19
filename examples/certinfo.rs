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

// helper structure to hold both the data and certificate together
struct CertificateData {
  der_data: Vec<u8>,
}

impl CertificateData {
  fn from_pem_file(path: &str) -> Result<Self> {
    let pem_data = std::fs::read(path).with_context(|| format!("reading {}", path))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
      .with_context(|| format!("parsing PEM in {}", path))?;

    Ok(CertificateData {
      der_data: pem.contents.to_vec(),
    })
  }

  fn parse_certificate(&self) -> Result<X509Certificate<'_>> {
    let (_, cert) =
      X509Certificate::from_der(&self.der_data).with_context(|| "decoding certificate DER")?;
    Ok(cert)
  }
}

fn print_certificate_info(cert: &X509Certificate<'_>) {
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

  // try to extract RSA modulus size if RSA
  let spk = cert.public_key();
  // clone the data to avoid moving out of shared reference
  let der = spk.subject_public_key.data.clone();
  if let Ok(rsa_pk) = RsaPublicKey::from_pkcs1_der(&der) {
    println!("RSA key size (bits): {}", rsa_pk.size() * 8);
    println!("RSA exponent       : {}", rsa_pk.e());
  } else {
    println!("(RSA details unavailable: SPKI didn't decode as PKCS#1 RSAPublicKey)")
  }
}

fn perform_minimal_checks(
  cert: &X509Certificate<'_>,
  ca_data: Option<&CertificateData>,
  check_signature: bool,
) -> Result<()> {
  println!("\n== Minimal Checks ==");

  // 1) validity window
  let now = ::time::OffsetDateTime::now_utc();
  let not_before = cert.validity().not_before.to_datetime();
  let not_after = cert.validity().not_after.to_datetime();
  let time_ok = now >= not_before && now <= not_after;
  println!("Current time within validity window? {}", time_ok);

  // 2) issuer-subject equality (when CA provided)
  if let Some(ca_data) = ca_data {
    let ca = ca_data.parse_certificate()?;
    let issuer_matches = cert.issuer() == ca.subject();
    println!("Issuer matches provided CA subject? {}", issuer_matches);

    // 3) (bonus/advanced) signature verification sketch with `ring`
    if check_signature {
      use ring::signature;
      let spki = ca.public_key();
      // prepare ring verifier from issuer SPKI
      let alg_id = &cert.signature_algorithm.algorithm;
      // basic mapping for RSA-with-SHA256 (extend as needed)
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

fn main() -> Result<()> {
  let args = Args::parse();

  // load leaf certificate data
  let cert_data = CertificateData::from_pem_file(&args.cert)?;
  let cert = cert_data.parse_certificate()?;

  print_certificate_info(&cert);

  // load issuer certificate data if provided
  let ca_data = if let Some(issuer_path) = args.issuer.as_deref() {
    Some(CertificateData::from_pem_file(issuer_path)?)
  } else {
    None
  };

  perform_minimal_checks(&cert, ca_data.as_ref(), args.check_signature)?;

  Ok(())
}
