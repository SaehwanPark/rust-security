//! Minimal TLS echo server using rustls + tokio.
//! Listens on 127.0.0.1:8443 and echoes each received line.
//!
//! Prereqs (choose one):
//! - Option A (quick): self-signed leaf in certs/server.pem (key + cert concatenated, key first)
//! - Option B (recommended): CA-signed leaf (still bundle key+cert as server.pem); keep CA at certs/ca.pem

use anyhow::{Context, Result, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{Item, read_one};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const BIND_ADDR: &str = "127.0.0.1:8443";
const SERVER_PEM: &str = "certs/server.pem";

fn load_server_identity() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let mut rdr =
    BufReader::new(File::open(SERVER_PEM).with_context(|| format!("open {}", SERVER_PEM))?);

  let mut certs: Vec<CertificateDer<'static>> = Vec::new();
  let mut key: Option<PrivateKeyDer<'static>> = None;

  while let Some(item) = read_one(&mut rdr)? {
    match item {
      Item::X509Certificate(der) => certs.push(CertificateDer::from(der)),
      // --- private keys (pick the first we encounter) ---
      Item::Pkcs8Key(der) if key.is_none() => {
        key = Some(PrivateKeyDer::Pkcs8(der));
      }
      Item::Pkcs1Key(der) if key.is_none() => {
        key = Some(PrivateKeyDer::Pkcs1(der));
      }
      Item::Sec1Key(der) if key.is_none() => {
        key = Some(PrivateKeyDer::Sec1(der));
      }
      _ => {}
    }
  }

  let key = key.ok_or_else(|| anyhow!("no private key found in {}", SERVER_PEM))?;
  if certs.is_empty() {
    return Err(anyhow!("no certificate(s) found in {}", SERVER_PEM));
  }
  Ok((certs, key))
}

#[tokio::main]
async fn main() -> Result<()> {
  // Load server cert chain + private key.
  let (certs, key) = load_server_identity()?;

  // Build rustls ServerConfig (no client auth for the basic lab).
  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("with_single_cert")?;

  let acceptor = TlsAcceptor::from(Arc::new(server_config));

  let listener = TcpListener::bind(BIND_ADDR)
    .await
    .with_context(|| format!("bind {}", BIND_ADDR))?;
  println!("TLS echo server listening on https://{BIND_ADDR}");

  loop {
    let (tcp, peer) = listener.accept().await?;
    let acceptor = acceptor.clone();

    tokio::spawn(async move {
      let tls = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
          eprintln!("[{peer:?}] handshake failed: {e:?}");
          return;
        }
      };

      let (r, mut w) = tokio::io::split(tls);
      let mut lines = AsyncBufReader::new(r).lines();

      while let Ok(Some(line)) = lines.next_line().await {
        // Simple echo + newline
        if let Err(e) = w.write_all(line.as_bytes()).await {
          eprintln!("[{peer:?}] write failed: {e:?}");
          break;
        }
        if let Err(e) = w.write_all(b"\n").await {
          eprintln!("[{peer:?}] write failed: {e:?}");
          break;
        }
      }
    });
  }
}
