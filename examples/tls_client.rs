//! Minimal TLS client using rustls + tokio.
//! Connects to 127.0.0.1:8443 as "localhost", verifies with local CA (certs/ca.pem),
//! sends a couple of lines, prints echoes.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_pemfile::{Item, read_one};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const ADDR: &str = "127.0.0.1:8443";
const SNI: &str = "localhost";
const CA_PEM: &str = "certs/ca.pem"; // Required for this client

fn client_config_with_local_ca() -> Result<Arc<rustls::ClientConfig>> {
  // Create an empty RootCertStore and fill it with our lab CA.
  let mut roots = rustls::RootCertStore::empty();

  let file = File::open(CA_PEM).with_context(|| format!("open {}", CA_PEM))?;
  let mut rdr = BufReader::new(file);

  let mut loaded_any = false;
  while let Some(item) = read_one(&mut rdr)? {
    if let Item::X509Certificate(der) = item {
      roots.add(CertificateDer::from(der))?;
      loaded_any = true;
    }
  }
  if !loaded_any {
    anyhow::bail!("no X.509 certificates found in {}", CA_PEM);
  }

  let cfg = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

  Ok(Arc::new(cfg))
}

#[tokio::main]
async fn main() -> Result<()> {
  let cfg = client_config_with_local_ca()?;
  let connector = TlsConnector::from(cfg);

  let tcp = TcpStream::connect(ADDR)
    .await
    .with_context(|| format!("connect {}", ADDR))?;

  let server_name = ServerName::try_from(SNI).context("invalid server name")?;
  let mut tls = connector
    .connect(server_name, tcp)
    .await
    .context("TLS connect")?;

  // Send a couple of test lines
  tls.write_all(b"hello\n").await?;
  tls.write_all(b"tls\n").await?;
  tls.flush().await?;

  // Read back echoes
  let (r, _w) = tokio::io::split(tls);
  let mut lines = AsyncBufReader::new(r).lines();
  while let Some(line) = lines.next_line().await? {
    println!("echo: {line}");
  }
  Ok(())
}
