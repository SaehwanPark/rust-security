//! Educational MITM-style TLS bump proxy for localhost.
//! Listens on 127.0.0.1:8444, presents its own cert to clients,
//! then connects INSECURELY to the real TLS server at 127.0.0.1:8443.
//! Purpose: demonstrate certificate warnings and why trust matters.
//!
//! Setup required:
//!   - Generate a DIFFERENT CA + leaf for the proxy, e.g. certs/evil_ca.pem and certs/evil_server.pem
//!   - The client should NOT trust evil_ca.pem by default -> verification fails (good!).

use anyhow::{Context, Result, anyhow};
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls_pemfile::{Item, read_one};
use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PROXY_BIND: &str = "127.0.0.1:8444";
const REAL_SERVER_ADDR: &str = "127.0.0.1:8443";
const REAL_SERVER_SNI: &str = "localhost";

// Proxy identity (its own cert/key shown to clients).
const EVIL_SERVER_PEM: &str = "certs/evil_server.pem"; // key + cert (key first)

fn load_identity(pem_path: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let mut rdr = BufReader::new(File::open(pem_path).with_context(|| format!("open {}", pem_path))?);

  let mut certs = Vec::new();
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

  Ok((
    certs,
    key.ok_or_else(|| anyhow!("no private key in {}", pem_path))?,
  ))
}

// A deliberately INSECURE verifier for the proxy's upstream connection to the real server.
// DO NOT USE IN PRODUCTION.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
  fn verify_server_cert(
    &self,
    _end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    _server_name: &ServerName<'_>,
    _ocsp: &[u8],
    _now: UnixTime,
  ) -> Result<ServerCertVerified, rustls::Error> {
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    Ok(HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    Ok(HandshakeSignatureValid::assertion())
  }

  // NEW in rustls 0.23: enumerate signature schemes this verifier supports.
  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    vec![
      SignatureScheme::ECDSA_NISTP256_SHA256,
      SignatureScheme::ECDSA_NISTP384_SHA384,
      SignatureScheme::ED25519,
      SignatureScheme::RSA_PSS_SHA256,
      SignatureScheme::RSA_PKCS1_SHA256,
    ]
  }
}

#[tokio::main]
async fn main() -> Result<()> {
  // Build TLS acceptor for client->proxy side (using proxy's own cert).
  let (certs, key) = load_identity(EVIL_SERVER_PEM)?;
  let server_cfg = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
  let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

  // Build TLS connector for proxy->real-server side (intentionally skipping verification!).
  let cfg = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify))
    .with_no_client_auth();
  let connector = TlsConnector::from(Arc::new(cfg));

  let listener = TcpListener::bind(PROXY_BIND).await?;
  println!("MITM demo proxy on https://{PROXY_BIND}  -> upstream {REAL_SERVER_ADDR}");

  loop {
    let (client_tcp, peer) = listener.accept().await?;

    let acceptor = acceptor.clone();
    let connector = connector.clone();

    tokio::spawn(async move {
      // Accept client TLS (client sees proxy's cert)
      let client_tls = match acceptor.accept(client_tcp).await {
        Ok(s) => s,
        Err(e) => {
          eprintln!("[{peer:?}] client handshake failed: {e:?}");
          return;
        }
      };

      // Connect to real server (proxy ignores verification!)
      let upstream_tcp = match TcpStream::connect(REAL_SERVER_ADDR).await {
        Ok(s) => s,
        Err(e) => {
          eprintln!("[{peer:?}] upstream connect failed: {e:?}");
          return;
        }
      };
      let sni = ServerName::try_from(REAL_SERVER_SNI).unwrap();
      let upstream_tls = match connector.connect(sni, upstream_tcp).await {
        Ok(s) => s,
        Err(e) => {
          eprintln!("[{peer:?}] upstream TLS connect failed: {e:?}");
          return;
        }
      };

      // Bi-directional copy between client <-> server
      let (mut cr, mut cw) = tokio::io::split(client_tls);
      let (mut sr, mut sw) = tokio::io::split(upstream_tls);

      let c2s = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
          let n = cr.read(&mut buf).await?;
          if n == 0 {
            break;
          }
          sw.write_all(&buf[..n]).await?;
        }
        sw.shutdown().await?;
        Result::<_, std::io::Error>::Ok(())
      };

      let s2c = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
          let n = sr.read(&mut buf).await?;
          if n == 0 {
            break;
          }
          cw.write_all(&buf[..n]).await?;
        }
        cw.shutdown().await?;
        Result::<_, std::io::Error>::Ok(())
      };

      if let Err(e) = tokio::try_join!(c2s, s2c) {
        eprintln!("[{peer:?}] relay error: {e:?}");
      }
    });
  }
}
