//! Minimal HTTP/HTTPS Anonymizing Proxy with CONNECT support
//!
//! Quick start:
//!   cargo run --example http_proxy -- 127.0.0.1:8080
//!
//! Test (HTTPS via CONNECT):
//!   curl -x http://127.0.0.1:8080 https://httpbin.org/ip
//!
//! Test (HTTP):
//!   curl -x http://127.0.0.1:8080 http://httpbin.org/get
//!
//! Notes:
//! - Educational proxy; no auth/access controls; do NOT expose to untrusted networks.

use std::{env, io, net::SocketAddr, str::FromStr, time::Duration};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  time::timeout,
};
use url::Url;

const READ_HEAD_LIMIT: usize = 32 * 1024;
const READ_TIMEOUT_MS: u64 = 5_000;
const CONNECT_TIMEOUT_MS: u64 = 5_000;

#[tokio::main]
async fn main() -> io::Result<()> {
  let listen_addr = env::args()
    .nth(1)
    .unwrap_or_else(|| "127.0.0.1:8080".to_string());
  let listen: SocketAddr =
    SocketAddr::from_str(&listen_addr).expect("listen addr, e.g., 127.0.0.1:8080");

  eprintln!("Proxy listening on {}", listen);

  let listener = TcpListener::bind(listen).await?;
  loop {
    let (mut client, peer) = listener.accept().await?;
    tokio::spawn(async move {
      if let Err(e) = handle_client(&mut client).await {
        eprintln!("[{}] error: {}", peer, e);
        let _ = client.shutdown().await;
      }
    });
  }
}

async fn handle_client(client: &mut TcpStream) -> io::Result<()> {
  // Read the request head (until \r\n\r\n), with timeout and limit.
  let mut head = Vec::with_capacity(512);
  read_until_double_crlf(client, &mut head).await?;

  let head_str = String::from_utf8_lossy(&head);
  let mut lines = head_str.split("\r\n");

  let request_line = lines.next().unwrap_or_default().trim();
  if request_line.is_empty() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "empty request line",
    ));
  }

  let mut parts = request_line.split_whitespace();
  let method = parts.next().unwrap_or("");
  let target = parts.next().unwrap_or("");
  let version = parts.next().unwrap_or("HTTP/1.1");

  if method.eq_ignore_ascii_case("CONNECT") {
    handle_connect(client, target, version).await
  } else {
    handle_forward_http(client, method, target, version, &mut lines).await
  }
}

async fn handle_connect(client: &mut TcpStream, target: &str, version: &str) -> io::Result<()> {
  // target like "example.com:443"
  let (host, port) = split_host_port(target, 443)?;
  let mut upstream = connect_with_timeout(&host, port).await?;

  // For CONNECT we just acknowledge tunnel establishment.
  let resp = format!("{version} 200 Connection Established\r\n\r\n");
  client.write_all(resp.as_bytes()).await?;

  // Tunnel bytes both ways
  tunnel(client, &mut upstream).await
}

async fn handle_forward_http<'a>(
  client: &mut TcpStream,
  method: &str,
  target: &str,
  version: &str,
  lines: &mut impl Iterator<Item = &'a str>,
) -> io::Result<()> {
  // Proxy requests use absolute-form URLs (e.g., GET http://example.com/path HTTP/1.1)
  let url = Url::parse(target)
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Expected absolute-form URL"))?;
  if url.scheme() != "http" {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "Only http:// supported in direct mode; use CONNECT for https://",
    ));
  }
  let host = url
    .host_str()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL missing host"))?
    .to_string();
  let port = url.port().unwrap_or(80);
  let path_q = if url.path().is_empty() {
    "/"
  } else {
    url.path()
  };
  let origin_form = if let Some(q) = url.query() {
    format!("{path_q}?{q}")
  } else {
    path_q.to_string()
  };

  // Connect upstream
  let mut upstream = connect_with_timeout(&host, port).await?;

  // Collect and filter headers from client
  let mut headers = Vec::<(&str, &str)>::new();
  for line in lines {
    if line.is_empty() {
      break;
    }
    if let Some((name, value)) = line.split_once(':') {
      let name = name.trim();
      let value = value.trim();
      if should_strip_header(name) {
        continue;
      }
      headers.push((name, value));
    }
  }

  // Ensure Host and a minimal, privacy-tuned header set
  let mut has_host = false;
  for (name, _) in &headers {
    if name.eq_ignore_ascii_case("Host") {
      has_host = true;
      break;
    }
  }
  if !has_host {
    headers.push(("Host", &*host));
  }
  // Overwrite/insert a generic user agent (demo)
  headers.retain(|(n, _)| !n.eq_ignore_ascii_case("User-Agent"));
  headers.push(("User-Agent", "anonymous-proxy/0.1"));
  // Keep it simple: close connection
  headers.retain(|(n, _)| !n.eq_ignore_ascii_case("Connection"));
  headers.push(("Connection", "close"));

  // Rebuild request head in origin-form
  let mut req = format!("{method} {origin_form} {version}\r\n");
  for (n, v) in headers {
    req.push_str(n);
    req.push_str(": ");
    req.push_str(v);
    req.push_str("\r\n");
  }
  req.push_str("\r\n");

  // Send head upstream
  upstream.write_all(req.as_bytes()).await?;

  // Switch to tunneling the remaining body (if any) and the response back
  tunnel(client, &mut upstream).await
}

async fn read_until_double_crlf(stream: &mut TcpStream, out: &mut Vec<u8>) -> io::Result<()> {
  let mut buf = [0u8; 1024];
  let deadline = Duration::from_millis(READ_TIMEOUT_MS);
  loop {
    let n = timeout(deadline, stream.read(&mut buf)).await??;
    if n == 0 {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "peer closed before headers",
      ));
    }
    out.extend_from_slice(&buf[..n]);
    if out.len() > READ_HEAD_LIMIT {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "header too large",
      ));
    }
    if twoliner(out).is_some() {
      break;
    }
  }
  Ok(())
}

fn twoliner(buf: &[u8]) -> Option<usize> {
  // find "\r\n\r\n"
  buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn connect_with_timeout(host: &str, port: u16) -> io::Result<TcpStream> {
  let addr = format!("{host}:{port}");
  timeout(
    Duration::from_millis(CONNECT_TIMEOUT_MS),
    TcpStream::connect(addr),
  )
  .await?
}

async fn tunnel(a: &mut TcpStream, b: &mut TcpStream) -> io::Result<()> {
  // Just use the two full-duplex streams; no split halves.
  match tokio::io::copy_bidirectional(a, b).await {
    Ok(_) => Ok(()),
    Err(e) => Err(io::Error::new(
      io::ErrorKind::Other,
      format!("tunnel error: {e}"),
    )),
  }
}

fn should_strip_header(name: &str) -> bool {
  matches!(
    name.to_ascii_lowercase().as_str(),
    "proxy-connection"
      | "connection"
      | "keep-alive"
      | "te"
      | "trailer"
      | "transfer-encoding"
      | "upgrade"
      | "x-forwarded-for"
      | "via"
      | "forwarded"
      | "referer"
  )
}

fn split_host_port(s: &str, default_port: u16) -> io::Result<(String, u16)> {
  if let Some((h, p)) = s.rsplit_once(':') {
    let port: u16 = p
      .parse()
      .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    Ok((h.to_string(), port))
  } else {
    Ok((s.to_string(), default_port))
  }
}
