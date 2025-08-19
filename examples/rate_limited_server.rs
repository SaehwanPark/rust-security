//! Rate-limited TCP Echo Server (per-IP concurrency limits)
//!
//! Usage:
//!   cargo run --example rate_limited_server -- 127.0.0.1:8080 --limit 5
//! Then try flooding it; connections beyond per-IP limit get dropped.

use std::{collections::HashMap, env, net::SocketAddr, str::FromStr, sync::Arc};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  sync::Mutex,
};

#[derive(Clone)]
struct Limits {
  per_ip: usize,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
  let mut args = env::args().skip(1);
  let listen = args.next().unwrap_or_else(|| "127.0.0.1:8080".into());
  let limit: usize = if let Some(flag) = args.next() {
    if flag == "--limit" {
      args.next().unwrap_or_else(|| "5".into()).parse().unwrap()
    } else {
      5
    }
  } else {
    5
  };

  let addr = SocketAddr::from_str(&listen).expect("listen addr like 127.0.0.1:8080");
  eprintln!("Rate-limited echo server on {addr} (per-ip limit: {limit})");

  let listener = TcpListener::bind(addr).await?;
  let state = Arc::new(Mutex::new(HashMap::<std::net::IpAddr, usize>::new()));
  let limits = Limits { per_ip: limit };

  loop {
    let (socket, peer) = listener.accept().await?;
    let state = state.clone();
    let limits = limits.clone();

    tokio::spawn(async move {
      if let Err(e) = handle_client(socket, peer, state, limits).await {
        eprintln!("[{peer}] error: {e}");
      }
    });
  }
}

async fn handle_client(
  mut stream: TcpStream,
  peer: SocketAddr,
  state: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
  limits: Limits,
) -> std::io::Result<()> {
  // Acquire per-IP slot
  {
    let mut map = state.lock().await;
    let cnt = map.entry(peer.ip()).or_insert(0);
    if *cnt >= limits.per_ip {
      // Exceeded limit
      let _ = stream.write_all(b"503 busy\r\n").await;
      let _ = stream.shutdown().await;
      return Ok(());
    }
    *cnt += 1;
  }

  let result = echo_loop(&mut stream).await;

  // Release slot
  {
    let mut map = state.lock().await;
    if let Some(cnt) = map.get_mut(&peer.ip()) {
      *cnt = cnt.saturating_sub(1);
      if *cnt == 0 {
        map.remove(&peer.ip());
      }
    }
  }

  result
}

async fn echo_loop(stream: &mut TcpStream) -> std::io::Result<()> {
  let (mut r, mut w) = stream.split();
  let mut buf = [0u8; 1024];
  w.write_all(b"hello; rate-limited echo. type to echo; ctrl-c to quit.\r\n")
    .await?;
  loop {
    let n = r.read(&mut buf).await?;
    if n == 0 {
      break;
    }
    w.write_all(&buf[..n]).await?;
  }
  Ok(())
}
