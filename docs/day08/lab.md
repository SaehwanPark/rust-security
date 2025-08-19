# Day 8 Lab — Secure Communication with TLS (Rust + `rustls`)

## What you’ll build (in \~3 focused tasks)

1. **A minimal TLS echo server and client** using `rustls` + `tokio`.
2. **Traffic inspection + verification** with `openssl`/`curl` to confirm certs, ciphers, and TLS versions.
3. **A “safe” MITM demo** to understand warnings and trust chains (no sensitive data; localhost only).

> You do **not** need full production code today. You’ll get scaffolds, commands, and checkpoints. Save deeper hardening for Project 2.

---

## Prereqs (5 min)

* Rust toolchain (`rustup update`)
* OpenSSL CLI (`openssl version`) or LibreSSL equivalent
* `curl` (modern build with TLS 1.3 support)
* Optional GUI: Wireshark (nice to have)

**Project structure (suggested):**

```
rust-security/
  examples/
    tls_server.rs
    tls_client.rs
    mitm.rs              # optional stretch
  certs/
    server.pem           # leaf (cert + key PEM bundle, see below)
    ca.pem               # root CA (for trust tests)
  Cargo.toml
```

**Cargo dependencies (add to root Cargo.toml):**

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net"] }
rustls = "0.23"
rustls-pemfile = "2"
webpki-roots = "0.26"
rcgen = "0.13"         # for generating test certs (optional but convenient)
anyhow = "1"
```

> Tip: avoid pinning exact patch versions unless you need reproducibility for grading.

---

## Step 0 — Generate test certificates (two paths)

### Option A (single self‑signed leaf for quick start)

```bash
# 1) Generate a self-signed “server” cert for localhost
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost"

# 2) Bundle key+cert into one PEM your server loader can read
cat certs/server.key certs/server.crt > certs/server.pem
```

### Option B (CA + leaf to demonstrate trust properly) — **recommended**

```bash
# Root CA
openssl genrsa -out certs/ca.key 2048
openssl req -x509 -new -key certs/ca.key -sha256 -days 30 \
  -out certs/ca.pem -subj "/CN=Local Test Root CA"

# Leaf (CSR)
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=localhost"

# Sign leaf with CA
openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 7 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost")

# Bundle for server
cat certs/server.key certs/server.crt > certs/server.pem
```

**Checkpoint:** You should now have:

* `certs/server.pem` (contains private key then cert)
* `certs/ca.pem` (if using Option B)

---

## Task 1 — Minimal TLS echo **server** (with `rustls`)

**Goal:** Accept TLS connections on `127.0.0.1:8443`, echo lines back.

**Key ideas (what your code should do):**

* Load `server.pem` using `rustls-pemfile` (read key + cert chain).
* Build `ServerConfig` with no client auth for now.
* Wrap a `TcpListener` in `TlsAcceptor` (from `rustls`).
* For each connection: complete handshake, then echo lines.

**Hints (drop‑in fragments):**

* Read certs/keys:

```rust
use rustls_pemfile::{read_one, Item};
use std::{fs::File, io::BufReader};

fn load_server_identity() -> anyhow::Result<(Vec<rustls::CertificateDer<'static>>, rustls::PrivateKeyDer<'static>)> {
    let mut rdr = BufReader::new(File::open("certs/server.pem")?);
    let mut certs = Vec::new();
    let mut key = None;

    while let Some(item) = read_one(&mut rdr)? {
        match item {
            Item::X509Certificate(der) => certs.push(rustls::CertificateDer::from(der)),
            Item::Pkcs8Key(der) | Item::RsaKey(der) => key = Some(rustls::PrivateKeyDer::from(der)),
            _ => {}
        }
    }
    Ok((certs, key.ok_or_else(|| anyhow::anyhow!("no private key found in server.pem"))?))
}
```

* Build server config:

```rust
use rustls::ServerConfig;

let (certs, key) = load_server_identity()?;
let config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
```

* Echo loop skeleton:

```rust
use tokio::{net::TcpListener, io::{AsyncBufReadExt, AsyncWriteExt, BufReader}};

let listener = TcpListener::bind("127.0.0.1:8443").await?;
loop {
    let (stream, _) = listener.accept().await?;
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
        if let Ok(tls) = acceptor.accept(stream).await {
            let (r, mut w) = tokio::io::split(tls);
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = w.write_all(line.as_bytes()).await;
                let _ = w.write_all(b"\n").await;
            }
        }
    });
}
```

**Run & smoke test:**

```bash
cargo run --example tls_server
```

---

## Task 2 — Minimal TLS **client** (with `rustls`)

**Goal:** Connect to `127.0.0.1:8443`, verify server using your CA (Option B), send a few lines, print echoes.

**Key ideas:**

* Create a `RootCertStore` and add `ca.pem`.
* Build `ClientConfig` with that root store.
* Use `ServerName::try_from("localhost")?` for SNI and hostname verification.
* Use `tokio_rustls::TlsConnector`.

**Hints (fragments):**

```rust
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::sync::Arc;

fn client_config_with_local_ca() -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let mut rdr = BufReader::new(File::open("certs/ca.pem")?);
    for item in std::iter::from_fn(|| read_one(&mut rdr).transpose()) {
        if let Item::X509Certificate(der) = item? {
            roots.add(rustls::CertificateDer::from(der))?;
        }
    }
    let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(cfg))
}
```

**Connect + send:**

```rust
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

let cfg = client_config_with_local_ca()?;
let connector = TlsConnector::from(cfg);
let tcp = TcpStream::connect("127.0.0.1:8443").await?;
let server_name = ServerName::try_from("localhost")?;
let mut tls = connector.connect(server_name, tcp).await?;

tls.write_all(b"hello\n").await?;
tls.write_all(b"tls\n").await?;
tls.shutdown().await?;
```

**Run:**

```bash
cargo run --example tls_client
```

**Checkpoint (expected behavior):**

* Client prints echoed lines from server.
* If you used Option B (CA+leaf), the client should **not** need `--insecure` flags.

---

## Task 3 — Verify with CLI tools (prove it’s TLS)

### A) Inspect handshake & cert

```bash
# Observe TLS handshake and server certificate
openssl s_client -connect 127.0.0.1:8443 -servername localhost -CAfile certs/ca.pem -tls1_3
```

**You should see:**

* Certificate chain ending in your CA
* `TLSv1.3` and a modern cipher like `TLS_AES_128_GCM_SHA256`
* “Verify return code: 0 (ok)”

### B) HTTPS-style test with curl

```bash
# Success path (trusted by provided CA)
curl --cacert certs/ca.pem https://localhost:8443/
# Failure path (no trust)
curl https://localhost:8443/     # expect certificate warning/failure
curl -k https://localhost:8443/  # -k ignores verification (NOT for prod)
```

### C) (Optional) Packet capture

Open Wireshark, filter on `tcp.port == 8443`:

* You should see TLS handshake frames and **encrypted** application data (no plaintext “hello”).

---

## Task 4 — “Safe” MITM demo (edu‑only, localhost)

**What you’ll learn:** Why trust matters. You will **not** steal data — you’ll see how clients react to an untrusted intermediate.

**Approach (choose one):**

**Option 1 — Quick concept with curl**

1. Spin up your server with the CA‑signed leaf (Option B).
2. Now run `curl` *without* `--cacert certs/ca.pem`:

   ```bash
   curl https://localhost:8443/
   ```

   You should get a trust error. This is the “MITM‑style” failure path: client can’t validate the presented cert chain.

**Option 2 — Local proxy (“bump”) with a *different* CA**

* Generate a **second** CA (call it `evil_ca.pem`) and a leaf for `localhost`.
* Point client to the proxy’s address; proxy connects to the real server.
* The client will see the proxy’s leaf (signed by `evil_ca`) → trust **fails** unless you explicitly trust `evil_ca.pem`.
* Message: browsers/clients save you by default; users “clicking through” warnings is the real danger.

> **Ethics & safety:** Do this **only** on your own machine/loopback with test traffic. Never intercept real users’ traffic.

---

## Quality checks (fast rubric)

* **Server** starts and serves TLS on `127.0.0.1:8443`.
* **Client** connects, verifies hostname `localhost`, and echoes lines.
* **OpenSSL** shows TLS 1.3 and a valid chain when using `-CAfile certs/ca.pem`.
* **curl** succeeds with `--cacert certs/ca.pem`, fails without it.
* **(Optional)** Wireshark shows encrypted AppData (no plaintext).

---

## Troubleshooting (copy‑paste fixes)

* **`no private key found in server.pem`**

  * Ensure `cat server.key server.crt > server.pem` (key first).
* **`InvalidCertificate` / hostname mismatch**

  * Your cert must have `CN=localhost` **and** `subjectAltName=DNS:localhost`.
* **`rustls` won’t load key**

  * Use PKCS#8 or traditional RSA keys; the snippet above handles both via `rustls-pemfile`.
* **TLS version mismatch**

  * Force test with `openssl s_client -tls1_3` to confirm 1.3 path. Update OpenSSL if it’s too old.
* **Firewall/port busy**

  * Change to `127.0.0.1:9443` temporarily; re‑run.

---

## Stretch (optional, for evening)

* Enable **client authentication**:

  * Issue a client cert from your CA, configure `ServerConfig::with_client_cert_verifier(...)`.
  * Prove mutual TLS by requiring the client cert to connect.
* Measure handshake latency (TLS 1.2 vs 1.3) with a simple timer around `connector.connect`.

---

## Deliverables (for check‑in)

* Screenshot or paste of:

  1. `openssl s_client` output showing TLS 1.3 and “Verify return code: 0 (ok)”.
  2. `curl` success with `--cacert` and failure without it.
* Short paragraph: *“How TLS prevents MITM by default, and when warnings appear.”*
