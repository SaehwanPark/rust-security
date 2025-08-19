# **Day 9 Lab — Web Security & Attacks**

## **Objective**

* Build a deliberately vulnerable Rust web service.
* Exploit **XSS** and **SQL injection**.
* Apply patches and confirm the fix.

---

## **1. Setup**

1. Make sure you’re in the project repo:

   ```bash
   cd rust-security/examples
   ```
2. Add web dependencies to `Cargo.toml`:

   ```toml
   actix-web = "4"
   serde = { version = "1", features = ["derive"] }
   sqlx = { version = "0.7", features = ["sqlite", "runtime-tokio-rustls"] }
   ```
3. Create a new file:

   ```
   examples/web_vuln.rs
   ```

---

## **2. Vulnerable Service**

Paste this starter code:

```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use serde::Deserialize;

#[derive(Deserialize)]
struct UserInput {
    name: String,
}

async fn greet(pool: web::Data<Pool<Sqlite>>, form: web::Query<UserInput>) -> impl Responder {
    // ⚠ Vulnerable: string concatenation
    let query = format!("SELECT 'Hello, {}!'", form.name);
    let row: (String,) = sqlx::query_as(&query)
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
    HttpResponse::Ok().body(row.0)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/greet", web::get().to(greet))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Run it:

```bash
cargo run --example web_vuln
```

---

## **3. Exploiting**

### **Step A: XSS**

Visit:

```
http://127.0.0.1:8080/greet?name=<script>alert(1)</script>
```

✅ The alert shows JavaScript executed in your browser → **XSS confirmed**.

### **Step B: SQL Injection**

Try:

```
http://127.0.0.1:8080/greet?name=' || 1=1 --
```

✅ If the service responds oddly (or errors), injection worked.

---

## **4. Patching**

1. **Fix SQL injection**: Use parameters instead of string concatenation.

   ```rust
   let row: (String,) = sqlx::query_as("SELECT 'Hello, ' || ?1 || '!'")
       .bind(&form.name)
       .fetch_one(pool.get_ref())
       .await
       .unwrap();
   ```
2. **Fix XSS**: Escape output before sending.
   Add:

   ```toml
   html-escape = "0.2"
   ```

   Then use:

   ```rust
   let safe_name = html_escape::encode_text(&form.name);
   let body = format!("Hello, {}!", safe_name);
   HttpResponse::Ok().body(body)
   ```

Re-run and re-test:

* `<script>alert(1)</script>` should now render harmless text.
* SQLi payload should no longer execute.

---

## **5. Reflection**

* You saw how tiny mistakes (string concatenation, unsanitized output) open the door to classic attacks.
* You confirmed how **parameterized queries** and **output encoding** shut those doors.
