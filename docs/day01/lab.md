# **Day 1 – Afternoon Lab: Rust Refresher & Password Strength Checker**

## **Lab Goals**

1. Refresh Rust fundamentals relevant for security: ownership, borrowing, lifetimes.
2. Build a **CLI password strength checker** that demonstrates secure input handling.
3. Learn to spot insecure patterns and replace them with safe idioms.

---

## **Part 1 – Rust Refresher (60 min)**

### **1. Ownership**

Rust’s ownership model is the *first line of defense* against memory corruption.

```rust
fn main() {
    let s = String::from("secure"); // owner: s
    let t = s; // ownership moves to t
    // println!("{}", s); // ❌ compile error: s no longer owns the data
}
```

**Security takeaway:** Ownership prevents accidental double-free or dangling references.

---

### **2. Borrowing**

Two modes:

* Immutable (`&T`) – many allowed
* Mutable (`&mut T`) – only one at a time

```rust
fn length(s: &String) -> usize {
    s.len()
}
fn main() {
    let data = String::from("safe");
    println!("{}", length(&data)); // borrowed immutably
}
```

**Security takeaway:** Borrowing rules prevent race conditions in shared memory.

---

### **3. Lifetimes**

Lifetimes ensure references are valid as long as you use them.

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}
```

**Security takeaway:** Lifetimes stop use-after-free at compile time.

---

💡 **Checkpoint:** If you truly understand ownership, borrowing, and lifetimes, you can reason about most safe Rust code and know when `unsafe` is truly needed.

---

## **Part 2 – Building the Password Strength Checker (90 min)**

### **Step 0 – Requirements**

* Input password from CLI
* Check:

  * Minimum length
  * Contains uppercase & lowercase
  * Contains digits
  * Contains symbols
* Optional: Check against a list of common passwords
* Output **strength score** and suggestions

---

### **Step 1 – CLI Scaffolding**

```rust
use std::io::{self, Write};

fn main() {
    print!("Enter password: ");
    io::stdout().flush().unwrap();

    let mut password = String::new();
    io::stdin().read_line(&mut password)
        .expect("Failed to read input");
    let password = password.trim(); // Remove trailing newline

    let score = evaluate_password(password);
    println!("Password score: {}/5", score);
}
```

**Security note:** Always trim input to avoid hidden newline characters that may bypass validation.

---

### **Step 2 – Evaluation Function**

```rust
fn evaluate_password(pw: &str) -> u8 {
    let mut score = 0;

    if pw.len() >= 12 { score += 1; } // length check
    if pw.chars().any(|c| c.is_uppercase()) { score += 1; }
    if pw.chars().any(|c| c.is_lowercase()) { score += 1; }
    if pw.chars().any(|c| c.is_ascii_digit()) { score += 1; }
    if pw.chars().any(|c| !c.is_alphanumeric()) { score += 1; }

    score
}
```

**Security note:** `chars()` is Unicode-aware, unlike `bytes()` — avoids splitting multi-byte characters in a way that attackers could exploit.

---

### **Step 3 – Adding Common Password List Check**

We’ll store a short list in `common_passwords.txt`:

```
password
123456
qwerty
letmein
admin
```

Code:

```rust
fn is_common_password(pw: &str) -> bool {
    let list = include_str!("common_passwords.txt");
    list.lines().any(|line| line.trim() == pw)
}
```

In `main`:

```rust
if is_common_password(password) {
    println!("❌ This is a common password — very weak!");
}
```

**Security note:** Use `include_str!` for small lists so you don’t need file I/O at runtime (avoids path traversal issues).

---

### **Step 4 – Strength Feedback**

```rust
match score {
    5 => println!("✅ Very strong"),
    4 => println!("🟢 Strong"),
    3 => println!("🟡 Moderate"),
    _ => println!("🔴 Weak"),
}
```

**Security note:** Avoid telling users *which* rule failed in public apps — can help attackers guess constraints. For local tools, it’s fine for learning.

---

### **Step 5 – Try Some Passwords**

Test:

```
Enter password: password
❌ This is a common password — very weak!
Password score: 1/5
🔴 Weak
```

```
Enter password: 9f@K#2mZqG&7
Password score: 5/5
✅ Very strong
```

---

## **Part 3 – Security Commentary (15 min)**

* We validated input length and composition to prevent **brute force susceptibility**.
* Using `chars()` avoids **Unicode confusion attacks**.
* By avoiding unsafe patterns and using the standard library, we get memory safety *for free*.
* This lab parallels **real-world password policy enforcement** in authentication systems.

---

## **Bonus Challenge**

* Add entropy estimation (Shannon entropy).
* Store common passwords in a hashed set using SHA-256 to avoid leaking the list in binaries.
