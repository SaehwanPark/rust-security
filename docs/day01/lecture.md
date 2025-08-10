# **Day 1 – Security Mindset & Rust Essentials for Security**

## **Morning Lecture (3h)**

---

### **0. Scene-Setting Story: “Two Doors” (10 min)**

Imagine you inherit a mansion with two grand doors: one oak, one steel. The oak is gorgeous but unlocked; the steel door is locked but has a hidden back panel. Which door would a thief try first?

Security is never just about the door — it’s about the **mindset** of the people who build, guard, and attack it. Today, you’ll learn to think like both thief *and* guard, and wield Rust like a modern steel-and-oak hybrid — beautiful, fast, and safe by default.

---

## **1. The Security Mindset (45 min)**

**1.1 Attacker Thinking**

* **Curiosity weaponized:** Attackers ask, *“What assumptions are wrong here?”*
* **Asymmetry:** Defenders must secure *all* paths; attackers only need one.
* **Economics of attack:** Low cost to try, high payoff if successful.

**Example:**
A login page with rate limiting prevents brute force… unless the attacker finds a forgotten API endpoint without limits.

**1.2 Defender Thinking**

* **Defense in depth:** Multiple layers — authentication, input validation, monitoring.
* **Least privilege:** Grant the bare minimum rights for the task.
* **Fail securely:** Systems should default to *safe states* on errors, not “permit all.”

**1.3 Mental Toolset for Both Sides**

* Red-team: “How would I break this?”
* Blue-team: “How do I detect and respond?”
* Gray-team: “How do I *model* both sides together?”

---

## **2. Attack Surface Mapping (40 min)**

### **2.1 What Is an Attack Surface?**

The sum of all points where an unauthorized user can interact with your system.

**Categories:**

1. **Network exposure** – Open ports, APIs, sockets.
2. **User input** – Forms, file uploads, command-line arguments.
3. **Third-party dependencies** – Crates, libraries, services.
4. **Human factors** – Social engineering, phishing.

**2.2 Exercise (Mental)**
Given a simple chat server:

* Ports: 80 (HTTP), 443 (HTTPS), 8080 (admin)
* Auth: username/password, no MFA
* Dependencies: `serde_json`, `tokio`

**Map the attack surface:**

* Unencrypted port 80 → MITM
* Admin port exposed → unauthorized config changes
* Password only → credential stuffing risk
* Third-party crate vulnerabilities

---

## **3. Rust’s Memory Safety Model vs. C (45 min)**

### **3.1 Memory Safety in C**

* Manual memory management → risk of **use-after-free**, **dangling pointers**, **buffer overflows**.
* No bounds checking by default.
* Security implication: memory corruption often leads to code execution.

### **3.2 Rust’s Approach**

* **Ownership** – Every value has a single owner.
* **Borrowing** – Multiple immutable references or one mutable reference at a time.
* **Lifetimes** – Compiler ensures references never outlive their data.
* **Safe by default** – `unsafe` is opt-in and visually obvious.

**Security impact:** Rust prevents entire classes of vulnerabilities *at compile time*.
Example:

```c
// C: Possible buffer overflow
char buf[10];
strcpy(buf, "This string is too long!");

// Rust: Compiler enforces bounds
let mut buf = [0u8; 10];
let data = b"This string is too long!";
buf.copy_from_slice(&data[..10]); // Truncated safely
```

---

## **4. Guided Example: Building a Mental Model (30 min)**

We’ll construct a **mental bridge** between attacker/defender thinking and Rust’s model.

1. Attacker loves **buffer overflows**.
2. Rust’s borrow checker shuts most of these down at compile time.
3. But attacker knows — if defender uses `unsafe`, new doors open.
4. Defender learns: minimize `unsafe`, audit it carefully, fuzz test.

---

## **5. Closing Story: “The Locked Garden” (10 min)**

Think of your code as a walled garden. Rust gives you tall, sturdy walls by default. But if you build a side gate (`unsafe`), you must guard it yourself. Day 1 is about recognizing where those gates are, and why your *mindset* is the true lock.

---

## **Afternoon Lab Preview (5 min)**

* Rust refresher: ownership, borrowing, lifetimes.
* Implement CLI **password strength checker**:

  * Rules: min length, mixed case, digits, symbols.
  * Bonus: check against a common-password list.

---

### **Evening Reading (Optional)**

* *Security Engineering*, Ross Anderson — Ch. 1 (*Why Security Is Hard*).

