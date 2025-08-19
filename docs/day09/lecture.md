# **Day 9 — Web Security & Attacks**

## **1. Opening Story: The Parable of the Poisoned Well**

Imagine a medieval town. Everyone drinks from a single well. One day, an attacker tosses poison into it—not enough to kill immediately, but enough to harm everyone slowly.
In the digital world, the “well” is a web application: thousands drink from it daily. Poison it with malicious scripts (XSS), hidden requests (CSRF), or tampered queries (SQL injection), and entire populations of users are silently harmed.

This is the essence of **web security**: the battlefield where human trust, browser quirks, and server logic collide.

---

## **2. The Modern Web Attack Surface**

* **Complex Stack**: HTML, JavaScript, databases, APIs, third-party widgets, browsers, CDNs.
* **Attacker’s Advantage**: Web apps must be open to the world; attackers only need one crack.
* **Defender’s Dilemma**: Patch quickly, validate input, sanitize output—all while maintaining usability.

Think of the web as a **giant glass house**: transparent, interconnected, but fragile.

---

## **3. Cross-Site Scripting (XSS)**

### **What it is**

An attacker injects malicious JavaScript into a trusted website, which then executes in the victim’s browser.

* **Reflected XSS**: Malicious payload is reflected immediately via a request parameter.
* **Stored XSS**: Payload persists in the database and executes for every visitor.
* **DOM-based XSS**: Vulnerability is in client-side JavaScript manipulating the DOM.

### **Why it matters**

* Steals cookies, tokens → hijack sessions.
* Keylogging, fake login prompts, phishing inside the app itself.
* Can chain into **full account takeover**.

### **Defense**

* **Output encoding**: Escape special characters before rendering (`<`, `>`, `"`).
* **Content Security Policy (CSP)**: Restrict what scripts can run.
* **Sanitize inputs**: Libraries like `ammonia` in Rust to scrub HTML.

*Epic analogy*: XSS is like smuggling a cursed note into a royal proclamation—read aloud by the king’s herald, infecting all who listen.

---

## **4. Cross-Site Request Forgery (CSRF)**

### **What it is**

Tricks a user into making a request they didn’t intend (e.g., transferring money, changing email).
Browser auto-sends cookies → attacker forges an action.

### **Real-world analogy**

Imagine a signed check in your wallet. CSRF is someone sliding the check under your pen hand while you’re distracted—you sign without realizing.

### **Defense**

* **CSRF tokens**: Unique per session and request.
* **SameSite cookies**: Restrict sending cookies on cross-site requests.
* **Re-authentication** for sensitive actions.

---

## **5. SQL Injection (SQLi)**

### **What it is**

Unsanitized user input alters database queries.
Classic example:

```sql
SELECT * FROM users WHERE name = 'input';
```

If input = `' OR '1'='1`, query becomes:

```sql
SELECT * FROM users WHERE name = '' OR '1'='1';
```

→ Returns all rows.

### **Impact**

* Credential dumps.
* Privilege escalation.
* Full database compromise.

### **Defense**

* **Parameterized queries / prepared statements** (no string concatenation).
* **Least privilege database accounts**.
* **Input validation** (whitelisting, not blacklisting).

*Epic analogy*: SQLi is like sneaking extra clauses into a royal decree by exploiting sloppy handwriting.

---

## **6. WebAssembly (WASM) Security Implications**

Rust compiles to WASM—awesome for performance, but new risks arise:

* **Sandboxing**: WASM runs in a secure sandbox, but bugs in browser engines = escape potential.
* **Non-traditional attack surface**: Memory corruption in compiled code.
* **Supply-chain risks**: Malicious NPM/WASM modules included unknowingly.

Defenders must **audit dependencies** and follow **least privilege imports**.

---

## **7. Defensive Mindset for Web Security**

1. **Never trust input** → sanitize, validate, encode.
2. **Assume compromise** → defense-in-depth, logs, monitoring.
3. **Security headers**: CSP, HSTS, X-Frame-Options, SameSite.
4. **Principle of least privilege** everywhere (database, API keys, browser capabilities).

---

## **8. Case Study: Samy’s MySpace Worm (2005)**

* First major XSS worm.
* Payload: “but most of all, Samy is my hero.”
* Spread to over **1 million profiles in 20 hours**.
  Lesson: even “harmless” XSS can go viral at internet scale.

---

## **9. Summary and Flow to Lab**

Today, we learned how attackers poison the web well:

* XSS = running their script in your kingdom.
* CSRF = making you unknowingly act against yourself.
* SQLi = rewriting your database commands.
* WASM = new frontier where native bugs meet the browser sandbox.

**Key defender tools**: validation, encoding, tokens, least privilege, security headers.

Tomorrow, we march from **application-layer attacks** to **network-layer assaults**—the battlefield shifts from poisoned wells to floods that overwhelm the village gates.

---

## Review Questions


### **Q1. Why is the web considered a “glass house” from a security perspective? What gives attackers a fundamental advantage?**

**A1.** Web apps must be open and accessible to the public, which makes them transparent and exposed like a glass house. Attackers only need to find one weakness to break in, while defenders must secure every possible entry point.

### **Q2. What’s the difference between stored XSS and reflected XSS, and why is stored usually more dangerous?**

**A2.**

* **Reflected XSS**: Malicious code is reflected off the server in an immediate response (requires user interaction, e.g., clicking a crafted link).
* **Stored XSS**: Malicious code is saved in the server/database and served to every user who views the content.
  Stored XSS is more dangerous because it spreads persistently and impacts many victims without requiring them to click a special link.

### **Q3. If a banking site relies only on cookies for session management, how could an attacker use CSRF to transfer money from a victim’s account?**

**A3.** The attacker could trick the victim into clicking a malicious link or visiting a page that submits a hidden request to the bank (e.g., POST /transfer?to=attacker\&amount=1000). Since the browser automatically includes cookies, the bank processes it as if it came from the victim.

### **Q4. Why are parameterized queries considered the ultimate defense against SQL injection?**

**A4.** Because they separate **code** from **data**. User input is treated strictly as a value, never as part of the SQL syntax. This prevents attackers from injecting additional commands into the query.

### **Q5. Why might a malicious WASM module be harder to detect than a malicious JavaScript snippet?**

**A5.** WASM is compiled binary-like code, not human-readable text like JavaScript. Malicious logic can be obfuscated in the bytecode, making it difficult to audit or spot with traditional script inspection tools.

### **Q6. Give one example of how the principle of least privilege applies to databases, and one for browsers.**

**A6.**

* **Databases**: A web app account should have only the permissions it needs (e.g., read-only for reporting) rather than full admin access.
* **Browsers**: Limit scripts’ ability with CSP, disable unneeded APIs (like geolocation or camera) unless explicitly required.

### **Q7. What does Samy’s worm teach us about the risks of dismissing “harmless” vulnerabilities?**

**A7.** Even a seemingly harmless XSS (just displaying text) can spread virally, cause massive disruption, and undermine trust. “Harmless” vulnerabilities can serve as proof-of-concept for much worse attacks.

### **Q8. How do the defenses for XSS, CSRF, and SQLi differ, and what common philosophy underlies all of them?**

**A8.**

* **XSS** → encode output, sanitize input, restrict scripts.
* **CSRF** → add tokens, control cookies, verify intent.
* **SQLi** → use parameterized queries, validate input.
  **Common philosophy**: *Never trust input, always validate and enforce strict separation of data from code/privileges.*
