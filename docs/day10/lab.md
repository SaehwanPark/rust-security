# **Day 10 Lab — Network Attacks & Privacy**

---

## **Lab 1: Simulating a SYN Flood in Rust**

### **Goal**

Understand how a SYN flood works by simulating one in Rust with asynchronous networking (`tokio`).

### **Setup**

* Rust project already initialized in `examples/` folder.
* Add dependencies to `Cargo.toml`:

  ```toml
  [dependencies]
  tokio = { version = "1", features = ["full"] }
  ```

### **Steps**

1. **Warm-up: Review TCP Handshake**

   * Draw or recall the 3-way handshake (SYN → SYN-ACK → ACK).
   * Discuss what happens if the last step is missing.

2. **Write a SYN Sender**

   * Create a Rust async task that sends TCP connection requests to a target.
   * Do **not** complete the handshake.
   * Use `TcpStream::connect` but drop the connection immediately.

3. **Loop and Intensify**

   * Wrap the above in a loop, sending thousands of rapid requests.
   * Observe system behavior (some OSes will throttle).

4. **Observe with Tools**

   * Run `netstat -an | grep SYN_SENT` to view half-open connections.
   * Discuss resource exhaustion effect.

5. **Reflection**

   * Why doesn’t this fully work on localhost (hint: kernel mitigations)?
   * What defenses would help if this were a real attack?

---

## **Lab 2: Building a Simple Anonymizing Proxy**

### **Goal**

Learn how anonymity works by constructing a minimal HTTP proxy that hides client identity.

### **Setup**

* Add dependencies:

  ```toml
  [dependencies]
  tokio = { version = "1", features = ["full"] }
  hyper = "0.14"
  ```

### **Steps**

1. **Write a Basic Proxy**

   * Listen on a local port (e.g., 8080).
   * For each incoming HTTP request, forward it to the target server.
   * Relay the response back to the client.

2. **Strip/Modify Headers**

   * Remove headers like `User-Agent`, `Referer`, `X-Forwarded-For`.
   * Replace with generic headers to mask the client.

3. **Chainable Proxy**

   * Optionally configure it to forward requests through another proxy.
   * Show how layering multiple proxies adds anonymity (mini-Tor analogy).

4. **Testing**

   * Use `curl -x http://localhost:8080 https://httpbin.org/ip`
   * Compare results with and without proxy.

5. **Reflection**

   * What privacy does this actually provide?
   * How is this weaker than Tor?

---

## **Lab 3 (Optional Stretch): Rate Limiting Defense**

### **Goal**

Experiment with defenses against flooding.

### **Steps**

1. Implement a simple server with `tokio`.
2. Add per-IP connection limiting using a hashmap.
3. Observe how it blocks flooding attempts.

---

## **Hints for Learners**

* Don’t expect to crash your local system — modern kernels mitigate SYN floods. Focus on **conceptual demonstration**.
* For the proxy: test step-by-step, first forwarding simple GET requests before adding header stripping.
* Use `RUST_LOG=debug` with `env_logger` to trace behavior.

---

✅ By completing these labs, learners **simulate an attack** (SYN flood), **build a privacy tool** (anonymizing proxy), and optionally **try a defense** (rate limiting). This gives hands-on mastery of Day 10’s core concepts.
