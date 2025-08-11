# **Day 2 – Memory Safety & Control Hijacking**

## **Narrative Hook: The Ghosts in the Machine**

Imagine a medieval castle. Rust’s compiler is the master architect — every brick carefully placed, every gate locked. But deep in the catacombs lies a secret passage — **`unsafe`**. Once you open it, the compiler’s guards turn away. Now, you walk in the same treacherous tunnels where C and C++ have fought decades of battles against memory bugs and control-flow hijackers.

Today, you are both **the infiltrator** and **the fortress keeper**. You’ll learn how these secret passages get exploited — and how to defend against them.

---

## **Learning Objectives**

By the end of today, you will:

1. **Understand memory safety** — how modern languages enforce it and how to bypass those safeguards.
2. **Recognize control hijacking attacks** — from classic stack smashing to overwriting return addresses.
3. **See how Rust can fall into C-like traps** when using `unsafe`.
4. **Gain hands-on exploitation skills** — writing, finding, and exploiting vulnerabilities in Rust.
5. **Start Project 1** — the *Exploit and Patch* challenge.

---

## **Part 1: Memory Safety — The Invisible Guardrails**

* **What is memory safety?**

  * Prevents buffer overflows, use-after-free, dangling pointers, double frees.
  * Guarantees each memory access is valid and within bounds.
* **C/C++ world**:

  * Powerful but dangerous: raw pointers, manual allocation.
  * Famous exploits: *Morris Worm (1988)*, *Heartbleed (2014)*.
* **Rust’s promise**:

  * Ownership + borrowing + lifetimes = no dangling references or data races.
  * No nulls, no uninitialized memory (without `unsafe`).

**Story beat:** Rust is like an autopilot that prevents you from flying into a mountain — unless you *turn it off*.

---

## **Part 2: Control Hijacking — When the Stack Becomes a Weapon**

* **How the stack works**:

  * Local variables, return addresses, saved registers.
* **Buffer overflow**:

  * Writing past the end of a buffer can overwrite saved return addresses.
  * Classic “stack smashing” example in C:

    ```c
    void vuln() {
        char buf[8];
        gets(buf); // No bounds check!
    }
    ```
* **Control hijacking path**:

  1. Overflow buffer.
  2. Overwrite return address.
  3. Redirect execution to attacker-controlled code (shellcode or ROP).

**Rust connection:**
With `unsafe` you can:

* Use raw pointers.
* Perform unchecked indexing (`get_unchecked_mut`).
* Call into vulnerable C libraries.

---

## **Part 3: Unsafe Rust — Opening Pandora’s Box**

* `unsafe` is **not evil**, but it **removes the compiler’s safety net**.
* Five superpowers `unsafe` unlocks:

  1. Dereferencing raw pointers.
  2. Calling unsafe functions (including FFI).
  3. Accessing/mutating static variables.
  4. Implementing unsafe traits.
  5. Performing unchecked memory operations.

**Example:**

```rust
fn unsafe_overflow() {
    let mut arr = [0u8; 8];
    unsafe {
        let ptr = arr.as_mut_ptr();
        for i in 0..16 {
            *ptr.add(i) = 42; // Writes beyond bounds!
        }
    }
}
```

In release mode, Rust will happily overwrite adjacent stack data here.

---

## **Part 4: Exploiting in Rust — A Controlled Dive into Danger**

* **Why bother?**

  * Understand the anatomy of attacks.
  * Learn how to recognize unsafe patterns in code reviews.
* **Tooling for discovery**:

  * `cargo fuzz` — fuzz inputs to trigger memory issues.
  * `asan` (AddressSanitizer) via `-Zsanitizer` in nightly Rust.

**Demo Flow**:

1. Write a small Rust program with an overflow in `unsafe`.
2. Compile with optimizations off for easier debugging.
3. Use crafted input to crash or hijack behavior.
4. Discuss exploit limitations due to modern defenses (ASLR, DEP).

---

## **Part 5: Preparing for the Lab**

**Afternoon challenge:**

1. Write a deliberately vulnerable Rust program with `unsafe`:

   * Use raw pointer writes beyond array bounds.
   * Allow attacker input to control overflow size/data.
2. Use `cargo fuzz` to generate crashing inputs.
3. Attempt to reproduce a control hijack in a controlled sandbox.
4. Document:

   * Root cause.
   * Exploitation method.
   * Mitigation strategies.

---

## **Part 6: Mitigations & Defensive Thinking**

Even though we’ll go deeper into defenses on Day 3, start thinking:

* Prefer safe Rust — `unsafe` in minimal, audited sections.
* Use bounds-checked APIs.
* Employ fuzz testing + sanitizers in CI.
* Leverage `miri` to catch undefined behavior in test builds.

---

## **Epic Wrap-Up: The Day’s Story Arc**

We began in a fortified city (safe Rust), opened a secret tunnel (`unsafe`), and saw how intruders could hijack control (buffer overflows).
Now, you hold **two powers**:

* The key to the hidden tunnels.
* The blueprint for locking them tighter than before.

**Evening (Optional Self-Learning)**

* Read *The Art of Exploitation* (Ch. 2–3).
* Explore the *Rustonomicon* section on `unsafe`.
