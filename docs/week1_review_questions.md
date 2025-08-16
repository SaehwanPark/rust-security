# 📘 Week 1 — Question Bank (Days 1–5)

---

## **Day 1: Security Mindset & Rust Essentials**

1. **Open-ended**:
   Explain what it means to "think like an attacker" when evaluating a software system. How does this mindset differ from that of a typical software engineer?
   **Answer**: Attackers look for unintended behaviors, edge cases, and weaknesses that can be exploited. Engineers often assume correct usage. The attacker mindset deliberately probes “what if” scenarios.

2. **Multiple Choice**:
   Which of the following best describes Rust’s key advantage over C for systems security?
   A) Garbage collection eliminates memory leaks
   B) Ownership and borrowing prevent most memory safety errors at compile time
   C) It is interpreted and therefore safer
   D) Rust code cannot use unsafe blocks
   **Answer**: **B**. Ownership/borrowing model ensures safety without GC.

3. **Code Interpretation**:
   What will happen when compiling this Rust snippet?

   ```rust
   fn main() {
       let x = String::from("hello");
       let y = x;
       println!("{}", x);
   }
   ```

   **Answer**: Compilation error: `x` is moved to `y`, so `x` cannot be used afterwards. Demonstrates ownership rules.

4. **Open-ended**:
   Suppose you are designing a password checker. Why is “time to brute force with a GPU” a more security-relevant metric than just “password length”?
   **Answer**: Length doesn’t capture entropy. GPUs exploit parallelism; weak character sets or predictable patterns reduce effective search space.

5. **Multiple Choice**:
   Which is NOT part of attack surface mapping?
   A) Open network ports
   B) Default credentials
   C) Compiler optimization flags
   D) Unpatched libraries
   **Answer**: **C**. Compiler optimizations usually don’t expose external attack surface directly.

---

## **Day 2: Memory Safety & Control Hijacking**

6. **Open-ended**:
   Why can `unsafe` in Rust reintroduce C-style vulnerabilities? Give an example.
   **Answer**: `unsafe` bypasses compiler’s guarantees — e.g., manual pointer dereferencing can cause buffer overflows or dangling pointers.

7. **Multiple Choice**:
   Which of the following is an example of stack smashing?
   A) Overwriting saved return address with attacker data
   B) Injecting SQL into an unvalidated input
   C) Flooding a network with SYN packets
   D) Using a weak password
   **Answer**: **A**.

8. **Code Interpretation**:

   ```rust
   use std::ptr;

   fn main() {
       let mut arr = [0u8; 4];
       unsafe {
           let p = arr.as_mut_ptr();
           *p.add(5) = 42;
       }
       println!("{:?}", arr);
   }
   ```

   What issue arises?
   **Answer**: Out-of-bounds write → undefined behavior. Demonstrates Rust’s `unsafe` can break memory safety.

9. **Open-ended**:
   Why might fuzzing (e.g., with `cargo fuzz`) be more effective than manual inspection for memory errors?
   **Answer**: Fuzzing generates diverse, unexpected inputs that humans may not anticipate, triggering rare edge-case bugs.

10. **Multiple Choice**:
    Which is a necessary condition for buffer overflow exploitation?
    A) Input validation
    B) Predictable memory layout
    C) Randomized addresses
    D) Hashing input before use
    **Answer**: **B**. Exploits need to know/control layout.

---

## **Day 3: Defenses & ROP**

11. **Open-ended**:
    Explain how ASLR hinders ROP attacks.
    **Answer**: ASLR randomizes memory addresses of libraries and stack, making it hard for attackers to predict gadget addresses.

12. **Multiple Choice**:
    Stack canaries are designed to:
    A) Encrypt return addresses
    B) Detect buffer overflows before they overwrite control data
    C) Prevent SQL injection
    D) Slow down password cracking
    **Answer**: **B**.

13. **Code Interpretation**:
    You find a binary compiled without stack canaries but with DEP enabled. Which type of exploit becomes easier, and which becomes harder?
    **Answer**: Easier → classic stack smashing (overwrite return address). Harder → code injection (DEP blocks execution of injected code).

14. **Open-ended**:
    Why is “control flow integrity” considered a stronger defense than stack canaries alone?
    **Answer**: Canaries detect some buffer overflows, but CFI enforces that execution follows valid paths, preventing arbitrary jumps even without overflows.

15. **Multiple Choice**:
    ROP chains rely on:
    A) Injecting entirely new code
    B) Reusing small instruction sequences already in memory
    C) Encrypting stack contents
    D) Timing side channels
    **Answer**: **B**.

---

## **Day 4: Privilege Separation & Authentication**

16. **Open-ended**:
    Why is privilege separation a stronger design than simply hardening a single process?
    **Answer**: Limits damage. Even if one process is compromised, attacker doesn’t automatically gain full system access.

17. **Multiple Choice**:
    Which of these is NOT an example of least privilege?
    A) Web server runs as root
    B) Database user restricted to SELECT only
    C) Sandbox process cannot open network sockets
    D) Regular user cannot write `/etc/passwd`
    **Answer**: **A**.

18. **Code Interpretation**:

```rust
use nix::unistd::{fork, ForkResult};

fn main() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => println!("Parent"),
        Ok(ForkResult::Child) => println!("Child"),
        Err(_) => println!("Error"),
    }
}
```

Why is this pattern useful in building privilege-separated servers?
**Answer**: Parent can keep privileged resources (like socket binding), child can drop privileges and handle requests safely.

19. **Open-ended**:
    Why are salted password hashes preferable to unsalted ones?
    **Answer**: Prevents use of precomputed rainbow tables; identical passwords produce different hashes.

20. **Multiple Choice**:
    Which authentication mechanism provides **something you are**?
    A) Password
    B) Security token
    C) Fingerprint
    D) OTP
    **Answer**: **C**.

---

## **Day 5: Cryptography Fundamentals**

21. **Open-ended**:
    State Kerckhoffs’s principle. Why is it crucial in modern cryptography?
    **Answer**: Security should depend only on secrecy of the key, not the algorithm. Ensures resilience even if system design is public.

22. **Multiple Choice**:
    Which of the following is true about symmetric vs. asymmetric cryptography?
    A) Symmetric uses different keys for encryption/decryption
    B) Asymmetric is generally faster than symmetric
    C) Symmetric requires key distribution problem
    D) Asymmetric is obsolete
    **Answer**: **C**.

23. **Code Interpretation**:

```rust
fn xor_cipher(data: &str, key: u8) -> Vec<u8> {
    data.bytes().map(|b| b ^ key).collect()
}

fn main() {
    let msg = "HELLO";
    let enc = xor_cipher(msg, 42);
    println!("{:?}", enc);
}
```

What weakness makes XOR cipher unsuitable for real use?
**Answer**: Key is too short, easily brute-forced; patterns in plaintext remain visible if reused.

24. **Open-ended**:
    Why is ECB mode considered insecure for block ciphers?
    **Answer**: Identical plaintext blocks → identical ciphertext blocks; patterns leak (e.g., encrypted image still shows outline).

25. **Multiple Choice**:
    CBC mode improves security by:
    A) Adding per-block padding
    B) XORing each plaintext block with previous ciphertext block before encryption
    C) Using a different algorithm
    D) Making encryption faster
    **Answer**: **B**.

26. **Open-ended**:
    Threat modeling often asks: “What if the adversary knows the system design?” Give one cryptographic reason why this assumption matters.
    **Answer**: Prevents security through obscurity; if design is exposed, weak ciphers can be broken even with secret keys.

27. **Multiple Choice**:
    Which of these is an example of symmetric cipher?
    A) AES
    B) RSA
    C) Diffie-Hellman
    D) ECDSA
    **Answer**: **A**.

28. **Open-ended**:
    What role do initialization vectors (IVs) play in CBC mode?
    **Answer**: Ensure first block is randomized even if plaintext repeats; must be unique, unpredictable.

29. **Multiple Choice**:
    Which threat model is best mitigated by authentication tags (e.g., AES-GCM)?
    A) Replay attacks
    B) Chosen ciphertext modification
    C) Key leakage
    D) Brute force
    **Answer**: **B**.

30. **Open-ended**:
    Why is it important to distinguish between confidentiality and integrity in cryptographic systems? Give an example of a system that had one but not the other.
    **Answer**: Confidentiality hides data, integrity ensures it’s not altered. Example: WEP provided weak confidentiality but almost no integrity, leading to practical exploits.
