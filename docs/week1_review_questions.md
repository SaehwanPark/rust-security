# 📘 Week 1 — Question Bank (Days 1–5)

---

## **Day 1: Security Mindset & Rust Essentials**

1. **Open-ended**:<br>
   Explain what it means to "think like an attacker" when evaluating a software system. How does this mindset differ from that of a typical software engineer?<br><br>
   **Answer**: Attackers look for unintended behaviors, edge cases, and weaknesses that can be exploited. Engineers often assume correct usage. The attacker mindset deliberately probes “what if” scenarios.

2. **Multiple Choice**:<br>
   Which of the following best describes Rust’s key advantage over C for systems security?<br>
   A) Garbage collection eliminates memory leaks<br>
   B) Ownership and borrowing prevent most memory safety errors at compile time<br>
   C) It is interpreted and therefore safer<br>
   D) Rust code cannot use unsafe blocks<br><br>
   **Answer**: **B**. Ownership/borrowing model ensures safety without GC.

3. **Code Interpretation**:<br>
   What will happen when compiling this Rust snippet?

   ```rust
   fn main() {
       let x = String::from("hello");
       let y = x;
       println!("{}", x);
   }
   ```

   **Answer**: Compilation error: `x` is moved to `y`, so `x` cannot be used afterwards. Demonstrates ownership rules.

4. **Open-ended**:<br>
   Suppose you are designing a password checker. Why is “time to brute force with a GPU” a more security-relevant metric than just “password length”?<br><br>
   **Answer**: Length doesn’t capture entropy. GPUs exploit parallelism; weak character sets or predictable patterns reduce effective search space.

5. **Multiple Choice**:<br>
   Which is NOT part of attack surface mapping?
   A) Open network ports
   B) Default credentials
   C) Compiler optimization flags
   D) Unpatched libraries<br><br>
   **Answer**: **C**. Compiler optimizations usually don’t expose external attack surface directly.

---

## **Day 2: Memory Safety & Control Hijacking**

6. **Open-ended**:<br>
   Why can `unsafe` in Rust reintroduce C-style vulnerabilities? Give an example.<br><br>
   **Answer**: `unsafe` bypasses compiler’s guarantees — e.g., manual pointer dereferencing can cause buffer overflows or dangling pointers.

7. **Multiple Choice**:<br>
   Which of the following is an example of stack smashing?<br>
   A) Overwriting saved return address with attacker data<br>
   B) Injecting SQL into an unvalidated input<br>
   C) Flooding a network with SYN packets<br>
   D) Using a weak password<br><br>
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

   What issue arises?<br><br>
   **Answer**: Out-of-bounds write → undefined behavior. Demonstrates Rust’s `unsafe` can break memory safety.

9. **Open-ended**:<br>
   Why might fuzzing (e.g., with `cargo fuzz`) be more effective than manual inspection for memory errors?<br><br>
   **Answer**: Fuzzing generates diverse, unexpected inputs that humans may not anticipate, triggering rare edge-case bugs.

10. **Multiple Choice**:<br>
    Which is a necessary condition for buffer overflow exploitation?<br>
    A) Input validation<br>
    B) Predictable memory layout<br>
    C) Randomized addresses<br>
    D) Hashing input before use<br><br>
    **Answer**: **B**. Exploits need to know/control layout.

---

## **Day 3: Defenses & ROP**

11. **Open-ended**:<br>
    Explain how ASLR hinders ROP attacks.<br><br>
    **Answer**: ASLR randomizes memory addresses of libraries and stack, making it hard for attackers to predict gadget addresses.

12. **Multiple Choice**:<br>
    Stack canaries are designed to:<br>
    A) Encrypt return addresses<br>
    B) Detect buffer overflows before they overwrite control data<br>
    C) Prevent SQL injection<br>
    D) Slow down password cracking<br><br>
    **Answer**: **B**.

13. **Code Interpretation**:<br>
    You find a binary compiled without stack canaries but with DEP enabled. Which type of exploit becomes easier, and which becomes harder?<br><br>
    **Answer**: Easier → classic stack smashing (overwrite return address). Harder → code injection (DEP blocks execution of injected code).

14. **Open-ended**:<br>
    Why is “control flow integrity” considered a stronger defense than stack canaries alone?<br><br>
    **Answer**: Canaries detect some buffer overflows, but CFI enforces that execution follows valid paths, preventing arbitrary jumps even without overflows.

15. **Multiple Choice**:<br>
    ROP chains rely on:<br>
    A) Injecting entirely new code<br>
    B) Reusing small instruction sequences already in memory<br>
    C) Encrypting stack contents<br>
    D) Timing side channels<br><br>
    **Answer**: **B**.

---

## **Day 4: Privilege Separation & Authentication**

16. **Open-ended**:<br>
    Why is privilege separation a stronger design than simply hardening a single process?<br><br>
    **Answer**: Limits damage. Even if one process is compromised, attacker doesn’t automatically gain full system access.

17. **Multiple Choice**:<br>
    Which of these is NOT an example of least privilege?<br>
    A) Web server runs as root<br>
    B) Database user restricted to SELECT only<br>
    C) Sandbox process cannot open network sockets<br>
    D) Regular user cannot write `/etc/passwd`<br><br>
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

    Why is this pattern useful in building privilege-separated servers?<br><br>
    **Answer**: Parent can keep privileged resources (like socket binding), child can drop privileges and handle requests safely.

19. **Open-ended**:<br>
    Why are salted password hashes preferable to unsalted ones?<br><br>
    **Answer**: Prevents use of precomputed rainbow tables; identical passwords produce different hashes.

20. **Multiple Choice**:<br>
    Which authentication mechanism provides **something you are**?<br>
    A) Password<br>
    B) Security token<br>
    C) Fingerprint<br>
    D) OTP<br><br>
    **Answer**: **C**.

---

## **Day 5: Cryptography Fundamentals**

21. **Open-ended**:<br>
    State Kerckhoffs’s principle. Why is it crucial in modern cryptography?<br><br>
    **Answer**: Security should depend only on secrecy of the key, not the algorithm. Ensures resilience even if system design is public.

22. **Multiple Choice**:<br>
    Which of the following is true about symmetric vs. asymmetric cryptography?<br>
    A) Symmetric uses different keys for encryption/decryption<br>
    B) Asymmetric is generally faster than symmetric<br>
    C) Symmetric requires key distribution problem<br>
    D) Asymmetric is obsolete<br><br>
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

    What weakness makes XOR cipher unsuitable for real use?<br><br>
    **Answer**: Key is too short, easily brute-forced; patterns in plaintext remain visible if reused.

24. **Open-ended**:<br>
    Why is ECB mode considered insecure for block ciphers?<br><br>
    **Answer**: Identical plaintext blocks → identical ciphertext blocks; patterns leak (e.g., encrypted image still shows outline).

25. **Multiple Choice**:<br>
    CBC mode improves security by:<br>
    A) Adding per-block padding<br>
    B) XORing each plaintext block with previous ciphertext block before encryption<br>
    C) Using a different algorithm<br>
    D) Making encryption faster<br><br>
    **Answer**: **B**.

26. **Open-ended**:<br>
    Threat modeling often asks: “What if the adversary knows the system design?” Give one cryptographic reason why this assumption matters.<br><br>
    **Answer**: Prevents security through obscurity; if design is exposed, weak ciphers can be broken even with secret keys.

27. **Multiple Choice**:<br>
    Which of these is an example of symmetric cipher?<br>
    A) AES<br>
    B) RSA<br>
    C) Diffie-Hellman<br>
    D) ECDSA<br><br>
    **Answer**: **A**.

28. **Open-ended**:<br>
    What role do initialization vectors (IVs) play in CBC mode?<br><br>
    **Answer**: Ensure first block is randomized even if plaintext repeats; must be unique, unpredictable.

29. **Multiple Choice**:<br>
    Which threat model is best mitigated by authentication tags (e.g., AES-GCM)?<br>
    A) Replay attacks<br>
    B) Chosen ciphertext modification<br>
    C) Key leakage<br>
    D) Brute force<br><br>
    **Answer**: **B**.

30. **Open-ended**:<br>
    Why is it important to distinguish between confidentiality and integrity in cryptographic systems? Give an example of a system that had one but not the other.<br><br>
    **Answer**: Confidentiality hides data, integrity ensures it’s not altered. Example: WEP provided weak confidentiality but almost no integrity, leading to practical exploits.
