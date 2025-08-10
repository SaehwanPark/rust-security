# Security Programming Bootcamp in Rust

A comprehensive 10-day intensive bootcamp focused on security programming using Rust. This bootcamp combines theoretical foundations with hands-on coding exercises to build secure systems.

## 🎯 Target Audience

People with systems programming background who are:
- Comfortable in Rust basic, OR
- Proficient in C and willing to learn Rust quickly

## 🏗️ Bootcamp Structure

### Daily Format
- **Morning** — Lecture & discussion
- **Afternoon** — Lab & coding exercises in Rust
- **Evening (optional)** — Reading assignments and challenges

### Assessment
- 3 mini-projects throughout the bootcamp
- Daily code challenges and exercises

## 📚 Course Outline

### Week 1 — Foundations and Core Defenses

| Day | Topic | Focus Areas |
|-----|-------|-------------|
| **Day 1** | Security Mindset & Rust Essentials | Attack/defense thinking, memory safety model |
| **Day 2** | Memory Safety & Control Hijacking | Buffer overflows, unsafe Rust exploitation |
| **Day 3** | Defenses & Return-Oriented Programming | ASLR, stack canaries, ROP chains |
| **Day 4** | Privilege Separation & Authentication | Least privilege, password hashing, MFA |
| **Day 5** | Cryptography Fundamentals | Symmetric/asymmetric crypto, threat models |

### Week 2 — Protocols, Web, and Networks

| Day | Topic | Focus Areas |
|-----|-------|-------------|
| **Day 6** | Symmetric Encryption & MACs | Block/stream ciphers, HMAC implementation |
| **Day 7** | Public-Key Cryptography & PKI | RSA, ECDSA, certificate validation |
| **Day 8** | Secure Communication | TLS/HTTPS, MITM attacks |
| **Day 9** | Web Security & Attacks | XSS, CSRF, SQL injection |
| **Day 10** | Network Attacks & Privacy | DoS/DDoS, anonymity networks |

## 🚀 Getting Started

### Prerequisites
- Rust toolchain (stable channel recommended)
- Basic familiarity with systems programming concepts
- Git for version control

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd rust-security-bootcamp

# Verify Rust installation
rustc --version
cargo --version

# Run the initial example
cargo run --example password_strength_checker
```

### Repository Structure
```
├── src/                    # Main source code
├── examples/              # Example implementations
│   ├── password_strength_checker.rs
│   └── common_passwords.txt
├── docs/                  # Course materials
│   ├── day01/
│   │   ├── lecture.md     # Morning lecture content
│   │   └── lab.md         # Afternoon lab exercises
│   └── outline.md         # Complete course outline
├── Cargo.toml            # Project dependencies
├── rustfmt.toml          # Code formatting configuration
└── README.md             # This file
```

## 🛠️ Major Projects

### Project 1: Exploit and Patch (Week 1)
Find and patch security vulnerabilities in Rust code using:
- `unsafe` code analysis
- Fuzzing with `cargo fuzz`
- Memory safety exploitation

### Project 2: Secure Chat (Week 2)
Build an end-to-end encrypted CLI messenger featuring:
- Symmetric and asymmetric cryptography
- Secure key exchange
- Message authentication

### Project 3: Hardened Web API (Week 2)
Implement a secure REST API with:
- TLS encryption
- Authentication mechanisms
- Input validation and sanitization

## 📖 Learning Path

### Day 1 Example: Password Strength Checker
Start your journey with a practical example that demonstrates:
- Rust's memory safety advantages
- Secure input handling
- Common password validation techniques

```bash
cargo run --example password_strength_checker
```

This example introduces core security concepts while reinforcing Rust fundamentals like ownership, borrowing, and lifetimes.

## 🔧 Development Environment

### Code Style
- Uses 2-space indentation (configured in `rustfmt.toml`)
- Follows idiomatic Rust patterns
- Functions are topologically sorted (callees before callers)
- Snake_case for variables and functions

### Recommended Tools
- **IDE**: VS Code with rust-analyzer extension
- **Debugging**: `gdb` for low-level analysis
- **Fuzzing**: `cargo fuzz` for vulnerability discovery
- **Security**: `cargo audit` for dependency scanning

## 📋 Prerequisites Knowledge

### Required
- Basic understanding of memory management
- Familiarity with systems programming concepts
- Command-line proficiency

### Helpful
- Previous exposure to security concepts
- Understanding of network protocols
- Basic cryptography knowledge

## 🎓 Learning Outcomes

By the end of this bootcamp, you will:
- Think with a security mindset (attacker + defender perspectives)
- Leverage Rust's memory safety for secure programming
- Implement cryptographic protocols correctly
- Build secure web applications and APIs
- Understand common attack vectors and defenses
- Apply fuzzing and testing for security validation

## 📚 Recommended Reading

### Core References
- *Security Engineering* by Ross Anderson (Ch. 1)
- *Handbook of Applied Cryptography* (Ch. 1-3)
- ROP (Return-Oriented Programming) primers

### Additional Resources
- Rust security best practices
- OWASP guidelines for web security
- Current vulnerability databases (CVE, NVD)

## 🤝 Contributing

This is an educational repository. If you find issues or have improvements:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear descriptions

## 📜 License

Educational use license - see LICENSE file for details.

---

**Ready to build secure systems with Rust?** Start with Day 1 materials in `docs/day01/` and begin your journey into security programming! 🔐
