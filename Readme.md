## Symetric Encryption

Purpose: Encrypt and decrypt messages using libsodium's crypto_aead_xchacha20poly1305_ietf_* functions. while using secure secret-handling practices throughout the program (mlocked buffers, explicit read/write access control, and best-effort zeroization).

Note: this reduces key exposure risk by keeping private content in secure buffer while also making sure the memory region is manually wiped after use, but does not provide formal memory-safety guarantees for all C++ code paths.

## Contents

- [How to Build and Run](#how-to-build-and-run)
- [Prerequisites](#prerequisites)
- [Verify libsodium](#verify-libsodium)
- [Build](#build)
- [Run](#run)
- [TODO - future improvements](#todo)


## How to Build and Run

### Prerequisites
- A C++ compiler with C++17 support (e.g., `g++`)
- `libsodium` installed on your system
- install `pkg-config` if not already installed

---
### Verify libsodium 
pkg-config --modversion libsodium

### Build

Navigate to the `src` directory and compile the program:

```bash
g++ -std=c++17 -Wall -Wextra -pedantic -O2 \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
  main.cpp \
  helper/encrypt_decrypt.cpp \
  helper/system_check.cpp \
  data-structure/SecureBuffer.cpp \
  data-structure/SecureAccessGuard.cpp \
  $(pkg-config --cflags --libs libsodium) \
  -pie \
  -o main
```
- Wextra: Enables additional compiler warnings beyond -Wall
- pedantic: Forces strict compliance with the C++ standard
- fstack-protector-strong: Detects stack buffer overflows at runtime
- fPIE: Makes your executable position-independent, Program gets loaded at random memory addresses each run

### Run
./main

---
### TODO

- get_message_secure terminal echo/prints - fix based on user needs
- SecureAccessGuard - bad for multithreaded
- sodium_stackzero(2048) unreliable
- Payload parsing - exception handling
