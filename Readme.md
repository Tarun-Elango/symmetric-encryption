## Symetric Encryption

Built with libsodium and secure secret-handling practices (mlocked buffers, explicit read/write access control, and best-effort zeroization). Note: this reduces key exposure risk, but does not provide formal memory-safety guarantees for all C++ code paths.

## How to Build and Run

### Prerequisites
- A C++ compiler with C++17 support (e.g., `g++`)
- `libsodium` installed on your system

---
### Verify libsodium 
pkg-config --modversion libsodium

### Build

Navigate to the `src` directory and compile the program:

```bash
g++ -O2 -std=c++17 main.cpp $(pkg-config --cflags --libs libsodium) -o main
```

### Run
./main
