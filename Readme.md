## Symetric Encryption

Designed using libsodium, with strong memory safety guarantees (mlocked buffers, explicit access control, and zeroization).

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

