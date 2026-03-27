## Symetric Encryption

## Contents

- [Purpose](#purpose)
- [How it works](#how-it-works)
- [How to Build and Run](#how-to-build-and-run)
- [TODO - future improvements](#todo )


## Purpose
Encrypt and decrypt messages using libsodium's **crypto_aead_xchacha20poly1305_ietf_encrypt** function. 

Secret material — plaintext, passphrase, and derived key — is confined to sodium_malloc'd regions for the lifetime of each value:

- mlock'd — pages are pinned in RAM, preventing swap to disk
- mprotect'd — memory is set to no-access by default; unlocked read-only only for the duration of each cryptographic call, then re-locked immediately after
- zeroed on release — sodium_free guarantees a secure wipe before the region is returned to the OS

**Note**: this reduces key exposure risk by keeping private content in secure buffer while also making sure the memory region is manually wiped after use, but does not provide formal memory-safety guarantees for all C++ code paths. Created for learning purposes.

---
## How it works

There are four phases to the encryption process:
- Phase 1 — Get Input Message
- Phase 2 — Get Passphrase/password
- Phase 3 — Key Derivation ( passphrase + salt → key )
- Phase 4 — encrypt_message ( message + key + nonce → ciphertext )

*Wont be explaining the decryption process here, but it is very similar*
## Phase 1 — Get Input Message

```mermaid
flowchart TD
    A([do_encrypt called]) --> B[get_message_secure prompt]

    B --> C["ScopedTermios\ndisables ECHO + ICANON"]
    C --> D["SecureBuffer buf\nsodium_malloc 16 KB\nstate: R/W"]

    D --> E{read char loop\ngetchar}
    E -- "printable char" --> F["buf.data\[len++\] = ch\necho char to stdout"]
    F --> E
    E -- "DEL / backspace" --> G["buf.data\[--len\] = 0\nerase display char"]
    G --> E
    E -- "newline / EOF" --> H["buf.set_size(len)\ntrim live byte count"]

    H --> I{len == 0?}
    I -- yes --> J([return nullopt\nno message entered])
    I -- no --> K["buf.lock_access()\nstate: NO ACCESS"]

    K --> L([return Optional&lt;SecureBuffer&gt;\nstate: NO ACCESS])

    style C fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style D fill:#9FE1CB,stroke:#0F6E56,color:#085041
    style K fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style L fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
```

**Buffer state summary**

| Step | State |
|------|-------|
| After `sodium_malloc` | R/W |
| While reading chars | R/W |
| After `set_size` | R/W |
| After `lock_access` | NO ACCESS |
| Returned to caller | NO ACCESS |

---

## Phase 2 — Get Passphrase

```mermaid
flowchart TD
    A([get_passphrase_with_confirmation called]) --> B

    subgraph LOOP ["retry loop — until passphrases match"]
        B["get_passphrase\n'Passphrase :'"] --> C["ScopedTermios\ndisables ECHO + ICANON + ISIG"]
        C --> D["SecureBuffer p1\nsodium_malloc 4 KB\nstate: R/W"]
        D --> E["read chars into p1\nno echo to terminal"]
        E --> F["p1.set_size(len)\np1.lock_access()\nstate: NO ACCESS"]

        F --> G["get_passphrase\n'Confirm passphrase :'"]
        G --> H["SecureBuffer p2\nsodium_malloc 4 KB\nstate: R/W"]
        H --> I["read chars into p2\nno echo to terminal"]
        I --> J["p2.set_size(len)\np2.lock_access()\nstate: NO ACCESS"]

        J --> K["SecureAccessGuard p1 + p2\nstate: READ-ONLY (scoped)\nsodium_memcmp(p1, p2)\nconstant-time compare"]
        K -- "no match" --> L["print mismatch warning\np1 + p2 destroyed\nsodium_free zeros memory"]
        L --> B
    end

    K -- "match" --> M["guards destruct\np1 + p2 -> NO ACCESS"]
    M --> N["p2 destroyed\nsodium_free zeros memory"]
    N --> O([return SecureBuffer p1\nstate: NO ACCESS])

    style D fill:#9FE1CB,stroke:#0F6E56,color:#085041
    style H fill:#9FE1CB,stroke:#0F6E56,color:#085041
    style K fill:#B5D4F4,stroke:#185FA5,color:#042C53
    style N fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style O fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style L fill:#F7C1C1,stroke:#A32D2D,color:#501313
```

**Buffer state summary**

| Buffer | After alloc | During read | During compare | After compare | Returned |
|--------|-------------|-------------|----------------|--------------------------|----------|
| p1 | R/W | R/W | READ-ONLY (guard) | NO ACCESS | NO ACCESS |
| p2 | R/W | R/W | READ-ONLY (guard) | NO ACCESS, then destroyed | — |

---

## Phase 3 — Key Derivation

```mermaid
flowchart TD
    A(["passphrase SecureBuffer\nstate: NO ACCESS"]) --> C
    B(["salt\[32\] stack array\nrandombytes_buf"]) --> D

    C["SecureAccessGuard pp_guard\nunlock_read on passphrase\nstate: READ-ONLY"] --> D

    D["SecureBuffer key 32 bytes\nsodium_malloc\nstate: R/W"] --> E

    E["crypto_pwhash — Argon2id\nOPSLIMIT_SENSITIVE\nMEMLIMIT_SENSITIVE\nwrites derived key into key buffer"] --> F

    F["sodium_stackzero 2048\nbest-effort stack wipe\nafter KDF returns"] --> G

    G{pwhash result == 0?}
    G -- "fail — OOM" --> H(["throw runtime_error\npp_guard destructs\npassphrase → NO ACCESS"])
    G -- "success" --> I

    I["key.lock_access()\nstate: NO ACCESS"] --> J["pp_guard destructs\npassphrase → NO ACCESS"]

    J --> K(["return SecureBuffer key\nstate: NO ACCESS"])

    style C fill:#FAC775,stroke:#854F0B,color:#412402
    style D fill:#9FE1CB,stroke:#0F6E56,color:#085041
    style E fill:#B5D4F4,stroke:#185FA5,color:#042C53
    style F fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style I fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style K fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style H fill:#F7C1C1,stroke:#A32D2D,color:#501313
```

**Buffer state summary**

| Buffer | On entry | During KDF | After KDF | Returned |
|--------|----------|------------|-----------|----------|
| passphrase | NO ACCESS | READ-ONLY (guard) | NO ACCESS (guard destructs) | — |
| key | — | R/W | NO ACCESS | NO ACCESS |
| salt (stack) | — | readable | wiped by `sodium_stackzero` | — |

---

## Phase 4 — encrypt_message

```mermaid
flowchart TD
    A(["plaintext SecureBuffer\nstate: NO ACCESS"]) --> E
    B(["passphrase SecureBuffer\nstate: NO ACCESS"]) --> C
    C["derive_key passphrase, salt\nsee phase 3"] --> D(["key SecureBuffer\nstate: NO ACCESS"])

    D --> E
    GEN["randombytes_buf\nnonce\[24\] stack\nsalt\[32\] stack"] --> E

    E["EncryptStackWiper registered\nwill wipe salt + nonce on scope exit"] --> F

    F["SecureAccessGuard pt_guard\nplaintext → READ-ONLY\nSecureAccessGuard key_guard\nkey → READ-ONLY"] --> G

    G["crypto_aead_xchacha20poly1305_ietf_encrypt\nciphertext_buf = plaintext + TAG_LEN 16 B\nPoly1305 authentication tag appended"] --> H

    H["pt_guard + key_guard destruct\nplaintext → NO ACCESS\nkey → NO ACCESS"] --> I

    I{result == 0?}
    I -- "fail" --> J(["throw runtime_error\nEncryptStackWiper fires\nnonce + salt wiped"])

    I -- "success" --> K["b64_encode salt\nb64_encode nonce\nb64_encode ciphertext_buf"]

    K --> L["joined = b64_salt : b64_nonce : b64_ct\ncopy into SecureBuffer output"]

    L --> M["sodium_memzero on\nb64 strings + joined string\nwipe std::string heap memory"]

    M --> N["sodium_memzero ciphertext_buf\nwipe std::vector plaintext copy"] --> O

    O["EncryptStackWiper destructs\nwipes salt\[32\] + nonce\[24\] on stack\nsodium_stackzero 1024"] --> P

    P["output.lock_access()\nstate: NO ACCESS"] --> Q

    Q(["return SecureBuffer output\nformat: b64salt:b64nonce:b64ct\nstate: NO ACCESS"])

    style E fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style F fill:#FAC775,stroke:#854F0B,color:#412402
    style G fill:#B5D4F4,stroke:#185FA5,color:#042C53
    style H fill:#FAC775,stroke:#854F0B,color:#412402
    style M fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style N fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style O fill:#D3D1C7,stroke:#5F5E5A,color:#2C2C2A
    style P fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style Q fill:#F5C4B3,stroke:#993C1D,color:#4A1B0C
    style J fill:#F7C1C1,stroke:#A32D2D,color:#501313
```

**Buffer / memory state summary**

| Item | On entry | During AEAD | After AEAD | Returned |
|------|----------|-------------|------------|----------|
| plaintext | NO ACCESS | READ-ONLY (guard) | NO ACCESS | — |
| key | NO ACCESS | READ-ONLY (guard) | NO ACCESS | — |
| nonce (stack) | — | readable | wiped by `EncryptStackWiper` | — |
| salt (stack) | — | readable | wiped by `EncryptStackWiper` | — |
| ciphertext_buf (vector) | — | written by AEAD | zeroed by `sodium_memzero` | — |
| b64 strings (heap) | — | constructed | zeroed by `sodium_memzero` | — |
| output SecureBuffer | — | — | NO ACCESS | NO ACCESS |

---
---
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
