#include <sodium.h>
#include <iostream>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
  #include <windows.h>
  #include <conio.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

#include "system_check.h"
#include "../data-structure/SecureBuffer.h"
#include "../data-structure/SecureAccessGuard.h"

// ─────────────────────────────────────────────────────────────────────────────
// Constants for key and encryption
// ─────────────────────────────────────────────────────────────────────────────
constexpr size_t SALT_LEN  = crypto_pwhash_SALTBYTES;
constexpr size_t NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr size_t KEY_LEN   = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr size_t TAG_LEN   = crypto_aead_xchacha20poly1305_ietf_ABYTES;

constexpr unsigned long long OPSLIMIT = crypto_pwhash_OPSLIMIT_SENSITIVE;
constexpr size_t             MEMLIMIT = crypto_pwhash_MEMLIMIT_SENSITIVE;

namespace {
// zero the salt, nonce, and ciphertext buffers on exits
struct DecodedBufferWiper {
    SecureBuffer* salt;
    SecureBuffer* nonce;
    SecureBuffer* ciphertext;

    ~DecodedBufferWiper() noexcept {
        if (salt && salt->size() > 0) sodium_memzero(salt->data(), salt->size());
        if (nonce && nonce->size() > 0) sodium_memzero(nonce->data(), nonce->size());
        if (ciphertext && ciphertext->size() > 0) sodium_memzero(ciphertext->data(), ciphertext->size());
    }
};

struct EncryptStackWiper {
    unsigned char* salt;
    size_t salt_len;
    unsigned char* nonce;
    size_t nonce_len;

    // on destruction, wipe stack secrets
    ~EncryptStackWiper() noexcept {
        if (salt && salt_len > 0) sodium_memzero(salt, salt_len);
        if (nonce && nonce_len > 0) sodium_memzero(nonce, nonce_len);
        sodium_stackzero(1024);
    }
};

#ifndef _WIN32
class ScopedTermios {
//Constructor: saves original terminal settings, then temporarily clears the bits in clear_lflag_bits.
//Destructor: restores the saved original settings.
public:
    explicit ScopedTermios(tcflag_t clear_lflag_bits) : active_(false) { // if clear_lflag_bits is ECHO, then turn off ECHO
        if (tcgetattr(STDIN_FILENO, &old_term_) != 0) return;

        termios new_term = old_term_;
        new_term.c_lflag &= ~clear_lflag_bits;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) return;

        active_ = true;
    }

    ~ScopedTermios() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term_);
        }
    }

    ScopedTermios(const ScopedTermios&) = delete;
    ScopedTermios& operator=(const ScopedTermios&) = delete;

private:
    termios old_term_{};
    bool active_;
};
#endif
} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Base64 helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string b64_encode(const unsigned char* data, size_t len) {
    size_t encoded_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(encoded_len, '\0');
    sodium_bin2base64(out.data(), encoded_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}
 
SecureBuffer b64_decode(const unsigned char* encoded, size_t encoded_len) {
    SecureBuffer out(encoded_len == 0 ? 1 : encoded_len);
    size_t decoded_len = 0;
    if (sodium_base642bin(
            out.data(), out.capacity(),
            reinterpret_cast<const char*>(encoded), encoded_len,
            " \t\r\n", &decoded_len, nullptr,
            sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    out.set_size(decoded_len);
    return out;
}
 
// ─────────────────────────────────────────────────────────────────────────────
// derive_key
//
// NOTE: We intentionally avoid sodium_stackzero() here. In practice, fixed-size
// stack wiping from this frame is only best-effort and can be platform-fragile.
// libsodium already clears its own sensitive internals; our primary defense is
// keeping derived key material in SecureBuffer and locking it immediately.
// ─────────────────────────────────────────────────────────────────────────────
SecureBuffer derive_key(const SecureBuffer& passphrase, const unsigned char* salt) {
    // The returned SecureBuffer starts R/W so crypto_pwhash can write into it.
    SecureBuffer key(KEY_LEN);

    // Passphrase must be readable.  Callers have already done unlock_read().
    int result = crypto_pwhash(
        key.data(), KEY_LEN,
        reinterpret_cast<const char*>(passphrase.data()), passphrase.size(),
        salt,
        OPSLIMIT, MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);

    // Best-effort: wipe our own stack frame after the expensive KDF.
        sodium_stackzero(2048);

    if (result != 0)
        throw std::runtime_error("Key derivation failed (out of memory?)");

    // key is R/W here; caller decides the protection level it needs.
    key.lock_access();
    return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// encrypt_message
// ─────────────────────────────────────────────────────────────────────────────
SecureBuffer encrypt_message(const SecureBuffer& plaintext,
                             const SecureBuffer& passphrase) {
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);
 
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);
    EncryptStackWiper stack_wiper{salt, SALT_LEN, nonce, NONCE_LEN};
 
    //std::cout << "\n  [*] Deriving key (this takes a moment by design)..." << std::flush;
 
    SecureBuffer key = derive_key(passphrase, salt);
    std::cout << " done.\n";
 
    // Guard unlocks key read-only on construction; re-locks on scope exit,
    // even if crypto_aead_xchacha20poly1305_ietf_encrypt throws.
    std::vector<unsigned char> ciphertext_buf(plaintext.size() + TAG_LEN);
    unsigned long long ciphertext_len = 0;
    int result;
    {
        SecureAccessGuard key_guard(key);
        result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext_buf.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr,
            nonce,
            key.data()
        );
        //  sodium_stackzero(2048);
    } // key locked here regardless of result or exception
 
    SecureBuffer output(1); // placeholder, size will be set later
    if (result == 0) {
        std::string salt_b64 = b64_encode(salt, SALT_LEN);
        std::string nonce_b64 = b64_encode(nonce, NONCE_LEN);
        std::string ct_b64 = b64_encode(ciphertext_buf.data(), ciphertext_len);
        std::string joined = salt_b64 + ":" + nonce_b64 + ":" + ct_b64;

        output = SecureBuffer(joined.size() == 0 ? 1 : joined.size());
        if (!joined.empty()) {
            std::memcpy(output.data(), joined.data(), joined.size());
        }
        output.set_size(joined.size());
        output.lock_access();

        sodium_memzero(salt_b64.data(), salt_b64.size());
        sodium_memzero(nonce_b64.data(), nonce_b64.size());
        sodium_memzero(ct_b64.data(), ct_b64.size());
        sodium_memzero(joined.data(), joined.size());
    }
 
    sodium_memzero(ciphertext_buf.data(), ciphertext_buf.size());
  
    if (result != 0)
        throw std::runtime_error("Encryption failed");

    
    return output;
}

// ─────────────────────────────────────────────────────────────────────────────
// decrypt_message
// ─────────────────────────────────────────────────────────────────────────────
std::optional<SecureBuffer> decrypt_message(SecureBuffer& payload,
                                             const SecureBuffer& passphrase) {
    SecureBuffer salt(1), nonce(1), ciphertext(1); // decode buffer wipers will wipe these on scope exit
    DecodedBufferWiper decoded_wiper{&salt, &nonce, &ciphertext};
    try {
        SecureAccessGuard payload_guard(payload);

        size_t p_begin = 0;// start of useful payload
        size_t p_end = payload.size();
        size_t first_colon = 0;
        size_t second_colon = 0;
        bool   invalid_colon_layout = false;

        const unsigned char* p = payload.data();

        // Trim ASCII whitespace without materializing payload in std::string.
        // static_cast<unsigned char> to prevent undefined behaviour.
        while (p_begin < p_end && std::isspace(static_cast<unsigned char>(p[p_begin]))) ++p_begin;
        while (p_end > p_begin && std::isspace(static_cast<unsigned char>(p[p_end - 1]))) --p_end;

        for (size_t i = p_begin; i < p_end; ++i) {
            if (p[i] == ':') {
                if (first_colon == 0 && i != p_begin) {
                    first_colon = i;
                } else if (second_colon == 0 && i > first_colon + 1) {
                    second_colon = i;
                } else {
                    invalid_colon_layout = true;
                    break;
                }
            }
        }

        const bool format_ok = !invalid_colon_layout &&
                               (p_begin < p_end) &&
                               (first_colon > p_begin) &&
                               (second_colon > first_colon + 1) &&
                               (second_colon + 1 < p_end);

        if (!format_ok) {
            std::cout << "\n  [!] Invalid payload format.\n";
            return std::nullopt;
        }

        salt       = b64_decode(p + p_begin, first_colon - p_begin);
        nonce      = b64_decode(p + first_colon + 1, second_colon - first_colon - 1);
        ciphertext = b64_decode(p + second_colon + 1, p_end - second_colon - 1);
    } catch (const std::exception&) {
        std::cout << "\n  [!] Base64 decode error — payload may be corrupted.\n";
        return std::nullopt;
    } 
 
    if (salt.size() != SALT_LEN || nonce.size() != NONCE_LEN ||
        ciphertext.size() < TAG_LEN) {
        std::cout << "\n  [!] Payload dimensions invalid.\n";
        return std::nullopt;
    }
 
    // ── Key derivation ────────────────────────────────────────────────────
    std::cout << "\n  [*] Deriving key (this takes a moment by design)..." << std::flush;
 
    SecureBuffer key = derive_key(passphrase, salt.data());
    std::cout << " done.\n";
 
    // ── Decryption ────────────────────────────────────────────────────────
    SecureBuffer plaintext_buf(ciphertext.size());
    unsigned long long plaintext_len = 0;
    int result;
    {
        // Guard unlocks key read-only; re-locks on scope exit even if decrypt throws.
        SecureAccessGuard key_guard(key);
        result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext_buf.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,
            nonce.data(),
            key.data()
        );
    } // key locked here regardless of result or exception
 
    if (result != 0) {
        std::cout << "\n  [!] Decryption failed: wrong passphrase or message was tampered with.\n";
        return std::nullopt;
    }
 
    // ── Produce a right-sized result buffer ───────────────────────────────
    SecureBuffer exact(plaintext_len == 0 ? 1 : plaintext_len);
    if (plaintext_len > 0)
        std::memcpy(exact.data(), plaintext_buf.data(), plaintext_len);
    exact.set_size(plaintext_len);
    exact.lock_access();
    

    return exact;
}

// ─────────────────────────────────────────────────────────────────────────────
// get_passphrase
// ─────────────────────────────────────────────────────────────────────────────
SecureBuffer get_passphrase(const std::string& prompt) {
    std::cout << prompt << std::flush;
 
    // Allocate a generously-sized SecureBuffer upfront and write directly into
    // it as characters are read.  No intermediate std::string is ever produced.
    // Cap at a reasonable maximum (4096 bytes); adjust if needed.
    constexpr size_t MAX_PASSPHRASE = 4096;
    SecureBuffer buf(MAX_PASSPHRASE);
    size_t len = 0;
 
#ifdef _WIN32
    char c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == '\b') {
            if (len > 0) {
                // Zero the removed byte.
                buf.data()[--len] = 0;
            }
        } else if (static_cast<unsigned char>(c) != '\b' && len < MAX_PASSPHRASE) {
            buf.data()[len++] = static_cast<unsigned char>(c);
        }
    }
    std::cout << '\n';
#else
    // Disable echo, canonical line buffering, and signal chars (^C/^Z) 
    ScopedTermios termios_guard(static_cast<tcflag_t>(ECHO | ICANON | ISIG));
 
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127 || ch == '\b') { // backspace / DEL
            if (len > 0) buf.data()[--len] = 0;
        } else if (len < MAX_PASSPHRASE) {
            buf.data()[len++] = static_cast<unsigned char>(ch);
        }
    }
 
    std::cout << '\n';
#endif
 
    buf.set_size(len);
    // Minimize exposure: return passphrase in no-access state.
    buf.lock_access();
    return buf;
}


// ─────────────────────────────────────────────────────────────────────────────
// get_passphrase_with_confirmation
// ─────────────────────────────────────────────────────────────────────────────
SecureBuffer get_passphrase_with_confirmation() {
    while (true) {
        SecureBuffer p1 = get_passphrase("  Passphrase        : ");
        SecureBuffer p2 = get_passphrase("  Confirm passphrase: ");
 
        bool match = false;
        if (p1.size() == p2.size()) {
            // Temporarily expose both buffers as read-only for constant-time compare.
            SecureAccessGuard p1_guard(p1);
            SecureAccessGuard p2_guard(p2);
            match = (sodium_memcmp(p1.data(), p2.data(), p1.size()) == 0);
        } // p1 and p2 destroyed here and locked
 
        if (match) return p1;
 
        std::cout << "\n  [!] Passphrases do not match. Try again.\n\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// get_message_secure
// Reads message bytes directly into secure memory to avoid plaintext std::string
// ─────────────────────────────────────────────────────────────────────────────
std::optional<SecureBuffer> get_message_secure(const std::string& prompt) {
    constexpr size_t MAX_MESSAGE = 16 * 1024;
    SecureBuffer buf(MAX_MESSAGE);
    size_t len = 0;

    std::cout << prompt << std::flush;

#ifdef _WIN32
    char c;
    while ((c = _getche()) != '\r' && c != '\n') {
        if (c == '\b' || static_cast<unsigned char>(c) == 127) {
            if (len > 0) {
                buf.data()[--len] = 0;
                std::cout << "\b \b" << std::flush;
            }
        } else if (len < MAX_MESSAGE) {
            buf.data()[len++] = static_cast<unsigned char>(c);
        }
    }
    std::cout << '\n';
#else
    ScopedTermios termios_guard(
        static_cast<tcflag_t>(ECHO | ICANON)
    );
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127 || ch == '\b') { // backspace / DEL
            if (len > 0) {
                buf.data()[--len] = 0;// Zero the removed byte.
                std::cout << "\b \b" << std::flush;
            }
        } else if (len < MAX_MESSAGE) {
            buf.data()[len++] = static_cast<unsigned char>(ch);
            std::cout << static_cast<char>(ch) << std::flush; // Remove: if you want more security
        }
    }

    std::cout << '\n';
#endif

    if (len == 0) return std::nullopt;
    buf.set_size(len);
    buf.lock_access();
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// do_encrypt
// Reads a single message line (spaces allowed), then encrypts it.
// ─────────────────────────────────────────────────────────────────────────────
void do_encrypt() {
    std::cout << "\n─── ENCRYPT ─────────────────────────────────────────────\n";
    std::cout << "  Enter the message to encrypt and press Enter:\n\n";
    auto plaintext_opt = get_message_secure("  > ");
    if (!plaintext_opt.has_value()) {
        std::cout << "\n  No message entered.\n";
        return;
    }

    SecureBuffer plaintext = std::move(*plaintext_opt); // plaintext_opt does not own the buffer/data
    plaintext.lock_access();
 
    std::cout << "\n";
    SecureBuffer passphrase = get_passphrase_with_confirmation();
    passphrase.lock_access();
    // Both buffers go read-only inside their own guards.
    // Guards unlock on construction and re-lock on destruction (scope exit),
    // so an exception inside encrypt_message cannot leave them unlocked.
    SecureBuffer ciphertext(1);
    {
        SecureAccessGuard pt_guard(plaintext);
        SecureAccessGuard pp_guard(passphrase);
        try {
            ciphertext = encrypt_message(plaintext, passphrase);
            
        } catch (const std::exception&) {
            std::cout << "\n  [!] Encryption failed.\n";
            return;
            // Both guards lock on scope exit here too.
        }
    } // plaintext and passphrase locked here
        
    std::cout << "\n─── ENCRYPTED MESSAGE ───────────────────────────────────\n\n";
    std::cout << "  " << std::string(54, '-') << '\n';
    {
        // unlock ciphertext for printing, will lock again on scope exit
        SecureAccessGuard ct_guard(ciphertext);
        const unsigned char* out = ciphertext.data();
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            std::cout << static_cast<char>(out[i]);
        }
        std::cout << '\n';
    }// ciphertext locked here
    std::cout << "  " << std::string(54, '-') << '\n';
    std::cout << "\n  Paste this into WhatsApp. It is safe to send openly.\n";
    std::cout << "\n  Press Enter to clear screen and return to menu...";
    std::cin.get();
    clear_screen();
}

// ─────────────────────────────────────────────────────────────────────────────
// do_decrypt
// ─────────────────────────────────────────────────────────────────────────────
void do_decrypt() {
    std::cout << "\n─── DECRYPT ─────────────────────────────────────────────\n";
    std::cout << "  Paste the encrypted message below and press Enter:\n\n";
    auto payload_opt = get_message_secure("  > ");
    if (!payload_opt.has_value()) {
        std::cout << "\n  [!] No input received.\n";
        return;
    }

    SecureBuffer payload = std::move(*payload_opt);
    payload.lock_access();
 
    std::cout << "\n";
    SecureBuffer passphrase = get_passphrase("  Passphrase: ");
    passphrase.lock_access();
 
    std::optional<SecureBuffer> result;
    {
        // Guard unlocks passphrase read-only; re-locks on scope exit even if
        // decrypt_message throws.
        SecureAccessGuard pp_guard(passphrase);
        result = decrypt_message(payload, passphrase);
    } // passphrase locked here
 
    if (result.has_value()) {
        std::cout << "\n─── DECRYPTED MESSAGE ───────────────────────────────────\n\n";
        {
            // Print directly from secure memory while unlocked read-only to
            SecureAccessGuard res_guard(result.value());
            const unsigned char* msg = result.value().data();
            const size_t msg_len = result.value().size();

            std::cout << "  ";
            for (size_t i = 0; i < msg_len; ++i) {
                const char ch = static_cast<char>(msg[i]);
                if (ch == '\r') continue; // ignore CR in CRLF payloads
                if (ch == '\n') {
                    std::cout << '\n';
                    if (i + 1 < msg_len) std::cout << "  ";
                } else {
                    std::cout << ch;
                }
            }
            if (msg_len == 0 || static_cast<char>(msg[msg_len - 1]) != '\n') {
                std::cout << '\n';
            }
        } // result buffer locked here

        std::cout << '\n' << std::string(58, '-') << '\n';
        std::cout << "\n  [!] READ ON THIS SCREEN ONLY. Do not copy to phone.\n";
        std::cout << "\n  Press Enter to WIPE message and return to menu...";
        std::cin.get();
 
        clear_screen();
        // result (SecureBuffer) destroyed here — destructor restores R/W,
        // then sodium_free zeros the guarded allocation.
    }
}
