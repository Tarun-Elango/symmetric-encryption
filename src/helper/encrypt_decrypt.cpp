#include <sodium.h>
#include <iostream>
#include <sstream>

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

#include "system_check.cpp"
#include "../data-structure/SecureBuffer.cpp"
#include "../data-structure/SecureAccessGuard.cpp"

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
constexpr size_t SALT_LEN  = crypto_pwhash_SALTBYTES;
constexpr size_t NONCE_LEN = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
constexpr size_t KEY_LEN   = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
constexpr size_t TAG_LEN   = crypto_aead_chacha20poly1305_ietf_ABYTES;

constexpr unsigned long long OPSLIMIT = crypto_pwhash_OPSLIMIT_SENSITIVE;
constexpr size_t             MEMLIMIT = crypto_pwhash_MEMLIMIT_SENSITIVE;

// ─────────────────────────────────────────────────────────────────────────────
// Base64 helpers (ciphertext / salt / nonce are not secret)
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// Base64 helpers (ciphertext / salt / nonce are not secret)
// ─────────────────────────────────────────────────────────────────────────────
std::string b64_encode(const unsigned char* data, size_t len) {
    size_t encoded_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(encoded_len, '\0');
    sodium_bin2base64(out.data(), encoded_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}
 
std::vector<unsigned char> b64_decode(const std::string& encoded) {
    std::vector<unsigned char> out(encoded.size());
    size_t decoded_len = 0;
    if (sodium_base642bin(
            out.data(), out.size(),
            encoded.c_str(), encoded.size(),
            nullptr, &decoded_len, nullptr,
            sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    out.resize(decoded_len);
    return out;
}
 
// ─────────────────────────────────────────────────────────────────────────────
// derive_key
//
// NOTE on sodium_stackzero: sodium_stackzero(N) zeroes N bytes of the
// *current* call frame's stack.  By the time we call it here, Argon2id's own
// stack frames have already been unwound and their memory may have been
// reused.  The call therefore zeroes OUR frame's locals (the `key` pointer,
// loop variables, etc.), which is marginally useful but does NOT reliably
// reach Argon2id's temporaries.
//
// There is no portable way to zero another function's already-freed stack
// frame.  The defence that actually works is letting libsodium's own internal
// sodium_memzero calls handle its state — which it does — and trusting that
// the SecureBuffer holding the derived key is protected immediately after.
// The sodium_stackzero call is kept as a best-effort measure.
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
    return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// encrypt_message
// ─────────────────────────────────────────────────────────────────────────────
std::string encrypt_message(const SecureBuffer& plaintext,
                            const SecureBuffer& passphrase) {
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);
 
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);
 
    std::cout << "\n  [*] Deriving key (this takes a moment by design)..." << std::flush;
 
    SecureBuffer key = derive_key(passphrase, salt);
    std::cout << " done.\n";
 
    // Guard unlocks key read-only on construction; re-locks on scope exit,
    // even if crypto_aead_chacha20poly1305_ietf_encrypt throws.
    std::vector<unsigned char> ciphertext_buf(plaintext.size() + TAG_LEN);
    unsigned long long ciphertext_len = 0;
    int result;
    {
        SecureAccessGuard key_guard(key);
        result = crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext_buf.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr,
            nonce,
            key.data()
        );
        sodium_stackzero(2048);
    } // key locked here regardless of result or exception
 
    std::string output;
    if (result == 0) {
        output = b64_encode(salt,  SALT_LEN)             + ":" +
                 b64_encode(nonce, NONCE_LEN)            + ":" +
                 b64_encode(ciphertext_buf.data(), ciphertext_len);
    }
 
    sodium_memzero(ciphertext_buf.data(), ciphertext_buf.size());
 
    if (result != 0)
        throw std::runtime_error("Encryption failed");
    return output;
}

// ─────────────────────────────────────────────────────────────────────────────
// decrypt_message
// ─────────────────────────────────────────────────────────────────────────────
std::optional<SecureBuffer> decrypt_message(const std::string& payload,
                                             const SecureBuffer& passphrase) {
    // ── Parse the base64:base64:base64 payload ────────────────────────────
    std::vector<std::string> parts;
    {
        std::istringstream stream(payload);
        std::string token;
        while (std::getline(stream, token, ':'))
            parts.push_back(token);
    }
 
    if (parts.size() != 3) {
        std::cout << "\n  [!] Invalid payload format.\n";
        return std::nullopt;
    }
 
    std::vector<unsigned char> salt, nonce, ciphertext;
    try {
        salt       = b64_decode(parts[0]);
        nonce      = b64_decode(parts[1]);
        ciphertext = b64_decode(parts[2]);
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
        result = crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext_buf.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,
            nonce.data(),
            key.data()
        );
        sodium_stackzero(2048);
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
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
 
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127 || ch == '\b') { // backspace / DEL
            if (len > 0) buf.data()[--len] = 0;
        } else if (len < MAX_PASSPHRASE) {
            buf.data()[len++] = static_cast<unsigned char>(ch);
        }
    }
 
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cout << '\n';
#endif
 
    buf.set_size(len);
    // Leave buffer R/W — caller will lock after use or pass to crypto.
    return buf;
}


// ─────────────────────────────────────────────────────────────────────────────
// get_passphrase_with_confirmation
// ─────────────────────────────────────────────────────────────────────────────
SecureBuffer get_passphrase_with_confirmation() {
    while (true) {
        SecureBuffer p1 = get_passphrase("  Passphrase        : ");
        SecureBuffer p2 = get_passphrase("  Confirm passphrase: ");
 
        bool match = (p1.size() == p2.size()) &&
                     (sodium_memcmp(p1.data(), p2.data(), p1.size()) == 0);
 
        if (match) return p1;
 
        std::cout << "\n  [!] Passphrases do not match. Try again.\n\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// do_encrypt
// Fix: plaintext is read directly into a SecureBuffer without any intermediate
// std::string accumulator.  The flow is:
//
//   Old: line → lines[i] → joined (std::string) → SecureBuffer   (3 copies)
//   New: line → stage (one short-lived std::string per line, zeroed immediately
//                      after copying into the SecureBuffer)        (1 copy)
//
// We don't know the total size up front for multi-line input, so we use a
// two-pass approach: collect raw line lengths to compute total size, then
// allocate exactly once and fill.  Each std::string line is zeroed as soon as
// its content has been transferred.
// ─────────────────────────────────────────────────────────────────────────────
void do_encrypt() {
    std::cout << "\n─── ENCRYPT ─────────────────────────────────────────────\n";
    std::cout << "  Enter the message to encrypt.\n";
    std::cout << "  (Finish with a blank line)\n\n";
 
    // ── Pass 1: read lines, track total byte count ────────────────────────
    // Each line is a short-lived std::string that we zero as soon as we're done
    // with it.  This is still one temporary string per line, but there is no
    // secondary accumulator (no `joined`, no `lines` vector kept alive).
    //
    // We store the raw bytes in a plain heap buffer just long enough to measure
    // and then move them into the SecureBuffer.  A std::vector<unsigned char>
    // with an immediate sodium_memzero after the SecureBuffer copy keeps the
    // exposure window as short as possible.
    std::vector<unsigned char> staging;   // ordinary heap — zeroed before free
    staging.reserve(4096);
 
    std::string line;
    bool first = true;
    while (true) {
        std::cout << " >";
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) break;
 
        // Prepend newline separator for lines after the first.
        if (!first) staging.push_back('\n');
        first = false;
 
        staging.insert(staging.end(),
                       reinterpret_cast<const unsigned char*>(line.data()),
                       reinterpret_cast<const unsigned char*>(line.data()) + line.size());
 
        // Zero and discard the std::string immediately — it has served its purpose.
        sodium_memzero(line.data(), line.size());
        line.clear();
    }
    // Ensure `line` is zeroed even on a break-without-clear path.
    if (!line.empty()) { sodium_memzero(line.data(), line.size()); line.clear(); }
 
    if (staging.empty()) {
        std::cout << "\n  No message entered.\n";
        return;
    }
 
    // ── Single allocation + single copy → SecureBuffer ───────────────────
    SecureBuffer plaintext(staging.size());
    std::memcpy(plaintext.data(), staging.data(), staging.size());
    plaintext.set_size(staging.size());
 
    // Zero and free the staging buffer immediately.
    sodium_memzero(staging.data(), staging.size());
    staging.clear();
    staging.shrink_to_fit(); // release heap memory now, not at scope exit
 
    std::cout << "\n";
    SecureBuffer passphrase = get_passphrase_with_confirmation();
 
    // Both buffers go read-only inside their own guards.
    // Guards unlock on construction and re-lock on destruction (scope exit),
    // so an exception inside encrypt_message cannot leave them unlocked.
    std::string ciphertext;
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
    std::cout << "  " << ciphertext << '\n';
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
    std::cout << "  > ";
 
    std::string payload;
    if (!std::getline(std::cin, payload) || payload.empty()) {
        std::cout << "\n  [!] No input received.\n";
        return;
    }
 
    auto trim = [](std::string& s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                [](unsigned char c) { return !std::isspace(c); }));
        s.erase(std::find_if(s.rbegin(), s.rend(),
                [](unsigned char c) { return !std::isspace(c); }).base(), s.end());
    };
    trim(payload);
 
    std::cout << "\n";
    SecureBuffer passphrase = get_passphrase("  Passphrase: ");
 
    std::optional<SecureBuffer> result;
    {
        // Guard unlocks passphrase read-only; re-locks on scope exit even if
        // decrypt_message throws.
        SecureAccessGuard pp_guard(passphrase);
        result = decrypt_message(payload, passphrase);
    } // passphrase locked here
 
    if (result.has_value()) {
        std::cout << "\n─── DECRYPTED MESSAGE ───────────────────────────────────\n\n";
 
        std::string display;
        {
            // Guard unlocks result buffer read-only for to_string(); re-locks
            // on scope exit before display is used (display is a copy, so that
            // is fine) and before we zero display below.
            SecureAccessGuard res_guard(result.value());
            display = result.value().to_string();
        } // result buffer locked here
 
        std::istringstream ss(display);
        std::string msg_line;
        while (std::getline(ss, msg_line))
            std::cout << "  " << msg_line << '\n';
 
        sodium_memzero(display.data(), display.size());
 
        std::cout << '\n' << std::string(58, '-') << '\n';
        std::cout << "\n  [!] READ ON THIS SCREEN ONLY. Do not copy to phone.\n";
        std::cout << "\n  Press Enter to WIPE message and return to menu...";
        std::cin.get();
 
        clear_screen();
        // result (SecureBuffer) destroyed here — destructor restores R/W,
        // then sodium_free zeros the guarded allocation.
    }
}