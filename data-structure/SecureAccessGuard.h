#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// SecureAccessGuard
//
// RAII wrapper that calls unlock_read() on construction and lock_access() on
// destruction. To close the gap for exception thrown between an
// explicit unlock_read() / lock_access -> this could leave the buffer
// permanently readable.
//
// Usage:
//   {
//       SecureAccessGuard g(buf);   // buf → read-only
//       use(buf);                   // safe
//   }                               // buf → no-access, even if an exception fires
// ─────────────────────────────────────────────────────────────────────────────
class SecureBuffer; // Forward declaration

class SecureAccessGuard {
public:
    explicit SecureAccessGuard(SecureBuffer& buf);
    ~SecureAccessGuard() noexcept;

    // Non-copyable, non-movable — guards are strictly scoped.
    SecureAccessGuard(const SecureAccessGuard&)            = delete;
    SecureAccessGuard& operator=(const SecureAccessGuard&) = delete;
    SecureAccessGuard(SecureAccessGuard&&)                 = delete;
    SecureAccessGuard& operator=(SecureAccessGuard&&)      = delete;

private:
    SecureBuffer& buf_;
};