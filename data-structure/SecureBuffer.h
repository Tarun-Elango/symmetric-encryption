#pragma once

#include <cstddef>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// SecureBuffer
//
//   capacity_  — the size passed to sodium_malloc(); never mutates after ctor.
//   size_       — how many bytes currently hold live data (≤ capacity_).
//
// Access-protection lifecycle:
//   After construction the region is left READ/WRITE, caller needs to lock access.
//
//   Before any read (unlock_read) or write (unlock_write) the corresponding
//   mprotect call must be made.  
// The destructor always restores R/W before sodium_free so libsodium can zero 
// the region.
// ─────────────────────────────────────────────────────────────────────────────
class SecureBuffer {
public:
    // Allocate `capacity` bytes via sodium_malloc (guarded pages, mlock'd, zeroed)
    //  Memory starts READ/WRITE so the caller can fill it.
    explicit SecureBuffer(size_t capacity);
    ~SecureBuffer();

    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& o) noexcept;
    SecureBuffer& operator=(SecureBuffer&& o) noexcept;

    // ── Access protection ─────────────────────────────
    void lock_access();    // no access
    void unlock_read();    // read-only
    void unlock_write();   // read/write

    // ── Data access ───────────────────────────────────
    unsigned char*       data();
    const unsigned char* data() const;

    size_t capacity() const;
    size_t size() const;

    void set_size(size_t n);

    // ── Helpers ───────────────────────────────────────
    void load_string(const std::string& s);
    std::string to_string() const;

private:
    void*  ptr_;
    size_t capacity_;
    size_t size_;
};