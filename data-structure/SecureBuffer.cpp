#include "SecureBuffer.h"

#include <sodium.h>
#include <cstring>
#include <stdexcept>

// ── Constructor / Destructor ─────────────────────────
SecureBuffer::SecureBuffer(size_t capacity)
: ptr_(nullptr),
    capacity_(capacity == 0 ? 1 : capacity),
    size_(0)
{
ptr_ = sodium_malloc(capacity_);
if (!ptr_) throw std::bad_alloc();

sodium_memzero(ptr_, capacity_);
}

SecureBuffer::~SecureBuffer() {
    if (ptr_) {
        // Guarantee the region is writable so sodium_free can zero it.
        // This is safe even if the buffer is already R/W.
        sodium_mprotect_readwrite(ptr_);
        sodium_free(ptr_);
        ptr_      = nullptr;
        capacity_ = 0;
        size_     = 0;
    }
}

// ── Move semantics ───────────────────────────────────
// When you create a new object from another one.
SecureBuffer::SecureBuffer(SecureBuffer&& o) noexcept
    : ptr_(o.ptr_), capacity_(o.capacity_), size_(o.size_)
{
    // ownershop of the buffer is now transferred to the new object, not copied.
    o.ptr_ = nullptr;
    o.capacity_ = 0;
    o.size_ = 0;
}

//When you assign to an already existing object.
SecureBuffer& SecureBuffer::operator=(SecureBuffer&& o) noexcept {
    if (this != &o) {
        // free existing
        if (ptr_) {
            sodium_mprotect_readwrite(ptr_);
            sodium_free(ptr_);
        }

        ptr_ = o.ptr_;
        capacity_ = o.capacity_;
        size_ = o.size_;

        o.ptr_ = nullptr;
        o.capacity_ = 0;
        o.size_ = 0;
    }
    return *this;
}

// ── Access protection ────────────────────────────────
void SecureBuffer::lock_access() {
    if (ptr_) sodium_mprotect_noaccess(ptr_);
}

void SecureBuffer::unlock_read() {
    if (ptr_) sodium_mprotect_readonly(ptr_);
}

void SecureBuffer::unlock_write() {
    if (ptr_) sodium_mprotect_readwrite(ptr_);
}

// ── Data access ──────────────────────────────────────
unsigned char* SecureBuffer::data() {
    return static_cast<unsigned char*>(ptr_);
}

const unsigned char* SecureBuffer::data() const {
    return static_cast<const unsigned char*>(ptr_);
}

size_t SecureBuffer::capacity() const {
    return capacity_;
}

size_t SecureBuffer::size() const {
    return size_;
}

    
// ── Size management ──────────────────────────────────
// Adjust the live-data count after writing raw bytes via data().
// Asserts capacity so callers can't silently lie about how much is live.
void SecureBuffer::set_size(size_t n) {
    if (n > capacity_) {
        throw std::runtime_error("set_size exceeds capacity");
    }
    size_ = n;
}

// ── Helpers ──────────────────────────────────────────
void SecureBuffer::load_string(const std::string& s) {
    if (s.size() > capacity_) {
        throw std::runtime_error("SecureBuffer too small");
    }

    std::memcpy(ptr_, s.data(), s.size());
    size_ = s.size();
}

// Copy live bytes into a plain std::string for display.
// Requires the buffer to be readable (unlock_read or unlock_write state).
// The caller must wipe the returned string with sodium_memzero() as soon
// as it is no longer needed.
//
// NOTE: this call does NOT change the buffer's protection level.  The
// caller is responsible for calling unlock_read() before this and
// lock_access() afterwards if desired.

std::string SecureBuffer::to_string() const {
    return std::string(reinterpret_cast<const char*>(ptr_), size_);
}

