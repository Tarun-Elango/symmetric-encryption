#include "SecureAccessGuard.h"
#include "SecureBuffer.h"  

SecureAccessGuard::SecureAccessGuard(SecureBuffer& buf)
    : buf_(buf)
{
    // constructor will allow reads
    buf_.unlock_read();
}

SecureAccessGuard::~SecureAccessGuard() noexcept
{
    // Destructors must not throw; best-effort relock.
    try {
        buf_.lock_access();
    } catch (...) {
    }
}
