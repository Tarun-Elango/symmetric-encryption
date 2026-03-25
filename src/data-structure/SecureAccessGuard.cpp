#include "SecureAccessGuard.h"
#include "SecureBuffer.h"  // Must include full definition here

SecureAccessGuard::SecureAccessGuard(SecureBuffer& buf)
    : buf_(buf)
{
    buf_.unlock_read();
}

SecureAccessGuard::~SecureAccessGuard()
{
    // we remembet to close the buffer, rehgardless of the exception
    buf_.lock_access();
}