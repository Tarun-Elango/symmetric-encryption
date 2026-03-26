#include "SecureAccessGuard.h"
#include "SecureBuffer.h"  

SecureAccessGuard::SecureAccessGuard(SecureBuffer& buf)
    : buf_(buf)
{
    // constructor will allow reads
    buf_.unlock_read();
}

SecureAccessGuard::~SecureAccessGuard()
{
    // lock it before the secure buffer wipes it   
    buf_.lock_access();
}
