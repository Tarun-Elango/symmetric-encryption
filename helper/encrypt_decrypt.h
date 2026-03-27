#pragma once

#include <optional>
#include <string>

#include "../data-structure/SecureBuffer.h"

SecureBuffer encrypt_message(const SecureBuffer& plaintext, const SecureBuffer& passphrase);
std::optional<SecureBuffer> decrypt_message(SecureBuffer& payload, const SecureBuffer& passphrase);

SecureBuffer get_passphrase(const std::string& prompt);
SecureBuffer get_passphrase_with_confirmation();

void do_encrypt();
void do_decrypt();
