#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include <cstdio>
#include <functional>

class SymmetricCryptor
{
public:
    static const auto kMaxInBufferSize = 1024 * 1024;
    static const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;

    explicit SymmetricCryptor(SecureBuffer &secret);
    long long encrypt_file(FILE *dst, FILE *src, std::function<bool(long long)> callback);
    long long decrypt_file(FILE *dst, FILE *src, std::function<bool(long long)> callback);

private:
    SecureBuffer key;
    SecureBuffer iv;
};

#endif // CRYPTOR_H
