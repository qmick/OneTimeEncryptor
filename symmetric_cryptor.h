#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include <cstdio>
#include <functional>

class SymmetricCryptor
{
public:
    //The size of buffer reading and writing
    static const auto kMaxInBufferSize = 1024 * 1024;
    static const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;

    explicit SymmetricCryptor(SecureBuffer &secret);

    /**
     * @brief Read data from `src` and write encrypted data to `dst`
     * @param dst File that encrypted data is written to
     * @param src File that read from
     * @param callback Callback used to send progress and recieve stop signal
     * @return Encrypted data size, -1 if stop by callback
     */
    long long encrypt_file(FILE *dst, FILE *src, std::function<bool(long long)> callback);
    long long decrypt_file(FILE *dst, FILE *src, std::function<bool(long long)> callback);

private:
    SecureBuffer key;
    SecureBuffer iv;
};

#endif // CRYPTOR_H