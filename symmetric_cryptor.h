#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include <cstdio>
#include <cstdint>
#include <functional>

class SymmetricCryptor
{
public:
    //The size of buffer reading and writing
    static const auto kMaxInBufferSize = 1024 * 1024;
    static const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;
    SecureBuffer key;
    SecureBuffer iv;

    SymmetricCryptor();
    explicit SymmetricCryptor(const EVP_CIPHER *cipher);
    explicit SymmetricCryptor(SecureBuffer &secret);
    SymmetricCryptor(SecureBuffer &secret, const EVP_CIPHER *cipher);

    /**
     * @brief Read data from `src` and write encrypted data to `dst`
     * @param dst File that encrypted data is written to
     * @param src File that read from
     * @param callback Callback used to send progress and recieve stop signal
     * @return Encrypted data size, -1 if stop by callback
     */
    int64_t encrypt_file(FILE *dst, FILE *src, std::function<bool(int64_t)> callback);
    int64_t decrypt_file(FILE *dst, FILE *src, std::function<bool(int64_t)> callback);

    int64_t seal_file(FILE *dst, FILE *src, EVP_PKEY_ptr pubk,
                        std::function<bool(int64_t)> callback);
    int64_t open_file(FILE *dst, FILE *src, EVP_PKEY_ptr priv,
                        std::function<bool(int64_t)> callback);

    const EVP_CIPHER *get_cipher() const;

private:
    const EVP_CIPHER *symmetric_cipher;
};

#endif // CRYPTOR_H
