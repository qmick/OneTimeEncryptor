#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include "crypto_io.h"
#include <cstdio>
#include <cstdint>
#include <functional>

class SymmetricCryptor
{
public:
    //The size of buffer reading and writing
    static const auto kMaxInBufferSize = 1024 * 1024;
    static const auto kMaxOutBufferSize = kMaxInBufferSize + EVP_MAX_BLOCK_LENGTH;
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
    int64_t encrypt_file(CryptoIO &dst, CryptoIO &src, std::function<bool(int64_t)> callback);

    /**
     * @brief Read data from `src` and write decrypted data to `dst`
     * @param dst File that decrypted data is written to
     * @param src File that read from
     * @param callback Callback used to send progress and recieve stop signal
     * @return Decrypted data size, -1 if stop by callback
     */
    int64_t decrypt_file(CryptoIO &dst, CryptoIO &src, std::function<bool(int64_t)> callback);

    /**
     * @brief Read data from `src` and write encrypted data to `dst` using public key encryption
     * @param dst File that encrypted data is written to
     * @param src File that read from
     * @param pubk Public key that used to encrypt symmetric key
     * @param callback Callback used to send progress and recieve stop signal
     * @return Encrypted data size, -1 if stopped by callback
     */
    int64_t seal_file(CryptoIO &dst, CryptoIO &src, EVP_PKEY_ptr pubk,
                        std::function<bool(int64_t)> callback);

    /**
     * @brief Read data from `src` and write decrypted data to `dst` using public key decryption
     * @param dst File that encrypted data is written to
     * @param src File that read from
     * @param priv Private key that used to decrypt symmetric key
     * @param callback Callback used to send progress and recieve stop signal
     * @return Decrypted data size, -1 if stopped by callback
     */
    int64_t open_file(CryptoIO &dst, CryptoIO &src, EVP_PKEY_ptr priv,
                        std::function<bool(int64_t)> callback);

    const EVP_CIPHER *get_cipher() const;

private:
    enum { DECRYPTION = 0, ENCRYPTION = 1 };

    const EVP_CIPHER *symmetric_cipher;

    int64_t cipher_file(CryptoIO &dst, CryptoIO &src,
                        std::function<bool(int64_t)> callback, int enc);
};

#endif // CRYPTOR_H
